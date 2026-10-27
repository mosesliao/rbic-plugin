"""rbic-init: onboarding toolkit - the toolkit proposes, a human approves.

    rbic-init schema  --config-dir DIR [--db PATH] [--write --actor NAME]
    rbic-init suggest --config-dir DIR [--no-values] [--sample-rows N]
    rbic-init status  --config-dir DIR
    rbic-init approve --config-dir DIR --actor NAME (COLUMN [CATEGORY] | --all-suggested)
                      [--downgrade-reason TEXT]
    rbic-init reject  --config-dir DIR --actor NAME COLUMN [COLUMN ...]
    rbic-init roles show|packs --config-dir DIR
    rbic-init roles add-pack NAME --config-dir DIR --actor NAME
    rbic-init roles set ROLE [--categories a,b] [--inherits x,y]
                             [--description TEXT] --config-dir DIR --actor NAME
    rbic-init roles scope ROLE TABLE "TEMPLATE" [--columns a,b] [--remove]
                             --config-dir DIR --actor NAME
    rbic-init roles all-rows ROLE TABLE (--reason TEXT | --remove)
                             --config-dir DIR --actor NAME
    rbic-init roles remove ROLE --config-dir DIR --actor NAME
    rbic-init import-users --config-dir DIR --csv FILE --actor NAME
                           [--group-map PATH] [--team-depth direct|all]
                           [--remove-missing]
    rbic-init import-users --config-dir DIR --undo --actor NAME
    rbic-init compile --config-dir DIR --actor NAME [--report PATH]
    rbic-init report  --config-dir DIR [--out PATH]
    rbic-init drift   --config-dir DIR [--db PATH] [--json]   # exit 0/1/2

Every write is shown first and needs a typed yes/y (any case); no/n
declines, anything else re-asks, EOF declines, and the decision is
audited. db_schema.json and policy.csv are written only through
PolicyAdmin (validated with the gate's loader, locked, changelogged
before replace). No data value is ever printed: suggestions show rule
ids, names and counts only; the access report names roles, usernames,
columns and rule templates, never a value or an email. import-users is
the HR / IdP channel (the only one that may set emails): it prints a
per-user summary with emails masked, never the diff.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from ..admin import MASTER_ROLE, PolicyAdmin
from ..audit import logger as audit
from ..config import ConfigError, resolve_config
from ..master import ask_yes_no
from ..onboarding import catalog_path, report_path, roles_path
from ..onboarding.block import BlockError
from ..onboarding.catalog import (CatalogError, apply_decisions, catalog_status,
                                  check_against_schema, load_catalog,
                                  merge_suggestions, plan_approvals,
                                  plan_rejections, save_catalog)
from ..onboarding.compile import (CompileError, build_policy_text,
                                  compile_from_files)
from ..onboarding.drift import (IN_SYNC, NOT_ONBOARDED, READABLE_VIA,
                                block_state, check_drift)
from ..onboarding.report import readable_from_files, report_from_bytes
from ..onboarding.roles import (RolesError, RowScope, add_scope, list_packs,
                                load_pack, load_roles, merge_pack,
                                remove_all_rows, remove_role, remove_scope,
                                save_roles, set_all_rows, set_role)
from ..onboarding.users import (TEAM_DEPTHS, UserImportError, group_map_path,
                                load_group_map, parse_csv, plan_import,
                                user_rules)
from ..onboarding.schema import diff_schema, introspect_sqlite, ordered_like
from ..onboarding.suggest import suggest_categories
from . import add_audit_log_argument, setup_logging

APPLY_PROMPT = "Apply? [yes/no]: "
HIDDEN_NOTE = ("not granted by the generated policy until approved (it "
               "grants approved columns only)")


class CommandError(Exception):
    """A refused command: printed as 'Error: ...', exit status 1."""


def _config(args):
    return resolve_config(args.config_dir, db_path=getattr(args, "db", None))


def _owner(admin, actor):
    """The actor must be a master user: the organization's policy owner
    (PolicyAdmin.apply() re-checks this under the lock for policy files)."""
    if not actor:
        raise CommandError("--actor NAME (a master user) is required to "
                           "write anything.")
    record = admin.attributes().get(actor)
    if not isinstance(record, dict) or record.get("role") != MASTER_ROLE:
        raise CommandError(f"{actor!r} is not a master user; rbic-init writes "
                           "need the organization's policy owner (a worker "
                           "with role 'master' in worker_attributes.json).")


# ----------------------------------------------------------------------
# schema
# ----------------------------------------------------------------------

def cmd_schema(args, input_fn, output):
    cfg = _config(args)
    admin = PolicyAdmin.from_config(cfg)
    notes = []
    try:
        found = introspect_sqlite(cfg.db_path, notes)
    except FileNotFoundError as err:
        raise CommandError(str(err)) from None
    current = admin.schema()
    diff = diff_schema(current, found)
    output(f"Database: {cfg.db_path}")
    output(f"Introspected {len(found)} table(s)/view(s), "
           f"{sum(map(len, found.values()))} column(s).")
    for note in notes:
        output(f"note: {note}")
    if diff.empty:
        output("db_schema.json is up to date.")
        return 0
    output("Differences from db_schema.json:")
    for line in diff.lines(found):
        output(f"  - {line}")
    if not args.write:
        output("(dry run: pass --write --actor NAME to update db_schema.json)")
        return 0
    _owner(admin, args.actor)
    try:
        change = admin.propose_schema_update(ordered_like(current, found),
                                             actor=args.actor)
    except ValueError as err:
        raise CommandError(f"Refused: {err}") from None
    output(f"\n--- Proposed change {change.id} ({change.kind}) ---")
    output(change.description)
    output(change.diff() or "(no textual difference)")
    confirmed = ask_yes_no(input_fn, output, APPLY_PROMPT)
    audit.info("POLICY_CONFIRM change=%s actor=%s decision=%s", change.id,
               args.actor, "confirmed" if confirmed else "declined")
    if not confirmed:
        output(f"Change {change.id} declined; nothing was written.")
        return 0
    try:
        admin.apply(change, actor=args.actor)
    except (ValueError, OSError) as err:
        raise CommandError(f"Change {change.id} was NOT applied: {err}") from None
    output(f"Change {change.id} APPLIED. The gate uses the new db_schema.json "
           "on its next request.")
    return 0


# ----------------------------------------------------------------------
# catalog: suggest / status / approve / reject
# ----------------------------------------------------------------------

def _load(cfg):
    schema = PolicyAdmin.from_config(cfg).schema()
    path = catalog_path(cfg.config_dir)
    try:
        catalog, sha = load_catalog(path, schema)
    except CatalogError as err:
        raise CommandError(f"{path}: {err}") from None
    return schema, path, catalog, sha


def _table(rows, headers):
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    return [fmt.format(*headers).rstrip(),
            *(fmt.format(*map(str, r)).rstrip() for r in rows)]


def cmd_suggest(args, input_fn, output):
    cfg = _config(args)
    schema, path, catalog, sha = _load(cfg)
    notes = []
    use_values = not args.no_values
    try:
        suggestions = suggest_categories(
            schema, db_path=cfg.db_path if use_values else None,
            sample_rows=args.sample_rows, use_values=use_values,
            categories=catalog.categories, notes=notes)
        merged, result = merge_suggestions(catalog, suggestions)
        save_catalog(path, merged, sha)
    except (CatalogError, ValueError) as err:
        raise CommandError(str(err)) from None
    audit.info("CATALOG_SUGGEST file=%s added=%d updated=%d kept=%d values=%s",
               path, len(result.added), len(result.updated), len(result.kept),
               "sampled" if use_values else "off")
    rows = []
    for s in suggestions:
        e = merged.columns[s.column]
        conf = "" if e.confidence is None else f"{e.confidence:.2f}"
        rows.append((s.column, e.status, e.category or "-", conf, e.evidence))
    for line in _table(rows, ("COLUMN", "STATUS", "CATEGORY", "CONF",
                              "EVIDENCE")):
        output(line)
    for note in notes:
        output(f"note: {note}")
    output(f"\nWrote {path}: {len(result.added)} added, {len(result.updated)} "
           f"updated, {len(result.kept)} human decision(s) kept.")
    st = catalog_status(merged, schema)
    if st.unlabelled_columns:
        output(f"Unlabelled ({HIDDEN_NOTE}): "
               + ", ".join(st.unlabelled_columns))
    output(f"{st.hidden} column(s) not approved: {HIDDEN_NOTE}. Review them, "
           "then: rbic-init approve --actor NAME (COLUMN [CATEGORY] | "
           "--all-suggested)")
    _readable_note(cfg, merged, schema, output)
    return 0


def _readable_note(cfg, catalog, schema, output):
    """Which not-approved columns are readable anyway (rules outside the
    rbic-init block, from the gate's snapshot) and which are hidden from
    everyone - never claim "hidden" for a column a role can read."""
    try:
        readers = readable_from_files(
            _bytes(cfg.model_path), _bytes(cfg.policy_path),
            _bytes(cfg.attributes_path), _bytes(cfg.schema_path),
            dialect=cfg.dialect)
    except Exception:  # noqa: BLE001 - whatever the gate refuses
        output("The current policy does not load in the SQL gate: everyone "
               "is denied (run rbic-init drift).")
        return
    readable, hidden = [], 0
    for table, cols in schema.items():
        for column in cols:
            e = catalog.columns.get(f"{table}.{column}")
            if e is not None and e.status == "approved":
                continue
            who = readers.get((table, column))
            if who:
                readable.append(f"{table}.{column} ({', '.join(who)})")
            else:
                hidden += 1
    if readable:
        output(f"WARNING: {len(readable)} not-approved column(s) are READABLE "
               f"now {READABLE_VIA}: " + "; ".join(readable))
    output(f"{hidden} not-approved column(s) are hidden from everyone (no "
           "role or user can read them).")


def cmd_status(args, input_fn, output):
    cfg = _config(args)
    schema, path, catalog, sha = _load(cfg)
    if sha is None:
        output(f"No catalog yet ({path}). Run: rbic-init suggest")
    st = catalog_status(catalog, schema)
    total = sum(map(len, schema.values()))
    output(f"Columns: {total} in db_schema.json")
    output(f"  approved:   {st.approved}")
    output(f"  suggested:  {st.suggested} (awaiting approval)")
    output(f"  rejected:   {st.rejected}")
    output(f"  unlabelled: {st.unlabelled}")
    output(f"{st.hidden} column(s) {HIDDEN_NOTE}.")
    _readable_note(cfg, catalog, schema, output)
    output("Fully approved tables: "
           + (", ".join(st.approved_tables) or "none"))
    if st.partial_tables:
        output("Not fully approved: " + ", ".join(
            f"{t} ({a}/{n})" for t, (a, n) in st.partial_tables.items()))
    state, messages = block_state(cfg)
    label = {IN_SYNC: "in sync", NOT_ONBOARDED: "not generated yet"}.get(
        state, state.replace("_", " ").upper())
    output(f"Generated block (policy.csv): {label}")
    for m in messages:
        output(f"  {m}")
    return 0


def _decide(args, input_fn, output, decisions, action):
    cfg = _config(args)
    admin = PolicyAdmin.from_config(cfg)
    _owner(admin, args.actor)
    schema, path, catalog, sha = _load(cfg)
    try:
        plan = decisions(catalog, schema)
    except CatalogError as err:
        raise CommandError(str(err)) from None
    output(f"Proposed {action} of {len(plan)} column(s) in {path}:")
    for d in plan:
        output(f"  - {d.describe()}")
    confirmed = ask_yes_no(input_fn, output, APPLY_PROMPT)
    audit.info("CATALOG_CONFIRM actor=%s action=%s columns=%d decision=%s",
               args.actor, action, len(plan),
               "confirmed" if confirmed else "declined")
    if not confirmed:
        output("Declined; nothing was written.")
        return 0
    try:
        updated = apply_decisions(catalog, plan, args.actor,
                                  datetime.now(timezone.utc))
        check_against_schema(updated, schema)
        new_sha = save_catalog(path, updated, sha)
    except CatalogError as err:
        raise CommandError(f"Nothing was written: {err}") from None
    audit.info("CATALOG_CHANGE actor=%s action=%s columns=%d file=%s "
               "sha256=%s", args.actor, action, len(plan), path, new_sha)
    for d in plan:
        if d.downgraded_from is not None:
            audit.warning("CATALOG_DOWNGRADE actor=%s column=%s from=%s to=%s "
                          "reason=%s", args.actor, d.column, d.downgraded_from,
                          d.category, d.downgrade_reason)
    output(f"APPLIED: {len(plan)} column(s) {action}d in {path}. Only "
           "approved columns will be compiled into policy.csv (rbic-init "
           "compile, the next onboarding step).")
    return 0


def cmd_approve(args, input_fn, output):
    if args.column is None and not args.all_suggested:
        raise CommandError("Give a COLUMN (table.column) or --all-suggested.")
    columns = {args.column: args.category} if args.column else {}
    return _decide(args, input_fn, output,
                   lambda c, s: plan_approvals(
                       c, s, columns, all_suggested=args.all_suggested,
                       downgrade_reason=args.downgrade_reason),
                   "approve")


def cmd_reject(args, input_fn, output):
    return _decide(args, input_fn, output,
                   lambda c, s: plan_rejections(c, s, args.columns), "reject")


# ----------------------------------------------------------------------
# roles.json
# ----------------------------------------------------------------------

def _roles_state(cfg):
    """(admin, schema, catalog, catalog sha, usernames, path, roles, sha)."""
    admin = PolicyAdmin.from_config(cfg)
    schema, _, catalog, csha = _load(cfg)
    usernames = sorted(admin.attributes())
    path = roles_path(cfg.config_dir)
    try:
        roles, sha = load_roles(path, catalog=catalog, schema=schema,
                                usernames=usernames)
    except RolesError as err:
        raise CommandError(f"{path}: {err}") from None
    return admin, schema, catalog, csha, usernames, path, roles, sha


def _show_role(name, role, output):
    output(f"{name}  [{role.source}]  {role.description}".rstrip())
    output(f"  categories: {', '.join(role.categories) or '-'}")
    output(f"  inherits:   {', '.join(role.inherits) or '-'}")
    for scope in role.row_scopes:
        output(f"  scope:      {scope.describe()}")


def cmd_roles_show(args, input_fn, output):
    cfg = _config(args)
    *_, path, roles, sha = _roles_state(cfg)
    if sha is None:
        output(f"No roles yet ({path}). Start with: rbic-init roles add-pack "
               f"NAME (packs: {', '.join(list_packs())})")
        return 0
    output(f"{path}: {len(roles.roles)} role(s); packs: "
           f"{', '.join(sorted(roles.packs)) or 'none'}")
    for name in sorted(roles.roles):
        _show_role(name, roles.roles[name], output)
    return 0


def cmd_roles_packs(args, input_fn, output):
    for name in list_packs():
        try:
            pack = load_pack(name)
        except RolesError as err:
            raise CommandError(str(err)) from None
        output(f"{pack.ref}: {pack.description}")
        for rname, r in pack.roles.items():
            extra = f", inherits {', '.join(r.inherits)}" if r.inherits else ""
            output(f"  {rname}: categories {', '.join(r.categories) or '-'}"
                   f"{extra}")
            for rule in r.scopes:
                kind = (f"scoped grant of {', '.join(rule.grant_categories)}"
                        if rule.grant_categories else "row filter")
                output(f"    {kind} on tables with column "
                       f"{'/'.join(rule.ownership_columns)}: {rule.template}")
    return 0


def _roles_write(args, input_fn, output, plan):
    """Show a roles.json edit, ask yes/no, save it (stale-safe), audit."""
    cfg = _config(args)
    admin, schema, catalog, csha, usernames, path, roles, sha = _roles_state(cfg)
    _owner(admin, args.actor)
    try:
        new, lines = plan(roles, catalog, csha, schema, usernames)
    except RolesError as err:
        raise CommandError(str(err)) from None
    output(f"Proposed change to {path}:")
    for line in lines:
        output(f"      {line.strip()}" if line.startswith("  ") else f"  - {line}")
    confirmed = ask_yes_no(input_fn, output, APPLY_PROMPT)
    audit.info("ROLES_CONFIRM actor=%s action=%s decision=%s", args.actor,
               args.roles_command, "confirmed" if confirmed else "declined")
    if not confirmed:
        output("Declined; nothing was written.")
        return 0
    try:
        new_sha = save_roles(path, new, sha, catalog=catalog, schema=schema,
                             usernames=usernames)
    except RolesError as err:
        raise CommandError(f"Nothing was written: {err}") from None
    audit.info("ROLES_CHANGE actor=%s action=%s roles=%d file=%s sha256=%s",
               args.actor, args.roles_command, len(new.roles), path, new_sha)
    output(f"APPLIED: {path} updated. Nothing changes in policy.csv until "
           "you run: rbic-init compile --actor NAME")
    return 0


def _csv(text):
    return [] if text is None or not text.strip() else \
        [x.strip() for x in text.split(",") if x.strip()]


def cmd_roles_add_pack(args, input_fn, output):
    def plan(roles, catalog, csha, schema, usernames):
        if csha is None:
            raise RolesError("onboarding/catalog.json does not exist yet: run "
                             "rbic-init suggest (and approve) first - a pack's "
                             "row scopes are derived from the catalog")
        pack = load_pack(args.name)
        new, merge = merge_pack(roles, pack, catalog, schema, usernames)
        lines = [f"add pack {pack.ref}"]
        for name in merge.added:
            lines.append(f"add role {name}")
        for name in merge.updated:
            lines.append(f"refresh role {name} (defined by this pack)")
        for name in merge.unchanged:
            lines.append(f"role {name} unchanged")
        for name, why in merge.conflicts:
            lines.append(f"CONFLICT role {name}: {why}")
        for name in [*merge.added, *merge.updated]:
            role = new.roles[name]
            lines.append(f"  {name}: categories {', '.join(role.categories) or '-'}"
                         f"; inherits {', '.join(role.inherits) or '-'}")
            lines += [f"  {name}: {s.describe()}" for s in role.row_scopes]
        lines += [f"skipped: {n}" for n in merge.notes]
        if new.to_json() == roles.to_json():
            raise RolesError(f"pack {pack.ref} is already in roles.json with "
                             "nothing to change"
                             + ("".join(f"; CONFLICT {n}: {w}"
                                        for n, w in merge.conflicts)))
        return new, lines
    return _roles_write(args, input_fn, output, plan)


def cmd_roles_set(args, input_fn, output):
    def plan(roles, catalog, csha, schema, usernames):
        if args.categories is None and args.inherits is None \
                and args.description is None:
            raise RolesError("give --categories, --inherits and/or "
                             "--description")
        return set_role(roles, args.role,
                        categories=None if args.categories is None
                        else _csv(args.categories),
                        inherits=None if args.inherits is None
                        else _csv(args.inherits),
                        description=args.description)
    return _roles_write(args, input_fn, output, plan)


def cmd_roles_scope(args, input_fn, output):
    def plan(roles, catalog, csha, schema, usernames):
        columns = _csv(args.columns) if args.columns is not None else None
        if columns == []:
            raise RolesError("--columns needs at least one column")
        scope = RowScope(args.table, args.template.strip(),
                         tuple(columns) if columns else None)
        return (remove_scope if args.remove else add_scope)(roles, args.role,
                                                             scope)
    return _roles_write(args, input_fn, output, plan)


def cmd_roles_all_rows(args, input_fn, output):
    def plan(roles, catalog, csha, schema, usernames):
        if args.remove == (args.reason is not None):
            raise RolesError("give --reason TEXT to acknowledge, or --remove")
        if args.table not in schema:
            raise RolesError(f"unknown table {args.table!r} (not in "
                             "db_schema.json)")
        if args.remove:
            return remove_all_rows(roles, args.role, args.table)
        return set_all_rows(roles, args.role, args.table, args.reason)
    return _roles_write(args, input_fn, output, plan)


def cmd_roles_remove(args, input_fn, output):
    return _roles_write(args, input_fn, output,
                        lambda roles, *_: remove_role(roles, args.role))


# ----------------------------------------------------------------------
# compile / report
# ----------------------------------------------------------------------

def _catalog_or_none(cfg, schema):
    path = catalog_path(cfg.config_dir)
    if not path.exists():
        return None
    try:
        return load_catalog(path, schema)[0]
    except CatalogError as err:
        raise CommandError(f"{path}: {err}") from None


def _bytes(path) -> bytes:
    return Path(path).read_bytes()


def cmd_compile(args, input_fn, output):
    cfg = _config(args)
    admin = PolicyAdmin.from_config(cfg)
    _owner(admin, args.actor)
    try:
        generated = compile_from_files(cfg.config_dir, cfg.schema_path,
                                       cfg.attributes_path)
    except (CompileError, CatalogError, RolesError) as err:
        raise CommandError(f"Cannot compile: {err}") from None
    schema = admin.schema()
    catalog = _catalog_or_none(cfg, schema)
    with open(cfg.policy_path, encoding="utf-8", newline="") as f:
        before = f.read()  # exactly as PolicyAdmin reads it (CRLF kept)
    try:
        after, notes = build_policy_text(before, generated)
    except BlockError as err:
        raise CommandError(f"policy.csv: {err}") from None
    rules = sum(1 for line in generated.body if not line.startswith("#"))
    output(f"Compiled {rules} rule(s) for {len(generated.roles)} role(s) from "
           "approved catalog columns and roles.json.")
    for n in notes:
        output(f"info: {n}")
    for w in generated.warnings:
        output(f"warning: {w}")
    if after == before:
        output("policy.csv already holds exactly this compiled policy; "
               "nothing to change.")
        return 0
    try:
        change = admin.propose_generated_policy(generated, actor=args.actor)
    except ValueError as err:
        raise CommandError(f"Refused: {err}") from None
    report = report_from_bytes(
        _bytes(cfg.model_path), change.after_text.encode("utf-8"),
        _bytes(cfg.attributes_path), _bytes(cfg.schema_path), catalog,
        dialect=cfg.dialect, title="Access report (proposed policy)",
        status=f"Proposed change {change.id}: not in force unless a master "
               "user confirmed it (see policy_changes.jsonl).")
    out_path = Path(args.report) if args.report else report_path(cfg.config_dir)
    output("\n" + report)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    output(f"(access report written to {out_path})")
    output(f"\n--- Proposed change {change.id} ({change.kind}) ---")
    output(change.description)
    output(change.diff() or "(no textual difference)")
    confirmed = ask_yes_no(input_fn, output, APPLY_PROMPT)
    audit.info("POLICY_CONFIRM change=%s actor=%s decision=%s", change.id,
               args.actor, "confirmed" if confirmed else "declined")
    if not confirmed:
        output(f"Change {change.id} declined; nothing was written.")
        return 0
    try:
        admin.apply(change, actor=args.actor)
    except (ValueError, OSError) as err:
        raise CommandError(f"Change {change.id} was NOT applied: {err}") from None
    output(f"Change {change.id} APPLIED. The gate enforces the new policy on "
           "its next request.")
    return 0


# ----------------------------------------------------------------------
# import-users (the HR / IdP channel)
# ----------------------------------------------------------------------

def _confirm_and_apply(args, input_fn, output, admin, change, done):
    confirmed = ask_yes_no(input_fn, output, APPLY_PROMPT)
    audit.info("POLICY_CONFIRM change=%s actor=%s decision=%s", change.id,
               args.actor, "confirmed" if confirmed else "declined")
    if not confirmed:
        output(f"Change {change.id} declined; nothing was written.")
        return 0
    try:
        admin.apply(change, actor=args.actor)
    except (ValueError, OSError) as err:
        raise CommandError(f"Change {change.id} was NOT applied: {err}") from None
    output(f"Change {change.id} APPLIED. {done}")
    return 0


def _show_import(change, output):
    output(f"\n--- Proposed change {change.id} ({change.kind}) ---")
    output(change.description)
    output("(the file diff is not shown: worker_attributes.json holds emails "
           "and attribute values; review the summary above)")


def cmd_import_users(args, input_fn, output):
    cfg = _config(args)
    admin = PolicyAdmin.from_config(cfg)
    _owner(admin, args.actor)
    done = ("The engine uses the new worker records on its next request "
            "(every open conversation resets once).")
    if args.undo:
        if args.csv or args.remove_missing:
            raise CommandError("--undo takes no --csv / --remove-missing.")
        try:
            change = admin.propose_undo(actor=args.actor, identity_channel=True)
        except ValueError as err:
            raise CommandError(f"Refused: {err}") from None
        _show_import(change, output)
        return _confirm_and_apply(args, input_fn, output, admin, change, done)
    if not args.csv:
        raise CommandError("--csv FILE (the HR / IdP export) is required.")
    try:
        data = Path(args.csv).read_bytes()
    except OSError as err:
        raise CommandError(f"cannot read {args.csv}: {err.strerror}") from None
    current = admin.attributes()
    known = {r["role"] for r in admin.list_roles()}
    rpath = roles_path(cfg.config_dir)
    if rpath.exists():
        try:
            known |= set(load_roles(rpath)[0].roles)
        except RolesError as err:
            raise CommandError(f"{rpath}: {err}") from None
    gpath = Path(args.group_map) if args.group_map \
        else group_map_path(cfg.config_dir)
    try:
        parsed = parse_csv(data)
        group_map = load_group_map(gpath, known_roles=known,
                                   usernames=[r.username for r in parsed.rows])
        plan = plan_import(current, parsed, group_map, known_roles=known,
                           team_depth=args.team_depth,
                           remove_missing=args.remove_missing,
                           rules_by_user=user_rules(admin._enforcer()))
    except UserImportError as err:
        raise CommandError(str(err)) from None
    output(f"Export: {plan.rows} row(s), delimiter {parsed.delimiter!r}, "
           f"columns: {', '.join(parsed.columns)}")
    output(f"Group map: {gpath} ({len(group_map)} mapping(s))")
    output(plan.headline())
    try:
        change = admin.propose_user_import(plan.attributes, actor=args.actor,
                                           headline=plan.headline(),
                                           extra_notes=plan.notes)
    except ValueError as err:
        raise CommandError(f"Refused: {err}") from None
    _show_import(change, output)
    return _confirm_and_apply(args, input_fn, output, admin, change, done)


# ----------------------------------------------------------------------
# drift
# ----------------------------------------------------------------------

def cmd_drift(args, input_fn, output):
    cfg = _config(args)
    try:
        report = check_drift(cfg, db_path=args.db)
    except Exception as err:  # noqa: BLE001 - exit 2: the check itself failed
        if args.json:
            output(json.dumps({"status": "error", "exit_code": 2,
                               "error": f"{type(err).__name__}: {err}"}))
        else:
            output(f"Error: drift check failed: {type(err).__name__}: {err}")
        return 2
    if args.json:
        output(json.dumps(report.to_json(), indent=2))
    else:
        for line in report.lines():
            output(line)
    return report.exit_code


def cmd_report(args, input_fn, output):
    cfg = _config(args)
    schema = PolicyAdmin.from_config(cfg).schema()
    catalog = _catalog_or_none(cfg, schema)
    try:
        report = report_from_bytes(
            _bytes(cfg.model_path), _bytes(cfg.policy_path),
            _bytes(cfg.attributes_path), _bytes(cfg.schema_path), catalog,
            dialect=cfg.dialect, title="Access report (current policy)")
    except Exception as err:  # noqa: BLE001 - whatever the gate refuses
        raise CommandError(f"The current policy does not load in the SQL gate "
                           f"(the gate denies everyone): {type(err).__name__}: "
                           f"{err}") from None
    output(report)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        output(f"(written to {args.out})")
    return 0


# ----------------------------------------------------------------------
# argument parsing
# ----------------------------------------------------------------------

def _sample_rows(text):
    try:
        n = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer") from None
    if not 1 <= n <= 10000:
        raise argparse.ArgumentTypeError("must be in 1..10000")
    return n


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config-dir",
                        help="policy/config directory (default: $RBIC_CONFIG_DIR)")
    add_audit_log_argument(common)

    parser = argparse.ArgumentParser(
        prog="rbic-init",
        description="Onboarding toolkit: introspect the schema, suggest "
                    "column categories, record a human's approvals, define "
                    "roles, import workers from the IdP / HR export, compile "
                    "them into policy.csv, and check for drift. Every write "
                    "needs your yes/no. Guide: docs/onboarding.md.")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND",
                                required=True)

    p = sub.add_parser("schema", parents=[common],
                       help="introspect the database; diff/update db_schema.json",
                       description="Introspect the database (read-only) and "
                                   "show how it differs from db_schema.json; "
                                   "with --write, update db_schema.json after "
                                   "your yes (validated with the gate's loader).")
    p.add_argument("--db", help="SQLite database (default: $RBIC_DB_PATH or "
                                "<config-dir>/company.db)")
    p.add_argument("--write", action="store_true",
                   help="propose the update and apply it on yes")
    p.add_argument("--actor", help="master user making the change "
                                   "(required with --write)")
    p.set_defaults(func=cmd_schema)

    p = sub.add_parser("suggest", parents=[common],
                       help="suggest a data category per column into "
                            "onboarding/catalog.json",
                       description="Suggest a category per column from name "
                                   "rules and (unless --no-values) local "
                                   "value rules; merge them into "
                                   "onboarding/catalog.json as 'suggested'. "
                                   "Approved/rejected entries are never "
                                   "changed. No data value is printed or "
                                   "stored.")
    p.add_argument("--db", help="SQLite database to sample (default: "
                                "$RBIC_DB_PATH or <config-dir>/company.db)")
    p.add_argument("--no-values", action="store_true",
                   help="use name rules only; do not read any row")
    p.add_argument("--sample-rows", type=_sample_rows, default=200,
                   metavar="N", help="non-null values sampled per column "
                                     "(default 200)")
    p.set_defaults(func=cmd_suggest)

    p = sub.add_parser("status", parents=[common],
                       help="approval progress of onboarding/catalog.json",
                       description="Count approved/suggested/rejected/"
                                   "unlabelled columns and list fully "
                                   "approved tables.")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("approve", parents=[common],
                       help="approve column categories (asks yes/no)",
                       description="Approve one column (with its suggested "
                                   "category, or the CATEGORY you give) or "
                                   "every suggested column. Only approved "
                                   "columns are ever compiled into policy.")
    p.add_argument("column", nargs="?", metavar="COLUMN",
                   help="table.column to approve")
    p.add_argument("category", nargs="?", metavar="CATEGORY",
                   help="category to approve it as (default: the suggestion)")
    p.add_argument("--all-suggested", action="store_true",
                   help="approve every suggested column that has a category")
    p.add_argument("--downgrade-reason", metavar="TEXT",
                   help="required when CATEGORY is less sensitive than the "
                        "suggested one (printable ASCII, at most 200 chars; "
                        "recorded in catalog.json, the audit log, compile "
                        "output and the access report)")
    p.add_argument("--actor", required=True,
                   help="master user approving (recorded as approved_by)")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("reject", parents=[common],
                       help="reject column suggestions (asks yes/no)",
                       description="Reject the suggestion for columns: the "
                                   "generated policy never grants them, and later "
                                   "suggestions never overwrite the decision.")
    p.add_argument("columns", nargs="+", metavar="COLUMN",
                   help="table.column to reject")
    p.add_argument("--actor", required=True,
                   help="master user rejecting (recorded as approved_by)")
    p.set_defaults(func=cmd_reject)

    roles = sub.add_parser(
        "roles", help="edit onboarding/roles.json (roles x categories, "
                      "inheritance, row scopes, starter packs)",
        description="Show or edit onboarding/roles.json. Every write asks "
                    "yes/no and needs --actor (a master user); nothing "
                    "changes in policy.csv until rbic-init compile.")
    rsub = roles.add_subparsers(dest="roles_command", metavar="ACTION",
                                required=True)
    r = rsub.add_parser("show", parents=[common], help="show roles.json",
                        description="Show every role in roles.json.")
    r.set_defaults(func=cmd_roles_show)
    r = rsub.add_parser("packs", parents=[common],
                        help="list the starter packs shipped with rbic",
                        description="List the starter packs and what they "
                                    "define.")
    r.set_defaults(func=cmd_roles_packs)
    actor = argparse.ArgumentParser(add_help=False)
    actor.add_argument("--actor", required=True,
                       help="master user making the change")
    r = rsub.add_parser("add-pack", parents=[common, actor],
                        help="merge a starter pack into roles.json",
                        description="Instantiate a starter pack against "
                                    "db_schema.json and catalog.json (scopes "
                                    "only on tables that have the ownership "
                                    "column; skipped tables are reported) "
                                    "and merge it. Roles a human edited or "
                                    "another pack defined are never "
                                    "overwritten (reported as conflicts).")
    r.add_argument("name", metavar="NAME", help="pack name (see roles packs)")
    r.set_defaults(func=cmd_roles_add_pack)
    r = rsub.add_parser("set", parents=[common, actor],
                        help="create or update a role",
                        description="Create a role (--categories required, "
                                    "may be empty) or update one; the role "
                                    "becomes human-owned (packs never "
                                    "overwrite it).")
    r.add_argument("role", metavar="ROLE")
    r.add_argument("--categories", metavar="A,B",
                   help="comma-separated catalog categories (replaces the list)")
    r.add_argument("--inherits", metavar="X,Y",
                   help="comma-separated parent roles (replaces the list)")
    r.add_argument("--description", help="what the role is for")
    r.set_defaults(func=cmd_roles_set)
    r = rsub.add_parser("scope", parents=[common, actor],
                        help="add (or --remove) a row scope of a role",
                        description="Add a row filter on TABLE (a p2 template "
                                    "such as \"dept = '{dept}'\"), or with "
                                    "--columns a scoped grant (those columns, "
                                    "for those rows). Templates follow the "
                                    "master bot's strict rules; a template "
                                    "without a {placeholder} is static (the "
                                    "same rows for every user) and is "
                                    "warned about.")
    r.add_argument("role", metavar="ROLE")
    r.add_argument("table", metavar="TABLE")
    r.add_argument("template", metavar="TEMPLATE")
    r.add_argument("--columns", metavar="A,B",
                   help="make it a scoped grant of these columns")
    r.add_argument("--remove", action="store_true",
                   help="remove this exact scope instead of adding it")
    r.set_defaults(func=cmd_roles_scope)
    r = rsub.add_parser("remove", parents=[common, actor],
                        help="remove a role from roles.json",
                        description="Remove a role (refused while another "
                                    "role inherits it).")
    r.add_argument("role", metavar="ROLE")
    r.set_defaults(func=cmd_roles_remove)
    r = rsub.add_parser("all-rows", parents=[common, actor],
                        help="acknowledge that a role reads a table on ALL "
                             "rows (needed for high-sensitivity columns)",
                        description="rbic-init compile refuses a role that "
                                    "would read a high-sensitivity category "
                                    "of TABLE with no row scope bound from "
                                    "the user's attributes in its role level "
                                    "(none, or only static ones such as "
                                    "'id > 0'), or through a static scoped "
                                    "grant, unless the role acknowledges it "
                                    "here with a reason (recorded in the "
                                    "generated block and the access report).")
    r.add_argument("role", metavar="ROLE")
    r.add_argument("table", metavar="TABLE")
    r.add_argument("--reason", help="why this role needs every row "
                                    "(printable ASCII, at most 200 chars)")
    r.add_argument("--remove", action="store_true",
                   help="remove the acknowledgement instead")
    r.set_defaults(func=cmd_roles_all_rows)

    p = sub.add_parser("compile", parents=[common],
                       help="compile approved columns + roles.json into "
                            "policy.csv's rbic-init block (asks yes/no)",
                       description="Compile approved catalog columns and "
                                   "roles.json into the rbic-init block of "
                                   "policy.csv (named columns, never "
                                   "table.*; lines outside the block are "
                                   "kept), print warnings, the access report "
                                   "and the diff with its effect summary, "
                                   "and apply through PolicyAdmin on yes.")
    p.add_argument("--actor", required=True,
                   help="master user applying the change")
    p.add_argument("--report", metavar="PATH",
                   help="where to write the access report (default: "
                        "<config-dir>/onboarding/access-report.md)")
    p.set_defaults(func=cmd_compile)

    p = sub.add_parser("import-users", parents=[common],
                       help="import workers from an IdP / HR CSV export "
                            "(asks yes/no)",
                       description="Import workers from an IdP / HR CSV "
                                   "export into worker_attributes.json: the "
                                   "HR / IdP channel, the only one that may "
                                   "set emails. Roles come from the groups "
                                   "column through group_map.json (first "
                                   "mapped group wins; unmapped workers get "
                                   "no role and are denied). Masters are "
                                   "never touched. Shows a per-user summary "
                                   "(emails masked), asks yes/no, applies "
                                   "through PolicyAdmin. CSV rules: see "
                                   "docs/onboarding.md.")
    p.add_argument("--csv", metavar="FILE",
                   help="the export (UTF-8; ',' or ';' delimited; header with "
                        "username, email[, groups, employee_id, manager, "
                        "attributes...])")
    p.add_argument("--actor", required=True,
                   help="master user applying the import")
    p.add_argument("--group-map", metavar="PATH",
                   help="IdP group -> role map (default: "
                        "<config-dir>/onboarding/group_map.json)")
    p.add_argument("--team-depth", choices=TEAM_DEPTHS, default="direct",
                   help="self_and_subordinate_ids from the manager column: "
                        "direct reports only (default) or all levels")
    p.add_argument("--remove-missing", action="store_true",
                   help="remove existing workers that are not in the export "
                        "(refused while they hold personal user: rules)")
    p.add_argument("--undo", action="store_true",
                   help="undo the last import instead (it must be the most "
                        "recent change)")
    p.set_defaults(func=cmd_import_users)

    p = sub.add_parser("drift", parents=[common],
                       help="check for drift (exit 0 clean, 1 drift, 2 error)",
                       description="Compare the live database with "
                                   "db_schema.json, catalog coverage, the "
                                   "generated block with its sources, "
                                   "roles.json with the schema/catalog, and "
                                   "workers with roles. Exit 0: clean, 1: "
                                   "drift found, 2: error. Never prints data "
                                   "values or emails.")
    p.add_argument("--db", help="SQLite database (default: $RBIC_DB_PATH or "
                                "<config-dir>/company.db)")
    p.add_argument("--json", action="store_true",
                   help="machine-readable output")
    p.set_defaults(func=cmd_drift)

    p = sub.add_parser("report", parents=[common],
                       help="access report for the current live policy",
                       description="Print the plain-language access report "
                                   "for the policy in force (no changes): "
                                   "what each role reads, which rows, "
                                   "denies, hidden columns, warnings.")
    p.add_argument("--out", metavar="PATH", help="also write it to PATH")
    p.set_defaults(func=cmd_report)
    return parser


def console(stream=None):
    """A print() that never fails on the console's encoding: characters it
    cannot encode (a Cyrillic table name on a cp1252 console) are written
    as backslash escapes instead of raising UnicodeEncodeError."""
    def write(text="", file=None):
        target = file or stream or sys.stdout
        encoding = getattr(target, "encoding", None) or "ascii"
        text = str(text)
        try:
            text.encode(encoding)
        except UnicodeEncodeError:
            text = text.encode(encoding, "backslashreplace").decode(encoding)
        except LookupError:
            text = text.encode("ascii", "backslashreplace").decode("ascii")
        print(text, file=target)
    return write


def main(argv=None, *, input_fn=input, output=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.audit_log)
    output = output or console()
    try:
        status = args.func(args, input_fn, output)
    except ConfigError as err:
        parser.error(str(err))
    except CommandError as err:
        console(sys.stderr)(f"Error: {err}")
        sys.exit(1)
    return status


if __name__ == "__main__":
    main()
