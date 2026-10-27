"""rbic-init: onboarding toolkit - the toolkit proposes, a human approves.

    rbic-init schema  --config-dir DIR [--db PATH] [--write --actor NAME]
    rbic-init suggest --config-dir DIR [--no-values] [--sample-rows N]
    rbic-init status  --config-dir DIR
    rbic-init approve --config-dir DIR --actor NAME (COLUMN [CATEGORY] | --all-suggested)
    rbic-init reject  --config-dir DIR --actor NAME COLUMN [COLUMN ...]

Every write is shown first and needs a typed yes/y (any case); no/n
declines, anything else re-asks, EOF declines, and the decision is
audited. db_schema.json is written only through PolicyAdmin (validated
with the gate's loader, locked, changelogged before replace). No data
value is ever printed: suggestions show rule ids, names and counts only.
"""

import argparse
import sys
from datetime import datetime, timezone

from ..admin import MASTER_ROLE, PolicyAdmin
from ..audit import logger as audit
from ..config import ConfigError, resolve_config
from ..master import ask_yes_no
from ..onboarding import catalog_path
from ..onboarding.catalog import (CatalogError, apply_decisions, catalog_status,
                                  check_against_schema, load_catalog,
                                  merge_suggestions, plan_approvals,
                                  plan_rejections, save_catalog)
from ..onboarding.schema import diff_schema, introspect_sqlite, ordered_like
from ..onboarding.suggest import suggest_categories
from . import add_audit_log_argument, setup_logging

APPLY_PROMPT = "Apply? [yes/no]: "
HIDDEN_NOTE = ("hidden from everyone until approved (the generated policy "
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
    return 0


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
    output("Fully approved tables: "
           + (", ".join(st.approved_tables) or "none"))
    if st.partial_tables:
        output("Not fully approved: " + ", ".join(
            f"{t} ({a}/{n})" for t, (a, n) in st.partial_tables.items()))
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
    output(f"APPLIED: {len(plan)} column(s) {action}d in {path}. Only "
           "approved columns will be compiled into policy.csv (rbic-init "
           "compile, the next onboarding step).")
    return 0


def cmd_approve(args, input_fn, output):
    if args.column is None and not args.all_suggested:
        raise CommandError("Give a COLUMN (table.column) or --all-suggested.")
    columns = {args.column: args.category} if args.column else {}
    return _decide(args, input_fn, output,
                   lambda c, s: plan_approvals(c, s, columns,
                                               all_suggested=args.all_suggested),
                   "approve")


def cmd_reject(args, input_fn, output):
    return _decide(args, input_fn, output,
                   lambda c, s: plan_rejections(c, s, args.columns), "reject")


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
                    "column categories, and record a human's approvals. "
                    "Every write needs your yes/no.")
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
    p.add_argument("--actor", required=True,
                   help="master user approving (recorded as approved_by)")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("reject", parents=[common],
                       help="reject column suggestions (asks yes/no)",
                       description="Reject the suggestion for columns: they "
                                   "stay hidden from everyone, and later "
                                   "suggestions never overwrite the decision.")
    p.add_argument("columns", nargs="+", metavar="COLUMN",
                   help="table.column to reject")
    p.add_argument("--actor", required=True,
                   help="master user rejecting (recorded as approved_by)")
    p.set_defaults(func=cmd_reject)
    return parser


def main(argv=None, *, input_fn=input, output=print) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.audit_log)
    try:
        status = args.func(args, input_fn, output)
    except ConfigError as err:
        parser.error(str(err))
    except CommandError as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
    return status


if __name__ == "__main__":
    main()
