"""Compile catalog.json + roles.json into the rbic-init block of policy.csv.

Guarantees (tests: tests/test_onboarding_compile.py):
- Only APPROVED catalog columns become rules. A role gets one
  `p, role, table.column, read` line per approved column of each of its
  categories - never `table.*`, so a column added to the database later
  stays hidden until someone approves it.
- Scoped grants (row scopes with columns) keep only approved columns; a
  scoped grant left with none is dropped (warned).
- `g, role, parent` per inheritance, `p2` per row scope (3 fields, or 4
  with `|`-joined columns). Deterministic order: roles by name, then g,
  p (schema order), p2 (schema order of the table, then template).
- Every rule round-trips Casbin's own tokenizer (rbic.admin's check).
- FAIL CLOSED for sensitive data on all rows: a role whose OWN grants
  include a column of a HIGH-sensitivity category on a table that no row
  scope of its role level limits is refused (CompileError), unless the
  role's roles.json entry acknowledges that table under `all_rows` with a
  reason. The reason is written into the block as a comment
  (`# all_rows <role> <table>: <reason>`), shown in the access report and
  in the change's effect summary. (A role that only INHERITS such columns
  needs no acknowledgement of its own: the ancestor granting them reads
  the table on all rows too, so it had to acknowledge it.) Medium
  sensitivity on all rows is a warning.
- compile_from_files puts a sources header first in the block:
  `# sources: catalog.json, roles.json, db_schema.json sha256=<fp> rbic=<v>`
  (sources_fingerprint), so `rbic-init status`/`drift` can tell a block
  that is out of date, edited by hand, or undone.
- Nothing is written here: PolicyAdmin.propose_generated_policy turns the
  result into a Change (validated with the gate's loader, effect
  summary, stale-source refusal) that a human confirms.

Warnings are about the onboarding SOURCES (the access report,
rbic.onboarding.report, describes what the gate will actually enforce,
manual rules included).
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from ..admin import CHANGES_HEADER, _casbin_tokens
from ..gate import (PTYPE_ALLOW_COLUMNS, PTYPE_ALLOW_ROWS, SCOPE_COLUMN_SEP,
                    check_schema)
from . import catalog_path, roles_path
from .block import find_block, outside_lines, replace_block, split_lines
from .catalog import Catalog, load_catalog
from .roles import Roles, RolesError, load_roles, validate_roles
from .store import file_sha, sha256_text

READ = "read"
HIGH = "high"
MEDIUM = "medium"
# The sources a block is compiled from, in fingerprint order. (worker_
# attributes.json is also read - usernames only, for validation - and its
# hash is checked before applying, but it is not part of the fingerprint:
# importing users does not make the generated block stale.)
FINGERPRINT_SOURCES = ("catalog", "roles", "schema")
HEADER_PREFIX = "# sources: catalog.json, roles.json, db_schema.json"
HEADER_RE = re.compile(
    r"# sources: catalog\.json, roles\.json, db_schema\.json "
    r"sha256=([0-9a-f]{64}) rbic=(\S+)\Z", re.ASCII)
ACK_RE = re.compile(r"# all_rows ([a-z][a-z0-9_]{1,40}) ([a-z_][a-z0-9_]{0,62}): "
                    r"([ -~]+)\Z", re.ASCII)


class CompileError(ValueError):
    """The onboarding sources cannot be compiled."""


@dataclass
class GeneratedPolicy:
    body: list                 # block lines (comments + rules), no line ends
    rules: list                # [[ptype, *fields]] in block order
    warnings: list = field(default_factory=list)
    hidden: list = field(default_factory=list)    # "table.column (status)"
    # sha256 (text) of the source files compiled from: catalog, roles,
    # schema, attributes
    sources: dict = field(default_factory=dict)
    # "role R reads high-sensitivity T.(...) on ALL rows - acknowledged: why"
    acknowledged: list = field(default_factory=list)

    @property
    def roles(self) -> list:
        return sorted({r[1] for r in self.rules})

    @property
    def fingerprint(self) -> Optional[str]:
        return sources_fingerprint(self.sources)


def sources_fingerprint(shas: dict) -> Optional[str]:
    """sha256 over the sha256 of each source's text (catalog.json,
    roles.json, db_schema.json; length-prefixed labels), or None when one
    is missing."""
    if any(not shas.get(k) for k in FINGERPRINT_SOURCES):
        return None
    h = hashlib.sha256(b"rbic-init-sources-v1\0")
    for k in FINGERPRINT_SOURCES:
        h.update(f"{k}\0{shas[k]}\0".encode("ascii"))
    return h.hexdigest()


def header_line(fingerprint: str) -> str:
    from .. import __version__  # rbic/__init__ imports the engine
    return f"{HEADER_PREFIX} sha256={fingerprint} rbic={__version__}"


def block_body(policy_text: str) -> Optional[list]:
    """The lines between the block markers (no line ends), or None when
    policy.csv has no block. Raises BlockError on malformed markers."""
    span = find_block(policy_text)
    if span is None:
        return None
    lines = split_lines(policy_text)[span[0] + 1:span[1]]
    return [line.rstrip("\r\n") for line in lines]


def block_header(policy_text: str) -> Optional[tuple]:
    """(fingerprint, rbic version) recorded in the block's sources header,
    or None (no block, or no header)."""
    body = block_body(policy_text) or []
    for line in body:
        m = HEADER_RE.fullmatch(line.strip())
        if m:
            return m.group(1), m.group(2)
    return None


def acknowledgements(policy_text: str) -> dict:
    """{(role, table): reason} from the `# all_rows` comments inside the
    block (only there: a comment elsewhere acknowledges nothing)."""
    try:
        body = block_body(policy_text) or []
    except ValueError:
        return {}
    out = {}
    for line in body:
        m = ACK_RE.fullmatch(line.strip())
        if m:
            out[(m.group(1), m.group(2))] = m.group(3)
    return out


def _line(fields: list) -> str:
    line = ", ".join(fields)
    if _casbin_tokens(line) != fields:
        raise CompileError(f"rule {line!r} would not round-trip through "
                           "Casbin's policy parser")
    return line


def _approved(catalog: Catalog, schema: dict) -> dict:
    """table.column -> category, for approved columns that exist."""
    out = {}
    for table, cols in schema.items():
        for c in cols:
            e = catalog.columns.get(f"{table}.{c}")
            if e is not None and e.status == "approved" and e.category:
                out[f"{table}.{c}"] = e.category
    return out


def _sensitivity(catalog: Catalog, category) -> Optional[str]:
    return catalog.categories.get(category, {}).get("sensitivity")


def compile_policy(catalog: Catalog, roles: Roles, schema: dict, *,
                   usernames: Iterable = ()) -> GeneratedPolicy:
    try:
        validate_roles(roles, catalog, schema, usernames)
    except RolesError as err:
        raise CompileError(f"roles.json: {err}") from None
    approved = _approved(catalog, schema)
    order = {t: i for i, t in enumerate(schema)}
    body, rules, warnings, acknowledged = [], [], [], []
    reads: dict = {}     # role -> {table: [columns]} (own p grants)
    filtered: dict = {}  # role -> {tables with a 3-field scope}
    scoped_any: dict = {}  # table -> {roles with any scope on it}
    acks: dict = {}      # role -> {table: reason} actually needed

    for name, role in roles.roles.items():
        own: dict = {}
        for table, cols in schema.items():
            for c in cols:
                if approved.get(f"{table}.{c}") in role.categories:
                    own.setdefault(table, []).append(c)
        reads[name] = own
        filtered[name] = {s.table for s in role.row_scopes if s.columns is None}
        for s in role.row_scopes:
            scoped_any.setdefault(s.table, set()).add(name)

    # Row-scope analysis per role LEVEL (the role and what it inherits):
    # same-table 3-field filters OR together across the level in the gate.
    refused = []
    for name in sorted(roles.roles):
        level = roles.level(name)
        role = roles.roles[name]
        tables = {}
        for r in level:
            for t, cols in reads.get(r, {}).items():
                tables.setdefault(t, []).extend(c for c in cols
                                                if c not in tables.get(t, []))
        limited = set().union(*(filtered.get(r, set()) for r in level))
        for table in sorted(tables, key=order.get):
            if table in limited:
                continue
            others = sorted(scoped_any.get(table, set()) - set(level))
            if others:
                warnings.append(
                    f"role {name} reads {table} on ALL rows (no row scope in "
                    f"its role level), while {', '.join(others)} "
                    f"{'has' if len(others) == 1 else 'have'} a row scope "
                    f"on {table}")
            sens = {c: _sensitivity(catalog, approved[f"{table}.{c}"])
                    for c in tables[table]}
            high = [c for c in tables[table] if sens[c] == HIGH]
            own_high = [c for c in reads[name].get(table, []) if sens[c] == HIGH]
            medium = [c for c in tables[table] if sens[c] == MEDIUM]
            if own_high:
                reason = role.acknowledged(table)
                cols = f"{table}.({', '.join(high)})"
                if reason is None:
                    refused.append(
                        f"role {name} would read high-sensitivity column(s) "
                        f"{cols} on ALL rows (no row scope in its role "
                        "level). Add a row scope (rbic-init roles scope "
                        f"{name} {table} \"TEMPLATE\"), or acknowledge it "
                        f"(rbic-init roles all-rows {name} {table} --reason "
                        "\"WHY\")")
                else:
                    acks.setdefault(name, {})[table] = reason
                    acknowledged.append(
                        f"role {name} reads high-sensitivity column(s) {cols} "
                        f"on ALL rows - acknowledged in roles.json: {reason}")
            if medium:
                warnings.append(
                    f"role {name} reads medium-sensitivity column(s) "
                    f"{table}.({', '.join(medium)}) on ALL rows (no row scope)")
        for a in role.all_rows:
            if a.table not in acks.get(name, {}):
                warnings.append(
                    f"role {name}: the all-rows acknowledgement for {a.table} "
                    "is not needed (no high-sensitivity column of it is read "
                    "on all rows through this role's own categories); "
                    "consider removing it")
    if refused:
        raise CompileError(
            "refused - high-sensitivity data on ALL rows needs a row scope or "
            "an explicit acknowledgement: " + "; ".join(refused))

    def emit(fields):
        body.append(_line(fields))
        rules.append(fields)

    for name in sorted(roles.roles):
        role = roles.roles[name]
        body.append(f"# role {name} ({role.source})")
        for parent in sorted(role.inherits):
            emit(["g", name, parent])
        for cat in role.categories:
            if not any(c == cat for c in approved.values()):
                warnings.append(f"role {name}: category {cat} has no approved "
                                "column (it grants nothing yet)")
        for table, cols in schema.items():
            for c in reads[name].get(table, []):
                emit([PTYPE_ALLOW_COLUMNS, name, f"{table}.{c}", READ])
        for scope in sorted(role.row_scopes,
                            key=lambda s: (order[s.table], s.template,
                                           s.columns or ())):
            if scope.columns is None:
                emit([PTYPE_ALLOW_ROWS, name, scope.table, scope.template])
                continue
            keep = [c for c in scope.columns
                    if f"{scope.table}.{c}" in approved]
            dropped = [c for c in scope.columns if c not in keep]
            if dropped:
                warnings.append(
                    f"role {name}: scoped grant on {scope.table} (rows where "
                    f"{scope.template}) leaves out not-approved column(s) "
                    f"{', '.join(dropped)}")
            if not keep:
                warnings.append(f"role {name}: scoped grant on {scope.table} "
                                "has no approved column and is skipped")
                continue
            emit([PTYPE_ALLOW_ROWS, name, scope.table, scope.template,
                  SCOPE_COLUMN_SEP.join(keep)])
        for table in sorted(acks.get(name, {}), key=order.get):
            body.append(f"# all_rows {name} {table}: {acks[name][table]}")
    hidden = []
    for table, cols in schema.items():
        for c in cols:
            key = f"{table}.{c}"
            if key in approved:
                continue
            e = catalog.columns.get(key)
            status = "unlabelled" if e is None or (e.status == "suggested"
                                                   and e.category is None) \
                else e.status
            hidden.append(f"{key} ({status})")
    if hidden:
        warnings.append(f"{len(hidden)} column(s) not approved - hidden from "
                        "every generated rule: " + ", ".join(hidden))
    return GeneratedPolicy(body, rules, warnings, hidden,
                           acknowledged=acknowledged)


def build_policy_text(policy_text: str, generated: GeneratedPolicy) -> tuple:
    """(new policy.csv text, notes): `policy_text` with its rbic-init block
    replaced by `generated` (or a new block inserted before the master
    chatbot's section, else at the end). Lines outside the block are kept
    byte for byte. EVERY generated rule is written inside the block, even
    when an identical line exists outside it (a rule listed twice means
    the same as once to Casbin and the gate): the block's copy is the
    authoritative one, which the master bot can never remove, so removing
    the outside copy can never take away what the onboarding sources
    grant or limit. Such duplicates are noted. Raises BlockError on
    malformed markers."""
    find_block(policy_text)  # malformed markers: refuse before anything
    outside = {tuple(t) for t in map(_casbin_tokens, outside_lines(policy_text))
               if t}
    notes = []
    for line in generated.body:
        tokens = _casbin_tokens(line)
        if tokens and tuple(tokens) in outside:
            notes.append(f"rule '{line}' is also present in policy.csv outside "
                         "the rbic-init block; the generated copy (inside the "
                         "block) is authoritative")
    return (replace_block(policy_text, list(generated.body),
                          before_header=CHANGES_HEADER), notes)


def source_paths(config_dir, schema_path, attributes_path) -> dict:
    """The files a compile reads, by the names GeneratedPolicy.sources uses."""
    return {"catalog": catalog_path(config_dir), "roles": roles_path(config_dir),
            "schema": Path(schema_path), "attributes": Path(attributes_path)}


def compile_from_files(config_dir, schema_path, attributes_path) -> GeneratedPolicy:
    """Load db_schema.json, worker_attributes.json (usernames only),
    catalog.json and roles.json (both must exist) and compile them,
    recording the sha256 of every source so that a proposal built from a
    stale compile is refused (PolicyAdmin.propose_generated_policy, and
    again in apply())."""
    paths = source_paths(config_dir, schema_path, attributes_path)
    for name, hint in (("catalog", "rbic-init suggest / approve"),
                       ("roles", "rbic-init roles add-pack / set")):
        if not paths[name].exists():
            raise CompileError(f"{paths[name]} does not exist yet (create it "
                               f"with {hint})")
    texts = {k: paths[k].read_text(encoding="utf-8")
             for k in ("schema", "attributes")}
    try:
        schema = check_schema(json.loads(texts["schema"]))
        attributes = json.loads(texts["attributes"])
    except ValueError as err:
        raise CompileError(f"cannot read db_schema.json / "
                           f"worker_attributes.json: {err}") from None
    usernames = sorted(attributes) if isinstance(attributes, dict) else []
    catalog, csha = load_catalog(paths["catalog"], schema)
    roles, rsha = load_roles(paths["roles"], catalog=catalog, schema=schema,
                             usernames=usernames)
    generated = compile_policy(catalog, roles, schema, usernames=usernames)
    generated.sources = {"catalog": csha, "roles": rsha,
                         "schema": sha256_text(texts["schema"]),
                         "attributes": sha256_text(texts["attributes"])}
    generated.body.insert(0, header_line(generated.fingerprint))
    return generated


def current_fingerprint(config_dir, schema_path) -> Optional[str]:
    """The sources fingerprint of the files as they are now (None when
    catalog.json or roles.json does not exist)."""
    paths = {"catalog": catalog_path(config_dir),
             "roles": roles_path(config_dir), "schema": Path(schema_path)}
    return sources_fingerprint({k: file_sha(p) for k, p in paths.items()})


def sources_current(generated: GeneratedPolicy, paths: dict) -> bool:
    """True when every recorded source still has the recorded sha256 (and
    every source was recorded)."""
    return (bool(generated.sources) and set(generated.sources) == set(paths)
            and all(file_sha(paths[k]) == v
                    for k, v in generated.sources.items()))
