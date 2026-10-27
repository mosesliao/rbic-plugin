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
- Nothing is written here: PolicyAdmin.propose_generated_policy turns the
  result into a Change (validated with the gate's loader, effect
  summary, stale-source refusal) that a human confirms.

Warnings are about the onboarding SOURCES (the access report,
rbic.onboarding.report, describes what the gate will actually enforce,
manual rules included).
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..admin import CHANGES_HEADER, _casbin_tokens
from ..gate import (PTYPE_ALLOW_COLUMNS, PTYPE_ALLOW_ROWS, SCOPE_COLUMN_SEP,
                    check_schema)
from . import catalog_path, roles_path
from .block import find_block, outside_lines, replace_block
from .catalog import Catalog, load_catalog
from .roles import Roles, RolesError, load_roles, validate_roles
from .store import file_sha, sha256_text

READ = "read"
HIGH = "high"


class CompileError(ValueError):
    """The onboarding sources cannot be compiled."""


@dataclass
class GeneratedPolicy:
    body: list                 # block lines (comments + rules), no line ends
    rules: list                # [[ptype, *fields]] in block order
    warnings: list = field(default_factory=list)
    hidden: list = field(default_factory=list)    # "table.column (status)"
    # sha256 (text) of the source files compiled from: catalog, roles, schema
    sources: dict = field(default_factory=dict)

    @property
    def roles(self) -> list:
        return sorted({r[1] for r in self.rules})


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


def compile_policy(catalog: Catalog, roles: Roles, schema: dict, *,
                   usernames: Iterable = ()) -> GeneratedPolicy:
    try:
        validate_roles(roles, catalog, schema, usernames)
    except RolesError as err:
        raise CompileError(f"roles.json: {err}") from None
    approved = _approved(catalog, schema)
    order = {t: i for i, t in enumerate(schema)}
    body, rules, warnings = [], [], []
    reads: dict = {}     # role -> {table: [columns]} (own p grants)
    filtered: dict = {}  # role -> {tables with a 3-field scope}
    scoped_any: dict = {}  # table -> {roles with any scope on it}

    def emit(fields):
        body.append(_line(fields))
        rules.append(fields)

    for name in sorted(roles.roles):
        role = roles.roles[name]
        body.append(f"# role {name} ({role.source})")
        for parent in sorted(role.inherits):
            emit(["g", name, parent])
        own: dict = {}
        for cat in role.categories:
            if not any(c == cat for c in approved.values()):
                warnings.append(f"role {name}: category {cat} has no approved "
                                "column (it grants nothing yet)")
        for table, cols in schema.items():
            for c in cols:
                if approved.get(f"{table}.{c}") in role.categories:
                    emit([PTYPE_ALLOW_COLUMNS, name, f"{table}.{c}", READ])
                    own.setdefault(table, []).append(c)
        reads[name] = own
        filtered[name] = set()
        for scope in sorted(role.row_scopes,
                            key=lambda s: (order[s.table], s.template,
                                           s.columns or ())):
            scoped_any.setdefault(scope.table, set()).add(name)
            if scope.columns is None:
                filtered[name].add(scope.table)
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

    # Row-scope warnings per role LEVEL (the role and what it inherits):
    # same-table 3-field filters OR together across the level in the gate.
    for name in sorted(roles.roles):
        level = roles.level(name)
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
            high = [c for c in tables[table]
                    if catalog.categories.get(approved[f"{table}.{c}"], {})
                    .get("sensitivity") == HIGH]
            if high:
                warnings.append(
                    f"role {name} reads high-sensitivity column(s) "
                    f"{table}.({', '.join(high)}) on ALL rows (no row scope)")
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
    return GeneratedPolicy(body, rules, warnings, hidden)


def build_policy_text(policy_text: str, generated: GeneratedPolicy) -> tuple:
    """(new policy.csv text, notes): `policy_text` with its rbic-init block
    replaced by `generated` (or a new block inserted before the master
    chatbot's section, else at the end). Lines outside the block are kept
    byte for byte; a generated rule that already exists outside the block
    stays there and is left out of the block (noted). Raises BlockError
    on malformed markers."""
    find_block(policy_text)  # malformed markers: refuse before anything
    outside = {tuple(t) for t in map(_casbin_tokens, outside_lines(policy_text))
               if t}
    notes, body = [], []
    for line in generated.body:
        tokens = _casbin_tokens(line)
        if tokens and tuple(tokens) in outside:
            notes.append(f"rule '{line}' already exists in policy.csv outside "
                         "the rbic-init block; kept there and left out of the "
                         "block")
            continue
        body.append(line)
    return replace_block(policy_text, body, before_header=CHANGES_HEADER), notes


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
    return generated


def sources_current(generated: GeneratedPolicy, paths: dict) -> bool:
    """True when every recorded source still has the recorded sha256 (and
    every source was recorded)."""
    return (bool(generated.sources) and set(generated.sources) == set(paths)
            and all(file_sha(paths[k]) == v
                    for k, v in generated.sources.items()))
