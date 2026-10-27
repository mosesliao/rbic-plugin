"""roles.json: the roles x categories grid, and the starter packs behind it.

    {
      "version": 1,
      "roles": {
        "hr_staff": {
          "description": "HR staff: directory, leave and training ...",
          "categories": ["directory", "leave", "training"],
          "inherits": ["employee"],
          "row_scopes": [
            {"table": "employees", "template": "dept = '{dept}'"},
            {"table": "payroll", "template": "employee_id = '{employee_id}'",
             "columns": ["id", "employee_id", "salary"]}     # scoped grant
          ],
          "all_rows": [                                      # optional
            {"table": "invoices", "reason": "AP clerks settle every invoice"}
          ],
          "source": "pack:hr"                                # or "human"
        }
      },
      "packs": ["hr@1"]
    }

A role reads every APPROVED column of its categories (rbic.onboarding
.compile); `row_scopes` become p2 rules: without `columns` a row filter
(3-field p2), with `columns` a scoped grant (4-field p2: exactly those
columns, for those rows, no other grant needed). Validation is strict:
role names follow the gate's rules (never `master`, never a `user:`
subject, never a username), inheritance names roles defined here and is
acyclic, categories exist in catalog.json, tables/columns exist in
db_schema.json, templates compile with the master bot's strict rules in
every dialect. Saved atomically under the onboarding lock, refusing a
file that changed since it was read.

`all_rows` is the explicit acknowledgement the compiler demands before a
role may read a HIGH-sensitivity category on a table without a row scope
bound from the user's attributes in its role level (none at all, or only
STATIC ones such as `employee_id > 0`, which give every user the same
rows), or through a static scoped grant (else `rbic-init compile`
refuses): one entry per table, with a non-empty printable-ASCII reason
that is recorded in the generated block and shown in the access report.
Packs never set it.

Starter packs (rbic/onboarding/packs/*.json, shipped in the wheel)
describe row ownership by COLUMN NAME ("scope tables that have a column
named dept/department by `$column = '{dept}'`") and are instantiated
against the actual schema and catalog: a pack never puts a scope on a
table that lacks the column, and reports every table it skipped.
Merging a pack never overwrites a role a human edited (or another pack
defined); those are reported as conflicts.

Library code: no terminal I/O.
"""

import copy
import json
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Iterable, Optional

from ..admin import FILTER_DIALECTS, MASTER_ROLE, ROLE_RE
from ..gate import (SCOPE_COLUMN_SEP, STATIC_FILTER_WARNING, USER_PREFIX,
                    FilterError, _placeholder_names, compile_row_filter,
                    parse_scope_columns)
from .catalog import CATEGORY_RE, Catalog
from .store import atomic_save, sha256_text

ROLES_VERSION = 1
PACK_FORMAT = 1
DESCRIPTION_MAX = 200
HUMAN = "human"
SOURCE_RE = re.compile(r"(?:pack:[a-z][a-z0-9_]{1,40}|human)\Z", re.ASCII)
PACK_NAME_RE = re.compile(r"[a-z][a-z0-9_]{1,40}\Z", re.ASCII)
PACK_VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z.]{0,19}\Z", re.ASCII)
PACK_REF_RE = re.compile(r"([a-z][a-z0-9_]{1,40})@([0-9A-Za-z][0-9A-Za-z.]{0,19})\Z",
                         re.ASCII)
COLUMN_TOKEN = "$column"
NAME_RE = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z", re.ASCII)


class RolesError(ValueError):
    """roles.json or a starter pack is invalid, or an edit was refused."""


@dataclass(frozen=True)
class RowScope:
    table: str
    template: str
    columns: Optional[tuple] = None  # None: row filter; else a scoped grant

    def to_json(self) -> dict:
        out = {"table": self.table, "template": self.template}
        if self.columns is not None:
            out["columns"] = list(self.columns)
        return out

    @property
    def static(self) -> bool:
        """No {placeholder}: the same rows for every user (`employee_id >
        0`, `status = 'unpaid'`) - it does not limit anyone to their own
        rows, so it never counts as a row limit for high-sensitivity data."""
        return not _placeholder_names(self.template)

    def describe(self) -> str:
        if self.columns is None:
            return f"rows of {self.table} where {self.template}"
        return (f"scoped grant on {self.table}.({', '.join(self.columns)}) "
                f"for rows where {self.template}")


@dataclass(frozen=True)
class AllRows:
    """A human's acknowledgement that a role reads a high-sensitivity
    category of `table` on ALL rows (no row scope)."""
    table: str
    reason: str

    def to_json(self) -> dict:
        return {"table": self.table, "reason": self.reason}


@dataclass
class RoleDef:
    description: str = ""
    categories: list = field(default_factory=list)
    inherits: list = field(default_factory=list)
    row_scopes: list = field(default_factory=list)  # [RowScope]
    source: str = HUMAN
    all_rows: list = field(default_factory=list)    # [AllRows]

    def to_json(self) -> dict:
        out = {"description": self.description,
               "categories": list(self.categories),
               "inherits": list(self.inherits),
               "row_scopes": [s.to_json() for s in self.row_scopes],
               "source": self.source}
        if self.all_rows:  # omitted when empty: older files stay byte-stable
            out["all_rows"] = [a.to_json() for a in self.all_rows]
        return out

    def acknowledged(self, table: str) -> Optional[str]:
        """The all-rows reason for `table`, or None."""
        return next((a.reason for a in self.all_rows if a.table == table),
                    None)

    def same_content(self, other: "RoleDef") -> bool:
        a, b = self.to_json(), other.to_json()
        a.pop("source"), b.pop("source")
        return a == b


@dataclass
class Roles:
    roles: dict = field(default_factory=dict)  # name -> RoleDef
    packs: list = field(default_factory=list)  # ["hr@1", ...]
    version: int = ROLES_VERSION

    def to_json(self) -> dict:
        return {"version": self.version,
                "roles": {k: self.roles[k].to_json() for k in sorted(self.roles)},
                "packs": sorted(self.packs)}

    def to_text(self) -> str:
        return json.dumps(self.to_json(), indent=2) + "\n"

    def copy(self) -> "Roles":
        return copy.deepcopy(self)

    def ancestors(self, name: str) -> list:
        """Every role `name` inherits from, directly or not (sorted)."""
        seen, todo = set(), list(self.roles.get(name, RoleDef()).inherits)
        while todo:
            r = todo.pop()
            if r not in seen:
                seen.add(r)
                todo.extend(self.roles.get(r, RoleDef()).inherits)
        return sorted(seen)

    def level(self, name: str) -> list:
        """The role and everything it inherits (the gate's role level)."""
        return [name, *self.ancestors(name)]


# ----------------------------------------------------------------------
# validation
# ----------------------------------------------------------------------

def _printable(text) -> bool:
    return isinstance(text, str) and all(" " <= c <= "~" for c in text)


def check_role_name(name, usernames: Iterable = (), what: str = "role") -> None:
    """The gate's role-name rules, as the master bot applies them."""
    if isinstance(name, str) and name.startswith(USER_PREFIX):
        raise RolesError(f"{name!r} is a user subject, not a {what}; roles.json "
                         "holds roles (groups) only - personal rules belong "
                         "to the master bot")
    if not isinstance(name, str) or not ROLE_RE.fullmatch(name):
        raise RolesError(f"invalid {what} name {name!r}: lowercase letters, "
                         "digits and underscores (2-41 chars, starting with a "
                         "letter)")
    if name == MASTER_ROLE:
        raise RolesError("the 'master' role manages policy and has no data "
                         "access; it cannot be defined in roles.json")
    if name in set(usernames):
        raise RolesError(f"{name!r} is a username, not a {what}: roles are "
                         "groups (e.g. hr_staff)")


def _names(raw, where: str, regex=CATEGORY_RE) -> list:
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise RolesError(f"{where} must be a list of names")
    if len(set(raw)) != len(raw):
        raise RolesError(f"{where} has duplicates")
    for x in raw:
        if not regex.fullmatch(x):
            raise RolesError(f"{where}: invalid name {x!r}")
    return list(raw)


def check_template(table: str, template, schema: dict) -> str:
    """A scope template must pass the master bot's strict rules in every
    dialect (no subqueries/other tables/comments/tautologies)."""
    if not isinstance(template, str) or not template.strip():
        raise RolesError(f"row scope on {table}: template must be a non-empty "
                         "string")
    template = template.strip()
    for dialect in FILTER_DIALECTS:
        try:
            compile_row_filter(table, template, schema, dialect=dialect,
                               strict=True)
        except FilterError as err:
            raise RolesError(f"row scope on {table} ({template}): {err}") from None
    return template


def _scope(raw, where: str, schema: Optional[dict]) -> RowScope:
    if not isinstance(raw, dict):
        raise RolesError(f"{where} must be an object")
    unknown = sorted(set(raw) - {"table", "template", "columns"})
    if unknown:
        raise RolesError(f"{where}: unknown field(s) {', '.join(unknown)}")
    table, template = raw.get("table"), raw.get("template")
    if not isinstance(table, str) or not NAME_RE.fullmatch(table):
        raise RolesError(f"{where}: invalid table {table!r}")
    if not isinstance(template, str):
        raise RolesError(f"{where}: template must be a string")
    columns = None
    if "columns" in raw:
        columns = tuple(_names(raw["columns"], f"{where}.columns", NAME_RE))
        if not columns:
            raise RolesError(f"{where}.columns must not be empty (omit it for "
                             "a plain row filter)")
    if schema is not None:
        if table not in schema:
            raise RolesError(f"{where}: unknown table {table!r} (not in "
                             "db_schema.json)")
        template = check_template(table, template, schema)
        if columns is not None:
            try:
                parse_scope_columns(table, SCOPE_COLUMN_SEP.join(columns), schema)
            except FilterError as err:
                raise RolesError(f"{where}: {err}") from None
    return RowScope(table, template.strip(), columns)


def check_reason(reason, where: str) -> str:
    """An all-rows reason: non-empty printable ASCII (it is written into a
    policy.csv comment line), at most DESCRIPTION_MAX characters."""
    if not isinstance(reason, str) or not _printable(reason) \
            or not reason.strip() or len(reason) > DESCRIPTION_MAX:
        raise RolesError(f"{where}: reason must be non-empty printable ASCII, "
                         f"at most {DESCRIPTION_MAX} characters")
    return reason.strip()


def _all_rows(raw, where: str, schema: Optional[dict]) -> list:
    if not isinstance(raw, list):
        raise RolesError(f"{where} must be a list")
    out = []
    for i, entry in enumerate(raw):
        w = f"{where}[{i}]"
        if not isinstance(entry, dict) or set(entry) != {"table", "reason"}:
            raise RolesError(f"{w} must be an object with exactly table and "
                             "reason")
        table = entry["table"]
        if not isinstance(table, str) or not NAME_RE.fullmatch(table):
            raise RolesError(f"{w}: invalid table {table!r}")
        if schema is not None and table not in schema:
            raise RolesError(f"{w}: unknown table {table!r} (not in "
                             "db_schema.json)")
        if any(a.table == table for a in out):
            raise RolesError(f"{where}: table {table} is listed twice")
        out.append(AllRows(table, check_reason(entry["reason"], w)))
    return out


def _role(name: str, raw, schema: Optional[dict]) -> RoleDef:
    where = f"roles[{name!r}]"
    if not isinstance(raw, dict):
        raise RolesError(f"{where} must be an object")
    allowed = {"description", "categories", "inherits", "row_scopes", "source",
               "all_rows"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise RolesError(f"{where}: unknown field(s) {', '.join(unknown)}")
    description = raw.get("description", "")
    if not _printable(description) or len(description) > DESCRIPTION_MAX:
        raise RolesError(f"{where}: description must be printable ASCII, at "
                         f"most {DESCRIPTION_MAX} characters")
    source = raw.get("source", HUMAN)
    if not isinstance(source, str) or not SOURCE_RE.fullmatch(source):
        raise RolesError(f"{where}: source must be 'human' or 'pack:<name>'")
    scopes_raw = raw.get("row_scopes", [])
    if not isinstance(scopes_raw, list):
        raise RolesError(f"{where}.row_scopes must be a list")
    scopes = [_scope(s, f"{where}.row_scopes[{i}]", schema)
              for i, s in enumerate(scopes_raw)]
    if len(set(scopes)) != len(scopes):
        raise RolesError(f"{where}.row_scopes has duplicates")
    return RoleDef(description,
                   _names(raw.get("categories", []), f"{where}.categories"),
                   _names(raw.get("inherits", []), f"{where}.inherits", ROLE_RE),
                   scopes, source,
                   _all_rows(raw.get("all_rows", []), f"{where}.all_rows",
                             schema))


def validate_roles(roles: Roles, catalog: Optional[Catalog] = None,
                   schema: Optional[dict] = None,
                   usernames: Iterable = ()) -> None:
    """Every cross-reference: names, inheritance (defined, acyclic),
    categories (catalog.json), tables/columns/templates (db_schema.json).
    Raises RolesError."""
    usernames = set(usernames)
    for name, role in roles.roles.items():
        check_role_name(name, usernames)
        for parent in role.inherits:
            check_role_name(parent, usernames, "parent role")
            if parent == name:
                raise RolesError(f"role {name} cannot inherit from itself")
            if parent not in roles.roles:
                raise RolesError(f"role {name} inherits {parent!r}, which "
                                 "roles.json does not define")
        if catalog is not None:
            unknown = [c for c in role.categories if c not in catalog.categories]
            if unknown:
                raise RolesError(f"role {name}: unknown category(ies) "
                                 f"{', '.join(unknown)} (catalog.json defines "
                                 f"{', '.join(sorted(catalog.categories))})")
        if schema is not None:
            for i, s in enumerate(role.row_scopes):
                _scope(s.to_json(), f"roles[{name!r}].row_scopes[{i}]", schema)
            _all_rows([a.to_json() for a in role.all_rows],
                      f"roles[{name!r}].all_rows", schema)
    # acyclic (depth-first, colours)
    state: dict = {}

    def visit(n, path):
        if state.get(n) == "done":
            return
        if state.get(n) == "active":
            cycle = path[path.index(n):] + [n]
            raise RolesError("inheritance cycle: " + " -> ".join(cycle))
        state[n] = "active"
        for p in roles.roles[n].inherits:
            visit(p, path + [n])
        state[n] = "done"

    for n in sorted(roles.roles):
        visit(n, [])
    for ref in roles.packs:
        if not isinstance(ref, str) or not PACK_REF_RE.fullmatch(ref):
            raise RolesError(f"packs: invalid entry {ref!r} (expected "
                             "name@version)")
    if len({PACK_REF_RE.fullmatch(r).group(1) for r in roles.packs}) \
            != len(roles.packs):
        raise RolesError("packs: a pack is listed twice")


def parse_roles(text: str, *, catalog: Optional[Catalog] = None,
                schema: Optional[dict] = None, usernames: Iterable = ()) -> Roles:
    try:
        raw = json.loads(text)
    except ValueError as err:
        raise RolesError(f"roles.json is not valid JSON: {err}") from None
    if not isinstance(raw, dict):
        raise RolesError("roles.json must be an object")
    unknown = sorted(set(raw) - {"version", "roles", "packs"})
    if unknown:
        raise RolesError(f"roles.json: unknown field(s) {', '.join(unknown)}")
    if raw.get("version") != ROLES_VERSION:
        raise RolesError(f"roles.json: version must be {ROLES_VERSION}")
    if not isinstance(raw.get("roles"), dict):
        raise RolesError("roles.json: roles must be an object")
    packs = raw.get("packs", [])
    if not isinstance(packs, list):
        raise RolesError("roles.json: packs must be a list")
    roles = Roles({}, list(packs))
    for name, entry in raw["roles"].items():
        check_role_name(name, usernames)
        roles.roles[name] = _role(name, entry, schema)
    validate_roles(roles, catalog, schema, usernames)
    return roles


def load_roles(path, *, catalog: Optional[Catalog] = None,
               schema: Optional[dict] = None, usernames: Iterable = ()) -> tuple:
    """(Roles, sha256 of the file text) - or (empty Roles, None) when the
    file does not exist yet."""
    path = Path(path)
    if not path.exists():
        return Roles(), None
    text = path.read_text(encoding="utf-8")
    return (parse_roles(text, catalog=catalog, schema=schema,
                        usernames=usernames), sha256_text(text))


def save_roles(path, roles: Roles, expected_sha: Optional[str], *,
               catalog: Optional[Catalog] = None, schema: Optional[dict] = None,
               usernames: Iterable = ()) -> str:
    """Validate and write roles.json atomically; returns the new sha256.
    Nothing is written if the file changed since it was read."""
    text = roles.to_text()
    parse_roles(text, catalog=catalog, schema=schema, usernames=usernames)
    return atomic_save(path, text, expected_sha, what="roles",
                       error=RolesError)


# ----------------------------------------------------------------------
# edits (pure: return a new Roles plus a description; never mutate)
# ----------------------------------------------------------------------

def set_role(roles: Roles, name: str, *, categories=None, inherits=None,
             description=None) -> tuple:
    """Create or update a role (it becomes human-owned). Returns
    (new Roles, [description lines])."""
    out = roles.copy()
    current = out.roles.get(name)
    if current is None:
        if categories is None:
            raise RolesError(f"role {name} does not exist yet: give "
                             "--categories (may be empty) to create it")
        current = RoleDef()
        lines = [f"create role {name}"]
    else:
        lines = [f"update role {name} (was {current.source})"]
    role = copy.deepcopy(current)
    if categories is not None:
        lines.append(f"categories: {', '.join(role.categories) or '-'} -> "
                     f"{', '.join(categories) or '-'}")
        role.categories = list(categories)
    if inherits is not None:
        lines.append(f"inherits: {', '.join(role.inherits) or '-'} -> "
                     f"{', '.join(inherits) or '-'}")
        role.inherits = list(inherits)
    if description is not None:
        lines.append(f"description: {description!r}")
        role.description = description
    role.source = HUMAN
    if name in roles.roles and role.to_json() == roles.roles[name].to_json():
        raise RolesError(f"role {name} already has these settings")
    out.roles[name] = role
    return out, lines


def add_scope(roles: Roles, name: str, scope: RowScope) -> tuple:
    out = roles.copy()
    role = out.roles.get(name)
    if role is None:
        raise RolesError(f"unknown role {name!r} (create it with roles set)")
    if scope in role.row_scopes:
        raise RolesError(f"role {name} already has {scope.describe()}")
    role.row_scopes.append(scope)
    role.source = HUMAN
    lines = [f"role {name}: add {scope.describe()}"]
    if scope.static:
        lines.append(f"{STATIC_FILTER_WARNING} A static scope does not count "
                     "as a row limit for high-sensitivity columns: rbic-init "
                     "compile still needs a scope bound from the user's "
                     f"attributes, or an all-rows acknowledgement for "
                     f"{scope.table}.")
    return out, lines


def remove_scope(roles: Roles, name: str, scope: RowScope) -> tuple:
    out = roles.copy()
    role = out.roles.get(name)
    if role is None:
        raise RolesError(f"unknown role {name!r}")
    if scope not in role.row_scopes:
        current = "; ".join(s.describe() for s in role.row_scopes) or "none"
        raise RolesError(f"role {name} has no {scope.describe()} (its scopes: "
                         f"{current})")
    role.row_scopes.remove(scope)
    role.source = HUMAN
    lines = [f"role {name}: remove {scope.describe()}"]
    if scope.columns is None:
        lines.append(f"WARNING: unless another scope of {name}'s role level "
                     f"limits {scope.table}, {name} reads ALL rows of it")
    return out, lines


def set_all_rows(roles: Roles, name: str, table: str, reason: str) -> tuple:
    """Acknowledge that role `name` reads `table` on ALL rows (needed for
    high-sensitivity columns without a row scope). Replaces an existing
    reason for that table; the role becomes human-owned."""
    out = roles.copy()
    role = out.roles.get(name)
    if role is None:
        raise RolesError(f"unknown role {name!r} (create it with roles set)")
    reason = check_reason(reason, f"role {name} all_rows {table}")
    old = role.acknowledged(table)
    if old == reason:
        raise RolesError(f"role {name} already acknowledges {table} with "
                         "this reason")
    role.all_rows = sorted([a for a in role.all_rows if a.table != table]
                           + [AllRows(table, reason)], key=lambda a: a.table)
    role.source = HUMAN
    verb = "replace" if old is not None else "add"
    return out, [f"role {name}: {verb} the acknowledgement that it reads "
                 f"{table} on ALL rows (reason: {reason})",
                 "WARNING: rbic-init compile then no longer refuses "
                 f"high-sensitivity columns of {table} without a row scope "
                 f"for {name}"]


def remove_all_rows(roles: Roles, name: str, table: str) -> tuple:
    out = roles.copy()
    role = out.roles.get(name)
    if role is None:
        raise RolesError(f"unknown role {name!r}")
    if role.acknowledged(table) is None:
        raise RolesError(f"role {name} has no all-rows acknowledgement for "
                         f"{table}")
    role.all_rows = [a for a in role.all_rows if a.table != table]
    role.source = HUMAN
    return out, [f"role {name}: remove the all-rows acknowledgement for "
                 f"{table} (compile refuses its high-sensitivity columns "
                 "without a row scope again)"]


def remove_role(roles: Roles, name: str) -> tuple:
    if name not in roles.roles:
        raise RolesError(f"unknown role {name!r}")
    heirs = sorted(r for r, d in roles.roles.items() if name in d.inherits)
    if heirs:
        raise RolesError(f"role {name} is inherited by {', '.join(heirs)}; "
                         "change their --inherits first")
    out = roles.copy()
    del out.roles[name]
    return out, [f"remove role {name} (its generated rules disappear on the "
                 "next rbic-init compile)"]


# ----------------------------------------------------------------------
# starter packs
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class ScopeRule:
    """A pack's row-ownership rule, by column name."""
    ownership_columns: tuple
    template: str              # contains $column
    grant_categories: Optional[tuple] = None   # set: scoped grant
    explain: str = ""


@dataclass
class PackRole:
    description: str
    categories: list
    inherits: list
    scopes: list               # [ScopeRule]


@dataclass
class Pack:
    name: str
    version: str
    description: str
    roles: dict                # name -> PackRole

    @property
    def ref(self) -> str:
        return f"{self.name}@{self.version}"


def _pack_dir():
    return resources.files("rbic.onboarding").joinpath("packs")


def list_packs() -> list:
    """Names of the starter packs shipped with rbic (sorted)."""
    return sorted(p.name[:-5] for p in _pack_dir().iterdir()
                  if p.name.endswith(".json"))


def parse_pack(text: str, name: str) -> Pack:
    try:
        raw = json.loads(text)
    except ValueError as err:
        raise RolesError(f"pack {name}: not valid JSON: {err}") from None
    where = f"pack {name}"
    if not isinstance(raw, dict) or set(raw) - {"format", "name", "version",
                                                "description", "roles"}:
        raise RolesError(f"{where}: unexpected structure")
    if raw.get("format") != PACK_FORMAT or raw.get("name") != name:
        raise RolesError(f"{where}: format must be {PACK_FORMAT} and name "
                         f"{name!r}")
    version = raw.get("version")
    if not isinstance(version, str) or not PACK_VERSION_RE.fullmatch(version):
        raise RolesError(f"{where}: invalid version {version!r}")
    description = raw.get("description", "")
    if not _printable(description) or len(description) > DESCRIPTION_MAX:
        raise RolesError(f"{where}: invalid description")
    if not isinstance(raw.get("roles"), dict) or not raw["roles"]:
        raise RolesError(f"{where}: roles must be a non-empty object")
    roles = {}
    for rname, r in raw["roles"].items():
        check_role_name(rname)
        rw = f"{where} role {rname}"
        if not isinstance(r, dict) or set(r) - {"description", "categories",
                                                "inherits", "row_scopes"}:
            raise RolesError(f"{rw}: unexpected structure")
        rdesc = r.get("description", "")
        if not _printable(rdesc) or len(rdesc) > DESCRIPTION_MAX:
            raise RolesError(f"{rw}: invalid description")
        scopes = []
        for i, s in enumerate(r.get("row_scopes", [])):
            sw = f"{rw} row_scopes[{i}]"
            if not isinstance(s, dict) or set(s) - {
                    "ownership_columns", "template", "grant_categories",
                    "explain"}:
                raise RolesError(f"{sw}: unexpected structure")
            owners = _names(s.get("ownership_columns"), f"{sw}.ownership_columns",
                            NAME_RE)
            template = s.get("template")
            if not owners or not isinstance(template, str) \
                    or COLUMN_TOKEN not in template or not _printable(template):
                raise RolesError(f"{sw}: needs ownership_columns and a "
                                 f"printable template containing {COLUMN_TOKEN}")
            grant = s.get("grant_categories")
            if grant is not None:
                grant = tuple(_names(grant, f"{sw}.grant_categories"))
                if not grant:
                    raise RolesError(f"{sw}.grant_categories must not be empty")
            explain = s.get("explain", "")
            if not _printable(explain) or len(explain) > DESCRIPTION_MAX:
                raise RolesError(f"{sw}: invalid explain")
            scopes.append(ScopeRule(tuple(owners), template, grant, explain))
        roles[rname] = PackRole(
            rdesc, _names(r.get("categories", []), f"{rw}.categories"),
            _names(r.get("inherits", []), f"{rw}.inherits", ROLE_RE), scopes)
    for rname, r in roles.items():
        for parent in r.inherits:
            if parent not in roles:
                raise RolesError(f"{where} role {rname} inherits {parent!r}, "
                                 "which the pack does not define")
    return Pack(name, version, description, roles)


def load_pack(name: str) -> Pack:
    if not isinstance(name, str) or not PACK_NAME_RE.fullmatch(name) \
            or name not in list_packs():
        raise RolesError(f"unknown starter pack {name!r}; available: "
                         f"{', '.join(list_packs())}")
    text = _pack_dir().joinpath(f"{name}.json").read_text(encoding="utf-8")
    return parse_pack(text, name)


def _columns_in(catalog: Catalog, table: str, cols, categories) -> list:
    """Columns of `table` whose catalog category is in `categories` and
    that are not rejected (approved or still suggested: the compiler
    grants approved ones only, so a later approval needs no re-add)."""
    out = []
    for c in cols:
        e = catalog.columns.get(f"{table}.{c}")
        if e is not None and e.status != "rejected" and e.category in categories:
            out.append(c)
    return out


def instantiate_pack(pack: Pack, catalog: Catalog, schema: dict) -> tuple:
    """({role: RoleDef}, [notes]) for `pack` against this schema/catalog.

    A ScopeRule without grant_categories becomes a row filter on every
    table that has one of its ownership columns AND holds columns of the
    role's own categories; with grant_categories, a scoped grant (those
    categories' columns of the table) on every table that has an
    ownership column. Tables lacking the column are skipped and noted."""
    notes = []
    out = {}
    for rname, prole in pack.roles.items():
        unknown = sorted({*prole.categories,
                          *(c for s in prole.scopes for c in s.grant_categories or ())}
                         - set(catalog.categories))
        if unknown:
            raise RolesError(f"pack {pack.name} role {rname} uses category(ies) "
                             f"{', '.join(unknown)} that catalog.json does not "
                             "define")
        scopes = []
        for rule in prole.scopes:
            cats = rule.grant_categories or tuple(prole.categories)
            for table, cols in schema.items():
                wanted = _columns_in(catalog, table, cols, cats)
                if not wanted:
                    continue
                owner = next((c for c in rule.ownership_columns if c in cols), None)
                if owner is None:
                    what = ("self-service grant" if rule.grant_categories
                            else "row scope")
                    notes.append(
                        f"{rname}: no {what} on {table} - it has no column "
                        f"named {'/'.join(rule.ownership_columns)}"
                        + ("" if rule.grant_categories else
                           f" (its {', '.join(wanted)} would be limited only "
                           "by other scopes of the role level, if any - "
                           "else ALL rows: add a scope with rbic-init roles "
                           "scope)"))
                    continue
                template = check_template(
                    table, rule.template.replace(COLUMN_TOKEN, owner), schema)
                scope = RowScope(table, template,
                                 tuple(wanted) if rule.grant_categories else None)
                if scope not in scopes:
                    scopes.append(scope)
        out[rname] = RoleDef(prole.description, list(prole.categories),
                             list(prole.inherits), scopes, f"pack:{pack.name}")
    return out, notes


@dataclass
class PackMerge:
    added: list = field(default_factory=list)
    updated: list = field(default_factory=list)
    unchanged: list = field(default_factory=list)
    conflicts: list = field(default_factory=list)   # (role, reason)
    notes: list = field(default_factory=list)


def merge_pack(roles: Roles, pack: Pack, catalog: Catalog, schema: dict,
               usernames: Iterable = ()) -> tuple:
    """(new Roles, PackMerge). Pack roles are added; a role this pack
    defined before is refreshed; a role a human edited or another pack
    defined is never overwritten (reported as a conflict)."""
    instantiated, notes = instantiate_pack(pack, catalog, schema)
    out = roles.copy()
    result = PackMerge(notes=notes)
    source = f"pack:{pack.name}"
    for name, role in instantiated.items():
        current = out.roles.get(name)
        if current is None:
            out.roles[name] = role
            result.added.append(name)
        elif current.source != source:
            if current.same_content(role):
                result.unchanged.append(name)
            else:
                owner = ("edited by a human" if current.source == HUMAN
                         else f"defined by {current.source}")
                result.conflicts.append((name, f"already {owner}; kept as is "
                                               "(edit it with rbic-init roles "
                                               "set/scope, or remove it and "
                                               "add the pack again)"))
        elif current.to_json() == role.to_json():
            result.unchanged.append(name)
        else:
            out.roles[name] = role
            result.updated.append(name)
    out.packs = [p for p in out.packs if not p.startswith(pack.name + "@")]
    out.packs.append(pack.ref)
    validate_roles(out, catalog, schema, usernames)
    return out, result
