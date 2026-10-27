"""Import workers from an IdP / HR CSV export (`rbic-init import-users`).

This is the HR / IdP channel: the one path that may create workers and
set or change their emails (the master bot never can). It only PLANS the
new worker_attributes.json; PolicyAdmin.propose_user_import validates it
with the gate's own loader and a human confirms it before anything is
written (rbic.cli.init).

CSV format (UTF-8, optional BOM, one header row):
- Delimiter: `,` or `;`, detected from the header row; a header holding
  both (or neither) is refused.
- Header names are trimmed and lowercased. Required: `username`, `email`.
  Optional: `groups`, `employee_id`, `manager`; every other column is a
  worker attribute whose name must match the gate's attribute-name rule
  (`[a-z][a-z0-9_]{0,40}`). `role` is refused (roles come from groups via
  group_map.json), and so is `self_and_subordinate_ids` when a `manager`
  column is present (it is derived).
- `groups`: the IdP groups of the worker, separated by `;` when the file's
  delimiter is `,`, and by `|` when it is `;` (the group separator is
  never the delimiter, so quoting is not needed). Group names cannot
  contain `;` or `|`.
- Cells are trimmed (spaces and tabs). An empty cell means "no value": the
  attribute is removed from an existing worker.
- `email`: a plain ASCII address (gate.normalize_email: no lookalikes, no
  non-ASCII), stored lowercased; unique across the file and the workers
  the import keeps. `employee_id`: digits only, stored as a number, unique
  across the RESULTING worker set (the file, kept workers and masters;
  the gate's loader refuses a duplicate too).
  `manager`: the manager's username, which must be a row of the same file.
- Attribute values follow PolicyAdmin's value rule (letters, digits,
  spaces and . , @ : / _ - , at most 200 characters), so spreadsheet
  formulas (`=...`, `+...`) are refused, and values such as `-5` or
  `@team` are stored as plain text: nothing is ever evaluated.
- Any invalid row rejects the WHOLE import; errors name the CSV row
  number and (when valid) the username - never a value.

group_map.json: `{"version": 1, "map": [{"group": "<IdP group>", "role":
"<role>"}, ...]}`, in priority order: a worker's role is the role of the
FIRST entry whose group they belong to (one role per worker in v1; other
mapped groups are reported). Roles must exist in roles.json or the
policy, never `master`, never a username. A worker in no mapped group is
imported WITHOUT a role: the engine denies them everything (fail closed).

Derived: with a `manager` column, every worker with an employee_id gets
`self_and_subordinate_ids` = their own id plus their reports' ids
(`direct`: direct reports; `all`: every transitive report), sorted, e.g.
"1, 2, 3". A manager cycle is refused.

Masters are never created, changed or removed (a row naming one is
refused). Existing workers missing from the file are kept (and listed)
unless remove_missing; removing one who still holds `user:` rules is
refused with the rules to remove first. Keys the file has no column for
are kept on existing workers.

Library code: no terminal I/O.
"""

import csv
import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from ..admin import (ATTR_KEY_RE, ATTR_VALUE_RE, COLUMN_PTYPES, INT_RE,
                     MASTER_ROLE, ROLE_RE, ROW_PTYPES, USER_RE)
from ..gate import (EMPLOYEE_ID, USER_PREFIX, _employee_id_key,
                    normalize_email)
from . import ONBOARDING_DIR

GROUP_MAP_FILE = ONBOARDING_DIR / "group_map.json"
GROUP_MAP_VERSION = 1
DELIMITERS = (",", ";")
GROUP_SEPARATORS = {",": ";", ";": "|"}
REQUIRED_COLUMNS = ("username", "email")
SPECIAL_COLUMNS = ("username", "email", "groups", "employee_id", "manager")
DERIVED = "self_and_subordinate_ids"
TEAM_DEPTHS = ("direct", "all")
GROUP_MAX = 200
CELL_STRIP = " \t"
MAX_ERRORS = 50


class UserImportError(ValueError):
    """The export or group map is invalid; nothing was imported."""


def group_map_path(config_dir) -> Path:
    return Path(config_dir) / GROUP_MAP_FILE


# ----------------------------------------------------------------------
# CSV
# ----------------------------------------------------------------------

@dataclass
class CsvRow:
    line: int                       # CSV row number (the header is row 1)
    username: str
    email: str                      # normalized (lowercased)
    groups: tuple = ()
    employee_id: Optional[int] = None
    manager: Optional[str] = None
    attributes: dict = field(default_factory=dict)  # column -> str ("" = none)


@dataclass
class ParsedCsv:
    delimiter: str
    columns: list                   # normalized header names
    rows: list                      # [CsvRow]

    @property
    def attribute_columns(self) -> list:
        return [c for c in self.columns if c not in SPECIAL_COLUMNS]

    @property
    def has_manager(self) -> bool:
        return "manager" in self.columns


def _raise(errors: list):
    shown = errors[:MAX_ERRORS]
    more = len(errors) - len(shown)
    raise UserImportError(
        "the import was refused (nothing was written):\n"
        + "\n".join(f"  - {e}" for e in shown)
        + (f"\n  - ... and {more} more" if more > 0 else ""))


def detect_delimiter(header: str) -> str:
    found = [d for d in DELIMITERS if d in header]
    if len(found) != 1:
        raise UserImportError(
            "row 1 (header): cannot tell the delimiter - the header must use "
            "exactly one of ',' or ';' between column names")
    return found[0]


def _who(row_no: int, username: Optional[str]) -> str:
    return f"row {row_no}" + (f" ({username})" if username else "")


def parse_csv(data: bytes) -> ParsedCsv:
    """Parse and validate an export (see the module doc). Raises
    UserImportError listing every invalid row (row numbers and usernames
    only, never a value)."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise UserImportError("the file is not UTF-8 text") from None
    first = text.split("\n", 1)[0].rstrip("\r")
    if not first.strip():
        raise UserImportError("row 1 (header) is empty")
    delimiter = detect_delimiter(first)
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter,
                        quotechar='"', strict=True)
    try:
        records = [(reader.line_num, r) for r in reader]
    except csv.Error:
        raise UserImportError(f"row {reader.line_num}: malformed CSV (quoting)"
                              ) from None
    header = [h.strip(CELL_STRIP).lower() for h in records[0][1]]
    errors = []
    for i, name in enumerate(header, 1):
        if not ATTR_KEY_RE.fullmatch(name):
            errors.append(f"row 1 (header): column {i} is not a valid column "
                          "name (lowercase letters, digits, underscores; "
                          "starting with a letter)")
    dupes = sorted({h for h in header if header.count(h) > 1})
    if dupes:
        errors.append(f"row 1 (header): duplicate column(s) {', '.join(dupes)}")
    for name in REQUIRED_COLUMNS:
        if name not in header:
            errors.append(f"row 1 (header): required column '{name}' is missing")
    if "role" in header:
        errors.append("row 1 (header): a 'role' column is not allowed - roles "
                      "come from the groups column through group_map.json")
    if DERIVED in header and "manager" in header:
        errors.append(f"row 1 (header): '{DERIVED}' is derived from the "
                      "manager column; remove one of them")
    if errors:
        _raise(errors)
    sep = GROUP_SEPARATORS[delimiter]
    rows, seen_user, seen_email, seen_eid = [], {}, {}, {}
    for row_no, cells in records[1:]:
        if not cells or all(not c.strip(CELL_STRIP) for c in cells):
            continue  # blank line
        if len(cells) != len(header):
            errors.append(f"row {row_no}: has {len(cells)} field(s), the "
                          f"header has {len(header)}")
            continue
        cell = {h: c.strip(CELL_STRIP) for h, c in zip(header, cells)}
        username = cell["username"]
        if not USER_RE.fullmatch(username):
            errors.append(f"row {row_no}: invalid or empty username (letters, "
                          "digits and _ . @ - only, at most 64)")
            continue
        who = _who(row_no, username)
        if username.lower() in seen_user:
            errors.append(f"{who}: duplicate username (also row "
                          f"{seen_user[username.lower()]}; usernames are "
                          "compared case-insensitively)")
            continue
        seen_user[username.lower()] = row_no
        email = normalize_email(cell["email"])
        if email is None:
            errors.append(f"{who}: invalid or empty email (a plain ASCII "
                          "address is required; non-ASCII and lookalike "
                          "characters are refused)")
        elif email in seen_email:
            errors.append(f"{who}: email already used by row "
                          f"{seen_email[email][0]} ({seen_email[email][1]})")
        else:
            seen_email[email] = (row_no, username)
        groups = ()
        if cell.get("groups"):
            parts = [g.strip(CELL_STRIP) for g in cell["groups"].split(sep)]
            parts = [g for g in parts if g]
            if any(len(g) > GROUP_MAX or not g.isprintable() for g in parts):
                errors.append(f"{who}: invalid group name in the groups column "
                              f"(printable, at most {GROUP_MAX} characters; "
                              f"groups are separated by '{sep}')")
            groups = tuple(dict.fromkeys(parts))
        employee_id = None
        if cell.get("employee_id"):
            if not INT_RE.fullmatch(cell["employee_id"]):
                errors.append(f"{who}: employee_id must be digits only "
                              "(value not shown)")
            else:
                employee_id = int(cell["employee_id"])
                if employee_id in seen_eid:
                    errors.append(f"{who}: employee_id already used by row "
                                  f"{seen_eid[employee_id][0]} "
                                  f"({seen_eid[employee_id][1]})")
                seen_eid[employee_id] = (row_no, username)
        manager = cell.get("manager") or None
        if manager is not None and not USER_RE.fullmatch(manager):
            errors.append(f"{who}: manager is not a valid username")
            manager = None
        attrs = {}
        for name in header:
            if name in SPECIAL_COLUMNS:
                continue
            value = cell[name]
            if value and not ATTR_VALUE_RE.fullmatch(value):
                errors.append(f"{who}: column '{name}' has an invalid value "
                              "(letters, digits, spaces and . , @ : / _ - "
                              "only, at most 200; value not shown)")
            attrs[name] = value
        rows.append(CsvRow(row_no, username, email or "", groups, employee_id,
                           manager, attrs))
    if errors:
        _raise(errors)
    if not rows:
        raise UserImportError("the file has a header but no worker rows")
    return ParsedCsv(delimiter, header, rows)


# ----------------------------------------------------------------------
# group_map.json
# ----------------------------------------------------------------------

def parse_group_map(text: str, *, known_roles: Iterable,
                    usernames: Iterable = ()) -> list:
    """[(group, role)] in priority order. Raises UserImportError."""
    try:
        raw = json.loads(text)
    except ValueError as err:
        raise UserImportError(f"group_map.json is not valid JSON: {err}") from None
    if not isinstance(raw, dict) or set(raw) != {"version", "map"}:
        raise UserImportError("group_map.json must be an object with exactly "
                              "version and map")
    if raw["version"] != GROUP_MAP_VERSION:
        raise UserImportError(f"group_map.json: version must be "
                              f"{GROUP_MAP_VERSION}")
    if not isinstance(raw["map"], list) or not raw["map"]:
        raise UserImportError("group_map.json: map must be a non-empty list")
    known, users = set(known_roles), set(usernames)
    out, seen = [], set()
    for i, entry in enumerate(raw["map"]):
        where = f"group_map.json map[{i}]"
        if not isinstance(entry, dict) or set(entry) != {"group", "role"}:
            raise UserImportError(f"{where} must be an object with exactly "
                                  "group and role")
        group, role = entry["group"], entry["role"]
        if not isinstance(group, str) or not group.strip() \
                or len(group) > GROUP_MAX or not group.isprintable() \
                or any(s in group for s in GROUP_SEPARATORS.values()):
            raise UserImportError(f"{where}: group must be a printable name "
                                  f"(at most {GROUP_MAX} characters, no ';' "
                                  "or '|')")
        group = group.strip(CELL_STRIP)
        if group in seen:
            raise UserImportError(f"{where}: group {group!r} is listed twice")
        seen.add(group)
        if isinstance(role, str) and role.startswith(USER_PREFIX):
            raise UserImportError(f"{where}: {role!r} is a user subject, not "
                                  "a role")
        if not isinstance(role, str) or not ROLE_RE.fullmatch(role):
            raise UserImportError(f"{where}: invalid role name {role!r}")
        if role == MASTER_ROLE:
            raise UserImportError(f"{where}: the master role cannot be "
                                  "assigned by an import")
        if role in users:
            raise UserImportError(f"{where}: {role!r} is a username, not a role")
        if role not in known:
            raise UserImportError(f"{where}: unknown role {role!r} (define it "
                                  "in roles.json or the policy first)")
        out.append((group, role))
    return out


def load_group_map(path, *, known_roles, usernames=()) -> list:
    path = Path(path)
    if not path.exists():
        raise UserImportError(
            f"{path} does not exist: create it ({{\"version\": 1, \"map\": "
            "[{\"group\": \"<IdP group>\", \"role\": \"<role>\"}]}) - without "
            "it no worker would get a role")
    return parse_group_map(path.read_text(encoding="utf-8"),
                           known_roles=known_roles, usernames=usernames)


# ----------------------------------------------------------------------
# the plan
# ----------------------------------------------------------------------

def user_rules(enforcer) -> dict:
    """{username: [rule lines]} for every rule held by `user:<name>`
    (p/p2/p3/p4 subjects and g children)."""
    out: dict = {}
    for ptype in (*COLUMN_PTYPES, *ROW_PTYPES):
        for rule in enforcer.get_named_policy(ptype):
            if rule and rule[0].startswith(USER_PREFIX):
                out.setdefault(rule[0][len(USER_PREFIX):], []).append(
                    ", ".join([ptype, *rule]))
    for rule in enforcer.get_grouping_policy():
        if rule and rule[0].startswith(USER_PREFIX):
            out.setdefault(rule[0][len(USER_PREFIX):], []).append(
                ", ".join(["g", *rule]))
    return out


@dataclass
class ImportPlan:
    attributes: dict                               # the new worker_attributes.json
    rows: int = 0
    added: list = field(default_factory=list)
    updated: list = field(default_factory=list)
    unchanged: list = field(default_factory=list)
    removed: list = field(default_factory=list)
    kept_missing: list = field(default_factory=list)
    unmapped: list = field(default_factory=list)
    notes: list = field(default_factory=list)      # names only, never values

    def headline(self) -> str:
        return (f"Import {self.rows} worker row(s) from the HR / IdP export: "
                f"{len(self.added)} added, {len(self.updated)} updated, "
                f"{len(self.removed)} removed, {len(self.unchanged)} unchanged, "
                f"{len(self.kept_missing)} kept (not in the export).")


def _team(manager_of: dict, depth: str) -> dict:
    """username -> [report usernames] (direct, or all transitive)."""
    direct: dict = {}
    for user, mgr in manager_of.items():
        if mgr is not None:
            direct.setdefault(mgr, []).append(user)
    if depth == "direct":
        return direct
    out = {}
    for user in manager_of:
        seen, todo = [], list(direct.get(user, []))
        while todo:
            r = todo.pop(0)
            if r not in seen:
                seen.append(r)
                todo.extend(direct.get(r, []))
        out[user] = seen
    return out


def _cycle(manager_of: dict) -> Optional[list]:
    for start in manager_of:
        path, user = [], start
        while user is not None:
            if user in path:
                return path[path.index(user):] + [user]
            path.append(user)
            user = manager_of.get(user)
    return None


def plan_import(current: dict, parsed: ParsedCsv, group_map: list, *,
                known_roles: Iterable = (), team_depth: str = "direct",
                remove_missing: bool = False,
                rules_by_user: Optional[dict] = None) -> ImportPlan:
    """The new worker_attributes.json for `parsed` applied to `current`
    (see the module doc). Raises UserImportError (row numbers and
    usernames only)."""
    if team_depth not in TEAM_DEPTHS:
        raise UserImportError(f"team depth must be one of {', '.join(TEAM_DEPTHS)}")
    rules_by_user = rules_by_user or {}
    known_roles = set(known_roles)
    masters = {u for u, r in current.items()
               if isinstance(r, dict) and r.get("role") == MASTER_ROLE}
    in_csv = {r.username for r in parsed.rows}
    errors = []
    lower_masters = {m.lower(): m for m in masters}
    existing_lower = {u.lower(): u for u in current}
    for row in parsed.rows:
        who = _who(row.line, row.username)
        if row.username.lower() in lower_masters:
            errors.append(f"{who}: is a master user - imports never create, "
                          "change or remove master users")
        other = existing_lower.get(row.username.lower())
        if other is not None and other != row.username:
            errors.append(f"{who}: differs only in letter case from the "
                          f"existing worker {other}")
        if row.username in known_roles:
            errors.append(f"{who}: the username is also a role name (roles "
                          "are groups; rename one of them)")
    missing = [u for u in current if u not in in_csv and u not in masters]
    kept = [] if remove_missing else missing
    taken = {}
    for user in [*masters, *kept]:
        record = current.get(user)
        email = normalize_email(record.get("email")) \
            if isinstance(record, dict) else None
        if email:
            taken[email] = user
    for row in parsed.rows:
        if row.email in taken:
            errors.append(f"{_who(row.line, row.username)}: email already "
                          f"belongs to {taken[row.email]}, who is not in the "
                          "export (kept)")
    # employee_id must be unique across the RESULTING worker set: row
    # filters such as `employee_id = '{employee_id}'` bind it, so a new row
    # reusing a kept worker's id would read that worker's rows (payslip).
    # (Rows of the file are compared with each other in parse_csv; the
    # gate's loader refuses any duplicate as well.)
    taken_eid = {}
    for user in [*masters, *kept]:
        record = current.get(user)
        if isinstance(record, dict) and EMPLOYEE_ID in record:
            taken_eid[_employee_id_key(record[EMPLOYEE_ID])] = user
    for row in parsed.rows:
        if row.employee_id is not None and row.employee_id in taken_eid:
            owner = taken_eid[row.employee_id]
            kind = "master user" if owner in masters else \
                "worker, who is not in the export (kept)"
            errors.append(f"{_who(row.line, row.username)}: employee_id "
                          f"already belongs to {owner} ({kind}); employee_ids "
                          "must be unique (value not shown)")
    manager_of = {}
    by_name = {r.username: r for r in parsed.rows}
    for row in parsed.rows:
        if row.manager is not None and row.manager not in by_name:
            errors.append(f"{_who(row.line, row.username)}: manager is not a "
                          "username in this export")
        manager_of[row.username] = row.manager if row.manager in by_name \
            else None
    if remove_missing:
        for user in missing:
            if rules_by_user.get(user):
                errors.append(
                    f"cannot remove {user}: they still hold personal rules - "
                    "remove them first (rbic-master: propose_revoke / "
                    "propose_remove_* / propose_remove_user_role): "
                    + "; ".join(rules_by_user[user]))
    if errors:
        _raise(errors)
    cycle = _cycle(manager_of)
    if cycle:
        raise UserImportError("the import was refused (nothing was written): "
                              "manager cycle " + " -> ".join(cycle))

    plan = ImportPlan({}, rows=len(parsed.rows), kept_missing=list(kept))
    derived = {}
    if parsed.has_manager:
        team = _team(manager_of, team_depth)
        for row in parsed.rows:
            if row.employee_id is None:
                continue
            ids = {row.employee_id} | {by_name[r].employee_id
                                       for r in team.get(row.username, [])
                                       if by_name[r].employee_id is not None}
            value = ", ".join(str(i) for i in sorted(ids))
            if not ATTR_VALUE_RE.fullmatch(value):
                errors.append(f"{_who(row.line, row.username)}: {DERIVED} would "
                              f"list {len(ids)} ids, more than an attribute "
                              "can hold (200 characters); use --team-depth "
                              "direct or split the team")
            derived[row.username] = value
        no_eid = sorted(u for u in team if by_name[u].employee_id is None
                        and team[u])
        if no_eid:
            plan.notes.append(f"{', '.join(no_eid)}: manager(s) without an "
                              f"employee_id get no {DERIVED}")
    if errors:
        _raise(errors)

    covered = {"role", "email", "employee_id", *parsed.attribute_columns}
    if parsed.has_manager:
        covered.add(DERIVED)
    multi = []
    new_records = {}
    for row in parsed.rows:
        roles = [role for group, role in group_map if group in row.groups]
        old = current.get(row.username)
        record = {}
        if roles:
            record["role"] = roles[0]
            extra = sorted(set(roles[1:]) - {roles[0]})
            if extra:
                multi.append(f"{row.username} (role {roles[0]}; also mapped: "
                             f"{', '.join(extra)})")
        else:
            plan.unmapped.append(row.username)
        record["email"] = row.email
        if row.employee_id is not None:
            record["employee_id"] = row.employee_id
        for name in parsed.attribute_columns:
            if row.attributes.get(name):
                record[name] = row.attributes[name]
        if row.username in derived:
            record[DERIVED] = derived[row.username]
        if isinstance(old, dict):
            record.update({k: v for k, v in old.items() if k not in covered})
            if record == old:
                record = old  # unchanged: keep the file's key order
        new_records[row.username] = record
    out = {}
    for user, record in current.items():
        if user in new_records:
            out[user] = new_records[user]
            (plan.unchanged if new_records[user] == record
             else plan.updated).append(user)
        elif user in masters or user in kept:
            out[user] = record
        else:
            plan.removed.append(user)
    for row in parsed.rows:
        if row.username not in current:
            out[row.username] = new_records[row.username]
            plan.added.append(row.username)
    plan.attributes = out
    if plan.unmapped:
        plan.notes.append("NO ROLE (in no mapped group - every request is "
                          f"denied): {', '.join(plan.unmapped)}")
    if multi:
        plan.notes.append("WARNING: in several mapped groups, the first one "
                          "in group_map.json wins (one role per worker): "
                          + "; ".join(multi))
    if kept:
        plan.notes.append("kept, not in the export (pass --remove-missing to "
                          f"remove them): {', '.join(kept)}")
    return plan
