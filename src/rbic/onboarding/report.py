"""The plain-language access report (Markdown) for sign-off.

Built from a PolicySnapshot - the gate's own compiled view of model.conf,
policy.csv (generated block AND every manual rule), worker_attributes.json
and db_schema.json - using the gate's lookups (columns_for, keyMatch over
the role level, p3/p4 at each level), not from the onboarding sources, so
the report cannot drift from what the gate enforces. catalog.json is only
used for labels (category, sensitivity, approval status).

It names roles, usernames, tables, columns and rule templates. It never
contains a data value, an email address or any other attribute value.
"""

import re
from typing import Optional

from ..admin import _visible
from ..gate import (MASTER_ROLE, PolicySnapshot, is_user_subject, load_snapshot,
                    user_subject)
from .catalog import Catalog

_PLACEHOLDER = re.compile(r"'\{([a-z][a-z0-9_]{0,40})\}'|\{([a-z][a-z0-9_]{0,40})\}")
ALL_ROWS = "**ALL rows**"


def plain_filter(template: str) -> str:
    """`dept = '{dept}'` -> "dept = the user's dept"."""
    return _PLACEHOLDER.sub(lambda m: f"the user's {m.group(1) or m.group(2)}",
                            template)


def _cell(text: str) -> str:
    return _visible(text).replace("\n", " ").replace("|", "\\|")


def _rows(filters) -> str:
    if not filters:
        return ALL_ROWS
    return "rows where " + " OR ".join(
        f"({plain_filter(rf.template)})" if len(filters) > 1
        else plain_filter(rf.template) for rf in filters)


class _View:
    """Read-only helpers over one snapshot."""

    def __init__(self, snap: PolicySnapshot, catalog: Optional[Catalog]):
        self.s = snap
        self.e = snap.enforcer
        self.schema = {t: list(c) for t, c in snap.schema.items()}
        self.attrs = {u: dict(r) for u, r in snap.attributes.items()}
        self.catalog = catalog

    def roles(self) -> list:
        subs = {sub for sub, _ in (*self.s.allow_grants, *self.s.deny_grants)}
        subs |= {sub for sub, _ in (*self.s.row_filters, *self.s.deny_filters)}
        for child, parent, *_ in self.e.get_grouping_policy():
            subs |= {child, parent}
        subs |= {r.get("role") for r in self.attrs.values()
                 if isinstance(r.get("role"), str)}
        return sorted(s for s in subs if s and not is_user_subject(s)
                      and s != MASTER_ROLE)

    def level(self, role: str) -> set:
        return {role, *self.e.get_implicit_roles_for_user(role)}

    def label(self, table: str, column: str) -> str:
        if self.catalog is None:
            return column
        e = self.catalog.columns.get(f"{table}.{column}")
        if e is None or e.status != "approved":
            status = "unlabelled" if e is None else e.status
            return f"{column} (NOT APPROVED: {status})"
        sens = self.catalog.categories.get(e.category, {}).get("sensitivity", "?")
        return f"{column} ({e.category}, {sens})"

    def sensitivity(self, table: str, column: str) -> Optional[str]:
        if self.catalog is None:
            return None
        e = self.catalog.columns.get(f"{table}.{column}")
        if e is None or e.category is None:
            return None
        return self.catalog.categories.get(e.category, {}).get("sensitivity")

    def denied(self, subjects, table: str, column: str) -> bool:
        return self.s._grant(self.s.deny_grants, subjects, table, column) is not None

    def filters(self, subjects, table, *, scoped, deny=False) -> list:
        return [rf for _, rf in self.s._filters(subjects, table, scoped=scoped,
                                                deny=deny)]

    def users_of(self, role: str) -> tuple:
        own = sorted(u for u, r in self.attrs.items() if r.get("role") == role)
        extra = sorted(
            u for u, r in self.attrs.items() if r.get("role") != MASTER_ROLE
            and role in self.e.get_implicit_roles_for_user(user_subject(u)))
        return own, extra


def _role_section(v: _View, role: str, readable_cells: set, warnings: list) -> list:
    level = v.level(role)
    inherited = sorted(level - {role})
    own, extra = v.users_of(role)
    out = [f"### Role `{role}`", ""]
    out.append(f"- Inherits: {', '.join(inherited) or 'nothing'}")
    out.append(f"- Users: {', '.join(own) or 'none'}"
               + (f"; extra role for: {', '.join(extra)}" if extra else ""))
    columns = v.s.columns_for(level, v.schema)
    rows = []
    for table in v.schema:
        cols = columns.get(table, [])
        base = v.filters(level, table, scoped=False)
        if cols:
            rule = _rows(base)
            rows.append((table, ", ".join(v.label(table, c) for c in cols), rule))
            readable_cells.update((table, c) for c in cols)
            if not base:
                high = [c for c in cols if v.sensitivity(table, c) == "high"]
                warnings.append(
                    f"role {role} reads {table} on ALL rows (no row filter in "
                    "its role level)"
                    + (f", including high-sensitivity {', '.join(high)}"
                       if high else ""))
        for rf in v.filters(level, table, scoped=True):
            usable = [c for c in rf.columns if not v.denied(level, table, c)]
            if not usable:
                continue
            readable_cells.update((table, c) for c in usable)
            rows.append((table, ", ".join(v.label(table, c) for c in usable)
                         + " [scoped grant: only these columns]",
                         _rows([rf])))
    if rows:
        out += ["", "| Table | Readable columns | Rows |", "| --- | --- | --- |"]
        out += [f"| {_cell(t)} | {_cell(c)} | {_cell(r)} |" for t, c, r in rows]
    else:
        out += ["", "No data access."]
    denies = sorted({(obj, sub) for sub, obj in v.s.deny_grants if sub in level})
    hidden = [(sub, rf) for sub, rf in v.s.deny_filters if sub in level]
    if denies or hidden:
        out += ["", "Denies:"]
        out += [f"- column {_cell(obj)} denied (rule held by {sub})"
                for obj, sub in denies]
        for sub, rf in hidden:
            when = (f" when reading {', '.join(rf.columns)}" if rf.scoped else "")
            out.append(f"- rows of {rf.table} where {_cell(plain_filter(rf.template))} "
                       f"are hidden{when} (rule held by {sub})")
    out.append("")
    return out


def _personal_section(v: _View, readable_cells: set) -> list:
    out = []
    for user in sorted(v.attrs):
        if v.attrs[user].get("role") == MASTER_ROLE:
            continue
        subj = user_subject(user)
        grants = sorted(obj for sub, obj in v.s.allow_grants if sub == subj)
        denies = sorted(obj for sub, obj in v.s.deny_grants if sub == subj)
        scopes = [rf for sub, rf in v.s.row_filters if sub == subj]
        hidden = [rf for sub, rf in v.s.deny_filters if sub == subj]
        extra = sorted(v.e.get_roles_for_user(subj))
        if not (grants or denies or scopes or hidden or extra):
            continue
        out.append(f"- **{user}** (role {v.attrs[user].get('role')}):")
        if extra:
            out.append(f"  - extra role(s): {', '.join(extra)}")
        subjects = v.s.subjects_for(user)
        for obj in grants:
            table = obj.partition(".")[0]
            for c in v.schema.get(table, []):
                if v.s._grant(((subj, obj),), {subj}, table, c) \
                        and not v.denied({subj}, table, c):
                    readable_cells.add((table, c))
            rows = (v.s.user_base_filters(subjects, table)[0]
                    if subjects else [])
            out.append(f"  - personal grant {_cell(obj)}: {_cell(_rows(rows))}")
        for rf in scopes:
            if rf.scoped:
                readable_cells.update((rf.table, c) for c in rf.columns
                                      if not v.denied({subj}, rf.table, c))
                out.append(f"  - personal scoped grant on {rf.table}."
                           f"({', '.join(rf.columns)}): {_cell(_rows([rf]))}")
            else:
                out.append(f"  - personal row scope on {rf.table}: "
                           f"{_cell(_rows([rf]))}")
        for obj in denies:
            out.append(f"  - column {_cell(obj)} DENIED (overrides every allow)")
        for rf in hidden:
            when = (f" when reading {', '.join(rf.columns)}" if rf.scoped else "")
            out.append(f"  - rows of {rf.table} where "
                       f"{_cell(plain_filter(rf.template))} hidden{when}")
    return out


def access_report(snapshot: PolicySnapshot, catalog: Optional[Catalog] = None,
                  *, title: str = "Access report",
                  status: Optional[str] = None) -> str:
    """The Markdown access report for `snapshot` (see the module doc)."""
    v = _View(snapshot, catalog)
    warnings: list = []
    readable: set = set()
    out = [f"# {_cell(title)}", ""]
    if status:
        out += [_cell(status), ""]
    out += ["What each role can read, as the SQL gate enforces it (generated "
            "and manual rules together). Placeholders are bound from each "
            "user's attributes at query time; a user lacking one is denied "
            "the queries that rule covers.", "", "## Roles", ""]
    for role in v.roles():
        out += _role_section(v, role, readable, warnings)
    personal = _personal_section(v, readable)
    if personal:
        out += ["## Personal rules", "",
                "Per-user rules (user deny > user allow > role deny > role "
                "allow).", "", *personal, ""]
    out += ["## Hidden columns", "",
            "No role and no user can read these columns.", ""]
    hidden = []
    for table, cols in v.schema.items():
        for c in cols:
            if (table, c) in readable:
                continue
            why = ""
            if catalog is not None:
                e = catalog.columns.get(f"{table}.{c}")
                why = (" (unlabelled)" if e is None else
                       f" ({e.status}{', ' + e.category if e.category else ''})")
            hidden.append(f"- {table}.{c}{why}")
    out += hidden or ["- none"]
    if catalog is not None:
        for table, c in sorted(readable):
            e = catalog.columns.get(f"{table}.{c}")
            if e is None or e.status != "approved":
                warnings.append(f"{table}.{c} is readable but not approved in "
                                "catalog.json (a rule outside the rbic-init "
                                "block, e.g. a table.* grant?)")
    for user, record in sorted(v.attrs.items()):
        role = record.get("role")
        if role == MASTER_ROLE:
            continue
        subj = snapshot.subjects_for(user)
        if subj is None:
            warnings.append(f"user {user} has no usable role: no data access")
            continue
        missing = set()
        for sub, rf in (*snapshot.row_filters, *snapshot.deny_filters):
            if sub == subj.user or sub in subj.roles:
                missing.update(p for p in rf.placeholders if p not in record)
        if missing:
            warnings.append(f"user {user} lacks attribute(s) "
                            f"{', '.join(sorted(missing))}: queries covered by "
                            "rules needing them are denied")
    out += ["", "## Warnings", ""]
    out += [f"- {_cell(w)}" for w in warnings] or ["- none"]
    return "\n".join(out) + "\n"


def report_from_bytes(model: bytes, policy: bytes, attributes: bytes,
                      schema: bytes, catalog: Optional[Catalog] = None, *,
                      dialect: str = "sqlite", **kwargs) -> str:
    """access_report over files' bytes, loaded with the gate's own loader
    (raises whatever load_snapshot refuses)."""
    snap = load_snapshot(model, policy, attributes, schema, dialect=dialect)
    return access_report(snap, catalog, **kwargs)
