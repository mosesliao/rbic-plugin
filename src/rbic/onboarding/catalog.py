"""catalog.json: which data category each column belongs to.

    {
      "version": 1,
      "categories": {
        "pay": {"description": "...", "sensitivity": "high"}, ...
      },
      "columns": {
        "payroll.salary": {
          "category": "pay",
          "status": "approved",              # suggested | approved | rejected
          "suggested_by": "name-rule:pay",   # name-rule:<id> | value-rule:<id>
                                             # | llm-names | human
          "evidence": "column name token 'salary'",
          "confidence": 0.9,                 # optional, 0..1
          "approved_by": "master",           # who decided (approved OR rejected)
          "approved_at": "2026-10-27T12:00:00+00:00"
        }
      }
    }

Only APPROVED entries ever become policy (the compiler, step 2, reads
nothing else): a suggested, rejected or unlisted column grants nothing.
Evidence never holds a data value (the suggesters only write rule ids,
names and counts; printable ASCII, at most EVIDENCE_MAX characters).
Merging new suggestions never overwrites a human decision.

Library code: no terminal I/O. Saving is atomic (temp file + os.replace)
under an exclusive lock file, and refuses to overwrite a catalog that
changed since it was loaded.
"""

import copy
import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from ..admin import USER_RE, exclusive_lock

CATALOG_VERSION = 1
STATUSES = ("suggested", "approved", "rejected")
SENSITIVITIES = ("low", "medium", "high")
SENSITIVITY_RANK = {s: i for i, s in enumerate(SENSITIVITIES)}
CATEGORY_RE = re.compile(r"[a-z][a-z0-9_]{1,40}\Z", re.ASCII)
SUGGESTED_BY_RE = re.compile(
    r"(?:(?:name-rule|value-rule):[a-z0-9_]{1,40}|llm-names|human)\Z", re.ASCII)
COLUMN_KEY_RE = re.compile(r"([a-z_][a-z0-9_]{0,62})\.([a-z_][a-z0-9_]{0,62})\Z",
                           re.ASCII)
EVIDENCE_MAX = 200
DESCRIPTION_MAX = 200
LOCK_NAME = ".catalog.lock"

DEFAULT_CATEGORIES = {
    "directory": ("Who works here: names, departments, job titles, start "
                  "dates.", "low"),
    "contact": ("How to reach a person: email, phone, postal address.",
                "medium"),
    "pay": ("Salary, wages, bonuses and other compensation.", "high"),
    "personal_identifier": ("Government or financial identifiers and "
                            "birth dates (NRIC/FIN, SSN, passport, card "
                            "numbers).", "high"),
    "leave": ("Leave and absence records.", "medium"),
    "training": ("Courses and training records.", "low"),
    "inventory": ("Stock, SKUs and quantities.", "low"),
    "logistics": ("Shipments, destinations, ETAs, warehouses.", "low"),
    "finance": ("Invoices, budgets, expenses, vendors, amounts.", "medium"),
    "safety": ("Safety incidents and their severity.", "medium"),
    "other": ("Anything else, incl. technical keys with no clearer "
              "category.", "low"),
}


class CatalogError(ValueError):
    """catalog.json is invalid, or an operation on it was refused."""


@dataclass
class ColumnEntry:
    category: Optional[str]
    status: str = "suggested"
    suggested_by: str = "human"
    evidence: str = ""
    confidence: Optional[float] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None

    def to_json(self) -> dict:
        out = {"category": self.category, "status": self.status,
               "suggested_by": self.suggested_by, "evidence": self.evidence}
        if self.confidence is not None:
            out["confidence"] = self.confidence
        out["approved_by"] = self.approved_by
        out["approved_at"] = self.approved_at
        return out

    @property
    def human_decision(self) -> bool:
        """Approved, rejected, or a category a human chose: merge keeps it."""
        return self.status in ("approved", "rejected") \
            or self.suggested_by == "human"


@dataclass
class Catalog:
    categories: dict = field(default_factory=dict)  # name -> {description, sensitivity}
    columns: dict = field(default_factory=dict)     # "table.column" -> ColumnEntry
    version: int = CATALOG_VERSION

    def to_json(self) -> dict:
        return {
            "version": self.version,
            "categories": {k: dict(v) for k, v in self.categories.items()},
            "columns": {k: self.columns[k].to_json()
                        for k in sorted(self.columns)},
        }

    def to_text(self) -> str:
        return json.dumps(self.to_json(), indent=2) + "\n"

    def sensitivity(self, category: Optional[str]) -> int:
        """Rank of a category's sensitivity (-1 for none/unknown)."""
        info = self.categories.get(category) if category else None
        return SENSITIVITY_RANK.get(info["sensitivity"], -1) if info else -1

    def copy(self) -> "Catalog":
        return copy.deepcopy(self)


def default_categories() -> dict:
    return {name: {"description": d, "sensitivity": s}
            for name, (d, s) in DEFAULT_CATEGORIES.items()}


def new_catalog() -> Catalog:
    return Catalog(categories=default_categories())


def _printable(text) -> bool:
    return isinstance(text, str) and all(" " <= c <= "~" for c in text)


def _check_iso(value, where):
    if not isinstance(value, str):
        raise CatalogError(f"{where}: must be an ISO 8601 timestamp")
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise CatalogError(f"{where}: {value!r} is not an ISO 8601 "
                           "timestamp") from None


def _entry(key: str, raw, categories: dict) -> ColumnEntry:
    where = f"columns[{key!r}]"
    if not isinstance(raw, dict):
        raise CatalogError(f"{where} must be an object")
    allowed = {"category", "status", "suggested_by", "evidence", "confidence",
               "approved_by", "approved_at"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise CatalogError(f"{where}: unknown field(s) {', '.join(unknown)}")
    category = raw.get("category")
    if category is not None:
        if not isinstance(category, str) or not CATEGORY_RE.fullmatch(category):
            raise CatalogError(f"{where}: invalid category name {category!r}")
        if category not in categories:
            raise CatalogError(f"{where}: category {category!r} is not defined "
                               "in categories")
    status = raw.get("status")
    if status not in STATUSES:
        raise CatalogError(f"{where}: status must be one of "
                           f"{', '.join(STATUSES)}")
    by = raw.get("suggested_by")
    if not isinstance(by, str) or not SUGGESTED_BY_RE.fullmatch(by):
        raise CatalogError(f"{where}: suggested_by must be name-rule:<id>, "
                           "value-rule:<id>, llm-names or human")
    evidence = raw.get("evidence", "")
    if not _printable(evidence) or len(evidence) > EVIDENCE_MAX:
        raise CatalogError(f"{where}: evidence must be printable ASCII, at "
                           f"most {EVIDENCE_MAX} characters")
    confidence = raw.get("confidence")
    if confidence is not None and (isinstance(confidence, bool) or not
                                   isinstance(confidence, (int, float))
                                   or not 0 <= confidence <= 1):
        raise CatalogError(f"{where}: confidence must be a number in 0..1")
    approved_by, approved_at = raw.get("approved_by"), raw.get("approved_at")
    if status in ("approved", "rejected"):
        if not isinstance(approved_by, str) or not USER_RE.fullmatch(approved_by):
            raise CatalogError(f"{where}: a {status} column needs approved_by "
                               "(the deciding user)")
        _check_iso(approved_at, f"{where}.approved_at")
    elif approved_by is not None or approved_at is not None:
        raise CatalogError(f"{where}: a suggested column has no approved_by/"
                           "approved_at")
    if status == "approved" and category is None:
        raise CatalogError(f"{where}: an approved column needs a category")
    return ColumnEntry(category, status, by, evidence,
                       None if confidence is None else float(confidence),
                       approved_by, approved_at)


def parse_catalog(text: str, schema: Optional[dict] = None) -> Catalog:
    """Validate catalog.json text; with `schema`, every column must exist
    in it (db_schema.json). Raises CatalogError."""
    try:
        raw = json.loads(text)
    except ValueError as err:
        raise CatalogError(f"catalog.json is not valid JSON: {err}") from None
    if not isinstance(raw, dict):
        raise CatalogError("catalog.json must be an object")
    unknown = sorted(set(raw) - {"version", "categories", "columns"})
    if unknown:
        raise CatalogError(f"catalog.json: unknown field(s) {', '.join(unknown)}")
    if raw.get("version") != CATALOG_VERSION:
        raise CatalogError(f"catalog.json: version must be {CATALOG_VERSION}")
    cats = raw.get("categories")
    if not isinstance(cats, dict):
        raise CatalogError("catalog.json: categories must be an object")
    categories = {}
    for name, info in cats.items():
        if not isinstance(name, str) or not CATEGORY_RE.fullmatch(name):
            raise CatalogError(f"invalid category name {name!r}: lowercase "
                               "letters, digits, underscores (2-41 chars, "
                               "starting with a letter)")
        if not isinstance(info, dict) or set(info) != {"description",
                                                         "sensitivity"}:
            raise CatalogError(f"category {name!r} must have exactly "
                               "description and sensitivity")
        if not _printable(info["description"]) \
                or len(info["description"]) > DESCRIPTION_MAX:
            raise CatalogError(f"category {name!r}: description must be "
                               f"printable ASCII, at most {DESCRIPTION_MAX} "
                               "characters")
        if info["sensitivity"] not in SENSITIVITIES:
            raise CatalogError(f"category {name!r}: sensitivity must be one "
                               f"of {', '.join(SENSITIVITIES)}")
        categories[name] = {"description": info["description"],
                            "sensitivity": info["sensitivity"]}
    cols = raw.get("columns")
    if not isinstance(cols, dict):
        raise CatalogError("catalog.json: columns must be an object")
    columns = {}
    for key, entry in cols.items():
        if not isinstance(key, str) or not COLUMN_KEY_RE.fullmatch(key):
            raise CatalogError(f"invalid column key {key!r}: expected "
                               "table.column")
        columns[key] = _entry(key, entry, categories)
    catalog = Catalog(categories=categories, columns=columns)
    if schema is not None:
        check_against_schema(catalog, schema)
    return catalog


def check_against_schema(catalog: Catalog, schema: dict) -> None:
    unknown = sorted(k for k in catalog.columns
                     if k.partition(".")[0] not in schema
                     or k.partition(".")[2] not in schema[k.partition(".")[0]])
    if unknown:
        raise CatalogError(
            "catalog.json lists column(s) that db_schema.json does not have: "
            + ", ".join(unknown) + " (remove them, or update db_schema.json)")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_catalog(path, schema: Optional[dict] = None) -> tuple:
    """(Catalog, sha256 of the file text) - or (a new default catalog,
    None) when the file does not exist yet."""
    path = Path(path)
    if not path.exists():
        return new_catalog(), None
    text = path.read_text(encoding="utf-8")
    return parse_catalog(text, schema), sha256_text(text)


def save_catalog(path, catalog: Catalog, expected_sha: Optional[str]) -> str:
    """Write catalog.json atomically; returns the new text's sha256.

    `expected_sha` is the sha256 load_catalog returned (None: the file must
    not exist yet). If the file changed meanwhile, nothing is written.
    """
    path = Path(path)
    text = catalog.to_text()
    parse_catalog(text)  # never write a catalog we would refuse to load
    path.parent.mkdir(parents=True, exist_ok=True)
    with exclusive_lock(path.parent / LOCK_NAME, what="catalog change"):
        current = (sha256_text(path.read_text(encoding="utf-8"))
                   if path.exists() else None)
        if current != expected_sha:
            raise CatalogError("catalog.json changed since it was read; "
                               "nothing was written. Run the command again.")
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp_",
                                   suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
    return sha256_text(text)


# ----------------------------------------------------------------------
# merging and decisions (pure: return a new Catalog, never mutate)
# ----------------------------------------------------------------------

@dataclass
class MergeResult:
    added: list = field(default_factory=list)
    updated: list = field(default_factory=list)
    kept: list = field(default_factory=list)  # human decisions left alone


def merge_suggestions(catalog: Catalog, suggestions: Iterable) -> tuple:
    """(new Catalog, MergeResult). Each suggestion (rbic.onboarding.suggest
    .Suggestion) becomes a "suggested" entry, unless the column holds a
    human decision (approved, rejected, or suggested_by human), which is
    never overwritten. Categories a suggestion uses but the catalog lacks
    are added from the defaults."""
    out = catalog.copy()
    result = MergeResult()
    defaults = default_categories()
    for s in suggestions:
        if s.category is not None and s.category not in out.categories:
            if s.category not in defaults:
                raise CatalogError(f"suggestion for {s.column} uses unknown "
                                   f"category {s.category!r}")
            out.categories[s.category] = defaults[s.category]
        current = out.columns.get(s.column)
        if current is not None and current.human_decision:
            result.kept.append(s.column)
            continue
        entry = ColumnEntry(s.category, "suggested", s.suggested_by,
                            s.evidence, round(s.confidence, 2))
        if current is None:
            result.added.append(s.column)
        elif current != entry:
            result.updated.append(s.column)
        out.columns[s.column] = entry
    parse_catalog(out.to_text())
    return out, result


@dataclass(frozen=True)
class Decision:
    column: str
    action: str            # "approve" | "reject"
    category: Optional[str]
    before: str            # human-readable previous state

    def describe(self) -> str:
        what = (f"approve as {self.category}" if self.action == "approve"
                else "reject (stays hidden from everyone)")
        return f"{self.column}: {self.before} -> {what}"


def _state(entry: Optional[ColumnEntry]) -> str:
    if entry is None:
        return "unlabelled"
    return f"{entry.status} {entry.category or '(no category)'}"


def plan_approvals(catalog: Catalog, schema: dict, columns: Optional[dict] = None,
                   *, all_suggested: bool = False) -> list:
    """Decisions for approving `columns` ({table.column: category or None:
    keep the suggested category}) and/or every suggested column that has
    a category. Validates everything; changes nothing."""
    decisions = []
    if all_suggested:
        for key in sorted(catalog.columns):
            e = catalog.columns[key]
            if e.status == "suggested" and e.category is not None:
                decisions.append(Decision(key, "approve", e.category, _state(e)))
    for key, category in (columns or {}).items():
        _check_column(key, schema)
        e = catalog.columns.get(key)
        if category is None:
            if e is None or e.category is None:
                raise CatalogError(f"{key} has no suggested category; give one "
                                   f"(one of {', '.join(sorted(catalog.categories))})")
            category = e.category
        elif category not in catalog.categories:
            raise CatalogError(f"Unknown category {category!r}; known: "
                               f"{', '.join(sorted(catalog.categories))}")
        if e is not None and e.status == "approved" and e.category == category:
            raise CatalogError(f"{key} is already approved as {category}")
        if not any(d.column == key for d in decisions):
            decisions.append(Decision(key, "approve", category, _state(e)))
        else:
            decisions = [Decision(key, "approve", category, _state(e))
                         if d.column == key else d for d in decisions]
    if not decisions:
        raise CatalogError("Nothing to approve.")
    return decisions


def plan_rejections(catalog: Catalog, schema: dict, columns: Iterable) -> list:
    decisions = []
    for key in columns:
        _check_column(key, schema)
        e = catalog.columns.get(key)
        if e is not None and e.status == "rejected":
            raise CatalogError(f"{key} is already rejected")
        decisions.append(Decision(key, "reject", e.category if e else None,
                                  _state(e)))
    if not decisions:
        raise CatalogError("Nothing to reject.")
    return decisions


def _check_column(key, schema):
    table, _, column = key.partition(".") if isinstance(key, str) else ("", "", "")
    if table not in schema or column not in schema[table]:
        raise CatalogError(f"Unknown column {key!r} (expected table.column "
                           "from db_schema.json)")


def apply_decisions(catalog: Catalog, decisions: list, actor: str,
                    now: datetime) -> Catalog:
    """A new Catalog with `decisions` recorded as made by `actor` at `now`."""
    if not isinstance(actor, str) or not USER_RE.fullmatch(actor):
        raise CatalogError(f"Invalid actor {actor!r}")
    out = catalog.copy()
    stamp = now.isoformat()
    for d in decisions:
        e = out.columns.get(d.column)
        if d.action == "approve":
            if e is None or e.category != d.category:
                # the human chose this category: theirs, not a rule's
                e = ColumnEntry(d.category, suggested_by="human",
                                evidence="category chosen by a human")
            out.columns[d.column] = ColumnEntry(
                d.category, "approved", e.suggested_by, e.evidence,
                e.confidence, actor, stamp)
        else:
            e = e or ColumnEntry(None, suggested_by="human",
                                 evidence="rejected by a human")
            out.columns[d.column] = ColumnEntry(
                e.category, "rejected", e.suggested_by, e.evidence,
                e.confidence, actor, stamp)
    parse_catalog(out.to_text())
    return out


# ----------------------------------------------------------------------
# status
# ----------------------------------------------------------------------

@dataclass
class CatalogStatus:
    approved: int = 0
    suggested: int = 0     # suggested WITH a category, awaiting approval
    rejected: int = 0
    unlabelled: int = 0    # no entry, or suggested without a category
    approved_tables: list = field(default_factory=list)   # every column approved
    partial_tables: dict = field(default_factory=dict)    # table -> (approved, total)
    unlabelled_columns: list = field(default_factory=list)

    @property
    def hidden(self) -> int:
        """Columns the generated policy will hide from everyone."""
        return self.suggested + self.rejected + self.unlabelled


def catalog_status(catalog: Catalog, schema: dict) -> CatalogStatus:
    st = CatalogStatus()
    for table, cols in schema.items():
        approved = 0
        for column in cols:
            e = catalog.columns.get(f"{table}.{column}")
            if e is None or (e.status == "suggested" and e.category is None):
                st.unlabelled += 1
                st.unlabelled_columns.append(f"{table}.{column}")
            elif e.status == "approved":
                st.approved += 1
                approved += 1
            elif e.status == "rejected":
                st.rejected += 1
            else:
                st.suggested += 1
        if approved == len(cols):
            st.approved_tables.append(table)
        else:
            st.partial_tables[table] = (approved, len(cols))
    return st
