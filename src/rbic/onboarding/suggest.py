"""Suggest a data category per column, locally, from names and values.

Two kinds of declarative rules (each with an id, so evidence can say which
one fired):

- NAME_RULES match whole tokens of column and table names
  (case-insensitive; "employee_id" -> employee, id; "startDate" -> start,
  date), so "eta" never matches "beta".
- VALUE_RULES (opt-in, use_values=True) test at most `sample_rows`
  non-null values per column, read over a read-only connection. Values
  are only matched and counted, never stored, returned, logged or sent
  anywhere: evidence reads "value-rule:email matched 37/40 sampled values".

Precedence ("never downgrade sensitivity"): a column rule beats the
table's context category only if its category is more sensitive
(employees.salary -> pay; trainings.title -> training); id columns
inherit the table's dominant category; a value rule wins when its
category is at least as sensitive as the name guess (a column named `ref`
holding emails -> contact; a `salary` column never becomes contact).

No LLM is called. Everything here is a suggestion: nothing grants access
until a human approves it in catalog.json.
"""

import re
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Callable, Optional

from ..engine import readonly_uri
from .catalog import SENSITIVITY_RANK, default_categories
from .schema import IDENTIFIER_RE


@dataclass(frozen=True)
class Suggestion:
    column: str                 # "table.column"
    category: Optional[str]     # None: no rule matched (unlabelled)
    confidence: float
    suggested_by: str           # name-rule:<id> | value-rule:<id>
    evidence: str               # rule ids, names and counts only


@dataclass(frozen=True)
class NameRule:
    id: str
    category: str
    tokens: frozenset = frozenset()
    phrases: tuple = ()          # token sequences, e.g. ("national", "id")
    confidence: float = 0.8
    tables_only: bool = False    # only matches table names


NAME_RULES = (
    NameRule("pay", "pay", frozenset({
        "salary", "wage", "pay", "payslip", "bonus", "compensation",
        "payroll", "remuneration"}), confidence=0.9),
    NameRule("national_id", "personal_identifier",
             frozenset({"nric", "ssn", "passport"}),
             (("national", "id"), ("tax", "id")), confidence=0.9),
    NameRule("fin", "personal_identifier", frozenset({"fin"}), confidence=0.5),
    NameRule("birth", "personal_identifier",
             frozenset({"dob", "birth", "birthday", "birthdate"}),
             confidence=0.85),
    NameRule("contact", "contact", frozenset({
        "email", "phone", "mobile", "telephone", "address", "postal",
        "postcode"}), confidence=0.85),
    NameRule("leave", "leave", frozenset({"leave", "vacation"}),
             confidence=0.8),
    NameRule("training", "training", frozenset({"training", "course"}),
             confidence=0.8),
    NameRule("inventory", "inventory", frozenset({
        "sku", "qty", "quantity", "stock", "inventory"}), confidence=0.8),
    NameRule("logistics", "logistics", frozenset({
        "shipment", "eta", "destination", "warehouse"}), confidence=0.75),
    NameRule("finance", "finance", frozenset({
        "invoice", "budget", "expense", "amount", "vendor"}), confidence=0.75),
    NameRule("safety", "safety", frozenset({"incident", "severity", "safety"}),
             confidence=0.8),
    NameRule("directory", "directory",
             frozenset({"name", "dept", "department", "title"}),
             (("start", "date"),), confidence=0.6),
    NameRule("directory_table", "directory", frozenset({
        "employee", "staff", "people", "person", "directory"}),
             confidence=0.6, tables_only=True),
)
ID_TOKENS = frozenset({"id", "uuid"})
ID_RULE = "id_column"
TABLE_CONTEXT_CONFIDENCE = 0.6
ID_CONFIDENCE = 0.4
OTHER_CONFIDENCE = 0.3


def tokens(name: str) -> list:
    """Lowercase word tokens of an identifier: snake_case, camelCase,
    letter/digit boundaries."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    spaced = re.sub(r"([A-Za-z])([0-9])|([0-9])([A-Za-z])", r"\1\3 \2\4", spaced)
    return [t.lower() for t in re.split(r"[^A-Za-z0-9]+", spaced) if t]


def _forms(token: str) -> set:
    """The token and its likely singulars (incidents -> incident)."""
    out = {token}
    if token.endswith("ies") and len(token) > 4:
        out.add(token[:-3] + "y")
    if token.endswith("es") and len(token) > 3:
        out.add(token[:-2])
    if token.endswith("s") and len(token) > 3:
        out.add(token[:-1])
    return out


def _match(rule: NameRule, toks: list) -> Optional[str]:
    """The token (or phrase) of `toks` that fires `rule`, or None."""
    for phrase in rule.phrases:
        n = len(phrase)
        for i in range(len(toks) - n + 1):
            if all(p in _forms(t) for p, t in zip(phrase, toks[i:i + n])):
                return "_".join(toks[i:i + n])
    for t in toks:
        if _forms(t) & rule.tokens:
            return t
    return None


def _best(matches: list, sens: Callable) -> Optional[tuple]:
    """Most sensitive, then most confident, then first (rule, token)."""
    if not matches:
        return None
    return max(enumerate(matches),
               key=lambda im: (sens(im[1][0].category), im[1][0].confidence,
                               -im[0]))[1]


def _name_matches(name: str, *, table: bool) -> list:
    toks = tokens(name)
    out = []
    for rule in NAME_RULES:
        if rule.tables_only and not table:
            continue
        hit = _match(rule, toks)
        if hit is not None:
            out.append((rule, hit))
    return out


def _is_id(name: str) -> bool:
    toks = tokens(name)
    return bool(toks) and toks[-1] in ID_TOKENS


# ----------------------------------------------------------------------
# value rules (local; values are counted, never kept)
# ----------------------------------------------------------------------

EMAIL_RE = re.compile(r"[^@\s]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\Z")
NRIC_RE = re.compile(r"[STFGM][0-9]{7}[A-Z]\Z")
E164_RE = re.compile(r"\+[1-9][0-9]{7,14}\Z")
SG_PHONE_RE = re.compile(r"(?:\+?65)?[3689][0-9]{7}\Z")
CARD_RE = re.compile(r"[0-9]{13,19}\Z")
ISO_DATE_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})(?:[ T].*)?\Z")


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _is_email(v: str) -> bool:
    return bool(EMAIL_RE.match(v))


def _is_nric(v: str) -> bool:
    return bool(NRIC_RE.match(v.upper()))


def _is_phone(v: str) -> bool:
    compact = re.sub(r"[\s().-]", "", v)
    return bool(E164_RE.match(compact) or SG_PHONE_RE.match(compact))


def _is_card(v: str) -> bool:
    compact = re.sub(r"[\s-]", "", v)
    return bool(CARD_RE.match(compact)) and len(set(compact)) > 1 \
        and _luhn(compact)


def _is_birth_date(v: str, today: Optional[date] = None) -> bool:
    m = ISO_DATE_RE.match(v)
    if not m:
        return False
    try:
        d = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return False
    today = today or date.today()
    age = today.year - d.year - ((today.month, today.day) < (d.month, d.day))
    return 16 <= age <= 100


@dataclass(frozen=True)
class ValueRule:
    id: str
    category: str
    test: Callable
    confidence: float
    min_ratio: float = 0.8


VALUE_RULES = (
    ValueRule("email", "contact", _is_email, 0.95),
    ValueRule("sg_nric", "personal_identifier", _is_nric, 0.95),
    ValueRule("card_number", "personal_identifier", _is_card, 0.9),
    ValueRule("phone", "contact", _is_phone, 0.8),
    ValueRule("birth_date", "personal_identifier", _is_birth_date, 0.5,
              min_ratio=0.9),
)


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _value_counts(conn, table: str, column: str, limit: int) -> tuple:
    """(non-null string values sampled, {rule id: matches}). The values
    themselves leave this function only as counts."""
    sql = (f"SELECT {_quote(column)} FROM {_quote(table)} "
           f"WHERE {_quote(column)} IS NOT NULL LIMIT ?")
    sampled = 0
    hits = Counter()
    for (value,) in conn.execute(sql, (int(limit),)):
        if not isinstance(value, str):
            continue  # value rules describe text; numbers prove nothing here
        value = value.strip()
        if not value:
            continue
        sampled += 1
        for rule in VALUE_RULES:
            if rule.test(value):
                hits[rule.id] += 1
    return sampled, hits


def _db_columns(conn, table: str, notes: list) -> set:
    """Columns the database really has. Sampling a column it lacks must not
    run: SQLite reads an unknown double-quoted identifier as a string
    literal, so "SELECT "missing" FROM t" would 'sample' its own name."""
    try:
        cols = {name for (name,) in conn.execute(
            "SELECT name FROM pragma_table_info(?)", (table,))}
    except sqlite3.Error as err:
        notes.append(f"{table}: could not read its columns "
                     f"({type(err).__name__}); value rules skipped")
        return set()
    if not cols:
        notes.append(f"{table}: not in the database; value rules skipped")
    return cols


def _value_suggestion(sampled: int, hits: Counter) -> Optional[tuple]:
    """(rule, matched) of the best value rule over its threshold."""
    best = None
    for rule in VALUE_RULES:
        n = hits.get(rule.id, 0)
        if sampled and n / sampled >= rule.min_ratio:
            if best is None or n > best[1]:
                best = (rule, n)
    return best


# ----------------------------------------------------------------------
# the suggester
# ----------------------------------------------------------------------

def suggest_categories(schema: dict, *, db_path=None, sample_rows: int = 200,
                       use_values: bool = True,
                       categories: Optional[dict] = None,
                       notes: Optional[list] = None) -> list:
    """One Suggestion per column of `schema` ({table: {column: type}}).

    Name rules always run. Value rules run when use_values is true and
    db_path is given: at most `sample_rows` non-null values per column,
    read-only connection (query_only), values matched in memory and
    discarded. `categories` ({name: {"sensitivity": ...}}) ranks
    sensitivity (default: the catalog's default categories). Notes
    (e.g. a column that could not be sampled) go to `notes` - never a
    value, only names and exception classes.
    """
    categories = categories or default_categories()
    notes = [] if notes is None else notes

    def sens(category):
        info = categories.get(category)
        return SENSITIVITY_RANK.get(info["sensitivity"], -1) if info else -1

    if not isinstance(sample_rows, int) or isinstance(sample_rows, bool) \
            or not 1 <= sample_rows <= 10000:
        raise ValueError("sample_rows must be an integer in 1..10000")
    conn = None
    if use_values and db_path is not None:
        if not Path(db_path).is_file():
            notes.append("database not found; value rules skipped")
        else:
            conn = sqlite3.connect(readonly_uri(db_path), uri=True)
            conn.execute("PRAGMA query_only = ON")
    try:
        out = []
        for table, cols in schema.items():
            names = [c for c in cols if IDENTIFIER_RE.match(c)]
            if not IDENTIFIER_RE.match(table) or len(names) != len(cols):
                notes.append(f"{ascii(table)}: names that are not lowercase "
                             "identifiers were skipped (the gate cannot "
                             "address them)")
            if IDENTIFIER_RE.match(table):
                out += _suggest_table(table, names, conn, sample_rows, sens,
                                      notes)
        return out
    finally:
        if conn is not None:
            conn.close()


def _suggest_table(table, cols, conn, sample_rows, sens, notes) -> list:
    context = _best(_name_matches(table, table=True), sens)
    guesses = {}  # column -> (category, confidence, suggested_by, evidence)
    for column in cols:
        if _is_id(column):
            strong = [(r, t) for r, t in _name_matches(column, table=False)
                      if r.category == "personal_identifier"]
            if strong:  # national_id, tax_id ...
                r, t = _best(strong, sens)
                guesses[column] = (r.category, r.confidence,
                                   f"name-rule:{r.id}",
                                   f"column name token '{t}'")
            continue  # other ids: decided below, from the table's category
        own = _best(_name_matches(column, table=False), sens)
        if own and context:
            (r, t), (cr, ct) = own, context
            if r.category == cr.category:
                guesses[column] = (r.category, min(0.95, r.confidence + 0.05),
                                   f"name-rule:{r.id}",
                                   f"column name token '{t}', table name "
                                   f"token '{ct}' agree")
            elif sens(r.category) > sens(cr.category):
                guesses[column] = (r.category, r.confidence,
                                   f"name-rule:{r.id}",
                                   f"column name token '{t}' (more sensitive "
                                   f"than table category {cr.category})")
            else:
                guesses[column] = (cr.category, TABLE_CONTEXT_CONFIDENCE,
                                   f"name-rule:{cr.id}",
                                   f"table name token '{ct}' (column token "
                                   f"'{t}' suggests {r.category}, not more "
                                   "sensitive)")
        elif own:
            r, t = own
            guesses[column] = (r.category, r.confidence, f"name-rule:{r.id}",
                               f"column name token '{t}'")
        elif context:
            cr, ct = context
            guesses[column] = (cr.category, TABLE_CONTEXT_CONFIDENCE - 0.1,
                               f"name-rule:{cr.id}",
                               f"table name token '{ct}'")
    if context:
        dominant = context[0].category
    else:
        counts = Counter(g[0] for c, g in guesses.items() if not _is_id(c))
        dominant = max(sorted(counts), key=lambda k: (counts[k], sens(k)),
                       default=None)
    for column in cols:
        if column in guesses or not _is_id(column):
            continue
        if dominant:
            guesses[column] = (dominant, ID_CONFIDENCE, f"name-rule:{ID_RULE}",
                               f"id column inherits table category {dominant}")
        else:
            guesses[column] = ("other", OTHER_CONFIDENCE,
                               f"name-rule:{ID_RULE}",
                               "id column; table has no clear category")
    out = []
    present = _db_columns(conn, table, notes) if conn is not None else set()
    for column in cols:
        category, conf, by, evidence = guesses.get(
            column, (None, 0.0, "name-rule:none", "no name rule matched"))
        if conn is not None and column not in present:
            if present:
                notes.append(f"{table}.{column}: not in the database; value "
                             "rules skipped")
        elif conn is not None:
            try:
                sampled, hits = _value_counts(conn, table, column, sample_rows)
            except sqlite3.Error as err:
                notes.append(f"{table}.{column}: value sampling failed "
                             f"({type(err).__name__})")
            else:
                best = _value_suggestion(sampled, hits)
                if best is not None:
                    rule, n = best
                    vconf = round(rule.confidence * n / sampled, 2)
                    vevidence = (f"value-rule:{rule.id} matched {n}/{sampled} "
                                 "sampled values")
                    if category is None or sens(rule.category) >= sens(category):
                        if rule.category == category:
                            vconf = min(0.99, max(vconf, conf) + 0.05)
                        category, conf = rule.category, vconf
                        by, evidence = f"value-rule:{rule.id}", vevidence
                    else:
                        evidence += (f"; {vevidence} ({rule.category}, less "
                                     "sensitive: ignored)")
        out.append(Suggestion(f"{table}.{column}", category, round(conf, 2),
                              by, evidence[:200]))
    return out
