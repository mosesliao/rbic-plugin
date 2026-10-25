"""SQL firewall between the LLM's text-to-SQL output and the database.

Pipeline: parse -> qualify -> RBAC check -> ABAC rewrite -> safe SQL.

Casbin is the policy decision point (PDP); this module is the policy
enforcement point (PEP). Nothing the LLM generates reaches the database
without passing through SQLGate.authorize(), and the deny message is
generated here in code — never by the model.

Fail-closed rules:
- unparseable SQL, multiple statements, non-SELECT statement -> deny
- bind parameters/placeholders in the worker's SQL           -> deny
- unknown table or unresolvable column (vs db_schema.json)    -> deny
- any SQL construct the pipeline does not model (see below)   -> deny
- any referenced column outside the role's RBAC grants        -> deny
- a table reference with no grant at all (even COUNT(*))      -> deny
- ABAC filter needing an attribute the worker lacks           -> deny
- any unexpected error while checking a query                 -> deny

Row filters are never built by string substitution. Each p2 template is
parsed once per policy load with every {placeholder} replaced by a
sentinel string literal; at query time the sentinels are swapped for
literal AST nodes built from the worker's attribute values, so a value can
never become an identifier, operator or subquery.

Only SQL the column-capture pipeline fully models is served: after
qualification every node of the tree must be an allowlisted expression
type (SELECT structure, columns, literals, operators, functions, windows,
subqueries). Anything else - whole-row references such as Postgres's
`e`, `(e).salary` or `to_jsonb(e)` (sqlglot: TableColumn), composite
field access (Dot), CTEs, set operations, LATERAL/UNNEST/VALUES, INTO,
locking clauses, TABLESAMPLE, schema-qualified tables or columns - is
denied as an unsupported construct (invariant #2).

Scopes. Access is decided per table reference (each alias in each SELECT,
so self-joins and subqueries are checked independently). Let C be the
columns of that reference used anywhere in the query. Candidate scopes:
- the base scope: columns = the subjects' p grants, rows = OR of their
  3-field ("legacy") p2 filters on the table, or every row if none;
- each scoped grant (4-field p2 row: sub, table, filter, col|col|...)
  held by the subjects: columns = exactly the listed ones, rows = its filter.
A scope covers the reference if C is a subset of its columns (minus any
column a p3 deny takes away at that level). A reference that uses no
column at all (COUNT(*), SELECT 1) is covered by every scope through which
at least one column of the table is readable - so it still needs a grant
on the table, and a whole-table column deny denies it. No covering scope
-> deny. Otherwise the OR of the covering scopes' filters is ANDed into
the SELECT (nothing if the unfiltered base scope covers). Every covering
scope's filter must bind: a missing attribute denies the query (a scoped
grant that does not cover the reference is simply ignored, so scoped
grants never narrow what another scope allows). Scoped grants are purely
additive: they can only add OR branches.

Subjects and precedence. A request is evaluated at two levels:
- the ROLE level: the worker's role (attributes), everything it inherits,
  and extra roles assigned per user (g, user:<name>, <role>) with theirs;
- the USER level: the subject "user:<name>" alone.
Allow rules are p (columns) and p2 (rows / scoped grants); deny rules are
p3 (columns, same shape as p) and p4 (rows, same shape as p2). Per
reference: visible rows =
  ((role_allow AND NOT role_deny_rows) OR user_allow) AND NOT user_deny_rows
A column deny touching C denies the query outright at the user level and
removes every role-level scope's coverage at the role level (so only a
user allow can still authorize). A row deny (optional column list; none =
whole table) touching C is injected as AND NOT (filter) at its level; in
SQL, NOT (NULL) excludes the row, so a NULL in a deny filter fails closed.
The user-level base scope (personal p grants) keeps the rows the user's
roles see: its filters are the user's own 3-field p2 filters on the table
if any, else the role level's 3-field filters, else every row. Personal
scoped grants keep their own filter. The gate evaluates all of this
itself (p/p3 with Casbin's keyMatch over the subject sets, p2/p4 as
rewrites); enforce() is not used. The `master` role may not appear
anywhere in the policy (subject, parent, table or object): the load fails.

Thread safety: the enforcer, attributes and compiled row filters live in
one immutable PolicySnapshot. A reload builds a complete new snapshot and
swaps it in under a lock; authorize() takes the snapshot once and every
stage of that request uses only it.
"""

import hashlib
import io
import json
import os
import re
import string
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import NoReturn, Optional

import casbin
import sqlglot
from casbin.model import Model
from casbin.persist.adapter import Adapter, load_policy_line
from casbin.util import key_match
from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.qualify import qualify

from .audit import logger
from .config import EngineConfig

DENY_MESSAGE = "You have no access to this information, please approach your manager."
READ = "read"

# Policy types. Allow and deny rules are separate ptypes (rather than an
# effect column) so every pre-existing row keeps its exact meaning, the
# rows round-trip through Casbin's comma tokenizer unchanged, and the gate
# can apply user-over-role precedence itself (Casbin's effect expression
# would let a role deny beat a user allow, because g links the two).
PTYPE_ALLOW_COLUMNS = "p"    # p,  sub, table.column, read
PTYPE_ALLOW_ROWS = "p2"      # p2, sub, table, filter[, col|col]
PTYPE_DENY_COLUMNS = "p3"    # p3, sub, table.column, read
PTYPE_DENY_ROWS = "p4"       # p4, sub, table, filter[, col|col]
KNOWN_PTYPES = frozenset({PTYPE_ALLOW_COLUMNS, PTYPE_ALLOW_ROWS,
                          PTYPE_DENY_COLUMNS, PTYPE_DENY_ROWS, "g"})
# Per-user subjects are namespaced so a username can never collide with a
# role name: "user:alice".
USER_PREFIX = "user:"


def user_subject(username: str) -> str:
    return USER_PREFIX + username


def is_user_subject(sub) -> bool:
    return isinstance(sub, str) and sub.startswith(USER_PREFIX)


class AccessDenied(Exception):
    """Query failed RBAC/ABAC or could not be safely analyzed."""


# ---------------------------------------------------------------------------
# row-filter templates (p2): compile once, bind values as literal AST nodes
# ---------------------------------------------------------------------------

class FilterError(ValueError):
    """A row-filter template is malformed/unsafe, or a value can't be bound."""


class MissingAttribute(FilterError):
    def __init__(self, name: str):
        super().__init__(name)
        self.name = name


PLACEHOLDER_NAME = r"[a-z][a-z0-9_]{0,40}"
_PLACEHOLDER_RE = re.compile(
    rf"'\{{({PLACEHOLDER_NAME})\}}'|\{{({PLACEHOLDER_NAME})\}}", re.ASCII)
_SENTINEL_RE = re.compile(rf"__rbic_(q|ph)_({PLACEHOLDER_NAME})__\Z", re.ASCII)
_SENTINEL_MARK = "__rbic_"
_INT_RE = re.compile(r"[0-9]{1,30}\Z", re.ASCII)
# Attribute values bound into filters: no backslashes or control characters
# (defense in depth — sqlglot escapes quotes, but backslash handling differs
# between SQL dialects).
_UNSAFE_VALUE_RE = re.compile(r"[\\\x00-\x1f\x7f]")

# Functions a row filter may call. Everything else (including functions
# sqlglot doesn't know, e.g. Postgres query_to_xml) is rejected: several
# DB functions execute or read arbitrary SQL/data.
SAFE_FILTER_FUNCS = (
    exp.Lower, exp.Upper, exp.Trim, exp.Coalesce, exp.Length, exp.Abs,
    exp.CurrentDate, exp.CurrentTimestamp,
    exp.Connector, exp.Case, exp.If,  # AND/OR/CASE are Func nodes in sqlglot
)
# Strict mode (templates proposed through the master bot) is predicate-only:
# no CASE/IF, which can hide an always-true branch.
STRICT_FILTER_FUNCS = tuple(f for f in SAFE_FILTER_FUNCS
                            if f not in (exp.Case, exp.If))
PREDICATE_LEAVES = (
    exp.EQ, exp.NEQ, exp.GT, exp.GTE, exp.LT, exp.LTE,
    exp.NullSafeEQ, exp.NullSafeNEQ,
    exp.In, exp.Is, exp.Like, exp.ILike, exp.Between,
)
_FORBIDDEN_FILTER_NODES = (exp.Query, exp.Subquery, exp.Table, exp.Command,
                           exp.DML, exp.DDL)
_BIND_NODES = tuple(n for n in (exp.Placeholder, exp.Parameter,
                                getattr(exp, "SessionParameter", None)) if n)
_FORBIDDEN_FILTER_TOKENS = (exp.Star, exp.Dot, *_BIND_NODES)


def _exp(*names) -> tuple:
    """The sqlglot expression classes among `names` that this version has."""
    return tuple(c for c in (getattr(exp, n, None) for n in names) if c)


# Worker SQL: the expression types the column-capture pipeline models. A
# query containing any other node type is denied (invariant #2). Func,
# Binary, Unary and Predicate are broad on purpose - their operands are
# ordinary expressions that are walked for columns - minus the explicit
# exclusions below.
SUPPORTED_NODES = _exp(
    "Select", "From", "Join", "Where", "Group", "Having", "Order", "Ordered",
    "Limit", "Offset", "Fetch", "LimitOptions", "Distinct", "Subquery",
    "Table", "TableAlias", "Alias", "Identifier", "Column", "Star", "Tuple",
    "Literal", "Boolean", "Null", "DataType", "DataTypeParam", "Interval",
    "Var", "Window", "WindowSpec", "Rollup", "Cube", "GroupingSets",
    "Func", "Binary", "Unary", "Predicate",
)
# Never served even though some are Func/Binary subclasses: whole-row
# references (TableColumn: Postgres `e`, `(e).col`, `to_jsonb(e)`),
# composite field access (Dot), table-valued constructs (UDTF: LATERAL,
# UNNEST, VALUES), set operations, CTEs, SELECT INTO, FOR UPDATE,
# TABLESAMPLE, statements, bind parameters.
UNSUPPORTED_NODES = _exp(
    "TableColumn", "Dot", "UDTF", "SetOperation", "Union", "With", "CTE",
    "Into", "Lock", "TableSample", "Command", "DML", "DDL",
) + _BIND_NODES
# Where a bare identifier may appear (an identifier anywhere else could be
# a column name the pipeline does not see).
_IDENTIFIER_PARENTS = _exp("Column", "Table", "TableAlias", "Alias", "Window",
                           "Collate")
STATIC_FILTER_WARNING = ("WARNING: this filter is the same for every user "
                         "(it does not depend on who is asking).")
MASTER_ROLE = "master"
# 4th p2 field: column names separated by "|" (Casbin's CSV splits on
# commas, so a comma-separated list is impossible there).
SCOPE_COLUMN_SEP = "|"
_COLUMN_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z", re.ASCII)


@dataclass(frozen=True)
class RowFilter:
    """A parsed p2 template. `tree` holds sentinel literals; never mutate it.

    `columns` is None for a legacy (3-field) row filter and the tuple of
    column names for a scoped grant (4-field row).
    """

    table: str
    template: str
    tree: exp.Expression
    placeholders: tuple  # attribute names, first-appearance order, unique
    columns: Optional[tuple] = None

    @property
    def static(self) -> bool:
        return not self.placeholders

    @property
    def scoped(self) -> bool:
        return self.columns is not None

    @property
    def columns_text(self) -> str:
        return SCOPE_COLUMN_SEP.join(self.columns or ())

    def uses(self) -> list:
        """[(name, quoted, in_list)] for every placeholder occurrence."""
        out = []
        for lit in self.tree.find_all(exp.Literal):
            m = _sentinel(lit)
            if m:
                out.append((m[1], m[0] == "q", _in_list(lit)))
        return out


def _sentinel(node) -> Optional[tuple]:
    if isinstance(node, exp.Literal) and node.is_string:
        m = _SENTINEL_RE.match(node.this)
        if m:
            return m.group(1), m.group(2)
    return None


def _in_list(node) -> bool:
    return isinstance(node.parent, exp.In) and node.arg_key == "expressions"


def _placeholder_names(template: str) -> list:
    try:
        parsed = list(string.Formatter().parse(template))
    except ValueError as err:
        raise FilterError(f"Malformed placeholder in filter: {err}")
    names = []
    for literal, field, spec, conv in parsed:
        if "{" in literal or "}" in literal:
            raise FilterError("Filter may not contain literal braces.")
        if field is None:
            continue
        if not re.fullmatch(PLACEHOLDER_NAME, field, re.ASCII) or spec or conv:
            raise FilterError(
                f"Invalid placeholder {{{field}}}: placeholders must be "
                "simple attribute names like {dept} (no indexing, "
                "attribute access, conversions or format specs).")
        names.append(field)
    return names


def _has_column(node) -> bool:
    return isinstance(node, exp.Column) or node.find(exp.Column) is not None


def _check_predicates(node) -> None:
    """Strict mode: a boolean combination of column-vs-constant predicates."""
    if isinstance(node, exp.Paren):
        return _check_predicates(node.this)
    if isinstance(node, (exp.And, exp.Or)):
        _check_predicates(node.left)
        _check_predicates(node.right)
        return
    if isinstance(node, exp.Not):
        return _check_predicates(node.this)
    if not isinstance(node, PREDICATE_LEAVES):
        raise FilterError(
            f"{node.sql()!r} is not a comparison. Every part of a row filter "
            "must compare a column with a value (=, <>, <, >, IN, IS, LIKE, "
            "BETWEEN), e.g. dept = '{dept}'; bare columns, constants like "
            "TRUE or 1, and CASE expressions are not allowed.")
    if isinstance(node, exp.In):
        subject, others = node.this, list(node.expressions)
        if node.args.get("query") is not None or not others:
            raise FilterError(f"{node.sql()!r}: IN needs a list of values.")
    elif isinstance(node, exp.Between):
        subject, others = node.this, [node.args.get("low"), node.args.get("high")]
    else:  # binary comparison
        left, right = node.left, node.right
        if left == right:
            raise FilterError(f"{node.sql()!r} compares an expression with "
                              "itself, so it is always true.")
        if not _has_column(left) and _has_column(right):
            left, right = right, left
        subject, others = left, [right]
    if not _has_column(subject):
        raise FilterError(f"{node.sql()!r} does not reference a column of the "
                          "table, so it does not restrict rows.")
    for other in others:
        if other is None or _has_column(other):
            raise FilterError(
                f"{node.sql()!r}: compare a column with a value or "
                "{placeholder}, not with another column (column-vs-column "
                "comparisons can be always true).")


def compile_row_filter(table: str, template, schema: dict, *, dialect: str,
                       strict: bool = False) -> RowFilter:
    """Parse and validate a p2 template; raise FilterError if unsafe.

    Always enforced (also by the gate on every policy load): valid SQL
    condition; no subqueries, table references, stars, bind parameters or
    unsafe functions; only unqualified columns of `table`; placeholders are
    simple names that stand alone as a value ('{dept}' or {ids}).

    strict=True adds the master-bot authoring rules: printable ASCII only,
    no SQL comments, and a predicate-only structure with no tautologies.

    `dialect` is required: the same template can parse differently in
    different dialects, so the caller states the one it will execute in.
    """
    if not isinstance(template, str) or not template.strip():
        raise FilterError("Filter template must be a non-empty string.")
    if table not in schema:
        raise FilterError(f"Unknown table {table!r}.")
    if strict:
        bad = next((c for c in template if not " " <= c <= "~"), None)
        if bad is not None:
            raise FilterError("Filter may only contain printable ASCII "
                              f"characters (found {bad!r}).")
        if any(tok in template for tok in ("--", "/*", "*/", "#")):
            raise FilterError("Filter may not contain SQL comments "
                              "('--', '/*', '*/' or '#').")
    if _SENTINEL_MARK in template:
        raise FilterError(f"Filter may not contain {_SENTINEL_MARK!r}.")
    names = _placeholder_names(template)

    def to_sentinel(m):
        if m.group(1):
            return f"'{_SENTINEL_MARK}q_{m.group(1)}__'"
        return f"'{_SENTINEL_MARK}ph_{m.group(2)}__'"

    text = _PLACEHOLDER_RE.sub(to_sentinel, template)
    if "{" in text or "}" in text:
        raise FilterError("Placeholders must be simple attribute names like "
                          "{dept} or '{dept}'.")
    try:
        tree = sqlglot.parse_one(text, dialect=dialect)
    except SqlglotError as err:
        raise FilterError(f"Filter is not valid SQL: {err}")
    if (tree is None or not isinstance(tree, exp.Condition)
            or isinstance(tree, (exp.Query, exp.Literal, exp.Column))):
        raise FilterError("Filter must be a boolean condition, "
                          "e.g. status = 'unpaid'.")
    funcs = STRICT_FILTER_FUNCS if strict else SAFE_FILTER_FUNCS
    sentinels = 0
    for node in tree.walk():
        if isinstance(node, _FORBIDDEN_FILTER_NODES):
            raise FilterError("Filter may not contain subqueries or "
                              "table references.")
        if isinstance(node, _FORBIDDEN_FILTER_TOKENS):
            raise FilterError(f"Filter may not contain {node.sql()!r}.")
        if isinstance(node, exp.Func) and not isinstance(node, funcs):
            raise FilterError(f"Function {node.sql()!r} is not allowed "
                              "in row filters.")
        if isinstance(node, exp.Column):
            if node.table:
                raise FilterError(f"Filter column {node.sql()!r} must be an "
                                  f"unqualified column of {table}.")
            if node.name not in schema[table]:
                raise FilterError(
                    f"Column {node.name!r} is not in table {table} "
                    f"(columns: {', '.join(schema[table])}).")
        if _sentinel(node):
            sentinels += 1
        elif isinstance(node, (exp.Literal, exp.Identifier)) \
                and _SENTINEL_MARK in str(node.this):
            sentinels = -1  # placeholder glued into a larger string/name
    if sentinels != len(names):
        raise FilterError("A placeholder must stand alone as a value: write "
                          "'{dept}' or {ids}, not part of a larger string "
                          "or name.")
    if strict:
        _check_predicates(tree)
    return RowFilter(table, template, tree, tuple(dict.fromkeys(names)))


def parse_scope_columns(table: str, text, schema: dict) -> tuple:
    """Validate the 4th p2 field ("id|name|salary") against the schema.

    Strict on purpose (a malformed list fails the whole policy load): a
    non-empty "|"-separated list of existing, distinct column names of
    `table`, with no surrounding whitespace, stars or empty items.
    """
    if table not in schema:
        raise FilterError(f"Unknown table {table!r}.")
    if isinstance(text, (list, tuple)):
        text = SCOPE_COLUMN_SEP.join(str(c) for c in text)
    if not isinstance(text, str) or not text:
        raise FilterError("Scoped grant needs a non-empty column list like "
                          f"id{SCOPE_COLUMN_SEP}name.")
    columns = []
    for item in text.split(SCOPE_COLUMN_SEP):
        if not _COLUMN_NAME_RE.fullmatch(item):
            raise FilterError(
                f"Bad column list {text!r}: {item!r} is not a plain column "
                f"name (use column names separated by {SCOPE_COLUMN_SEP!r}, "
                "no spaces, no '*').")
        if item not in schema[table]:
            raise FilterError(f"Column {item!r} is not in table {table} "
                              f"(columns: {', '.join(schema[table])}).")
        if item in columns:
            raise FilterError(f"Column {item!r} is listed twice in {text!r}.")
        columns.append(item)
    return tuple(columns)


def _value_literals(name: str, value, quoted: bool, in_list: bool) -> list:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise FilterError(f"attribute {name!r} has unsupported type "
                          f"{type(value).__name__}")
    if isinstance(value, str) and _UNSAFE_VALUE_RE.search(value):
        raise FilterError(f"attribute {name!r} contains a backslash or "
                          "control character")
    if quoted:  # '{name}' — the author asked for a string, keep it one
        return [exp.Literal.string(str(value))]
    if isinstance(value, int):
        return [exp.Literal.number(value)]
    parts = [p.strip() for p in value.split(",")] if in_list else [value]
    if in_list and any(p == "" for p in parts):
        raise FilterError(f"attribute {name!r} has an empty list item")
    return [exp.Literal.number(p) if _INT_RE.match(p) else exp.Literal.string(p)
            for p in parts]


_INT_LIST_RE = re.compile(r"[0-9]{1,30}(\s*,\s*[0-9]{1,30})*\Z", re.ASCII)


def check_unquoted_values(rf: RowFilter, attrs: dict) -> None:
    """Every value bound into an unquoted {placeholder} must be a number
    (inside IN (...): a comma-separated list of numbers). Raises
    MissingAttribute / FilterError."""
    for name, quoted, in_list in rf.uses():
        if name not in attrs:
            raise MissingAttribute(name)
        value = attrs[name]
        if quoted or (isinstance(value, int) and not isinstance(value, bool)):
            continue
        pattern = _INT_LIST_RE if in_list else _INT_RE
        if not isinstance(value, str) or not pattern.match(value):
            raise FilterError(f"attribute {name!r} = {value!r} is not a number"
                              + (" list" if in_list else "")
                              + f" but {{{name}}} is unquoted")


def bind_row_filter(rf: RowFilter, attrs: dict, owner: str) -> exp.Expression:
    """Return a fresh copy of the filter with values bound as literals.

    Columns are qualified with `owner` (the table's alias in the query).
    Raises MissingAttribute / FilterError.
    """
    for name in rf.placeholders:
        if name not in attrs:
            raise MissingAttribute(name)
    tree = rf.tree.copy()
    for in_node in list(tree.find_all(exp.In)):
        items, changed = [], False
        for item in in_node.expressions:
            m = _sentinel(item)
            if m:
                items += _value_literals(m[1], attrs[m[1]], m[0] == "q", True)
                changed = True
            else:
                items.append(item)
        if changed:
            in_node.set("expressions", items)
    for lit in list(tree.find_all(exp.Literal)):
        m = _sentinel(lit)
        if m:
            (value,) = _value_literals(m[1], attrs[m[1]], m[0] == "q", False)
            new = lit.replace(value)
            if lit is tree:
                tree = new
    for node in tree.walk():
        if _sentinel(node):  # paranoia: nothing may be left unbound
            raise FilterError("unbound placeholder")
    for col in tree.find_all(exp.Column):
        col.set("table", exp.to_identifier(owner))
    return tree


# ---------------------------------------------------------------------------
# policy snapshot
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Subjects:
    """The policy subjects one worker's request is evaluated against."""

    user: str         # "user:<username>" - the user level
    role: str         # the worker's role from their attributes
    roles: frozenset  # the role level: role + inherited + extra (g, user:x, r)


def subjects_for(enforcer: casbin.Enforcer, username: str, role: str) -> Subjects:
    """Role level = role, its inherited roles, and every role reachable from
    the user subject through g (extra roles assigned per user) with theirs.
    User subjects never appear in the role level (the loader rejects
    g rows whose parent is a user subject)."""
    user = user_subject(username)
    roles = {role, *enforcer.get_implicit_roles_for_user(role),
             *enforcer.get_implicit_roles_for_user(user)}
    return Subjects(user, role, frozenset(r for r in roles
                                          if not is_user_subject(r)))


@dataclass
class Decision:
    """How one table reference is authorized (see module docstring).

    role_cov / user_cov: [(label, RowFilter|None)] covering scopes at that
    level ((label, None) = the unfiltered base scope); role_deny /
    user_deny: [(label, RowFilter)] row denies touching the reference.
    failure is set when no level covers (failure_col orders failures).
    """

    role_cov: list = field(default_factory=list)
    role_deny: list = field(default_factory=list)
    user_cov: list = field(default_factory=list)
    user_deny: list = field(default_factory=list)
    failure: Optional[str] = None
    failure_col: Optional[str] = None

    @property
    def covered(self) -> bool:
        return self.failure is None


@dataclass(frozen=True)
class PolicySnapshot:
    """Everything one request needs, loaded together and never mutated."""

    version: int
    enforcer: casbin.Enforcer
    # Deeply read-only (MappingProxyType / tuples, see freeze()): the
    # snapshot is shared with attribute providers and every request.
    attributes: Mapping
    row_filters: tuple    # ((sub, RowFilter), ...) p2 rows, policy order
    sig: Optional[tuple]
    broken: Optional[str] = None
    deny_filters: tuple = ()   # ((sub, RowFilter), ...) p4 rows
    allow_grants: tuple = ()   # ((sub, obj), ...) p rows with act = read
    deny_grants: tuple = ()    # ((sub, obj), ...) p3 rows with act = read
    # table -> {column: type} (db_schema.json, read-only), loaded with
    # the snapshot: every gate stage resolves columns against THIS schema.
    schema: Mapping = field(default_factory=lambda: MappingProxyType({}))
    # sha256 of the model/policy/attributes/schema bytes this snapshot was
    # built from ("" for PolicyAdmin's dry-run snapshots).
    fingerprint: str = ""

    # -- subjects -----------------------------------------------------------

    def subjects_for(self, username: str) -> Optional[Subjects]:
        worker = self.attributes.get(username)
        role = worker.get("role") if isinstance(worker, Mapping) else None
        if not isinstance(role, str) or is_user_subject(role):
            return None
        return subjects_for(self.enforcer, username, role)

    # -- rule lookups -------------------------------------------------------

    @staticmethod
    def _grant(rules, subjects, table: str, column: str) -> Optional[str]:
        """Subject of the first rule granting/denying table.column, if any.
        Same semantics as Casbin's matcher: keyMatch on the object."""
        obj = f"{table}.{column}"
        for sub, pobj in rules:
            if sub in subjects and key_match(obj, pobj):
                return sub
        return None

    def _filters(self, subjects, table: str, scoped: bool, deny=False) -> list:
        source = self.deny_filters if deny else self.row_filters
        return [(sub, rf) for sub, rf in source
                if sub in subjects and rf.table == table and rf.scoped == scoped]

    def role_base_filters(self, subj: Subjects, table: str) -> list:
        """The role level's 3-field row filters on `table` (OR-combined)."""
        return [rf for _, rf in self._filters(subj.roles, table, scoped=False)]

    def user_base_filters(self, subj: Subjects, table: str) -> tuple:
        """(filters, borrowed) for the user-level base scope (personal p
        grants): the user's own 3-field p2 filters on `table` if any,
        else the role level's (borrowed=True), else none = every row. A
        personal grant therefore keeps the rows the user's roles see
        unless a master deliberately gave the user their own row scope."""
        own = [rf for _, rf in self._filters({subj.user}, table, scoped=False)]
        if own:
            return own, False
        role = self.role_base_filters(subj, table)
        return role, bool(role)

    def _covering(self, subjects, table, cols, denied, base_filters,
                  base_label, scoped_label):
        """(covering scopes, uncovered columns, scoped grants) at one level.

        `denied`: columns a p3 takes away at this level. With columns C a
        scope covers iff C is within its columns minus `denied`; with no
        columns (COUNT(*)) iff at least one column of the table is
        readable through it.
        """
        uncovered = [c for c in cols
                     if self._grant(self.allow_grants, subjects, table, c) is None]
        grants = self._filters(subjects, table, scoped=True)

        def covers(columns) -> bool:
            usable = [c for c in columns if c not in denied]
            return set(cols) <= set(usable) if cols else bool(usable)

        granted = [c for c in self.schema.get(table, ())
                   if self._grant(self.allow_grants, subjects, table, c)]
        covering = []
        if covers(granted):
            if not base_filters:  # every row: scoped grants can add nothing
                return [(base_label, None)], uncovered, grants
            covering = [(base_label, rf) for rf in base_filters]
        for sub, rf in grants:
            if covers(rf.columns):
                covering.append((scoped_label(sub, rf), rf))
        return covering, uncovered, grants

    def _denies(self, subjects, table, cols, prefix) -> list:
        out = []
        for sub, rf in self.deny_filters:
            if sub not in subjects or rf.table != table:
                continue
            if rf.columns is None or set(cols) & set(rf.columns):
                suffix = f":{rf.columns_text}" if rf.scoped else ""
                out.append((f"{prefix}[{sub}{suffix}]", rf))
        return out

    # -- the decision -------------------------------------------------------

    def decide(self, subj: Subjects, table: str, cols: list) -> Decision:
        """Authorize one reference to `table` using columns `cols`.

        Precedence (highest first): user deny > user allow > role deny >
        role allow. The deny reason for a reference nobody covers names
        the first (in query order) column no scope covers - with no user
        or deny rules on the table this is exactly the classic
        "role lacks read on table.column".
        """
        d = Decision()
        user = {subj.user}
        for c in cols:
            sub = self._grant(self.deny_grants, user, table, c)
            if sub is not None:
                d.failure = (f"user rule denies {READ} on '{table}.{c}' "
                             f"(deny:user[{sub}] {table}.{c})")
                d.failure_col = c
                return d
        d.user_deny = self._denies(user, table, cols, "user_deny")
        # Column denies apply to every scope of their level and below: a
        # user deny also removes the column from every role-level scope.
        all_cols = self.schema.get(table, ())
        user_denied = {c for c in all_cols
                       if self._grant(self.deny_grants, user, table, c)}
        role_denied_cols = user_denied | {
            c for c in all_cols if self._grant(self.deny_grants, subj.roles, table, c)}
        user_filters, borrowed = self.user_base_filters(subj, table)
        user_label = f"user_allow[{subj.user}]" + ("(role rows)" if borrowed else "")
        d.user_cov, user_uncovered, user_grants = self._covering(
            user, table, cols, user_denied, user_filters, user_label,
            lambda s, rf: f"user_allow[{s}:{rf.columns_text}]")
        role_denied = None
        for c in cols:
            sub = self._grant(self.deny_grants, subj.roles, table, c)
            if sub is not None:
                role_denied = (sub, c)
                break
        d.role_cov, uncovered, grants = self._covering(
            subj.roles, table, cols, role_denied_cols,
            self.role_base_filters(subj, table), "base",
            lambda s, rf: f"scoped[{s}:{rf.columns_text}]")
        d.role_deny = self._denies(subj.roles, table, cols, "role_deny")
        if d.role_cov or d.user_cov:
            return d
        if not cols:
            if user_denied >= set(all_cols):
                d.failure = f"user rule denies {READ} on every column of {table!r}"
            elif role_denied_cols >= set(all_cols):
                d.failure = f"role rule denies {READ} on every column of {table!r}"
            else:
                d.failure = (f"role {subj.role!r} lacks {READ} on any column of "
                             f"{table!r} (a query on a table needs a grant on "
                             "it even if it reads no column)")
            return d
        if role_denied is not None:
            sub, c = role_denied
            d.failure = (f"role rule denies {READ} on '{table}.{c}' "
                         f"(deny:role[{sub}] {table}.{c})")
            d.failure_col = c
        else:
            obj = f"{table}.{uncovered[0]}"
            d.failure = f"role {subj.role!r} lacks {READ} on {obj!r}"
            if grants:
                d.failure += (
                    f": no scope on {table!r} covers columns "
                    f"({', '.join(cols)}); scoped grants cover ("
                    + ", ".join(rf.columns_text for _, rf in grants) + ")")
            d.failure_col = uncovered[0]
        # A user allow is its own scope: say what it covers, so the mixed
        # case (user rules cover some columns, the role the rest) is clear.
        if len(user_uncovered) < len(cols):
            covered = [c for c in cols if c not in user_uncovered]
            d.failure += (f"; {subj.user}'s grants cover ({', '.join(covered)})"
                          f" but not ({', '.join(user_uncovered)})")
        if user_grants:
            d.failure += (f"; {subj.user}'s scoped grants cover ("
                          + ", ".join(rf.columns_text for _, rf in user_grants)
                          + ")")
        return d

    # -- effective access (UX / admin summaries; the gate uses decide()) ----

    def columns_for(self, subjects, schema: dict) -> dict:
        """table -> [columns] granted to `subjects` by p and not taken away
        by p3 (one level only, no precedence between levels)."""
        out: dict = {}
        for table, cols in schema.items():
            allowed = [c for c in cols
                       if self._grant(self.allow_grants, subjects, table, c)
                       and not self._grant(self.deny_grants, subjects, table, c)]
            if allowed:
                out[table] = allowed
        return out

    def effective_columns(self, username: str, schema: dict) -> dict:
        """table -> [columns] the user can read via plain (unscoped) grants
        after precedence: user deny > user allow > role deny > role allow."""
        subj = self.subjects_for(username)
        out: dict = {}
        if subj is None:
            return out
        user = {subj.user}
        for table, cols in schema.items():
            allowed = []
            for c in cols:
                if self._grant(self.deny_grants, user, table, c):
                    continue
                if self._grant(self.allow_grants, user, table, c) or (
                        self._grant(self.allow_grants, subj.roles, table, c)
                        and not self._grant(self.deny_grants, subj.roles, table, c)):
                    allowed.append(c)
            if allowed:
                out[table] = allowed
        return out

    def scoped_columns(self, username: str) -> dict:
        """table -> [(subject, [columns])] scoped grants the user holds, with
        columns a deny takes away removed (empty grants dropped)."""
        subj = self.subjects_for(username)
        out: dict = {}
        if subj is None:
            return out
        user = {subj.user}
        for sub, rf in self.row_filters:
            if not rf.scoped or sub not in subj.roles | user:
                continue
            level = user if sub == subj.user else subj.roles | user
            cols = [c for c in rf.columns
                    if not self._grant(self.deny_grants, level, rf.table, c)]
            if cols:
                out.setdefault(rf.table, []).append((sub, cols))
        return out

    def denied_columns(self, username: str, schema: dict) -> dict:
        """table -> [columns] a column deny takes away from this user (user
        denies always; role denies unless a user allow overrides)."""
        subj = self.subjects_for(username)
        out: dict = {}
        if subj is None:
            return out
        user = {subj.user}
        for table, cols in schema.items():
            denied = [c for c in cols if self._grant(self.deny_grants, user, table, c)
                      or (self._grant(self.deny_grants, subj.roles, table, c)
                          and not self._grant(self.allow_grants, user, table, c))]
            if denied:
                out[table] = denied
        return out


def compile_snapshot(version: int, enforcer: casbin.Enforcer, attributes,
                     schema: dict, *, dialect: str, sig=None,
                     fingerprint: str = "") -> PolicySnapshot:
    """Validate a loaded policy + attributes and build the snapshot.

    Raises ValueError on anything the gate refuses to serve (fail closed):
    malformed rule arity, a model.conf without p3/p4, a user subject that
    is not a known non-master worker, a g row whose parent is a user
    subject, or a row filter compile_row_filter rejects, an invalid
    worker email, or two workers sharing an email. Called by
    load_snapshot, the loader the gate and PolicyAdmin share.

    `fingerprint` identifies the exact file bytes the snapshot was built
    from (the gate always passes it; PolicyAdmin's dry-run snapshots don't
    need one). The snapshot holds deeply read-only copies of `attributes`
    and `schema` (freeze()), so nothing that receives them - an attribute
    provider, a host - can change what later requests see.
    """
    if not isinstance(attributes, Mapping) or not all(
            isinstance(r, Mapping) for r in attributes.values()):
        raise ValueError("worker attributes must map username -> object")
    schema = check_schema(schema)
    check_worker_emails(attributes)
    for ptype in (PTYPE_DENY_COLUMNS, PTYPE_DENY_ROWS):
        if ptype not in enforcer.model.model["p"]:
            raise ValueError(f"model.conf does not define {ptype} (deny rules)")

    def check_subject(sub, rule):
        if not is_user_subject(sub):
            return
        record = attributes.get(sub[len(USER_PREFIX):])
        if not isinstance(record, Mapping) or record.get("role") == MASTER_ROLE:
            raise ValueError(f"rule {rule!r}: user subject {sub!r} is not a "
                             "known non-master worker")

    def check_no_master(rule, *fields):
        # Invariant #8 at the gate: `master` manages policy and has no
        # data access. A hand-edited "g, user:bob, master" + "p, master,
        # ..." must fail the load, not grant anything.
        for f in fields:
            if f == MASTER_ROLE or f.partition(".")[0] == MASTER_ROLE:
                raise ValueError(f"rule {rule!r}: the {MASTER_ROLE!r} role "
                                 "may not appear in the policy")

    grants = {PTYPE_ALLOW_COLUMNS: [], PTYPE_DENY_COLUMNS: []}
    for ptype, out in grants.items():
        for rule in enforcer.get_named_policy(ptype):
            # Casbin has no inline comments: "read # temp" is the action.
            # Anything but exactly "read" would silently drop the rule.
            if len(rule) != 3 or rule[2] != READ:
                raise ValueError(f"malformed {ptype} rule {rule!r}: expected "
                                 f"{ptype}, subject, table.column, {READ}")
            check_subject(rule[0], rule)
            check_no_master(rule, rule[0], rule[1])
            if ptype == PTYPE_DENY_COLUMNS:
                table, _, column = rule[1].partition(".")
                if table not in schema or not (column == "*" or column in schema[table]):
                    raise ValueError(f"{ptype} rule {rule!r} denies an unknown "
                                     "table.column (it would deny nothing)")
            out.append((rule[0], rule[1]))
    for rule in enforcer.get_grouping_policy():
        if len(rule) != 2:
            raise ValueError(f"malformed g rule {rule!r}")
        check_subject(rule[0], rule)
        check_no_master(rule, rule[0], rule[1])
        if is_user_subject(rule[1]):
            raise ValueError(f"rule {rule!r}: nothing may inherit from a user "
                             "subject")
    filters = {PTYPE_ALLOW_ROWS: [], PTYPE_DENY_ROWS: []}
    for ptype, out in filters.items():
        for rule in enforcer.get_named_policy(ptype):
            # 3 fields: row filter; 4 fields: column-scoped. pycasbin's file
            # adapter keeps every field a line has regardless of the model's
            # definition, and p2/p4 never go through enforce(), so arity is
            # checked here (and only here).
            if len(rule) not in (3, 4):
                raise ValueError(f"malformed {ptype} rule {rule!r}")
            sub, table, template = rule[:3]
            check_subject(sub, rule)
            check_no_master(rule, sub, table)
            try:
                rf = compile_row_filter(table, template, schema,
                                        dialect=dialect)
                if len(rule) == 4:
                    rf = replace(rf, columns=parse_scope_columns(
                        table, rule[3], schema))
            except FilterError as err:
                raise ValueError(f"unsafe row filter {rule!r}: {err}") from None
            out.append((sub, rf))
    return PolicySnapshot(
        version, enforcer, freeze(attributes),
        tuple(filters[PTYPE_ALLOW_ROWS]), sig,
        deny_filters=tuple(filters[PTYPE_DENY_ROWS]),
        allow_grants=tuple(grants[PTYPE_ALLOW_COLUMNS]),
        deny_grants=tuple(grants[PTYPE_DENY_COLUMNS]),
        schema=freeze(schema),
        fingerprint=fingerprint,
    )


def freeze(value):
    """A deeply read-only copy of JSON-like data: mappings become
    MappingProxyType over fresh dicts (no one holds the underlying dict),
    lists/tuples become tuples; scalars are returned as they are."""
    if isinstance(value, Mapping):
        return MappingProxyType({k: freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(v) for v in value)
    return value


def check_schema(schema) -> dict:
    """Validate db_schema.json's shape - {table: {column: type}} with
    non-empty string names and string types - and return a plain copy.
    Raises ValueError (a bad schema fails the load: deny everyone)."""
    if not isinstance(schema, Mapping):
        raise ValueError("db_schema.json must map table -> {column: type}")
    out = {}
    for table, cols in schema.items():
        if not isinstance(table, str) or not table:
            raise ValueError(f"db_schema.json: invalid table name {table!r}")
        if not isinstance(cols, Mapping) or not cols:
            raise ValueError(f"db_schema.json: table {table!r} must map "
                             "column -> type")
        for col, typ in cols.items():
            if not isinstance(col, str) or not col or not isinstance(typ, str):
                raise ValueError(f"db_schema.json: table {table!r} has an "
                                 f"invalid column entry {col!r}: {typ!r}")
        out[table] = dict(cols)
    return out


# A deliberately conservative address shape (ASCII only, no quoting, no IP
# literals): an identity key must compare reliably after ASCII lowercasing.
EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+", re.ASCII)
EMAIL_MAX_LEN = 254


# Only ASCII whitespace is stripped from an identity email: str.strip()
# would also eat U+00A0, U+2003, ... that a lookalike sign-up can carry.
EMAIL_STRIP_CHARS = " \t\r\n"


def normalize_email(value) -> Optional[str]:
    """The identity key for an email, or None if it can't be one.

    Strips ASCII whitespace only, requires a plain ASCII address
    (EMAIL_RE, at most EMAIL_MAX_LEN characters) and lowercases it with
    ASCII rules. Never casefold(): it maps lookalikes onto ASCII (U+017F
    long s -> "s", the Kelvin sign -> "k", sharp s -> "ss", the "fi"
    ligature -> "fi"), so "carol@example.te\u017ft" would resolve to
    carol while the host (Open WebUI compares with .lower()) treats it as
    a different account. Used for identity emails and worker emails alike.
    """
    if not isinstance(value, str):
        return None
    value = str.__str__(value).strip(EMAIL_STRIP_CHARS)  # plain str
    if len(value) > EMAIL_MAX_LEN or not EMAIL_RE.fullmatch(value):
        return None
    return value.lower()


def check_worker_emails(attributes: dict) -> None:
    """`email` is optional per worker; when present it must be a string of
    conservative address shape, and lowercased emails must be unique. An
    email is an identity key (hosts map a signed-in user to a worker by
    it), so an invalid or shared one fails the whole load (deny everyone)
    rather than letting one sign-in resolve to the wrong worker."""
    seen: dict = {}
    for username, record in attributes.items():
        if "email" not in record:
            continue
        value = record["email"]
        if (not isinstance(value, str) or len(value) > EMAIL_MAX_LEN
                or not EMAIL_RE.fullmatch(value)):
            raise ValueError(f"worker {username!r} has an invalid email "
                             "(expected a plain ASCII address like "
                             "name@example.com)")
        key = normalize_email(value)
        if key in seen:
            raise ValueError(f"workers {seen[key]!r} and {username!r} share "
                             "the same email (emails must be unique)")
        seen[key] = username


def policy_fingerprint(model_bytes: bytes, policy_bytes: bytes,
                       attributes_bytes: bytes, schema_bytes: bytes) -> str:
    """sha256 over the exact bytes of model.conf, policy.csv,
    worker_attributes.json and db_schema.json (length-prefixed, so no two
    different file sets share a fingerprint by concatenation)."""
    h = hashlib.sha256(b"rbic-policy-fingerprint-v2\0")
    for label, data in ((b"model", model_bytes), (b"policy", policy_bytes),
                        (b"attributes", attributes_bytes),
                        (b"schema", schema_bytes)):
        h.update(label + b"\0" + str(len(data)).encode("ascii") + b"\0")
        h.update(data)
    return h.hexdigest()


class _BytesPolicyAdapter(Adapter):
    """Loads policy lines from bytes exactly as Casbin's FileAdapter loads
    them from a file (LF-separated, UTF-8, each line stripped), so the gate
    parses the very bytes it fingerprints instead of re-reading the file."""

    def __init__(self, data: bytes):
        self._data = data

    def load_policy(self, model):
        for raw in self._data.split(b"\n"):
            load_policy_line(raw.decode().strip(), model)

    def save_policy(self, model):
        raise NotImplementedError("the gate never writes policy")


def load_enforcer(model_bytes: bytes, policy_bytes: bytes) -> casbin.Enforcer:
    """A Casbin enforcer built from file bytes, equivalent to
    casbin.Enforcer(model_path, policy_path) over files with those bytes
    (the model is decoded as UTF-8 with universal newlines, as open() in
    text mode does)."""
    text = io.TextIOWrapper(io.BytesIO(model_bytes), encoding="utf-8").read()
    model = Model()
    model.load_model_from_text(text)
    return casbin.Enforcer(model, _BytesPolicyAdapter(policy_bytes))


def check_policy_ptypes(policy_path: str) -> None:
    """check_policy_bytes over a policy file."""
    with open(policy_path, "rb") as f:
        check_policy_bytes(f.read())


def check_policy_bytes(data: bytes) -> None:
    """Refuse policy lines with an unknown ptype: Casbin's adapter silently
    drops them, which could hide a mistyped deny rule.

    Lines are split exactly as Casbin does (LF only, bytes). A lone CR is
    refused: an editor shows it as a line break, Casbin does not, so
    "# note\\rp3, ..." would look like a deny while being a comment.
    """
    for n, raw in enumerate(data.split(b"\n"), 1):
        if b"\r" in raw.rstrip(b"\r") or raw.count(b"\r") > 1:
            raise ValueError(f"policy line {n}: contains a lone carriage "
                             "return (use LF or CRLF line endings)")
        text = raw.decode("utf-8", errors="replace").strip()
        if not text or text.startswith("#"):
            continue
        ptype = text.split(",", 1)[0].strip()
        if ptype not in KNOWN_PTYPES:
            raise ValueError(f"policy line {n}: unknown rule type {ptype!r}"
                             f" (expected one of {sorted(KNOWN_PTYPES)})")


def load_snapshot(model_bytes: bytes, policy_bytes: bytes,
                  attributes_bytes: bytes, schema_bytes: bytes, *,
                  dialect: str, version: int = 0, sig=None) -> PolicySnapshot:
    """THE policy loader: file bytes -> validated PolicySnapshot.

    The gate builds every snapshot with it, and PolicyAdmin validates
    every proposal (and re-validates at apply time) with it, so the admin
    can never write a policy the gate would refuse. Raises on anything the
    gate refuses to serve: a lone CR or unknown ptype (check_policy_bytes),
    a policy Casbin can't load, attributes or a schema that aren't JSON,
    and everything compile_snapshot refuses (schema shape, arity, user
    subjects, master, unsafe filters, invalid or duplicate emails).
    """
    if not isinstance(schema_bytes, (bytes, bytearray)):
        raise TypeError("load_snapshot takes db_schema.json's bytes")
    schema_bytes = bytes(schema_bytes)
    check_policy_bytes(policy_bytes)
    enforcer = load_enforcer(model_bytes, policy_bytes)
    attributes = json.loads(attributes_bytes)
    schema = json.loads(schema_bytes)
    return compile_snapshot(
        version, enforcer, attributes, schema, dialect=dialect, sig=sig,
        fingerprint=policy_fingerprint(model_bytes, policy_bytes,
                                       attributes_bytes, schema_bytes))


def _read_bytes(path) -> bytes:
    with open(path, "rb") as f:
        return f.read()


class _TableRef:
    """One table reference (alias) in one SELECT and its access decision."""

    __slots__ = ("select", "table", "decision", "first")

    def __init__(self, select: exp.Select, table: exp.Table, decision: Decision,
                 first: int):
        self.select = select
        self.table = table
        self.decision = decision
        self.first = first


class SQLGate:
    def __init__(
        self,
        model_path,
        policy_path,
        schema_path,
        attributes_path,
        *,
        dialect: str,
    ):
        # No default paths or dialect: the caller (normally from_config)
        # decides both, so nothing depends on the current directory.
        self.dialect = dialect
        model_path, policy_path, schema_path, attributes_path = (
            os.fspath(p) for p in (model_path, policy_path, schema_path,
                                   attributes_path))
        self.model_path = model_path
        self.policy_path = policy_path
        self.schema_path = schema_path
        self.attributes_path = attributes_path
        # db_schema.json is policy input like the others: PolicyAdmin
        # validates proposals against the file on disk, so the gate must
        # serve the same schema (a p3 on a newly added column would
        # otherwise break the reload and deny everyone).
        self._reload_paths = (policy_path, model_path, attributes_path,
                              schema_path)
        self._lock = threading.Lock()
        self._snapshot = self._build_snapshot(1, self._stat_signature())

    @classmethod
    def from_config(cls, cfg: EngineConfig) -> "SQLGate":
        """Gate over an EngineConfig's policy files, in its dialect."""
        return cls(cfg.model_path, cfg.policy_path, cfg.schema_path,
                   cfg.attributes_path, dialect=cfg.dialect)

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def authorize(self, username: str, sql: str) -> str:
        """Validate + rewrite LLM-generated SQL.

        Returns SQL that is safe to execute, or raises AccessDenied.
        """
        snap = self._maybe_reload()  # the ONE snapshot this request uses
        try:
            return self._authorize(snap, username, sql)
        except AccessDenied:
            raise
        except Exception as err:  # noqa: BLE001 - anything unexpected denies
            self._deny(username, sql, "internal error while checking query: "
                                      f"{type(err).__name__}: {err}")

    def refresh(self) -> int:
        """Pick up policy/attribute file changes now; return policy_version."""
        return self._maybe_reload().version

    def refreshed_snapshot(self) -> PolicySnapshot:
        """Pick up file changes now and return the resulting snapshot (the
        one consistent view a caller should use for a whole request)."""
        return self._maybe_reload()

    @property
    def snapshot(self) -> PolicySnapshot:
        return self._snapshot

    @property
    def policy_version(self) -> int:
        return self._snapshot.version

    @property
    def fingerprint(self) -> str:
        """sha256 of the model.conf, policy.csv, worker_attributes.json and
        db_schema.json bytes the current snapshot was built from. Stable across restarts
        and processes (unlike policy_version). A broken snapshot keeps the
        fingerprint of the last good load; check `broken` too."""
        return self._snapshot.fingerprint

    @property
    def enforcer(self) -> casbin.Enforcer:
        return self._snapshot.enforcer

    @property
    def attributes(self) -> Mapping:
        """The current snapshot's worker attributes (read-only)."""
        return self._snapshot.attributes

    @property
    def schema(self) -> Mapping:
        """The current snapshot's db_schema.json (read-only,
        table -> {column: type}); reloaded with the policy files."""
        return self._snapshot.schema

    @property
    def broken(self) -> Optional[str]:
        """Reason the last reload failed (gate denies everything), or None."""
        return self._snapshot.broken

    # ------------------------------------------------------------------
    # hot reload
    # ------------------------------------------------------------------

    def _stat_signature(self) -> tuple:
        sig = []
        for path in self._reload_paths:
            st = os.stat(path)
            sig.append((st.st_mtime_ns, st.st_size, st.st_ino))
        return tuple(sig)

    def _build_snapshot(self, version: int, sig) -> PolicySnapshot:
        # Each file is read exactly once; the bytes parsed are the bytes
        # fingerprinted. (_maybe_reload re-stats afterwards, so files that
        # change mid-load fail the reload.)
        return load_snapshot(
            _read_bytes(self.model_path), _read_bytes(self.policy_path),
            _read_bytes(self.attributes_path), _read_bytes(self.schema_path),
            dialect=self.dialect, version=version, sig=sig)

    def _maybe_reload(self) -> PolicySnapshot:
        """Return the current snapshot, rebuilding it if a policy file changed.

        Fail closed: while a reload is failing, every request is denied.
        A file that changes mid-load is treated as a failed reload so a
        half-written policy (e.g. grants without their row filters) is
        never served. The new snapshot is built completely before it is
        swapped in, under the lock, as a single reference assignment.
        """
        with self._lock:
            snap = self._snapshot
            try:
                sig = self._stat_signature()
            except OSError as err:
                # sig=None forces a full reload once the files are back
                return self._mark_broken(snap, None,
                                         f"cannot stat policy files: {err}")
            if sig == snap.sig:
                return snap
            try:
                new = self._build_snapshot(snap.version + 1, sig)
                if self._stat_signature() != sig:
                    raise RuntimeError("policy files changed during reload")
            except Exception as err:  # noqa: BLE001 - any failure fails closed
                return self._mark_broken(snap, sig, f"{type(err).__name__}: {err}")
            self._snapshot = new
            logger.info("POLICY_RELOAD version=%d", new.version)
            return new

    def _mark_broken(self, snap, sig, reason: str) -> PolicySnapshot:
        if snap.broken != reason:
            logger.error("POLICY_RELOAD_FAILED reason=%s", reason)
        self._snapshot = replace(snap, sig=sig, broken=reason)
        return self._snapshot

    # ------------------------------------------------------------------
    # pipeline stages (each takes the request's snapshot explicitly)
    # ------------------------------------------------------------------

    def _authorize(self, snap: PolicySnapshot, username: str, sql: str) -> str:
        if snap.broken:
            self._deny(username, sql, f"policy reload failed: {snap.broken}")
        worker = snap.attributes.get(username)
        if not isinstance(worker, Mapping):
            self._deny(username, sql, "unknown worker")
        role = worker.get("role")
        if not isinstance(role, str):
            self._deny(username, sql, "worker has no role")
        if is_user_subject(role):
            self._deny(username, sql, "worker role may not be a user subject")
        if role == MASTER_ROLE:
            self._deny(username, sql, "master users have no data access")
        subj = subjects_for(snap.enforcer, username, role)

        tree = self._parse_single_select(username, sql)
        tree = self._qualify(snap, username, sql, tree)
        self._check_constructs(username, sql, tree)
        self._check_rbac(snap, username, subj, sql, tree)
        scopes = self._inject_abac(snap, username, subj, worker, sql, tree)

        safe_sql = tree.sql(dialect=self.dialect)
        logger.info(
            "ALLOW user=%s role=%s policy_version=%d scopes=%s sql=%r rewritten=%r",
            username, role, snap.version, scopes, sql, safe_sql,
        )
        return safe_sql

    def _parse_single_select(self, username: str, sql: str) -> exp.Select:
        try:
            statements = sqlglot.parse(sql, dialect=self.dialect)
        except SqlglotError:  # ParseError, TokenError, ...
            self._deny(username, sql, "unparseable SQL")
        statements = [s for s in statements if s is not None]
        if len(statements) != 1:
            self._deny(username, sql, "expected exactly one statement")
        tree = statements[0]
        if not isinstance(tree, exp.Select):
            # v1 is deliberately narrow: a single SELECT only.
            # No UNION/INTERSECT, no INSERT/UPDATE/DELETE, no DDL.
            self._deny(
                username, sql, f"{type(tree).__name__} statements are not allowed"
            )
        param = tree.find(*_BIND_NODES)
        if param is not None:
            self._deny(username, sql,
                       f"bind parameter {param.sql()!r} is not allowed")
        return tree

    def _qualify(self, snap: PolicySnapshot, username: str, sql: str,
                 tree: exp.Select) -> exp.Select:
        """Resolve every column against the snapshot's schema and expand
        SELECT *.

        After this step every column node is table-qualified, so RBAC is
        checked on real (table, column) pairs — a bare `SELECT *` becomes
        explicit columns and is gated column-by-column.
        """
        for t in tree.find_all(exp.Table):
            if t.name not in snap.schema:
                self._deny(username, sql, f"unknown table {t.name!r}")
        # sqlglot gets a private plain copy (it never sees the shared one)
        schema = {t: dict(cols) for t, cols in snap.schema.items()}
        try:
            tree = qualify(tree, schema=schema, dialect=self.dialect)
        except SqlglotError:
            self._deny(username, sql, "could not resolve all columns against schema")
        if self._has_unexpanded_star(tree):
            self._deny(username, sql, "unresolved star expression")
        return tree

    def _check_constructs(self, username: str, sql: str, tree: exp.Select) -> None:
        """Deny any SQL construct the column-capture pipeline does not model.

        Runs on the qualified tree (what RBAC sees). Every node must be an
        allowlisted type and none an excluded one; tables and columns must
        be plain, unqualified names (a schema-qualified `hr.employees` could
        be a different table than the one db_schema.json describes); a
        bare identifier may only appear where it names an alias, table,
        column or window.
        """
        for node in tree.walk():
            if isinstance(node, UNSUPPORTED_NODES) or not isinstance(
                    node, SUPPORTED_NODES):
                self._deny(username, sql, "unsupported SQL construct "
                                          f"{type(node).__name__}: {node.sql()!r}")
            if isinstance(node, (exp.Table, exp.Column)):
                if not isinstance(node.this, (exp.Identifier, exp.Star)) or any(
                        node.args.get(k) for k in ("db", "catalog")):
                    self._deny(username, sql, "unsupported qualified reference "
                                              f"{node.sql()!r}")
            elif isinstance(node, exp.Identifier) and not isinstance(
                    node.parent, _IDENTIFIER_PARENTS):
                self._deny(username, sql, f"unsupported identifier {node.sql()!r} "
                                          f"in {type(node.parent).__name__}")

    def _check_rbac(
        self, snap: PolicySnapshot, username: str, subj: Subjects, sql: str,
        tree: exp.Select,
    ) -> None:
        """Deny unless every table reference is covered at some level.

        The deny reason is the first failing reference's (in query order;
        see PolicySnapshot.decide).
        """
        failed = [ref for ref in self._scope_plan(snap, username, subj, sql, tree)
                  if not ref.decision.covered]
        if failed:
            self._deny(username, sql,
                       min(failed, key=lambda r: r.first).decision.failure)

    def _inject_abac(
        self, snap: PolicySnapshot, username: str, subj: Subjects, worker: dict,
        sql: str, tree: exp.Select,
    ) -> str:
        """AND each table reference's visible-row predicate into its SELECT.

        Per level, the covering scopes are OR-combined (each is a
        sufficient scope, so the worker sees their union) and the level's
        row denies are ANDed in as NOT (...). Then
          ((role allow AND NOT role denies) OR user allow) AND NOT user denies
        is ANDed into the SELECT; an unfiltered, undenied level needs no
        predicate at all. Different tables (and different references to
        the same table) stay independent. Returns an audit summary naming
        the scopes and denies that decided each reference, e.g.
        "employees:base-role_deny[hr_staff]+user_allow[user:alice]".
        """
        audit = []
        for ref in self._scope_plan(snap, username, subj, sql, tree):
            d = ref.decision
            if not d.covered:  # _check_rbac already denied; paranoia
                self._deny(username, sql, d.failure)
            owner = ref.table.alias_or_name
            role = self._bind_level(username, worker, sql, ref, d.role_cov)
            user = self._bind_level(username, worker, sql, ref, d.user_cov)
            # A predicate of None means "every row" (nothing to AND in).
            summary, role_pred, user_pred = "", None, None
            if role is not None:
                role_pred, labels = role
                summary = "+".join(labels)
                if d.role_deny:
                    role_pred = self._and_not(role_pred, self._bind_denies(
                        username, worker, sql, ref, d.role_deny))
                    summary += "".join(f"-{label}" for label, _ in d.role_deny)
            if user is not None:
                user_pred, labels = user
                summary += ("+" if summary else "") + "+".join(labels)
            if role is not None and user is not None:  # union of both levels
                allow = (None if role_pred is None or user_pred is None
                         else role_pred.or_(user_pred))
            else:
                allow = role_pred if role is not None else user_pred
            if d.user_deny:
                allow = self._and_not(allow, self._bind_denies(
                    username, worker, sql, ref, d.user_deny))
                summary += "".join(f"-{label}" for label, _ in d.user_deny)
            if allow is not None:
                ref.select.where(allow, copy=False)
            audit.append(f"{owner}:{summary}")
        return ";".join(audit) or "-"

    def _bind_level(self, username, worker, sql, ref, covering):
        """(predicate|None, labels) for one level, or None if nothing covers.

        predicate None with labels = the unfiltered base scope (every row).
        Every covering scope must bind (fail closed): a row filter or
        scoped grant that covers the reference but needs an attribute the
        worker lacks denies the query. Scoped grants that do not cover the
        reference are not here, so they never narrow another scope.
        """
        if not covering:
            return None
        conds, labels = [], []
        for label, rf in covering:
            if rf is None:  # unfiltered base scope
                labels.append(label)
                continue
            what = "scoped grant" if rf.scoped else "row filter"
            try:
                cond = bind_row_filter(rf, worker, ref.table.alias_or_name)
            except MissingAttribute as missing:
                self._deny(
                    username, sql,
                    f"worker lacks attribute {missing.name!r} required by "
                    f"{what} on {ref.table.name!r}",
                )
            except FilterError as err:
                self._deny(username, sql, f"cannot bind {what} on "
                                          f"{ref.table.name!r}: {err}")
            conds.append(cond)
            labels.append(label)
        if not conds:
            return None, labels
        combined = conds[0]
        for extra in conds[1:]:
            combined = combined.or_(extra)
        return combined, labels

    def _bind_denies(self, username, worker, sql, ref, denies):
        """OR of the bound deny filters. A deny that can't bind fails
        closed: the whole query is denied. An unquoted placeholder must
        bind a number: a string there (employee_id = 'x') is simply FALSE,
        and NOT FALSE would hide nothing."""
        conds = []
        for _, rf in denies:
            try:
                check_unquoted_values(rf, worker)
                conds.append(bind_row_filter(rf, worker, ref.table.alias_or_name))
            except MissingAttribute as missing:
                self._deny(username, sql,
                           f"worker lacks attribute {missing.name!r} required "
                           f"by deny filter on {ref.table.name!r}")
            except FilterError as err:
                self._deny(username, sql, f"cannot bind deny filter on "
                                          f"{ref.table.name!r}: {err}")
        combined = conds[0]
        for extra in conds[1:]:
            combined = combined.or_(extra)
        return combined

    @staticmethod
    def _and_not(pred, deny):
        """pred AND NOT (deny); pred None means every row. In SQL,
        NOT (NULL) is NULL, so a row where the deny filter is NULL is
        excluded (fail closed)."""
        hidden = exp.Not(this=exp.Paren(this=deny))
        return hidden if pred is None else pred.and_(hidden)

    def _scope_plan(self, snap, username, subj, sql, tree) -> list:
        """One _TableRef per table reference with its Decision, in
        injection order (SELECT traversal, then FROM/JOIN order)."""
        used, order = self._column_refs(username, sql, tree)
        plan = []
        for select in list(tree.find_all(exp.Select)):
            for table in self._tables_in_from(select):
                cols = used.get(id(table), [])
                decision = snap.decide(subj, table.name, cols)
                first = order.get((id(table), decision.failure_col), 0)
                plan.append(_TableRef(select, table, decision, first))
        return plan

    def _column_refs(self, username: str, sql: str, tree: exp.Select) -> tuple:
        """(id(table node) -> [column names used, first-use order],
            (id(table node), column) -> position in the query).

        Each column is resolved against the FROM/JOIN tables of its own
        SELECT, then of the enclosing SELECTs (correlated references), so
        an alias reused in a subquery can never stand in for an outer
        table.
        """
        used: dict = {}
        order: dict = {}
        for ordinal, col in enumerate(tree.find_all(exp.Column)):
            if isinstance(col.this, exp.Star):
                continue  # leftover stars already denied in _qualify
            if not col.table and self._is_output_alias_ref(col):
                continue  # ORDER BY/GROUP BY ref to an already-checked projection
            table = self._resolve_table(username, sql, col)
            if table is None:
                self._deny(
                    username, sql, f"cannot resolve table for column {col.sql()!r}"
                )
            cols = used.setdefault(id(table), [])
            if col.name not in cols:
                cols.append(col.name)
                order[(id(table), col.name)] = ordinal
        return used, order

    def _resolve_table(self, username, sql, col: exp.Column):
        if not col.table:
            return None
        select = col.find_ancestor(exp.Select)
        while select is not None:
            matches = [t for t in self._tables_in_from(select)
                       if t.alias_or_name == col.table]
            if len(matches) > 1:
                self._deny(username, sql, f"ambiguous table alias {col.table!r}")
            if matches:
                return matches[0]
            select = select.find_ancestor(exp.Select)
        return None

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_output_alias_ref(col: exp.Column) -> bool:
        """True if an unqualified column names an output alias of its SELECT.

        e.g. ORDER BY employee_id where employee_id is a projection alias —
        the aliased expression's own columns were already RBAC-checked.

        Only the bare, whole ORDER BY / GROUP BY key counts: inside an
        expression (ORDER BY CASE WHEN salary > 1 ...) databases resolve the
        name to the table column, so it must stay in C.
        """
        select = col.find_ancestor(exp.Select)
        if select is None:
            return False
        parent = col.parent
        if isinstance(parent, exp.Ordered):
            parent = parent.parent
        if not isinstance(parent, (exp.Order, exp.Group)) or parent.parent is not select:
            return False
        return col.name in {e.alias_or_name for e in select.expressions}

    @staticmethod
    def _tables_in_from(select: exp.Select) -> list:
        """Tables directly in this SELECT's FROM/JOINs (not subquery innards)."""
        tables = []
        # sqlglot >=30 stores FROM under "from_"; older versions used "from".
        from_ = select.args.get("from_") or select.args.get("from")
        if from_ is not None and isinstance(from_.this, exp.Table):
            tables.append(from_.this)
        for join in select.args.get("joins") or []:
            if isinstance(join.this, exp.Table):
                tables.append(join.this)
        return tables

    @staticmethod
    def _has_unexpanded_star(tree: exp.Select) -> bool:
        for star in tree.find_all(exp.Star):
            if isinstance(star.parent, exp.Count):
                continue  # COUNT(*) is fine — rows are already ABAC-filtered
            return True
        return any(
            isinstance(col.this, exp.Star) for col in tree.find_all(exp.Column)
        )

    @staticmethod
    def _deny(username: str, sql: str, reason: str) -> NoReturn:
        logger.warning("DENY user=%s reason=%s sql=%r", username, reason, sql)
        raise AccessDenied(reason)
