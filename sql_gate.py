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
- any referenced column outside the role's RBAC grants        -> deny
- ABAC filter needing an attribute the worker lacks           -> deny
- any unexpected error while checking a query                 -> deny

Row filters are never built by string substitution. Each p2 template is
parsed once per policy load with every {placeholder} replaced by a
sentinel string literal; at query time the sentinels are swapped for
literal AST nodes built from the worker's attribute values, so a value can
never become an identifier, operator or subquery.

Thread safety: the enforcer, attributes and compiled row filters live in
one immutable PolicySnapshot. A reload builds a complete new snapshot and
swaps it in under a lock; authorize() takes the snapshot once and every
stage of that request uses only it.
"""

import json
import logging
import os
import re
import string
import threading
from dataclasses import dataclass, replace
from typing import NoReturn, Optional

import casbin
import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.qualify import qualify

logger = logging.getLogger("rbic.audit")

DENY_MESSAGE = "You have no access to this information, please approach your manager."
READ = "read"


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
STATIC_FILTER_WARNING = ("WARNING: this filter is the same for every user "
                         "(it does not depend on who is asking).")


@dataclass(frozen=True)
class RowFilter:
    """A parsed p2 template. `tree` holds sentinel literals; never mutate it."""

    table: str
    template: str
    tree: exp.Expression
    placeholders: tuple  # attribute names, first-appearance order, unique

    @property
    def static(self) -> bool:
        return not self.placeholders

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


def compile_row_filter(table: str, template, schema: dict,
                       dialect: str = "postgres", strict: bool = False
                       ) -> RowFilter:
    """Parse and validate a p2 template; raise FilterError if unsafe.

    Always enforced (also by the gate on every policy load): valid SQL
    condition; no subqueries, table references, stars, bind parameters or
    unsafe functions; only unqualified columns of `table`; placeholders are
    simple names that stand alone as a value ('{dept}' or {ids}).

    strict=True adds the master-bot authoring rules: printable ASCII only,
    no SQL comments, and a predicate-only structure with no tautologies.
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
class PolicySnapshot:
    """Everything one request needs, loaded together and never mutated."""

    version: int
    enforcer: casbin.Enforcer
    attributes: dict
    row_filters: tuple  # ((role, RowFilter), ...) in policy order
    sig: Optional[tuple]
    broken: Optional[str] = None

    def filters_for_role(self, role: str) -> dict:
        """table -> [RowFilter] for the role, including inherited roles."""
        roles = {role, *self.enforcer.get_implicit_roles_for_user(role)}
        filters: dict = {}
        for sub, rf in self.row_filters:
            if sub in roles:
                filters.setdefault(rf.table, []).append(rf)
        return filters


class SQLGate:
    def __init__(
        self,
        model_path: str = "casbin/model.conf",
        policy_path: str = "casbin/policy.csv",
        schema_path: str = "db_schema.json",
        attributes_path: str = "worker_attributes.json",
        dialect: str = "postgres",
    ):
        self.dialect = dialect
        with open(schema_path) as f:
            self.schema = json.load(f)
        self.model_path = model_path
        self.policy_path = policy_path
        self.attributes_path = attributes_path
        self._reload_paths = (policy_path, model_path, attributes_path)
        self._lock = threading.Lock()
        self._snapshot = self._build_snapshot(1, self._stat_signature())

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

    @property
    def snapshot(self) -> PolicySnapshot:
        return self._snapshot

    @property
    def policy_version(self) -> int:
        return self._snapshot.version

    @property
    def enforcer(self) -> casbin.Enforcer:
        return self._snapshot.enforcer

    @property
    def attributes(self) -> dict:
        return self._snapshot.attributes

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
        enforcer = casbin.Enforcer(self.model_path, self.policy_path)
        row_filters = []
        for rule in enforcer.get_named_policy("p2"):
            if len(rule) != 3:
                raise ValueError(f"malformed p2 rule {rule!r}")
            sub, table, template = rule
            try:
                rf = compile_row_filter(table, template, self.schema,
                                        self.dialect)
            except FilterError as err:
                raise ValueError(f"unsafe row filter {rule!r}: {err}") from None
            row_filters.append((sub, rf))
        with open(self.attributes_path) as f:
            attributes = json.load(f)
        if not isinstance(attributes, dict) or not all(
                isinstance(r, dict) for r in attributes.values()):
            raise ValueError("worker attributes must map username -> object")
        return PolicySnapshot(version, enforcer, attributes, tuple(row_filters),
                              sig)

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
        if not isinstance(worker, dict):
            self._deny(username, sql, "unknown worker")
        role = worker.get("role")
        if not isinstance(role, str):
            self._deny(username, sql, "worker has no role")

        tree = self._parse_single_select(username, sql)
        tree = self._qualify(username, sql, tree)
        self._check_rbac(snap, username, role, sql, tree)
        self._inject_abac(snap, username, role, worker, sql, tree)

        safe_sql = tree.sql(dialect=self.dialect)
        logger.info(
            "ALLOW user=%s role=%s policy_version=%d sql=%r rewritten=%r",
            username, role, snap.version, sql, safe_sql,
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

    def _qualify(self, username: str, sql: str, tree: exp.Select) -> exp.Select:
        """Resolve every column against the schema and expand SELECT *.

        After this step every column node is table-qualified, so RBAC is
        checked on real (table, column) pairs — a bare `SELECT *` becomes
        explicit columns and is gated column-by-column.
        """
        for t in tree.find_all(exp.Table):
            if t.name not in self.schema:
                self._deny(username, sql, f"unknown table {t.name!r}")
        try:
            tree = qualify(tree, schema=self.schema, dialect=self.dialect)
        except SqlglotError:
            self._deny(username, sql, "could not resolve all columns against schema")
        if self._has_unexpanded_star(tree):
            self._deny(username, sql, "unresolved star expression")
        return tree

    def _check_rbac(
        self, snap: PolicySnapshot, username: str, role: str, sql: str,
        tree: exp.Select,
    ) -> None:
        aliases = {t.alias_or_name: t.name for t in tree.find_all(exp.Table)}
        for col in tree.find_all(exp.Column):
            if isinstance(col.this, exp.Star):
                continue  # leftover stars already denied in _qualify
            if not col.table and self._is_output_alias_ref(col):
                continue  # ORDER BY/GROUP BY ref to an already-checked projection
            table = aliases.get(col.table)
            if table is None:
                self._deny(
                    username, sql, f"cannot resolve table for column {col.sql()!r}"
                )
            obj = f"{table}.{col.name}"
            if not snap.enforcer.enforce(role, obj, READ):
                self._deny(username, sql, f"role {role!r} lacks {READ} on {obj!r}")

    def _inject_abac(
        self, snap: PolicySnapshot, username: str, role: str, worker: dict,
        sql: str, tree: exp.Select,
    ) -> None:
        """AND each table's row scope into every SELECT that touches it.

        A worker's roles may carry several p2 rows for the same table
        (e.g. "own row" from a base role plus a manager scope). Each p2
        row is a sufficient scope, so same-table scopes are OR-combined
        (the union of what the roles may see) and that union is then
        ANDed into the query. Scopes on different tables stay independent.
        """
        filters = snap.filters_for_role(role)
        if not filters:
            return
        for select in list(tree.find_all(exp.Select)):
            for table in self._tables_in_from(select):
                scope = self._render_scope(
                    username, sql, filters.get(table.name, ()), worker, table
                )
                if scope is not None:
                    select.where(scope, copy=False)

    def _render_scope(
        self, username: str, sql: str, row_filters, worker: dict,
        table: exp.Table,
    ):
        """OR together a table's bound row filters; None if it has none."""
        scopes = []
        for rf in row_filters:
            try:
                cond = bind_row_filter(rf, worker, table.alias_or_name)
            except MissingAttribute as missing:
                self._deny(
                    username,
                    sql,
                    f"worker lacks attribute {missing.name!r} required by "
                    f"row filter on {table.name!r}",
                )
            except FilterError as err:
                self._deny(username, sql, f"cannot bind row filter on "
                                          f"{table.name!r}: {err}")
            scopes.append(cond)
        if not scopes:
            return None
        combined = scopes[0]
        for extra in scopes[1:]:
            combined = combined.or_(extra)
        return combined

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_output_alias_ref(col: exp.Column) -> bool:
        """True if an unqualified column names an output alias of its SELECT.

        e.g. ORDER BY employee_id where employee_id is a projection alias —
        the aliased expression's own columns were already RBAC-checked.
        """
        select = col.find_ancestor(exp.Select)
        if select is None:
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
            if isinstance(star.parent, exp.Func):
                continue  # COUNT(*) is fine — rows are already ABAC-filtered
            return True
        return any(
            isinstance(col.this, exp.Star) for col in tree.find_all(exp.Column)
        )

    @staticmethod
    def _deny(username: str, sql: str, reason: str) -> NoReturn:
        logger.warning("DENY user=%s reason=%s sql=%r", username, reason, sql)
        raise AccessDenied(reason)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    gate = SQLGate()
    demos = [
        # (user, LLM-generated SQL)
        ("alice", "SELECT sku, qty FROM inventory WHERE qty < 10"),
        ("alice", "SELECT * FROM inventory"),
        ("bob", "SELECT name, dept FROM employees"),
        ("bob", "SELECT name, salary FROM employees"),      # salary -> deny
        ("bob", "SELECT * FROM employees"),                 # * expands to salary -> deny
        ("carol", "SELECT name, salary FROM employees"),    # hr_manager inherits + salary
        ("dave", "SELECT vendor, amount FROM invoices"),
        ("dave", "SELECT name FROM employees"),             # finance can't read HR -> deny
        ("alice", "DROP TABLE inventory"),                  # not a SELECT -> deny
        ("alice", "SELECT secret FROM classified"),         # unknown table -> deny
    ]
    for user, sql in demos:
        print(f"{user}: {sql}")
        try:
            print(f"  -> ALLOW: {gate.authorize(user, sql)}\n")
        except AccessDenied as e:
            print(f"  -> DENY ({e})")
            print(f"     bot says: {DENY_MESSAGE}\n")
