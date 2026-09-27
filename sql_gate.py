"""SQL firewall between the LLM's text-to-SQL output and the database.

Pipeline: parse -> qualify -> RBAC check -> ABAC rewrite -> safe SQL.

Casbin is the policy decision point (PDP); this module is the policy
enforcement point (PEP). Nothing the LLM generates reaches the database
without passing through SQLGate.authorize(), and the deny message is
generated here in code — never by the model.

Fail-closed rules:
- unparseable SQL, multiple statements, non-SELECT statement -> deny
- unknown table or unresolvable column (vs db_schema.json)    -> deny
- any referenced column outside the role's RBAC grants        -> deny
- ABAC filter needing an attribute the worker lacks           -> deny
"""

import json
import logging
from typing import NoReturn

import casbin
import sqlglot
from sqlglot import exp
from sqlglot.errors import OptimizeError, ParseError
from sqlglot.optimizer.qualify import qualify

logger = logging.getLogger("rbic.audit")

DENY_MESSAGE = "You have no access to this information, please approach your manager."
READ = "read"


class AccessDenied(Exception):
    """Query failed RBAC/ABAC or could not be safely analyzed."""


class SQLGate:
    def __init__(
        self,
        model_path: str = "casbin/model.conf",
        policy_path: str = "casbin/policy.csv",
        schema_path: str = "db_schema.json",
        attributes_path: str = "worker_attributes.json",
        dialect: str = "postgres",
    ):
        self.enforcer = casbin.Enforcer(model_path, policy_path)
        self.dialect = dialect
        with open(schema_path) as f:
            self.schema = json.load(f)
        with open(attributes_path) as f:
            self.attributes = json.load(f)

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def authorize(self, username: str, sql: str) -> str:
        """Validate + rewrite LLM-generated SQL.

        Returns SQL that is safe to execute, or raises AccessDenied.
        """
        worker = self.attributes.get(username)
        if worker is None:
            self._deny(username, sql, "unknown worker")
        role = worker["role"]

        tree = self._parse_single_select(username, sql)
        tree = self._qualify(username, sql, tree)
        self._check_rbac(username, role, sql, tree)
        self._inject_abac(username, role, worker, sql, tree)

        safe_sql = tree.sql(dialect=self.dialect)
        logger.info(
            "ALLOW user=%s role=%s sql=%r rewritten=%r", username, role, sql, safe_sql
        )
        return safe_sql

    # ------------------------------------------------------------------
    # pipeline stages
    # ------------------------------------------------------------------

    def _parse_single_select(self, username: str, sql: str) -> exp.Select:
        try:
            statements = sqlglot.parse(sql, dialect=self.dialect)
        except ParseError:
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
        except (OptimizeError, ParseError):
            self._deny(username, sql, "could not resolve all columns against schema")
        if self._has_unexpanded_star(tree):
            self._deny(username, sql, "unresolved star expression")
        return tree

    def _check_rbac(
        self, username: str, role: str, sql: str, tree: exp.Select
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
            if not self.enforcer.enforce(role, obj, READ):
                self._deny(username, sql, f"role {role!r} lacks {READ} on {obj!r}")

    def _inject_abac(
        self, username: str, role: str, worker: dict, sql: str, tree: exp.Select
    ) -> None:
        """AND each table's row scope into every SELECT that touches it.

        A worker's roles may carry several p2 rows for the same table
        (e.g. "own row" from a base role plus a manager scope). Each p2
        row is a sufficient scope, so same-table scopes are OR-combined
        (the union of what the roles may see) and that union is then
        ANDed into the query. Scopes on different tables stay independent.
        """
        filters = self._filters_for_role(role)
        if not filters:
            return
        # SQL-escape attribute values before substitution. Production
        # should bind these as query parameters instead.
        attrs = {k: str(v).replace("'", "''") for k, v in worker.items()}
        for select in tree.find_all(exp.Select):
            for table in self._tables_in_from(select):
                scope = self._render_scope(
                    username, sql, filters.get(table.name, ()), attrs, table
                )
                if scope is not None:
                    select.where(scope, copy=False)

    def _render_scope(
        self, username: str, sql: str, templates, attrs: dict, table: exp.Table
    ):
        """OR together a table's rendered filter templates; None if no templates."""
        scopes = []
        for template in templates:
            try:
                rendered = template.format(**attrs)
            except KeyError as missing:
                self._deny(
                    username,
                    sql,
                    f"worker lacks attribute {missing} required by "
                    f"row filter on {table.name!r}",
                )
            cond = sqlglot.parse_one(rendered, dialect=self.dialect)
            owner = table.alias_or_name
            for col in cond.find_all(exp.Column):
                col.set("table", exp.to_identifier(owner))
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

    def _filters_for_role(self, role: str) -> dict:
        """Collect p2 filter templates for the role, including inherited roles."""
        roles = {role, *self.enforcer.get_implicit_roles_for_user(role)}
        filters: dict = {}
        for sub, table, template in self.enforcer.get_named_policy("p2"):
            if sub in roles:
                filters.setdefault(table, []).append(template)
        return filters

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
