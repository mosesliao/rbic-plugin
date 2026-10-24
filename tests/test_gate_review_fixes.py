"""Regression tests for the independent security review of the gate.

1. Whole-row references ((e).salary, to_jsonb(e), SELECT e ...) and every
   other construct the column-capture pipeline does not model are denied
   (allowlist of expression types), under both dialects.
2. A table reference that uses no column (COUNT(*), SELECT 1) still needs
   a grant on the table and gets the covering scopes' row filters.
3. A personal p grant keeps the rows the user's roles see (their own
   3-field p2 filter, if any, replaces that).
4. A covering scope whose filter can't bind denies, consistently.
6. `master` anywhere in the policy fails the load (gate-level invariant 8).

Every test works on tmp_path copies; the repo's files are never touched.
Run: pytest -q
"""

import json
import logging
import sqlite3
from types import SimpleNamespace as NS

import pytest

from rbic.admin import CHANGES_HEADER, PolicyAdmin
from rbic.gate import AccessDenied, SQLGate

logging.disable(logging.CRITICAL)

WW_LINE = "p2, warehouse_worker, employees, id = '{employee_id}', id|name|salary"
ALICE_LINE = "p2, user:alice, employees, id = 2, id|name|salary"
DIALECTS = ("postgres", "sqlite")
ENG_NAMES = [("Bob Tan",), ("Carol Lim",), ("Erin Ng",)]


def base_policy_text(root) -> str:
    return (root / "casbin" / "policy.csv").read_text(
        encoding="utf-8").split(CHANGES_HEADER)[0]


def make_env(tmp_path, dialect):
    """tmp_path: a demo_dir copy; policy.csv = base policy + WW_LINE + ALICE_LINE."""
    (tmp_path / "casbin" / "policy.csv").write_text(
        base_policy_text(tmp_path) + CHANGES_HEADER + "\n" + WW_LINE + "\n"
        + ALICE_LINE + "\n", encoding="utf-8", newline="\n")
    paths = NS(
        root=tmp_path,
        policy=tmp_path / "casbin" / "policy.csv",
        model=tmp_path / "casbin" / "model.conf",
        schema=tmp_path / "db_schema.json",
        attrs=tmp_path / "worker_attributes.json",
        changelog=tmp_path / "policy_changes.jsonl",
        db=tmp_path / "company.db",
        dialect=dialect,
    )
    paths.admin = PolicyAdmin(
        policy_path=str(paths.policy), attributes_path=str(paths.attrs),
        schema_path=str(paths.schema), model_path=str(paths.model),
        changelog_path=str(paths.changelog),
    )
    paths.gate = SQLGate(
        model_path=str(paths.model), policy_path=str(paths.policy),
        schema_path=str(paths.schema), attributes_path=str(paths.attrs),
        dialect=dialect,
    )
    return paths


@pytest.fixture(params=DIALECTS)
def env(request, demo_dir):
    """Gate under each dialect (authorize-only tests)."""
    return make_env(demo_dir, request.param)


@pytest.fixture
def senv(demo_dir):
    """SQLite gate whose rewritten SQL is executed against the demo DB."""
    return make_env(demo_dir, "sqlite")


def rows(env, username, sql):
    safe_sql = env.gate.authorize(username, sql)
    conn = sqlite3.connect(f"file:{env.db}?mode=ro", uri=True)
    try:
        return conn.execute(safe_sql).fetchall()
    finally:
        conn.close()


def denied(env, username, sql) -> str:
    with pytest.raises(AccessDenied) as exc:
        env.gate.authorize(username, sql)
    return str(exc.value)


def add_lines(env, *lines):
    with open(env.policy, "a", encoding="utf-8", newline="") as f:
        f.write("".join(line + "\n" for line in lines))
    env.gate.refresh()


def set_attrs(env, user, **values):
    data = json.loads(env.attrs.read_text(encoding="utf-8"))
    data[user].update(values)
    env.attrs.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    env.gate.refresh()


# ---- 1. whole-row references and unsupported constructs -----------------------------

WHOLE_ROW = [
    "SELECT name FROM employees e WHERE (e).salary > 100000",
    "SELECT name, (e).salary FROM employees e",
    "SELECT e FROM employees e",
    "SELECT to_jsonb(e) FROM employees e",
    "SELECT row_to_json(e) FROM employees e",
    "SELECT name FROM employees e ORDER BY (e).salary",
    "SELECT employees FROM employees",
    "SELECT name FROM employees WHERE employees > 1",
    "SELECT (employees).salary FROM employees",
    "SELECT name FROM employees e WHERE (e.name).x > 1",
]


@pytest.mark.parametrize("sql", WHOLE_ROW)
def test_whole_row_references_are_denied_for_everyone(env, sql):
    # bob (no salary grant): previously a salary oracle under postgres
    denied(env, "bob", sql)
    # carol may read every employees column and is still denied: the
    # construct itself is outside what the pipeline models
    denied(env, "carol", sql)
    denied(env, "alice", sql)


def test_review_repros_whole_row(env):
    add_lines(env, "p3, hr_manager, employees.salary, read")
    denied(env, "carol", "SELECT name, (e).salary FROM employees e")
    denied(env, "alice", "SELECT name, (e).dept, (e).start_date FROM employees e")
    reason = denied(env, "bob", "SELECT name FROM employees e WHERE (e).salary > 100000")
    if env.dialect == "postgres":
        assert reason.startswith("unsupported SQL construct")
    else:
        assert "resolve" in reason


UNSUPPORTED = [
    "SELECT name FROM public.employees",
    "SELECT name FROM employees WHERE public.employees.id = 1",
    "SELECT name INTO x FROM employees",
    "SELECT name FROM employees FOR UPDATE",
    "WITH employees AS (SELECT 1 AS salary) SELECT salary FROM employees",
    "WITH t AS (SELECT name FROM employees) SELECT name FROM t",
    "SELECT name FROM employees WHERE id IN (SELECT id FROM employees UNION SELECT id FROM employees)",
    "SELECT name FROM employees e, LATERAL (SELECT 1 AS x) l",
    "SELECT name FROM employees TABLESAMPLE SYSTEM (10)",
    "SELECT name FROM employees e WHERE e.* IS NOT NULL",
    "SELECT name FROM employees WHERE id = $1",
]


@pytest.mark.parametrize("sql", UNSUPPORTED)
def test_unmodeled_constructs_are_denied(env, sql):
    denied(env, "carol", sql)


ALLOWED = [
    ("carol", "SELECT name, salary FROM employees WHERE salary > 100000"),
    ("carol", "SELECT e.name, p.salary FROM employees AS e JOIN payroll AS p "
              "ON p.employee_id = e.id WHERE p.salary > 1"),
    ("carol", "SELECT e.name FROM employees e JOIN payroll p USING (id)"),
    ("carol", "SELECT name FROM employees e WHERE EXISTS (SELECT 1 FROM payroll p "
              "WHERE p.employee_id = e.id)"),
    ("carol", "SELECT dept, COUNT(*), AVG(salary) FROM employees GROUP BY dept "
              "HAVING COUNT(*) > 1 ORDER BY 2 DESC LIMIT 5 OFFSET 1"),
    ("carol", "SELECT DISTINCT dept FROM employees WHERE name LIKE '%a%' AND id NOT IN (1, 2) "
              "AND dept IS NOT NULL AND NOT (id = 3) AND -id < 0 AND id BETWEEN 1 AND 9"),
    ("carol", "SELECT name, SUM(salary) OVER (PARTITION BY dept ORDER BY id) FROM employees"),
    ("carol", "SELECT CASE WHEN salary > 1 THEN 'a' ELSE 'b' END AS band, CAST(id AS TEXT), "
              "COALESCE(dept, 'x'), LOWER(name), name || ' x', id % 2 FROM employees"),
    ("carol", "SELECT name AS n FROM employees ORDER BY n"),
    ("carol", "SELECT dept AS d, COUNT(*) FROM employees GROUP BY d"),
    ("carol", "SELECT name FROM employees WHERE id = (SELECT MAX(id) FROM employees)"),
    ("carol", "SELECT name FROM employees WHERE (id, name) IN ((1, 'a'))"),
    ("carol", "SELECT name FROM employees WHERE start_date > CAST('2020-01-01' AS DATE)"),
    ("carol", "SELECT COUNT(*) FROM employees"),
    ("carol", "SELECT 1 FROM employees"),
    ("carol", "SELECT * FROM employees"),
    ("bob", "SELECT name, dept FROM employees"),
    ("bob", "SELECT id, name FROM employees WHERE id IN (SELECT employee_id FROM leave_requests)"),
    ("alice", "SELECT sku, qty FROM inventory WHERE qty < 10"),
    ("alice", "SELECT * FROM inventory"),
    ("alice", "SELECT name, salary FROM employees WHERE name LIKE '%Carol%'"),
    ("dave", "SELECT vendor, amount FROM invoices"),
    ("carol", "SELECT employee_id, salary FROM payroll ORDER BY employee_id"),
]


@pytest.mark.parametrize("user, sql", ALLOWED)
def test_ordinary_queries_still_pass(env, user, sql):
    assert env.gate.authorize(user, sql)


def test_postgres_only_constructs_still_pass(demo_dir):
    env = make_env(demo_dir, "postgres")
    for sql in ("SELECT EXTRACT(YEAR FROM start_date), start_date + INTERVAL '1 day' "
                "FROM employees",
                "SELECT name FROM employees e WHERE e.id = ANY(ARRAY[1, 2])",
                "SELECT name FROM employees e WHERE e.name ~ 'x'",
                "SELECT name FROM employees FETCH FIRST 3 ROWS ONLY",
                "SELECT name, SUM(salary) OVER w FROM employees WINDOW w AS (PARTITION BY dept)"):
        assert env.gate.authorize("carol", sql)


def test_star_only_allowed_inside_count(env):
    denied(env, "carol", "SELECT ROW(*) FROM employees")
    assert env.gate.authorize("carol", "SELECT COUNT(*) FROM employees")


# ---- 2. column-less references need a grant ------------------------------------------

@pytest.mark.parametrize("sql", ["SELECT COUNT(*) FROM employees",
                                 "SELECT 1 FROM employees",
                                 "SELECT COUNT(*) FROM employees, payroll"])
def test_column_less_reference_needs_a_grant(env, sql):
    reason = denied(env, "dave", sql)
    assert "lacks read on any column of 'employees'" in reason
    reason = denied(env, "master", sql)
    assert "master" in reason
    assert env.gate.authorize("bob", sql)


def test_column_less_reference_gets_the_covering_scopes_rows(senv):
    # bob: the base scope (dept filter) covers
    assert rows(senv, "bob", "SELECT COUNT(*) FROM employees") == [(3,)]
    assert "employees.dept = 'engineering'" in senv.gate.authorize(
        "bob", "SELECT COUNT(*) FROM employees")
    # alice: only scoped grants (own row via the role, Carol's via user:alice)
    assert rows(senv, "alice", "SELECT COUNT(*) FROM employees") == [(2,)]
    assert rows(senv, "alice", "SELECT 1 FROM employees") == [(1,), (1,)]
    # dave has no grant on employees at all
    denied(senv, "dave", "SELECT COUNT(*) FROM employees")
    assert rows(senv, "dave", "SELECT COUNT(*) FROM invoices") == [(3,)]


def test_whole_table_column_deny_denies_column_less_reference(senv):
    add_lines(senv, "p3, user:carol, employees.*, read")
    reason = denied(senv, "carol", "SELECT COUNT(*) FROM employees")
    assert reason == "user rule denies read on every column of 'employees'"
    denied(senv, "carol", "SELECT 1 FROM employees")
    assert rows(senv, "bob", "SELECT COUNT(*) FROM employees") == [(3,)]


def test_deny_on_every_column_denies_column_less_reference(senv):
    add_lines(senv, *(f"p3, hr_staff, employees.{c}, read"
                      for c in ("id", "name", "dept", "start_date", "salary")))
    reason = denied(senv, "bob", "SELECT COUNT(*) FROM employees")
    assert "role rule denies read on every column of 'employees'" in reason
    denied(senv, "carol", "SELECT COUNT(*) FROM employees")
    # a personal allow on one column re-opens it, with the role's rows
    add_lines(senv, "p, user:bob, employees.name, read")
    assert rows(senv, "bob", "SELECT COUNT(*) FROM employees") == [(3,)]
    denied(senv, "carol", "SELECT COUNT(*) FROM employees")


def test_partial_column_deny_keeps_column_less_reference(senv):
    add_lines(senv, "p3, hr_staff, employees.dept, read")
    assert rows(senv, "bob", "SELECT COUNT(*) FROM employees") == [(3,)]


# ---- 3. a personal grant keeps the role's rows ----------------------------------------

def test_personal_grant_borrows_role_row_filter(senv):
    add_lines(senv, "p, user:bob, employees.salary, read")
    assert rows(senv, "bob", "SELECT salary FROM employees ORDER BY salary") == [
        (65000,), (78000,), (112000,)]
    safe = senv.gate.authorize("bob", "SELECT salary FROM employees")
    assert "employees.dept = 'engineering'" in safe
    assert rows(senv, "bob", "SELECT COUNT(*) FROM employees") == [(3,)]


def test_personal_row_filter_replaces_the_borrowed_one(senv):
    add_lines(senv, "p, user:bob, employees.salary, read",
              "p2, user:bob, employees, id = 4")
    assert rows(senv, "bob", "SELECT salary FROM employees") == [(58000,)]   # widened
    assert "employees.dept" not in senv.gate.authorize("bob", "SELECT salary FROM employees")
    # the role's own scope is untouched
    assert rows(senv, "bob", "SELECT name FROM employees ORDER BY id") == ENG_NAMES


def test_personal_grant_without_any_filter_sees_every_row(senv):
    # dave's finance_analyst has no row filter on invoices; neither has he
    add_lines(senv, "p, user:dave, employees.name, read")
    assert len(rows(senv, "dave", "SELECT name FROM employees")) == 7
    add_lines(senv, "p, user:alice, invoices.vendor, read")
    assert len(rows(senv, "alice", "SELECT vendor FROM invoices")) == 3


def test_user_allow_over_role_column_deny_keeps_role_rows(senv):
    add_lines(senv, "p3, hr_staff, employees.dept, read",
              "p, user:carol, employees.dept, read")
    assert rows(senv, "carol", "SELECT dept FROM employees") == [("engineering",)] * 3
    denied(senv, "bob", "SELECT dept FROM employees")


def test_personal_scoped_grant_keeps_its_own_filter(senv):
    assert rows(senv, "alice", "SELECT name, salary FROM employees WHERE id = 2") == [
        ("Carol Lim", 112000)]
    add_lines(senv, "p2, user:bob, employees, id = 4, id|name")
    assert rows(senv, "bob", "SELECT name FROM employees ORDER BY id") == [
        ("Bob Tan",), ("Carol Lim",), ("Erin Ng",), ("Frank Ho",)]


def test_borrowed_filter_that_cannot_bind_denies_personal_grant(senv):
    add_lines(senv, "p, user:bob, employees.salary, read")
    set_attrs(senv, "bob", dept=None)
    data = json.loads(senv.attrs.read_text(encoding="utf-8"))
    del data["bob"]["dept"]
    senv.attrs.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    reason = denied(senv, "bob", "SELECT salary FROM employees")
    assert "lacks attribute 'dept'" in reason


def test_audit_label_marks_borrowed_rows(senv, caplog):
    add_lines(senv, "p, user:bob, employees.salary, read",
              "p, user:dave, employees.name, read")
    logging.disable(logging.NOTSET)
    try:
        with caplog.at_level(logging.INFO, logger="rbic.audit"):
            senv.gate.authorize("bob", "SELECT salary FROM employees")
            senv.gate.authorize("dave", "SELECT name FROM employees")
    finally:
        logging.disable(logging.CRITICAL)
    allow = [r.getMessage() for r in caplog.records if r.getMessage().startswith("ALLOW")]
    assert "scopes=employees:user_allow[user:bob](role rows)" in allow[0]
    assert "scopes=employees:user_allow[user:dave] " in allow[1]


def test_admin_describes_personal_grant_rows(senv):
    change = senv.admin.propose_grant(username="bob", table="employees",
                                      column="salary")
    assert "rows their role sees: (dept = '{dept}')" in change.description
    assert "ALL rows" not in change.description
    senv.admin.apply(change, actor="master")
    info = senv.admin.describe_user("bob")
    assert info["personal_grant_rows"] == {
        "employees": "rows their role sees: (dept = '{dept}')"}
    scope = senv.admin.propose_row_scope(username="bob", table="employees",
                                         filter_template="id = 4")
    assert "replacing the rows they saw before (rows their role sees" \
        in scope.description
    assert "WIDEN" in scope.description
    senv.admin.apply(scope, actor="master")
    assert senv.admin.describe_user("bob")["personal_grant_rows"] == {
        "employees": "only rows matching their personal row filter: (id = 4)"}
    # a grant on a table with no filter anywhere says so loudly
    change = senv.admin.propose_grant(username="dave", table="employees",
                                      column="name")
    assert "ALL rows of employees - no row filter at role or personal level" \
        in change.description
    assert "WARNING: ALL rows" in change.description


# ---- 4. an unbindable covering filter always denies -----------------------------------

def test_unbindable_role_filter_denies_consistently(senv):
    add_lines(senv, "g, user:alice, hr_staff")
    # every reference the hr_staff base scope covers is denied (its filter
    # needs dept, which alice lacks) - whatever other scopes would allow
    for sql in ("SELECT name FROM employees", "SELECT id, name FROM employees",
                "SELECT COUNT(*) FROM employees", "SELECT id FROM leave_requests"):
        reason = denied(senv, "alice", sql)
        assert "lacks attribute 'dept'" in reason
    # a reference the base scope does NOT cover (salary is not an hr_staff
    # column) is decided by the scoped grants alone, which bind fine
    assert rows(senv, "alice", "SELECT name, salary FROM employees ORDER BY id") == [
        ("Carol Lim", 112000), ("Alice Wong", 42000)]
    set_attrs(senv, "alice", dept="engineering")
    # base (dept) OR her own scoped grant (id = 6) OR user:alice (id = 2)
    assert rows(senv, "alice", "SELECT name FROM employees ORDER BY id") == \
        ENG_NAMES + [("Alice Wong",)]
    assert rows(senv, "alice", "SELECT name, dept FROM employees ORDER BY id") == [
        ("Bob Tan", "engineering"), ("Carol Lim", "engineering"),
        ("Erin Ng", "engineering")]
    assert rows(senv, "alice", "SELECT name, salary FROM employees ORDER BY id") == [
        ("Carol Lim", 112000), ("Alice Wong", 42000)]


def test_unbindable_scoped_grant_denies_only_what_it_covers(senv):
    add_lines(senv, "p2, hr_staff, employees, id = '{manager_id}', id|name")
    reason = denied(senv, "bob", "SELECT name FROM employees")
    assert "manager_id" in reason and "scoped grant" in reason
    assert rows(senv, "bob", "SELECT name, dept FROM employees ORDER BY id") == [
        ("Bob Tan", "engineering"), ("Carol Lim", "engineering"),
        ("Erin Ng", "engineering")]
    assert rows(senv, "carol", "SELECT name, salary FROM employees ORDER BY id")
    set_attrs(senv, "bob", manager_id=4)
    assert rows(senv, "bob", "SELECT name FROM employees ORDER BY id") == [
        ("Bob Tan",), ("Carol Lim",), ("Erin Ng",), ("Frank Ho",)]


def test_unfiltered_base_scope_is_not_narrowed_by_a_scoped_grant(senv):
    add_lines(senv, "p2, finance_analyst, invoices, id = '{manager_id}', id|vendor")
    assert len(rows(senv, "dave", "SELECT id, vendor FROM invoices")) == 3


def test_admin_warns_about_unbindable_scoped_grant(senv):
    change = senv.admin.propose_row_scope("hr_staff", "employees",
                                          "id = '{manager_id}'", columns="id, name")
    assert "bob lacks attribute(s) manager_id" in change.description
    assert "carol lacks attribute(s) manager_id" in change.description


# ---- 6. master anywhere in the policy fails the load ----------------------------------

@pytest.mark.parametrize("lines", [
    ("g, user:bob, master", "p, master, employees.salary, read"),
    ("p, master, employees.name, read",),
    ("p3, master, employees.name, read",),
    ("p2, master, employees, id = 1",),
    ("p4, master, employees, id = 1",),
    ("g, master, hr_staff",),
    ("g, hr_staff, master",),
    ("g, user:bob, master",),
    ("p, hr_staff, master.x, read",),
    ("p2, hr_staff, master, id = 1",),
])
def test_master_in_policy_breaks_the_snapshot(senv, lines):
    good = senv.policy.read_text(encoding="utf-8")
    senv.policy.write_text(good + "".join(l + "\n" for l in lines),
                           encoding="utf-8", newline="\n")
    reason = denied(senv, "bob", "SELECT salary FROM employees")
    assert "reload" in reason and "master" in reason
    assert senv.gate.broken
    denied(senv, "alice", "SELECT sku FROM inventory")
    senv.policy.write_text(good, encoding="utf-8", newline="\n")
    assert rows(senv, "bob", "SELECT name FROM employees ORDER BY id") == ENG_NAMES
    assert not senv.gate.broken


def test_admin_refuses_policy_with_master(senv):
    add_lines(senv, "g, user:bob, master", "p, master, employees.salary, read")
    with pytest.raises(ValueError, match="master"):
        senv.admin.propose_grant("hr_staff", "employees", "salary")


def test_master_user_has_no_data_access(env):
    for sql in ("SELECT name FROM employees", "SELECT COUNT(*) FROM employees",
                "SELECT 1 FROM invoices"):
        assert "master" in denied(env, "master", sql)
