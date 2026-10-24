"""Per-user rules with allow AND deny, user overriding role.

Subjects: a role, or "user:<username>" (a personal rule). Allow rules are
p/p2, deny rules p3/p4 (same shapes). Precedence, highest first:
user deny > user allow > role deny > role allow; per table reference
  visible = ((role_allow AND NOT role_deny) OR user_allow) AND NOT user_deny

Every test works on tmp_path copies; the repo's files are never touched.
Run: pytest -q
"""

import json
import logging
import sqlite3
from types import SimpleNamespace as NS

import pytest

from rbic.cli import master as master_cli
from rbic import engine as chatbot
from rbic import master as master_bot
from rbic.admin import CHANGES_HEADER, PolicyAdmin
from rbic.gate import AccessDenied, SQLGate, subjects_for

logging.disable(logging.CRITICAL)

# The two scoped grants the tests assume (written into the temp policy;
# the live policy.csv is read only up to the master-chatbot changes block,
# so what has since been applied through the bot cannot affect the tests).
WW_LINE = "p2, warehouse_worker, employees, id = '{employee_id}', id|name|salary"
ALICE_LINE = "p2, user:alice, employees, id = 2, id|name|salary"
CAROL = ("Carol Lim", 112000)
ALICE = ("Alice Wong", 42000)
SALARY_Q = "SELECT name, salary FROM employees ORDER BY id"
NAMES_Q = "SELECT name FROM employees ORDER BY id"
ENG_NAMES = [("Bob Tan",), ("Carol Lim",), ("Erin Ng",)]


def base_policy_text(root) -> str:
    return (root / "casbin" / "policy.csv").read_text(
        encoding="utf-8").split(CHANGES_HEADER)[0]


@pytest.fixture
def env(demo_dir):
    tmp_path = demo_dir
    """tmp copies of the shipped files; policy.csv = base policy + the
    role-level scoped grant WW_LINE + the personal rule ALICE_LINE; plus a
    second warehouse worker."""
    (tmp_path / "casbin" / "policy.csv").write_text(
        base_policy_text(tmp_path) + CHANGES_HEADER + "\n" + WW_LINE + "\n"
        + ALICE_LINE + "\n", encoding="utf-8", newline="\n")
    attrs = json.loads((tmp_path / "worker_attributes.json").read_text())
    attrs["wes"] = {"role": "warehouse_worker", "site": "SG-02", "employee_id": 8}
    (tmp_path / "worker_attributes.json").write_text(
        json.dumps(attrs, indent=2) + "\n", encoding="utf-8")
    paths = NS(
        root=tmp_path,
        policy=tmp_path / "casbin" / "policy.csv",
        model=tmp_path / "casbin" / "model.conf",
        schema=tmp_path / "db_schema.json",
        attrs=tmp_path / "worker_attributes.json",
        changelog=tmp_path / "policy_changes.jsonl",
        db=tmp_path / "company.db",
    )
    assert ALICE_LINE in paths.policy.read_text(encoding="utf-8")
    paths.admin = PolicyAdmin(
        policy_path=str(paths.policy), attributes_path=str(paths.attrs),
        schema_path=str(paths.schema), model_path=str(paths.model),
        changelog_path=str(paths.changelog),
    )
    paths.gate = SQLGate(
        model_path=str(paths.model), policy_path=str(paths.policy),
        schema_path=str(paths.schema), attributes_path=str(paths.attrs),
        dialect="sqlite",
    )
    return paths


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


def remove_lines(env, *lines):
    text = env.policy.read_text(encoding="utf-8")
    for line in lines:
        assert line + "\n" in text
        text = text.replace(line + "\n", "")
    env.policy.write_text(text, encoding="utf-8", newline="\n")
    env.gate.refresh()


def set_attrs(env, user, **values):
    data = json.loads(env.attrs.read_text(encoding="utf-8"))
    data[user].update(values)
    env.attrs.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    env.gate.refresh()


# ---- the migrated rule: alice (and only alice) reads Carol's salary ------------

def test_alice_reads_carols_salary_via_personal_rule(env):
    assert rows(env, "alice", "SELECT name, salary FROM employees WHERE id = 2") \
        == [CAROL]
    # the shipped role-level scoped grant adds her own row; nothing else
    assert rows(env, "alice", SALARY_Q) == [CAROL, ALICE]
    denied(env, "alice", "SELECT name, dept FROM employees")


def test_other_warehouse_worker_does_not_see_carol(env):
    assert rows(env, "wes", SALARY_Q) == []          # own row (id 8) doesn't exist
    assert rows(env, "wes", "SELECT name, salary FROM employees WHERE id = 2") == []
    reason = denied(env, "wes", "SELECT name, dept FROM employees")
    assert "user:" not in reason


# ---- precedence -----------------------------------------------------------------

def test_user_column_deny_beats_role_allow(env):
    assert rows(env, "bob", "SELECT name, dept FROM employees ORDER BY id")
    add_lines(env, "p3, user:bob, employees.dept, read")
    reason = denied(env, "bob", "SELECT name, dept FROM employees")
    assert reason == ("user rule denies read on 'employees.dept' "
                      "(deny:user[user:bob] employees.dept)")
    assert rows(env, "bob", NAMES_Q) == ENG_NAMES   # other columns untouched
    assert rows(env, "carol", "SELECT name, dept FROM employees")  # others untouched


def test_user_row_deny_beats_role_allow(env):
    add_lines(env, "p4, user:bob, employees, id = 2")
    assert rows(env, "bob", NAMES_Q) == [("Bob Tan",), ("Erin Ng",)]
    assert rows(env, "carol", NAMES_Q) == ENG_NAMES
    safe = env.gate.authorize("bob", NAMES_Q)
    assert "AND NOT (employees.id = 2)" in safe


def test_user_allow_beats_role_column_deny(env):
    add_lines(env, "p3, hr_staff, employees.dept, read")
    denied(env, "bob", "SELECT dept FROM employees")
    denied(env, "carol", "SELECT dept FROM employees")   # inherits the deny
    add_lines(env, "p, user:carol, employees.dept, read")
    # the personal allow overrides the role deny but keeps the role's rows
    assert rows(env, "carol", "SELECT dept FROM employees") == [("engineering",)] * 3
    denied(env, "bob", "SELECT dept FROM employees")
    # a personal grant is its own scope: mixing it with role-only columns
    # is denied, and the reason says what the personal rules cover
    reason = denied(env, "carol", "SELECT name, dept FROM employees")
    assert reason.startswith("role rule denies read on 'employees.dept' "
                             "(deny:role[hr_staff] employees.dept)")
    assert "user:carol's grants cover (dept) but not (name)" in reason


def test_user_allow_beats_role_row_deny(env):
    add_lines(env, "p4, hr_staff, employees, id = 2")
    assert rows(env, "bob", NAMES_Q) == [("Bob Tan",), ("Erin Ng",)]
    assert rows(env, "carol", NAMES_Q) == [("Bob Tan",), ("Erin Ng",)]
    add_lines(env, "p2, user:bob, employees, id = 2, id|name")
    assert rows(env, "bob", NAMES_Q) == ENG_NAMES   # (eng AND NOT id=2) OR id=2
    assert rows(env, "carol", NAMES_Q) == [("Bob Tan",), ("Erin Ng",)]


def test_user_deny_beats_user_allow(env):
    add_lines(env, "p3, user:alice, employees.salary, read")
    reason = denied(env, "alice", "SELECT name, salary FROM employees WHERE id = 2")
    assert "deny:user[user:alice] employees.salary" in reason
    assert rows(env, "alice", "SELECT name FROM employees WHERE id = 2") == \
        [("Carol Lim",)]
    add_lines(env, "p4, user:alice, employees, id = 2")
    assert rows(env, "alice", "SELECT name FROM employees WHERE id = 2") == []


def test_role_deny_beats_role_allow_and_is_inherited(env):
    add_lines(env, "p3, hr_staff, employees.name, read")
    for user in ("bob", "carol"):
        reason = denied(env, user, NAMES_Q)
        assert reason == ("role rule denies read on 'employees.name' "
                          "(deny:role[hr_staff] employees.name)")
    add_lines(env, "p4, employee, payroll, employee_id = 2")
    assert rows(env, "carol", "SELECT employee_id FROM payroll ORDER BY 1") == \
        [(1,), (3,)]
    assert rows(env, "bob", "SELECT employee_id FROM payroll") == [(1,)]


def test_column_scoped_row_deny_only_bites_when_reading_those_columns(env):
    add_lines(env, "p4, finance_analyst, invoices, status = 'paid', amount|vendor")
    assert rows(env, "dave", "SELECT id FROM invoices ORDER BY id") == [(1,), (2,), (3,)]
    assert rows(env, "dave", "SELECT id, amount FROM invoices ORDER BY id") == [
        (1, 15400.0), (3, 980.0)]


def test_deny_filter_null_fails_closed(env):
    add_lines(env, "p4, finance_analyst, invoices, status = 'paid'")
    safe = env.gate.authorize("dave", "SELECT id FROM invoices ORDER BY id")
    assert "NOT (invoices.status = 'paid')" in safe
    mem = sqlite3.connect(":memory:")
    mem.execute("CREATE TABLE invoices (id INTEGER, vendor TEXT, amount REAL, "
                "due_date TEXT, status TEXT)")
    mem.executemany("INSERT INTO invoices VALUES (?, ?, ?, ?, ?)", [
        (1, "a", 1.0, "2026-01-01", "unpaid"), (2, "b", 1.0, "2026-01-01", "paid"),
        (3, "c", 1.0, "2026-01-01", None)])
    assert mem.execute(safe).fetchall() == [(1,)]   # the NULL row is hidden


def test_deny_filter_missing_attribute_denies_outright(env):
    add_lines(env, "p4, hr_staff, employees, id = {manager_id}")
    reason = denied(env, "bob", NAMES_Q)
    assert "manager_id" in reason and "deny filter" in reason


def test_personal_grant_keeps_the_roles_row_filter(env):
    # a personal p grant borrows the role level's row filters (bob: dept)
    add_lines(env, "p, user:bob, employees.salary, read")
    assert rows(env, "bob", "SELECT salary FROM employees ORDER BY salary") == [
        (65000,), (78000,), (112000,)]
    safe = env.gate.authorize("bob", "SELECT salary FROM employees")
    assert "employees.dept = 'engineering'" in safe
    # role columns keep the role's dept filter; the mix is still denied
    assert rows(env, "bob", NAMES_Q) == ENG_NAMES
    reason = denied(env, "bob", "SELECT name, salary FROM employees")
    assert "user:bob's grants cover (salary) but not (name)" in reason
    # a personal 3-field p2 replaces the borrowed filter (here: widens)
    add_lines(env, "p2, user:bob, employees, id = 4")
    assert rows(env, "bob", "SELECT salary FROM employees") == [(58000,)]
    assert rows(env, "bob", NAMES_Q) == ENG_NAMES      # role scope unchanged


def test_count_star_is_covered_by_both_levels_with_the_roles_rows(env):
    # a column-less reference is covered by every scope with a readable
    # column; the personal grant borrows bob's dept filter, so still 3
    add_lines(env, "p, user:bob, employees.start_date, read")
    assert rows(env, "bob", "SELECT COUNT(*) FROM employees") == [(3,)]
    safe = env.gate.authorize("bob", "SELECT COUNT(*) FROM employees")
    assert safe.count("employees.dept = 'engineering'") == 2   # base OR user


# ---- take-over: alice covers for carol ------------------------------------------

def test_takeover_via_extra_role_and_removal_restores(env):
    assert rows(env, "alice", SALARY_Q) == [CAROL, ALICE]
    denied(env, "alice", "SELECT name, dept FROM employees")
    set_attrs(env, "alice", dept="engineering", self_and_subordinate_ids="1, 2, 3")
    add_lines(env, "g, user:alice, hr_manager")
    assert rows(env, "alice", SALARY_Q) == [
        ("Bob Tan", 78000), CAROL, ("Erin Ng", 65000), ALICE]
    assert rows(env, "alice", "SELECT name, dept FROM employees ORDER BY id") == [
        ("Bob Tan", "engineering"), CAROL[:1] + ("engineering",),
        ("Erin Ng", "engineering")]
    assert rows(env, "alice", "SELECT employee_id FROM payroll ORDER BY 1") == [
        (1,), (2,), (3,), (6,)]
    assert rows(env, "alice", "SELECT sku FROM inventory")   # own role intact
    remove_lines(env, "g, user:alice, hr_manager")
    assert rows(env, "alice", SALARY_Q) == [CAROL, ALICE]
    denied(env, "alice", "SELECT name, dept FROM employees")


def test_takeover_without_attributes_fails_closed(env):
    add_lines(env, "g, user:alice, hr_manager")
    reason = denied(env, "alice", NAMES_Q)
    assert "lacks attribute 'dept'" in reason
    # consistent: every reference the unbindable hr_manager base scope
    # covers is denied, even where scoped grants alone would have allowed
    for sql in (SALARY_Q, "SELECT COUNT(*) FROM employees"):
        assert "lacks attribute 'dept'" in denied(env, "alice", sql)


def test_subjects_for_includes_extra_roles_but_never_user_subjects(env):
    add_lines(env, "g, user:alice, hr_manager")
    subj = subjects_for(env.gate.enforcer, "alice", "warehouse_worker")
    assert subj.user == "user:alice" and subj.role == "warehouse_worker"
    assert subj.roles == {"warehouse_worker", "employee", "hr_manager",
                          "hr_staff", "payroll_manager"}


# ---- load-time validation: broken snapshot until fixed ---------------------------

@pytest.mark.parametrize("line", [
    "p2, user:zed, employees, id = 1",                 # unknown user
    "p, user:master, employees.name, read",            # master user
    "p3, user:nobody, employees.name, read",
    "p4, user:, employees, id = 1",                    # empty name
    "g, hr_staff, user:alice",                         # role inherits from a user
    "g, user:bob, user:alice",                         # user inherits from a user
    "p3, hr_staff, employees.salary",                  # 2 fields
    "p3, hr_staff, employees.salary, read, extra",
    "p4, hr_staff, employees",
    "p4, hr_staff, employees, id = 2, ssn",            # unknown column
    "p4, hr_staff, employees, id IN (SELECT id FROM payroll)",
    "p4, hr_staff, employees, payroll.id = 2",
    "p4, master, employees, id = 2, id",
    "p5, hr_staff, employees.salary, read",            # unknown ptype
    "P3, hr_staff, employees.salary, read",
])
def test_bad_rule_breaks_snapshot_until_fixed(env, line):
    good = env.policy.read_text(encoding="utf-8")
    env.policy.write_text(good + line + "\n", encoding="utf-8", newline="\n")
    for user, sql in (("alice", "SELECT sku FROM inventory"),
                      ("bob", NAMES_Q)):
        with pytest.raises(AccessDenied, match="reload"):
            env.gate.authorize(user, sql)
    assert env.gate.broken
    env.policy.write_text(good, encoding="utf-8", newline="\n")
    assert rows(env, "alice", "SELECT sku FROM inventory")
    assert not env.gate.broken


def test_user_subject_breaks_when_its_user_disappears_or_becomes_master(env):
    data = json.loads(env.attrs.read_text(encoding="utf-8"))
    del data["alice"]
    env.attrs.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(AccessDenied, match="user:alice"):
        env.gate.authorize("bob", NAMES_Q)
    assert env.gate.broken


def test_model_without_deny_ptypes_is_refused(env):
    text = env.model.read_text(encoding="utf-8")
    env.model.write_text(text.replace("p3 = sub, obj, act\n", ""),
                         encoding="utf-8", newline="\n")
    with pytest.raises(AccessDenied, match="p3"):
        env.gate.authorize("alice", "SELECT sku FROM inventory")


def test_worker_whose_role_is_a_user_subject_is_denied(env):
    set_attrs(env, "wes", role="user:alice")
    assert "user subject" in denied(env, "wes", "SELECT name FROM employees WHERE id = 2")


@pytest.mark.parametrize("line", [
    "p3, user:bob, employees.name, read # temp",   # Casbin has no inline comments
    "p3, user:bob, employees.name, READ",
    "p3, user:bob, employees.name, *",
    "p, user:bob, employees.name, write",
    "p3, user:bob, employees, read",               # no column: denies nothing
    "p3, user:bob, employees.ssn, read",
    "g, user:bob, hr_manager, dom",                # extra field
])
def test_rules_that_would_silently_deny_nothing_break_the_snapshot(env, line):
    good = env.policy.read_text(encoding="utf-8")
    env.policy.write_text(good + line + "\n", encoding="utf-8", newline="\n")
    with pytest.raises(AccessDenied, match="reload"):
        env.gate.authorize("bob", NAMES_Q)
    env.policy.write_text(good, encoding="utf-8", newline="\n")
    assert rows(env, "bob", NAMES_Q) == ENG_NAMES


def test_lone_carriage_return_cannot_hide_a_deny(env):
    good = env.policy.read_bytes()
    env.policy.write_bytes(good + b"# note\rp3, user:bob, employees.name, read\n")
    with pytest.raises(AccessDenied, match="carriage return"):
        env.gate.authorize("bob", NAMES_Q)
    env.policy.write_bytes(good)
    assert rows(env, "bob", NAMES_Q) == ENG_NAMES


def test_deny_filter_with_non_numeric_unquoted_value_denies_query(env):
    # employee_id = 'engineering' is FALSE, and NOT FALSE would hide nothing
    add_lines(env, "p4, user:carol, payroll, employee_id = {dept}")
    reason = denied(env, "carol", "SELECT employee_id FROM payroll")
    assert "not a number" in reason and "deny filter" in reason
    add_lines(env, "p4, user:carol, payroll, employee_id IN ({self_and_subordinate_ids})")
    set_attrs(env, "carol", self_and_subordinate_ids="1, employee_id")
    denied(env, "carol", "SELECT employee_id FROM payroll")


def test_column_inside_order_by_expression_stays_gated(env):
    # A name shadowed by a projection alias inside an ORDER BY expression
    # resolves to the table column in the DB; the gate no longer treats it
    # as an alias reference, and (unresolvable after qualify) fails closed
    # for everyone - a salary-threshold oracle for bob, and a bypass of a
    # personal salary deny for carol, are both blocked.
    sql = ("SELECT name AS salary FROM employees ORDER BY CASE WHEN salary > 150 "
           "THEN 0 ELSE 1 END")
    denied(env, "bob", sql)
    denied(env, "carol", sql)
    add_lines(env, "p3, user:carol, employees.salary, read")
    denied(env, "carol", sql)
    # the bare alias as the whole key is still fine
    assert rows(env, "bob", "SELECT name AS salary FROM employees ORDER BY salary")
    assert rows(env, "bob", "SELECT dept AS d, COUNT(*) FROM employees GROUP BY d")


# ---- hot reload ------------------------------------------------------------------

def test_hot_reload_applies_and_lifts_a_deny(env):
    version = env.gate.policy_version
    assert rows(env, "bob", NAMES_Q) == ENG_NAMES
    add_lines(env, "p3, hr_staff, employees.name, read")
    denied(env, "bob", NAMES_Q)
    assert env.gate.policy_version == version + 1
    remove_lines(env, "p3, hr_staff, employees.name, read")
    assert rows(env, "bob", NAMES_Q) == ENG_NAMES
    assert env.gate.policy_version == version + 2


# ---- audit labels ---------------------------------------------------------------

def test_audit_log_names_level_subject_and_effect(env, caplog):
    add_lines(env, "p4, hr_staff, employees, id = 3",
              "p4, user:bob, employees, id = 1, id|name",
              "p3, user:dave, invoices.amount, read")
    logging.disable(logging.NOTSET)
    try:
        with caplog.at_level(logging.INFO, logger="rbic.audit"):
            env.gate.authorize("alice", "SELECT name, salary FROM employees WHERE id = 2")
            env.gate.authorize("bob", NAMES_Q)
            with pytest.raises(AccessDenied):
                env.gate.authorize("dave", "SELECT amount FROM invoices")
    finally:
        logging.disable(logging.CRITICAL)
    msgs = [r.getMessage() for r in caplog.records]
    allow = [m for m in msgs if m.startswith("ALLOW")]
    assert ("scopes=employees:scoped[warehouse_worker:id|name|salary]"
            "+user_allow[user:alice:id|name|salary]") in allow[0]
    assert ("scopes=employees:base-role_deny[hr_staff]-user_deny[user:bob:id|name]"
            in allow[1])
    assert any("DENY user=dave reason=user rule denies read on 'invoices.amount' "
               "(deny:user[user:dave] invoices.amount)" in m for m in msgs)


# ---- parity: no deny / user rules present -> identical to the old gate -------------

def test_rewritten_sql_matches_pre_user_rule_gate(env):
    # Golden strings captured from the gate before per-user rules existed
    # (postgres dialect, base policy + the two role-level scoped grants).
    env.policy.write_text(
        base_policy_text(env.root) + CHANGES_HEADER + "\n"
        + "p2, warehouse_worker, employees, id = 2, id|name|salary\n"
        + "p2, warehouse_worker, employees, id = '{employee_id}', id|name|salary\n",
        encoding="utf-8", newline="\n")
    gate = SQLGate(model_path=str(env.model), policy_path=str(env.policy),
                   schema_path=str(env.schema), attributes_path=str(env.attrs),
                   dialect="postgres")
    golden = {
        ("alice", "SELECT sku, qty FROM inventory WHERE qty < 10"):
            'SELECT "inventory"."sku" AS "sku", "inventory"."qty" AS "qty" FROM '
            '"inventory" AS "inventory" WHERE "inventory"."qty" < 10 AND '
            "inventory.warehouse_id = 'SG-01'",
        ("bob", "SELECT name, dept FROM employees"):
            'SELECT "employees"."name" AS "name", "employees"."dept" AS "dept" '
            'FROM "employees" AS "employees" WHERE employees.dept = \'engineering\'',
        ("carol", "SELECT name, salary FROM employees"):
            'SELECT "employees"."name" AS "name", "employees"."salary" AS "salary" '
            'FROM "employees" AS "employees" WHERE employees.dept = \'engineering\'',
        ("dave", "SELECT vendor, amount FROM invoices"):
            'SELECT "invoices"."vendor" AS "vendor", "invoices"."amount" AS '
            '"amount" FROM "invoices" AS "invoices"',
        ("alice", "SELECT name, salary FROM employees WHERE name LIKE '%Carol%'"):
            'SELECT "employees"."name" AS "name", "employees"."salary" AS "salary" '
            'FROM "employees" AS "employees" WHERE "employees"."name" LIKE '
            "'%Carol%' AND (employees.id = 2 OR employees.id = '6')",
        ("carol", "SELECT employee_id, salary FROM payroll ORDER BY employee_id"):
            'SELECT "payroll"."employee_id" AS "employee_id", "payroll"."salary" '
            'AS "salary" FROM "payroll" AS "payroll" WHERE payroll.employee_id = '
            "'2' OR payroll.employee_id IN (1, 2, 3) ORDER BY \"employee_id\"",
    }
    for (user, sql), expected in golden.items():
        assert gate.authorize(user, sql) == expected
    for user, sql, reason in (
            ("bob", "SELECT name, salary FROM employees",
             "role 'hr_staff' lacks read on 'employees.salary'"),
            ("dave", "SELECT name FROM employees",
             "role 'finance_analyst' lacks read on 'employees.name'"),
            ("alice", "SELECT name, dept FROM employees",
             "role 'warehouse_worker' lacks read on 'employees.name': no scope on "
             "'employees' covers columns (name, dept); scoped grants cover "
             "(id|name|salary, id|name|salary)")):
        with pytest.raises(AccessDenied) as exc:
            gate.authorize(user, sql)
        assert str(exc.value) == reason


def test_manual_grant_evaluation_matches_casbin_enforce(env):
    snap = env.gate.snapshot
    e = snap.enforcer
    roles = {r[0] for r in e.get_policy()} | {"hr_manager", "employee"}
    for role in roles:
        subjects = {role, *e.get_implicit_roles_for_user(role)}
        for table, cols in env.gate.schema.items():
            for c in cols:
                manual = snap._grant(snap.allow_grants, subjects, table, c) is not None
                assert manual == e.enforce(role, f"{table}.{c}", "read"), (role, table, c)


# ---- per-reference checks with denies --------------------------------------------

def test_self_join_each_reference_gets_the_deny(env):
    add_lines(env, "p4, hr_staff, employees, id = 3")
    sql = ("SELECT a.name, b.salary FROM employees AS a JOIN employees AS b "
           "ON a.id = b.id ORDER BY a.id")
    safe = env.gate.authorize("carol", sql)
    assert "NOT (a.id = 3)" in safe and "NOT (b.id = 3)" in safe
    assert rows(env, "carol", sql) == [("Bob Tan", 78000), CAROL]


def test_subquery_reference_hit_by_user_deny(env):
    add_lines(env, "p3, user:carol, employees.salary, read")
    reason = denied(env, "carol", "SELECT name FROM employees WHERE id IN "
                                  "(SELECT id FROM employees WHERE salary > 1)")
    assert "deny:user[user:carol] employees.salary" in reason
    assert rows(env, "carol", NAMES_Q) == ENG_NAMES
    denied(env, "carol", "SELECT * FROM employees")   # star expands to salary


def test_correlated_subquery_rows_hidden_in_both_scopes(env):
    add_lines(env, "p4, user:carol, payroll, employee_id = 1")
    sql = ("SELECT e.name FROM employees AS e WHERE EXISTS (SELECT 1 FROM payroll "
           "AS p WHERE p.employee_id = e.id) ORDER BY e.id")
    safe = env.gate.authorize("carol", sql)
    assert "NOT (p.employee_id = 1)" in safe
    assert rows(env, "carol", sql) == [("Carol Lim",), ("Erin Ng",)]


# ---- PolicyAdmin: validation ------------------------------------------------------

@pytest.mark.parametrize("call", [
    lambda a: a.propose_grant("alice", "employees", "salary"),       # username as role
    lambda a: a.propose_deny("bob", "employees", "salary"),
    lambda a: a.propose_grant("user:alice", "employees", "salary"),
    lambda a: a.propose_grant(username="zed", table="employees", column="name"),
    lambda a: a.propose_grant(username="master", table="employees", column="name"),
    lambda a: a.propose_deny(username="master", table="employees", column="name"),
    lambda a: a.propose_grant("hr_staff", "employees", "name", username="bob"),
    lambda a: a.propose_grant(table="employees", column="name"),      # no subject
    lambda a: a.propose_inherit("hr_staff", "user:alice"),
    lambda a: a.propose_inherit("user:alice", "hr_staff"),
    lambda a: a.propose_add_user_role("alice", "master"),
    lambda a: a.propose_add_user_role("alice", "warehouse_worker"),   # already has it
    lambda a: a.propose_add_user_role("carol", "hr_staff"),           # inherited already
    lambda a: a.propose_add_user_role("master", "hr_staff"),
    lambda a: a.propose_add_user_role("alice", "wizard"),
    lambda a: a.propose_remove_user_role("alice", "hr_manager"),      # not held
    lambda a: a.propose_deny_rows("hr_staff", "employees", "id = id"),
    lambda a: a.propose_deny_rows("hr_staff", "employees", "TRUE"),
    lambda a: a.propose_deny_rows("hr_staff", "employees", "id = 2 -- x"),
    lambda a: a.propose_deny_rows("hr_staff", "employees",
                                  "id IN (SELECT id FROM payroll)"),
    lambda a: a.propose_deny_rows("hr_staff", "employees", "id = 2", columns="ssn"),
    lambda a: a.propose_remove_deny("hr_staff", "employees", "salary"),  # absent
    lambda a: a.propose_remove_deny_rows("hr_staff", "employees", "id = 2"),
    lambda a: a.propose_remove_row_scope("warehouse_worker", "employees", "id = 2",
                                         columns="id|name|salary"),  # now personal
    lambda a: a.propose_row_scope("alice", "employees", "id = 2", columns="id"),
])
def test_admin_rejects(env, call):
    before = env.policy.read_bytes()
    with pytest.raises(ValueError):
        call(env.admin)
    assert env.policy.read_bytes() == before


def test_admin_rejects_role_named_like_a_user_with_a_hint(env):
    with pytest.raises(ValueError, match="username"):
        env.admin.propose_grant("alice", "employees", "salary")
    with pytest.raises(ValueError, match="username"):
        env.admin.propose_grant("user:alice", "employees", "salary")


def test_admin_refuses_hand_edited_policy_the_gate_would_not_load(env):
    add_lines(env, "p2, user:zed, employees, id = 1")
    with pytest.raises(ValueError, match="user:zed"):
        env.admin.propose_grant("hr_staff", "employees", "salary")


# ---- PolicyAdmin: propose / apply / undo for every new tool ---------------------------

def apply(env, change):
    env.admin.apply(change, actor="master")
    entry = json.loads(env.changelog.read_text().splitlines()[-1])
    assert entry["id"] == change.id and entry["status"] == "applied"
    return change


def undo(env):
    change = env.admin.propose_undo()
    env.admin.apply(change, actor="master")
    return change


def test_personal_grant_revoke_and_undo(env):
    original = env.policy.read_bytes()
    change = env.admin.propose_grant(username="bob", table="employees",
                                     column="salary")
    assert "+p, user:bob, employees.salary, read" in change.diff()
    assert "User bob (role hr_staff) will be able to read employees.salary" \
        in change.description
    assert "overriding role hr_staff" in change.description
    assert "ALL rows" not in change.description
    assert "rows their role sees" in change.description
    assert "dept = '{dept}'" in change.description
    assert "personal grant is its own scope" in change.description
    assert "hr_staff [users" not in change.description      # role untouched
    apply(env, change)
    assert len(rows(env, "bob", "SELECT salary FROM employees")) == 3
    assert env.admin.describe_user("bob")["personal_grant_rows"] == {
        "employees": "rows their role sees: (dept = '{dept}')"}
    assert env.admin.describe_user("bob")["personal_rules"]["grants"] == [
        "employees.salary"]
    assert "salary" in env.admin.describe_user("bob")["effective_read"]["employees"]
    assert "salary" not in env.admin.describe_role("hr_staff")["effective_read"][
        "employees"]
    undo_change = undo(env)
    assert "bob (role hr_staff): loses read on employees.(salary)" in \
        undo_change.description
    assert env.policy.read_bytes() == original
    denied(env, "bob", "SELECT salary FROM employees")

    apply(env, env.admin.propose_grant(username="bob", table="employees",
                                       column="salary"))
    revoke = env.admin.propose_revoke(username="bob", table="employees",
                                      column="salary")
    assert "-p, user:bob, employees.salary, read" in revoke.diff()
    apply(env, revoke)
    assert env.policy.read_bytes() == original


def test_role_deny_remove_and_undo(env):
    change = env.admin.propose_deny("hr_staff", "employees", "dept")
    assert "+p3, hr_staff, employees.dept, read" in change.diff()
    assert "Role hr_staff (and every role inheriting it) will be denied read" \
        in change.description
    assert "hr_staff [users: bob]: loses read on employees.(dept)" in change.description
    assert "hr_manager [users: carol]: loses read on employees.(dept)" \
        in change.description
    apply(env, change)
    denied(env, "bob", "SELECT dept FROM employees")
    denied(env, "carol", "SELECT dept FROM employees")
    assert env.admin.describe_role("hr_manager")["column_denies"] == [
        {"column": "employees.dept", "from_role": "hr_staff"}]
    assert env.admin.describe_user("carol")["denied_columns"] == {
        "employees": ["dept"]}
    _, prompt = chatbot.system_prompt_for(env.gate, "bob")
    assert "- employees(id, name, start_date)\n" in prompt
    undo(env)
    assert rows(env, "bob", "SELECT dept FROM employees")
    apply(env, env.admin.propose_deny("hr_staff", "employees", "dept"))
    removal = env.admin.propose_remove_deny("hr_staff", "employees", "dept")
    assert "-p3, hr_staff, employees.dept, read" in removal.diff()
    assert "gains read on employees.(dept)" in removal.description
    apply(env, removal)
    assert rows(env, "bob", "SELECT dept FROM employees")


def test_personal_deny_overrides_and_effects_say_so(env):
    change = env.admin.propose_deny(username="carol", table="employees",
                                    column="salary")
    assert "+p3, user:carol, employees.salary, read" in change.diff()
    assert "overrides every role and personal allow" in change.description
    assert ("carol (role hr_manager): loses read on employees.(salary) by "
            "personal deny, overriding role hr_manager") in change.description
    apply(env, change)
    denied(env, "carol", "SELECT salary FROM employees")
    assert rows(env, "carol", NAMES_Q) == ENG_NAMES
    _, prompt = chatbot.system_prompt_for(env.gate, "carol")
    assert "- employees(id, name, dept, start_date)\n" in prompt
    # a role-level grant that a personal deny masks is reported as such
    apply(env, env.admin.propose_deny(username="bob", table="employees",
                                      column="salary"))
    grant = env.admin.propose_grant("hr_staff", "employees", "salary")
    assert "hr_staff [users: bob]: gains read on employees.(salary)" \
        in grant.description
    assert ("bob (role hr_staff): employees.(salary) stays denied by a personal "
            "deny") in grant.description
    apply(env, grant)
    denied(env, "bob", "SELECT salary FROM employees")
    denied(env, "carol", "SELECT salary FROM employees")


def test_role_and_personal_row_denies(env):
    change = env.admin.propose_deny_rows("hr_staff", "employees", "id = 2")
    assert "+p4, hr_staff, employees, id = 2" in change.diff()
    assert "will not see rows of employees where id = 2" in change.description
    assert "NULL are hidden too" in change.description
    assert "hr_staff [users: bob]: rows of employees where id = 2 hidden" \
        in change.description
    assert "hr_manager [users: carol]" in change.description
    apply(env, change)
    assert rows(env, "bob", NAMES_Q) == [("Bob Tan",), ("Erin Ng",)]
    assert env.admin.describe_role("hr_manager")["hidden_rows"] == [
        {"table": "employees", "filter": "id = 2", "from_role": "hr_staff"}]
    assert env.admin.describe_user("carol")["hidden_rows"] == {"employees": ["id = 2"]}

    personal = env.admin.propose_row_scope(username="carol", table="employees",
                                           filter_template="id = 2",
                                           columns="id, name")
    assert "+p2, user:carol, employees, id = 2, id|name" in personal.diff()
    assert "applies even where role rules deny" in personal.description
    apply(env, personal)
    assert rows(env, "carol", NAMES_Q) == ENG_NAMES
    assert rows(env, "bob", NAMES_Q) == [("Bob Tan",), ("Erin Ng",)]

    pdeny = env.admin.propose_deny_rows(username="carol", table="employees",
                                        filter_template="id = 1", columns="name")
    assert "+p4, user:carol, employees, id = 1, name" in pdeny.diff()
    assert "whatever their roles or personal grants say" in pdeny.description
    assert "carol (role hr_manager): rows of employees where id = 1 hidden when " \
           "reading columns (name) (personal deny" in pdeny.description
    apply(env, pdeny)
    assert rows(env, "carol", NAMES_Q) == [("Carol Lim",), ("Erin Ng",)]
    assert rows(env, "carol", "SELECT id FROM employees ORDER BY id") == [(1,), (2,), (3,)]

    removal = env.admin.propose_remove_deny_rows(username="carol", table="employees",
                                                 filter_template="id = 1",
                                                 columns="name")
    assert "-p4, user:carol, employees, id = 1, name" in removal.diff()
    assert "no longer hidden" in removal.description
    apply(env, removal)
    assert rows(env, "carol", NAMES_Q) == ENG_NAMES
    apply(env, env.admin.propose_remove_row_scope(
        username="carol", table="employees", filter_template="id = 2",
        columns="id|name"))
    assert rows(env, "carol", NAMES_Q) == [("Bob Tan",), ("Erin Ng",)]
    apply(env, env.admin.propose_remove_deny_rows("hr_staff", "employees", "id = 2"))
    assert rows(env, "carol", NAMES_Q) == ENG_NAMES


def test_add_user_role_takeover_and_undo(env):
    apply(env, env.admin.propose_set_attribute("alice", "dept", "engineering"))
    apply(env, env.admin.propose_set_attribute("alice", "self_and_subordinate_ids",
                                               "1, 2, 3"))
    original = env.policy.read_bytes()
    change = env.admin.propose_add_user_role("alice", "hr_manager")
    assert "+g, user:alice, hr_manager" in change.diff()
    assert ("User alice (role warehouse_worker) will additionally hold role "
            "hr_manager") in change.description
    assert "alice (role warehouse_worker): gains read on employees.(" \
        in change.description
    assert "additionally holds role(s) hr_manager" in change.description
    assert "warehouse_worker [users" not in change.description
    apply(env, change)
    assert rows(env, "alice", SALARY_Q) == [
        ("Bob Tan", 78000), CAROL, ("Erin Ng", 65000), ALICE]
    assert env.admin.describe_user("alice")["extra_roles"] == ["hr_manager"]
    assert "alice" in env.admin.describe_role("hr_manager")["extra_for_users"]
    assert "alice" not in env.admin.describe_role("hr_manager")["users"]
    undo_change = undo(env)
    assert "no longer holds extra role(s) hr_manager" in undo_change.description
    assert env.policy.read_bytes() == original
    assert rows(env, "alice", SALARY_Q) == [CAROL, ALICE]

    apply(env, env.admin.propose_add_user_role("alice", "hr_manager"))
    removal = env.admin.propose_remove_user_role("alice", "hr_manager")
    assert "-g, user:alice, hr_manager" in removal.diff()
    apply(env, removal)
    assert env.policy.read_bytes() == original


def test_add_user_role_warns_about_missing_attributes(env):
    change = env.admin.propose_add_user_role("alice", "hr_manager")
    assert "WARNING: lacks attribute(s) dept" in change.description
    assert "self_and_subordinate_ids" in change.description


def test_list_roles_never_lists_user_subjects(env):
    apply(env, env.admin.propose_grant(username="bob", table="employees",
                                       column="salary"))
    names = {r["role"] for r in env.admin.list_roles()}
    assert not any(n.startswith("user:") for n in names)
    with pytest.raises(ValueError, match="Unknown role"):
        env.admin.describe_role("user:bob")


def test_proposals_are_stale_after_attribute_change(env):
    change = env.admin.propose_grant(username="bob", table="employees",
                                     column="salary")
    apply(env, env.admin.propose_set_attribute("bob", "dept", "logistics"))
    with pytest.raises(ValueError, match="changed since"):
        env.admin.apply(change, actor="master")


# ---- master bot tool flow --------------------------------------------------------

class FakeClient:
    def __init__(self, responses):
        self.responses, self.calls, self.messages = list(responses), [], self

    def create(self, **kwargs):
        self.calls.append(dict(kwargs, messages=list(kwargs["messages"])))
        return self.responses.pop(0)


def tool_use(name, tool_input):
    return NS(stop_reason="tool_use", content=[
        NS(type="tool_use", id="tu_1", name=name, input=tool_input)])


def end_turn(text):
    return NS(stop_reason="end_turn", content=[NS(type="text", text=text)])


@pytest.mark.parametrize("name, args, line", [
    ("propose_deny", {"username": "carol", "table": "employees",
                      "column": "salary"}, "p3, user:carol, employees.salary, read"),
    ("propose_deny", {"role": "hr_staff", "table": "employees",
                      "column": "dept"}, "p3, hr_staff, employees.dept, read"),
    ("propose_deny_rows", {"username": "bob", "table": "employees",
                           "filter_template": "id = 2"},
     "p4, user:bob, employees, id = 2"),
    ("propose_row_scope", {"username": "bob", "table": "employees",
                           "filter_template": "id = 4", "columns": "id, name"},
     "p2, user:bob, employees, id = 4, id|name"),
    ("propose_grant", {"username": "bob", "table": "employees",
                       "column": "salary"}, "p, user:bob, employees.salary, read"),
    ("propose_add_user_role", {"username": "alice", "role": "finance_analyst"},
     "g, user:alice, finance_analyst"),
])
def test_master_bot_new_tools_propose_then_apply(env, name, args, line):
    client = FakeClient([tool_use(name, args), end_turn("Proposed.")])
    inputs = iter(["please", "yes", "exit"])
    out = []
    master_cli.run_master_bot("master", client=client,
                              input_fn=lambda _: next(inputs),
                              output=out.append, admin=env.admin)
    assert line in env.policy.read_text(encoding="utf-8")
    assert any("+" + line in o for o in out)
    assert json.loads(env.changelog.read_text().splitlines()[-1])["actor"] == "master"


def test_master_bot_tool_schemas_and_prompt(env):
    names = {t["name"] for t in master_bot.TOOLS}
    assert names == set(master_bot.DISPATCH)
    assert not any("apply" in n or "sql" in n for n in names)
    for n in ("propose_deny", "propose_remove_deny", "propose_deny_rows",
              "propose_remove_deny_rows", "propose_add_user_role",
              "propose_remove_user_role"):
        assert n in names
    schema = {t["name"]: t["input_schema"] for t in master_bot.TOOLS}
    for n in ("propose_grant", "propose_revoke", "propose_deny", "propose_row_scope",
              "propose_deny_rows"):
        assert {"role", "username"} <= set(schema[n]["properties"])
        assert "role" not in schema[n]["required"]
        assert "username" not in schema[n]["required"]
    assert "role" in schema["propose_add_user_role"]["required"]
    assert "username" in schema["propose_add_user_role"]["required"]
    prompt = master_bot.build_system_prompt(env.admin)
    assert "personal deny > personal allow > role deny > role allow" in prompt
    assert "Carol is on leave" in prompt
    assert "Never widen or narrow a whole role" in prompt


def test_master_bot_reports_both_subjects_error_to_model(env):
    client = FakeClient([
        tool_use("propose_grant", {"role": "hr_staff", "username": "bob",
                                   "table": "employees", "column": "salary"}),
        end_turn("Which one?"),
    ])
    inputs = iter(["let bob see salaries", "exit"])
    master_cli.run_master_bot("master", client=client,
                              input_fn=lambda _: next(inputs),
                              output=lambda *_: None, admin=env.admin)
    result = client.calls[1]["messages"][-1]["content"][0]
    assert result["is_error"] is True and "not both" in result["content"]


# ---- worker chatbot prompt reflects precedence -----------------------------------------

def test_worker_prompt_shows_personal_scope_and_hides_denied_columns(env):
    role, prompt = chatbot.system_prompt_for(env.gate, "alice")
    assert role == "warehouse_worker"
    assert prompt.count("- employees(id, name, salary)") == 2  # role + personal scope
    add_lines(env, "p3, user:alice, employees.salary, read")
    _, prompt = chatbot.system_prompt_for(env.gate, "alice")
    assert "- employees(id, name)\n" in prompt
    assert "employees(id, name, salary)" not in prompt
    add_lines(env, "g, user:alice, finance_analyst")
    _, prompt = chatbot.system_prompt_for(env.gate, "alice")
    assert "- invoices(id, vendor, amount, due_date, status)" in prompt
