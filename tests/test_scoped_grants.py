"""Scoped grants: 4-field p2 rows that carry their own column list.

    p2, warehouse_worker, employees, id = 2, id|name|salary

One rule grants both the rows and the columns; no p grant is needed. The
gate decides per table reference: a scope "covers" a reference if every
column of that reference used in the query is in the scope's columns.
Every test works on tmp_path copies; the repo's files are never touched.
Run: pytest -q
"""

import json
import logging
import sqlite3
from types import SimpleNamespace as NS

import pytest

from rbic import engine as chatbot
from rbic import master as master_bot
from rbic.admin import CHANGES_HEADER, PolicyAdmin
from rbic.gate import AccessDenied, SQLGate, parse_scope_columns

logging.disable(logging.CRITICAL)

SCOPED_LINE = "p2, warehouse_worker, employees, id = 2, id|name|salary"
CAROL = [("Carol Lim", 112000)]


def base_policy_text(root) -> str:
    """The shipped policy.csv up to the master-chatbot changes block, so
    these tests do not depend on what has since been applied through the
    bot (e.g. the per-user rule that replaced SCOPED_LINE)."""
    text = (root / "casbin" / "policy.csv").read_text(encoding="utf-8")
    return text.split(CHANGES_HEADER)[0]


@pytest.fixture
def env(demo_dir):
    tmp_path = demo_dir
    """tmp copies of the shipped files; policy.csv = base policy + SCOPED_LINE."""
    (tmp_path / "casbin" / "policy.csv").write_text(
        base_policy_text(tmp_path) + CHANGES_HEADER + "\n" + SCOPED_LINE + "\n",
        encoding="utf-8", newline="\n")
    paths = NS(
        root=tmp_path,
        policy=tmp_path / "casbin" / "policy.csv",
        model=tmp_path / "casbin" / "model.conf",
        schema=tmp_path / "db_schema.json",
        attrs=tmp_path / "worker_attributes.json",
        changelog=tmp_path / "policy_changes.jsonl",
        db=tmp_path / "company.db",
    )
    assert SCOPED_LINE in paths.policy.read_text(encoding="utf-8")
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


def set_policy(env, text):
    env.policy.write_text(text, encoding="utf-8")
    env.gate.refresh()


def without_scoped_line(env) -> str:
    return env.policy.read_text(encoding="utf-8").replace(SCOPED_LINE + "\n", "")


# ---- the motivating case: alice reads Carol's salary, nothing else ----------

def test_alice_reads_carols_salary_by_name_and_id(env):
    assert rows(env, "alice", "SELECT name, salary FROM employees "
                              "WHERE name LIKE '%Carol%'") == CAROL
    assert rows(env, "alice", "SELECT name, salary FROM employees WHERE id = 2") \
        == CAROL


def test_scoped_grant_clamps_rows_to_its_filter(env):
    # no WHERE, or a WHERE for someone else: only Carol's row can come back
    assert rows(env, "alice", "SELECT name, salary FROM employees") == CAROL
    assert rows(env, "alice", "SELECT name, salary FROM employees WHERE id = 1") \
        == []
    assert rows(env, "alice", "SELECT id, name FROM employees ORDER BY id") \
        == [(2, "Carol Lim")]


def test_alice_still_denied_outside_the_scope(env):
    reason = denied(env, "alice", "SELECT name, dept FROM employees")
    assert "employees.dept" in reason or "dept" in reason
    assert "id|name|salary" in reason  # the audit reason names the scopes
    denied(env, "alice", "SELECT name, salary FROM employees WHERE dept = 'engineering'")
    denied(env, "alice", "SELECT start_date FROM employees WHERE id = 2")


def test_star_expands_beyond_scope_and_is_denied(env):
    denied(env, "alice", "SELECT * FROM employees")
    denied(env, "alice", "SELECT * FROM employees WHERE id = 2")


def test_other_users_unaffected(env):
    denied(env, "bob", "SELECT name, salary FROM employees")
    assert rows(env, "bob", "SELECT name FROM employees ORDER BY id") == [
        ("Bob Tan",), ("Carol Lim",), ("Erin Ng",)]
    denied(env, "dave", "SELECT name FROM employees")
    assert rows(env, "carol", "SELECT name, salary FROM employees ORDER BY id") == [
        ("Bob Tan", 78000), ("Carol Lim", 112000), ("Erin Ng", 65000)]


def test_without_the_scoped_line_alice_is_denied_as_before(env):
    set_policy(env, without_scoped_line(env))
    reason = denied(env, "alice", "SELECT name, salary FROM employees WHERE id = 2")
    assert reason == "role 'warehouse_worker' lacks read on 'employees.name'"


def test_audit_log_names_the_authorizing_scope(env, caplog):
    logging.disable(logging.NOTSET)
    try:
        with caplog.at_level(logging.INFO, logger="rbic.audit"):
            env.gate.authorize("alice", "SELECT name, salary FROM employees")
            env.gate.authorize("bob", "SELECT name FROM employees")
    finally:
        logging.disable(logging.CRITICAL)
    allow = [r.getMessage() for r in caplog.records if r.getMessage().startswith("ALLOW")]
    assert "scopes=employees:scoped[warehouse_worker:id|name|salary]" in allow[0]
    assert "scopes=employees:base" in allow[1]


# ---- additivity: scoped grants never narrow what a role already had ---------

def test_scoped_grant_does_not_clamp_unfiltered_base_access(env):
    # finance_analyst reads every invoice with no row filter; a scoped grant
    # on invoices must not clamp its existing unfiltered queries.
    all_invoices = rows(env, "dave", "SELECT id, status FROM invoices ORDER BY id")
    assert len(all_invoices) == 3
    set_policy(env, env.policy.read_text(encoding="utf-8")
               + "p2, finance_analyst, invoices, id = 1, id|vendor\n")
    assert rows(env, "dave", "SELECT id, status FROM invoices ORDER BY id") \
        == all_invoices
    assert rows(env, "dave", "SELECT id, vendor FROM invoices ORDER BY id") \
        == rows(env, "dave", "SELECT id, vendor FROM invoices ORDER BY id")
    assert len(rows(env, "dave", "SELECT id FROM invoices")) == 3


def test_base_and_scoped_union_when_both_cover(env):
    # bob (hr_staff) sees engineering employees; a scoped grant on the
    # columns he already has adds Frank Ho (id 4) rather than replacing.
    set_policy(env, env.policy.read_text(encoding="utf-8")
               + "p2, hr_staff, employees, id = 4, id|name\n")
    assert rows(env, "bob", "SELECT name FROM employees ORDER BY id") == [
        ("Bob Tan",), ("Carol Lim",), ("Erin Ng",), ("Frank Ho",)]
    # a column only the base scope has keeps the base filter alone
    assert rows(env, "bob", "SELECT name, dept FROM employees ORDER BY id") == [
        ("Bob Tan", "engineering"), ("Carol Lim", "engineering"),
        ("Erin Ng", "engineering")]


def test_scoped_grant_gives_rows_beyond_the_base_filter(env):
    # bob can't read salary via p grants; a scoped grant lets him read
    # Frank's (id 4, logistics) name+salary even though his base filter
    # is dept = 'engineering'.
    set_policy(env, env.policy.read_text(encoding="utf-8")
               + "p2, hr_staff, employees, id = 4, name|salary\n")
    assert rows(env, "bob", "SELECT name, salary FROM employees") == [
        ("Frank Ho", 58000)]


def test_scoped_grant_is_inherited_through_g(env):
    # hr_manager inherits hr_staff; a scoped grant on hr_staff reaches carol
    set_policy(env, env.policy.read_text(encoding="utf-8")
               + "p2, hr_staff, invoices, id = 1, id|vendor\n")
    assert rows(env, "carol", "SELECT id, vendor FROM invoices") == [
        (1, "Acme Pallets Pte Ltd")]
    denied(env, "carol", "SELECT id, amount FROM invoices")


def test_scoped_grant_missing_attribute_denies_what_it_covers(env):
    # Fail closed, consistently with row filters: a scoped grant that
    # COVERS the reference but can't bind denies the query, whatever other
    # scopes would have allowed; one that doesn't cover is simply ignored.
    set_policy(env, env.policy.read_text(encoding="utf-8")
               + "p2, hr_staff, employees, id = '{manager_id}', id|name\n"
               + "p2, hr_staff, invoices, id = '{manager_id}', id|vendor\n")
    reason = denied(env, "bob", "SELECT name FROM employees ORDER BY id")
    assert "manager_id" in reason and "scoped grant" in reason
    reason = denied(env, "bob", "SELECT id, vendor FROM invoices")
    assert "manager_id" in reason
    # dept is outside the scoped grant's columns: base access is untouched
    assert rows(env, "bob", "SELECT name, dept FROM employees ORDER BY id") == [
        ("Bob Tan", "engineering"), ("Carol Lim", "engineering"),
        ("Erin Ng", "engineering")]


# ---- per-reference checks: self-joins, subqueries, alias shadowing ------------

def test_self_join_each_reference_filtered(env):
    sql = ("SELECT a.name, b.salary FROM employees AS a JOIN employees AS b "
           "ON a.id = b.id")
    safe = env.gate.authorize("alice", sql)
    assert "a.id = 2" in safe and "b.id = 2" in safe
    assert rows(env, "alice", sql) == CAROL
    # one reference stepping outside the scope denies the whole query
    denied(env, "alice", "SELECT a.name, b.dept FROM employees AS a "
                         "JOIN employees AS b ON a.id = b.id")


def test_subquery_reference_checked_independently(env):
    sql = ("SELECT name, salary FROM employees WHERE id IN "
           "(SELECT id FROM employees WHERE salary > 100000)")
    assert rows(env, "alice", sql) == CAROL
    denied(env, "alice", "SELECT name, salary FROM employees WHERE id IN "
                         "(SELECT id FROM employees WHERE dept = 'engineering')")


def test_alias_reused_in_subquery_cannot_borrow_outer_table(env):
    # Regression: a global alias map let the inner `e` (payroll, where
    # alice has payroll.*) stand in for the outer `e` (employees).
    for col in ("dept", "start_date"):
        denied(env, "alice", f"SELECT e.{col} FROM employees AS e WHERE EXISTS "
                             "(SELECT 1 FROM payroll AS e)")
    denied(env, "alice", "SELECT e.name FROM employees AS e WHERE EXISTS "
                         "(SELECT 1 FROM payroll AS e WHERE e.dept = 'x')")


def test_correlated_column_counts_toward_outer_reference(env):
    # e.dept inside the subquery belongs to the outer employees reference
    denied(env, "alice", "SELECT e.name, e.salary FROM employees AS e WHERE "
                         "EXISTS (SELECT 1 FROM payroll AS p "
                         "WHERE p.employee_id = e.id AND e.dept = 'x')")


# ---- load-time validation: a malformed 4th field breaks the snapshot --------

@pytest.mark.parametrize("line", [
    "p2, warehouse_worker, employees, id = 2, id|ssn",          # unknown column
    "p2, warehouse_worker, employees, id = 2, id||name",        # empty item
    "p2, warehouse_worker, employees, id = 2, id|name|id",      # duplicate
    "p2, warehouse_worker, employees, id = 2, id | name",       # whitespace junk
    "p2, warehouse_worker, employees, id = 2, *",               # star
    "p2, warehouse_worker, employees, id = 2, payroll.salary",  # qualified
    "p2, master, employees, id = 2, id|name",                   # master role
    "p2, warehouse_worker, employees, id = 2, id|name, extra",  # 5 fields
    "p2, warehouse_worker, employees, dept IN (SELECT dept FROM payroll), id",
])
def test_malformed_scoped_grant_breaks_snapshot_until_fixed(env, line):
    good = env.policy.read_text(encoding="utf-8")
    env.policy.write_text(good + line + "\n", encoding="utf-8")
    for user, sql in (("alice", "SELECT sku FROM inventory"),
                      ("bob", "SELECT name FROM employees")):
        with pytest.raises(AccessDenied, match="reload"):
            env.gate.authorize(user, sql)
    assert env.gate.broken
    env.policy.write_text(good, encoding="utf-8")
    assert rows(env, "alice", "SELECT sku FROM inventory")
    assert not env.gate.broken


def test_parse_scope_columns_keeps_order_and_rejects_junk(demo_template):
    schema = json.loads((demo_template / "db_schema.json").read_text())
    assert parse_scope_columns("employees", "salary|id", schema) == ("salary", "id")
    for bad in ("", "id,name", "id|", "|id", "id|Name"):
        with pytest.raises(Exception):
            parse_scope_columns("employees", bad, schema)


# ---- hot reload ------------------------------------------------------------------

def test_hot_reload_picks_up_scoped_grant(env):
    set_policy(env, without_scoped_line(env))
    denied(env, "alice", "SELECT name, salary FROM employees WHERE id = 2")
    version = env.gate.policy_version
    with open(env.policy, "a", encoding="utf-8", newline="") as f:
        f.write(SCOPED_LINE + "\n")
    assert rows(env, "alice", "SELECT name, salary FROM employees WHERE id = 2") \
        == CAROL
    assert env.gate.policy_version == version + 1


# ---- master bot: propose / apply / remove / undo ----------------------------------

def test_admin_propose_scoped_grant_then_apply_remove_and_undo(env):
    set_policy(env, without_scoped_line(env))
    denied(env, "alice", "SELECT name, salary FROM employees WHERE id = 2")
    change = env.admin.propose_row_scope("warehouse_worker", "employees",
                                         "id = 2", columns="id, name, salary")
    assert "+" + SCOPED_LINE in change.diff()
    assert "gains scoped read on employees.(id, name, salary)" in change.description
    assert "rows where id = 2" in change.description
    assert "never narrows" in change.description
    env.admin.apply(change, actor="master")
    assert SCOPED_LINE in env.policy.read_text(encoding="utf-8")
    assert rows(env, "alice", "SELECT name, salary FROM employees WHERE id = 2") \
        == CAROL
    entry = json.loads(env.changelog.read_text().splitlines()[-1])
    assert entry["kind"] == "row_scope" and entry["status"] == "applied"

    describe = env.admin.describe_role("warehouse_worker")
    assert describe["scoped_grants"] == [{"table": "employees",
                                         "columns": ["id", "name", "salary"],
                                         "filter": "id = 2",
                                         "from_role": "warehouse_worker"}]
    assert env.admin.describe_user("alice")["scoped_grants"]["employees"] == [
        {"columns": ["id", "name", "salary"], "rows_where": "id = 2"}]

    undo = env.admin.propose_undo()
    assert "loses scoped read on employees.(id, name, salary)" in undo.description
    env.admin.apply(undo, actor="master")
    denied(env, "alice", "SELECT name, salary FROM employees WHERE id = 2")

    env.admin.apply(env.admin.propose_row_scope(
        "warehouse_worker", "employees", "id = 2", columns=["id", "name", "salary"]),
        actor="master")
    removal = env.admin.propose_remove_row_scope(
        "warehouse_worker", "employees", "id = 2", columns="id|name|salary")
    assert "-" + SCOPED_LINE in removal.diff()
    env.admin.apply(removal, actor="master")
    assert SCOPED_LINE not in env.policy.read_text(encoding="utf-8")
    denied(env, "alice", "SELECT name, salary FROM employees WHERE id = 2")


@pytest.mark.parametrize("columns", [
    "ssn", "id, *", "id, id", ["id", "payroll.salary"], "id;name",
])
def test_admin_rejects_bad_scoped_columns(env, columns):
    before = env.policy.read_bytes()
    with pytest.raises(ValueError):
        env.admin.propose_row_scope("hr_staff", "employees", "id = 4",
                                    columns=columns)
    assert env.policy.read_bytes() == before


def test_empty_columns_means_plain_row_filter(env):
    change = env.admin.propose_row_scope("finance_analyst", "invoices",
                                         "status = 'unpaid'", columns="")
    assert "+p2, finance_analyst, invoices, status = 'unpaid'\n" in change.diff()
    assert "scoped" not in change.description


def test_admin_rejects_duplicate_and_master_scoped_grants(env):
    with pytest.raises(ValueError, match="already present"):
        env.admin.propose_row_scope("warehouse_worker", "employees", "id = 2",
                                    columns=["id", "name", "salary"])
    with pytest.raises(ValueError):
        env.admin.propose_row_scope("master", "employees", "id = 2",
                                    columns=["id"])
    with pytest.raises(ValueError, match="No rule"):
        env.admin.propose_remove_row_scope("warehouse_worker", "employees",
                                           "id = 2")  # columns required to match


def test_remove_legacy_filter_lists_scoped_grants_too(env):
    with pytest.raises(ValueError, match=r"id = 2, id\|name\|salary"):
        env.admin.propose_remove_row_scope("warehouse_worker", "employees",
                                           "id = 3")


def test_strict_template_rules_apply_to_scoped_grants(env):
    for template in ("id = 2 OR 1 = 1", "TRUE", "id = 2 -- x",
                     "id IN (SELECT id FROM payroll)"):
        with pytest.raises(ValueError):
            env.admin.propose_row_scope("hr_staff", "employees", template,
                                        columns=["id", "name"])


def test_master_bot_scoped_grant_tool_flow(env):
    set_policy(env, without_scoped_line(env))
    call = {"role": "warehouse_worker", "table": "employees",
            "filter_template": "id = 2", "columns": "id, name, salary"}

    def tool_use(name, tool_input):
        return NS(stop_reason="tool_use", content=[
            NS(type="tool_use", id="tu_1", name=name, input=tool_input)])

    def end_turn(text):
        return NS(stop_reason="end_turn", content=[NS(type="text", text=text)])

    class FakeClient:
        def __init__(self, responses):
            self.responses, self.calls, self.messages = list(responses), [], self

        def create(self, **kwargs):
            self.calls.append(dict(kwargs, messages=list(kwargs["messages"])))
            return self.responses.pop(0)

    client = FakeClient([tool_use("propose_row_scope", call), end_turn("Done?")])
    inputs = iter(["let warehouse workers see carol's salary", "yes", "exit"])
    out = []
    master_bot.run_master_bot("master", client=client,
                              input_fn=lambda _: next(inputs),
                              output=out.append, admin=env.admin)
    assert SCOPED_LINE in env.policy.read_text(encoding="utf-8")
    assert any("+" + SCOPED_LINE in o for o in out)
    assert rows(env, "alice", "SELECT name, salary FROM employees WHERE id = 2") \
        == CAROL
    # the tool schema marks columns optional; plain row filters still work
    schema = next(t for t in master_bot.TOOLS if t["name"] == "propose_row_scope")
    assert "columns" in schema["input_schema"]["properties"]
    assert "columns" not in schema["input_schema"]["required"]


# ---- worker chatbot prompt -----------------------------------------------------------

def test_worker_prompt_lists_scoped_columns_without_the_filter(env):
    role, prompt = chatbot.system_prompt_for(env.gate, "alice")
    assert role == "warehouse_worker"
    assert "- employees(id, name, salary)" in prompt
    assert "Row-limited" in prompt
    assert "id = 2" not in prompt
    assert "- employees(id, name, dept, start_date, salary)" not in prompt
    _, bob_prompt = chatbot.system_prompt_for(env.gate, "bob")
    assert "Row-limited" not in bob_prompt
    assert "- employees(id, name, dept, start_date)\n" in bob_prompt
