"""Master chatbot + live policy changes.

Every test works on tmp_path copies of the policy, schema, attributes and
database — the repo's real files are never touched. No real API calls:
the Anthropic client is a scripted fake. Run: pytest -q
"""

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import threading
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

import chatbot
import master_bot
import policy_admin
import seed_db
from policy_admin import CHANGES_HEADER, PolicyAdmin
from sql_gate import (
    DENY_MESSAGE, STATIC_FILTER_WARNING, AccessDenied, FilterError, SQLGate,
    compile_row_filter,
)

logging.disable(logging.CRITICAL)

ROOT = Path(__file__).parent
SALARY_Q = "SELECT name, salary FROM employees"


@pytest.fixture(scope="session")
def seeded_db(tmp_path_factory):
    db = tmp_path_factory.mktemp("seed") / "company.db"
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(seed_db, "DB_PATH", str(db))
        seed_db.main()
    return db


@pytest.fixture
def env(tmp_path, seeded_db):
    (tmp_path / "casbin").mkdir()
    for rel in ("casbin/model.conf", "casbin/policy.csv", "db_schema.json",
                "worker_attributes.json"):
        shutil.copy(ROOT / rel, tmp_path / rel)
    shutil.copy(seeded_db, tmp_path / "company.db")
    paths = NS(
        root=tmp_path,
        policy=tmp_path / "casbin" / "policy.csv",
        model=tmp_path / "casbin" / "model.conf",
        schema=tmp_path / "db_schema.json",
        attrs=tmp_path / "worker_attributes.json",
        changelog=tmp_path / "policy_changes.jsonl",
        db=tmp_path / "company.db",
    )
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


def sha(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rows(env, username, sql):
    safe_sql = env.gate.authorize(username, sql)
    conn = sqlite3.connect(f"file:{env.db}?mode=ro", uri=True)
    try:
        return conn.execute(safe_sql).fetchall()
    finally:
        conn.close()


class FakeClient:
    """Stands in for anthropic.Anthropic(); replays scripted responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.messages = self

    def create(self, **kwargs):
        self.calls.append(dict(kwargs, messages=list(kwargs["messages"])))
        return self.responses.pop(0)


def tool_use(name, tool_input, tu_id="tu_1"):
    return NS(stop_reason="tool_use",
              content=[NS(type="tool_use", id=tu_id, name=name, input=tool_input)])


def end_turn(text):
    return NS(stop_reason="end_turn", content=[NS(type="text", text=text)])


# ---- 1. grant flips access live -------------------------------------------

def test_grant_flips_access_live(env):
    with pytest.raises(AccessDenied):
        env.gate.authorize("bob", SALARY_Q)
    version = env.gate.policy_version

    change = env.admin.propose_grant("hr_staff", "employees", "salary")
    assert "hr_staff will be able to read employees.salary" in change.description
    env.admin.apply(change, actor="master")

    assert rows(env, "bob", SALARY_Q) == [
        ("Bob Tan", 78000), ("Carol Lim", 112000), ("Erin Ng", 65000)]
    assert env.gate.policy_version > version
    entry = json.loads(env.changelog.read_text().splitlines()[-1])
    assert entry["id"] == change.id and entry["actor"] == "master"
    assert entry["kind"] == "grant"
    assert entry["after_sha256"] == sha(env.policy)
    for key in ("ts", "description", "file", "before_sha256", "before_text",
                "after_text"):
        assert key in entry


# ---- 2. revoke explains inheritance ---------------------------------------

def test_revoke_inherited_grant_explains_source(env):
    with pytest.raises(ValueError, match=r"inherit.*hr_staff|hr_staff.*inherit"):
        env.admin.propose_revoke("hr_manager", "employees", "name")


# ---- 3. validation rejects --------------------------------------------------

REJECTS = {
    "unknown table": lambda a: a.propose_grant("hr_staff", "nope", "x"),
    "unknown column": lambda a: a.propose_grant("hr_staff", "employees", "ssn"),
    "subquery filter": lambda a: a.propose_row_scope(
        "hr_staff", "employees", "dept IN (SELECT dept FROM payroll)"),
    "qualified other-table column": lambda a: a.propose_row_scope(
        "hr_staff", "employees", "payroll.salary > 0"),
    "other table's column": lambda a: a.propose_row_scope(
        "hr_staff", "employees", "effective_date > '2020-01-01'"),
    "placeholder attribute access": lambda a: a.propose_row_scope(
        "hr_staff", "employees", "dept = '{dept.name}'"),
    "positional placeholder": lambda a: a.propose_row_scope(
        "hr_staff", "employees", "dept = '{0}'"),
    "placeholder conversion": lambda a: a.propose_row_scope(
        "hr_staff", "employees", "dept = '{dept!r}'"),
    "unsafe function": lambda a: a.propose_row_scope(
        "finance_analyst", "invoices", "query_to_xml('x', true, true, '') IS NULL"),
    "comma outside parens": lambda a: a.propose_row_scope(
        "finance_analyst", "invoices", "status = 'a,b'"),
    "assign master role": lambda a: a.propose_assign_role("bob", "master"),
    "edit master record": lambda a: a.propose_set_attribute("master", "dept", "x"),
    "reassign master user": lambda a: a.propose_assign_role("master", "hr_staff"),
    "master role in policy": lambda a: a.propose_grant("master", "employees", "name"),
    "inherit from master": lambda a: a.propose_inherit("hr_staff", "master"),
    "inheritance cycle": lambda a: a.propose_inherit("employee", "hr_manager"),
    "duplicate grant": lambda a: a.propose_grant("hr_staff", "employees", "name"),
    "duplicate scope": lambda a: a.propose_row_scope(
        "hr_staff", "employees", "dept = '{dept}'"),
    "duplicate inherit": lambda a: a.propose_inherit("hr_manager", "hr_staff"),
    "bad role name": lambda a: a.propose_grant("HR Staff", "employees", "name"),
    "unknown user": lambda a: a.propose_assign_role("zed", "hr_staff"),
    "unknown role": lambda a: a.propose_assign_role("bob", "wizard"),
    "set role via attribute": lambda a: a.propose_set_attribute("bob", "role", "x"),
    "quote in attribute": lambda a: a.propose_set_attribute(
        "bob", "dept", "x' OR '1'='1"),
    "attribute widens IN list": lambda a: a.propose_set_attribute(
        "carol", "self_and_subordinate_ids", "1, employee_id"),
}


@pytest.mark.parametrize("case", sorted(REJECTS))
def test_validation_rejects(env, case):
    before = (sha(env.policy), sha(env.attrs))
    with pytest.raises(ValueError):
        REJECTS[case](env.admin)
    assert (sha(env.policy), sha(env.attrs)) == before


def test_master_user_has_no_data_access(env):
    with pytest.raises(AccessDenied):
        env.gate.authorize("master", "SELECT sku FROM inventory")


def test_apply_requires_master_actor(env):
    change = env.admin.propose_grant("hr_staff", "employees", "salary")
    with pytest.raises(ValueError, match="not a master"):
        env.admin.apply(change, actor="bob")


# ---- 4. proposals never write -----------------------------------------------

def test_propose_writes_nothing(env):
    before = (sha(env.policy), sha(env.attrs))
    env.admin.propose_grant("hr_staff", "employees", "salary")
    env.admin.propose_row_scope("finance_analyst", "invoices", "status = 'unpaid'")
    env.admin.propose_inherit("auditor", "finance_analyst")
    env.admin.propose_assign_role("dave", "hr_staff")
    env.admin.propose_set_attribute("bob", "dept", "logistics")
    assert (sha(env.policy), sha(env.attrs)) == before
    assert not env.changelog.exists()


# ---- 5. stale proposals are refused -----------------------------------------

def test_apply_refuses_if_file_changed(env):
    change = env.admin.propose_grant("hr_staff", "employees", "salary")
    with open(env.policy, "a", encoding="utf-8") as f:
        f.write("# edited by hand\n")
    edited = sha(env.policy)
    with pytest.raises(ValueError, match="changed since"):
        env.admin.apply(change, actor="master")
    assert sha(env.policy) == edited
    with pytest.raises(AccessDenied):
        env.gate.authorize("bob", SALARY_Q)


# ---- 6. comments survive edits ----------------------------------------------

def test_comments_preserved_after_add_and_remove(env):
    comments = [l for l in env.policy.read_text(encoding="utf-8").splitlines()
                if l.startswith("#")]
    env.admin.apply(env.admin.propose_grant("hr_staff", "employees", "salary"),
                    actor="master")
    env.admin.apply(env.admin.propose_revoke("hr_staff", "trainings", "*"),
                    actor="master")
    text = env.policy.read_text(encoding="utf-8")
    after = [l for l in text.splitlines() if l.startswith("#")]
    assert after == comments + [CHANGES_HEADER]
    assert "p, hr_staff, trainings.*, read" not in text
    assert text.count(CHANGES_HEADER) == 1


# ---- 7. undo ----------------------------------------------------------------

def test_undo_restores_previous_file_exactly(env):
    original = env.policy.read_bytes()
    env.admin.apply(env.admin.propose_grant("hr_staff", "employees", "salary"),
                    actor="master")
    assert rows(env, "bob", SALARY_Q)
    undo = env.admin.propose_undo()
    env.admin.apply(undo, actor="master")
    assert env.policy.read_bytes() == original
    with pytest.raises(AccessDenied):
        env.gate.authorize("bob", SALARY_Q)
    with pytest.raises(ValueError, match="Nothing to undo"):
        env.admin.propose_undo()


def test_undo_refuses_if_file_changed_after(env):
    env.admin.apply(env.admin.propose_grant("hr_staff", "employees", "salary"),
                    actor="master")
    with open(env.policy, "a", encoding="utf-8") as f:
        f.write("# edited by hand\n")
    with pytest.raises(ValueError, match="undo manually"):
        env.admin.propose_undo()


def test_undo_attribute_change(env):
    original = env.attrs.read_bytes()
    env.admin.apply(env.admin.propose_set_attribute("bob", "dept", "logistics"),
                    actor="master")
    env.admin.apply(env.admin.propose_undo(), actor="master")
    assert env.attrs.read_bytes() == original


# ---- 8. row scope changes rows live -----------------------------------------

def test_row_scope_added_live(env):
    q = "SELECT id, status FROM invoices ORDER BY id"
    assert rows(env, "dave", q) == [(1, "unpaid"), (2, "paid"), (3, "unpaid")]
    change = env.admin.propose_row_scope("finance_analyst", "invoices",
                                         "status = 'unpaid'")
    env.admin.apply(change, actor="master")
    assert rows(env, "dave", q) == [(1, "unpaid"), (3, "unpaid")]


def test_parenthesized_commas_round_trip(env):
    change = env.admin.propose_row_scope(
        "finance_analyst", "invoices", "status IN ('unpaid', 'overdue')")
    env.admin.apply(change, actor="master")
    assert rows(env, "dave", "SELECT id FROM invoices ORDER BY id") == [(1,), (3,)]


# ---- 9. reload is fail-closed -----------------------------------------------

def test_reload_failure_denies_everything_until_fixed(env):
    good = env.policy.read_text(encoding="utf-8")
    q = "SELECT sku FROM inventory"
    assert rows(env, "alice", q)
    env.policy.write_text(good + "p, broken), line, read\n", encoding="utf-8")
    for user, sql in (("alice", q), ("bob", "SELECT name FROM employees")):
        with pytest.raises(AccessDenied, match="reload"):
            env.gate.authorize(user, sql)
    env.policy.write_text(good, encoding="utf-8")
    assert rows(env, "alice", q)


# ---- 10. role reassignment is live ------------------------------------------

def test_assign_role_on_the_fly(env):
    with pytest.raises(AccessDenied):
        env.gate.authorize("dave", "SELECT name FROM employees")
    env.admin.apply(env.admin.propose_assign_role("dave", "hr_staff"),
                    actor="master")
    assert rows(env, "dave", "SELECT name FROM employees ORDER BY id") == [
        ("Frank Ho",), ("Grace Koh",)]
    with pytest.raises(AccessDenied):
        env.gate.authorize("dave", "SELECT vendor FROM invoices")


# ---- 11. master bot flow ----------------------------------------------------

GRANT_CALL = {"role": "hr_staff", "table": "employees", "column": "salary"}


def test_master_bot_decline_then_apply(env):
    original = sha(env.policy)
    client = FakeClient([
        tool_use("propose_grant", GRANT_CALL),
        end_turn("I proposed letting hr_staff read employees.salary."),
        end_turn("Understood."),
    ])
    inputs = iter(["let hr_staff see salaries", "no", "ok", "exit"])
    out = []
    master_bot.run_master_bot("master", client=client,
                              input_fn=lambda _: next(inputs),
                              output=out.append, admin=env.admin)
    assert sha(env.policy) == original
    assert not env.changelog.exists()
    tool_result = client.calls[1]["messages"][-1]["content"][0]
    assert tool_result["is_error"] is False
    assert master_bot.AWAITING in tool_result["content"]
    assert "DECLINED" in json.dumps(client.calls[2]["messages"][-1]["content"])
    assert any("+p, hr_staff, employees.salary, read" in o for o in out)

    client = FakeClient([tool_use("propose_grant", GRANT_CALL), end_turn("Done?")])
    inputs = iter(["let hr_staff see salaries", "yes", "exit"])
    master_bot.run_master_bot("master", client=client,
                              input_fn=lambda _: next(inputs),
                              output=out.append, admin=env.admin)
    assert "p, hr_staff, employees.salary, read" in env.policy.read_text(
        encoding="utf-8")
    assert rows(env, "bob", SALARY_Q)
    assert json.loads(env.changelog.read_text().splitlines()[-1])["actor"] == "master"


def test_master_bot_validation_error_goes_to_model(env):
    client = FakeClient([
        tool_use("propose_assign_role", {"username": "bob", "role": "master"}),
        end_turn("That is not allowed."),
    ])
    inputs = iter(["make bob a master", "exit"])
    master_bot.run_master_bot("master", client=client,
                              input_fn=lambda _: next(inputs),
                              output=lambda *_: None, admin=env.admin)
    result = client.calls[1]["messages"][-1]["content"][0]
    assert result["is_error"] is True
    assert '"role": "hr_staff"' in env.attrs.read_text().replace("\n", "")[:200] \
        or json.loads(env.attrs.read_text())["bob"]["role"] == "hr_staff"


@pytest.mark.parametrize("user", ["bob", "nobody"])
def test_master_bot_refuses_non_master(env, user):
    with pytest.raises(SystemExit) as exc:
        master_bot.run_master_bot(user, client=FakeClient([]),
                                  input_fn=lambda _: "exit",
                                  output=lambda *_: None, admin=env.admin)
    assert exc.value.code not in (0, None)


def test_master_bot_has_no_apply_or_data_tool():
    names = {t["name"] for t in master_bot.TOOLS}
    assert not any("apply" in n or "sql" in n for n in names)
    assert names == set(master_bot.DISPATCH)


# ---- 12. worker chatbot resets history on policy change ----------------------

def test_chatbot_resets_history_on_policy_change(env, monkeypatch, capsys):
    monkeypatch.setattr(chatbot, "DB_PATH", str(env.db))
    client = FakeClient([
        tool_use("run_sql", {"sql": "SELECT sku, qty FROM inventory"}),
        end_turn("You have PAL-4512, BOX-2210 and GLV-0031."),
        end_turn("Fresh start."),
    ])

    def revoke_then(question):
        env.admin.apply(env.admin.propose_revoke("warehouse_worker",
                                                 "inventory", "*"),
                        actor="master")
        return question

    script = iter([lambda: "what's in stock?",
                   lambda: revoke_then("and now?"),
                   lambda: "exit"])
    chatbot.run_chatbot("alice", client=client, gate=env.gate,
                        input_fn=lambda _: next(script)())

    first_turn = client.calls[1]["messages"]
    assert "PAL-4512" in json.dumps(first_turn[-1]["content"])  # tool rows
    second_turn = client.calls[2]
    assert second_turn["messages"] == [{"role": "user", "content": "and now?"}]
    assert "inventory(" in client.calls[0]["system"]
    assert "inventory(" not in second_turn["system"]
    assert chatbot.POLICY_RESET_NOTICE in capsys.readouterr().out


def test_refresh_session_no_reset_without_change(env):
    history = [{"role": "user", "content": "hi"}]
    role, prompt, version, reset = chatbot.refresh_session(
        env.gate, "bob", history, env.gate.policy_version)
    assert (role, reset, len(history)) == ("hr_staff", False, 1)
    assert "- employees(id, name, dept, start_date)\n" in prompt


# =============================================================================
# Security regressions (one per confirmed exploit). All hand edits go to the
# tmp_path copies from the `env` fixture — never to the repo's data files.
# =============================================================================

PAYSLIP_Q = "SELECT employee_id, salary FROM payroll ORDER BY employee_id"
ALICE_OWN_PAYSLIP = [(6, 42000)]


def hand_edit_attrs(env, user, **values):
    data = json.loads(env.attrs.read_text(encoding="utf-8"))
    data[user].update(values)
    env.attrs.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def hand_append_policy(env, line):
    with open(env.policy, "a", encoding="utf-8", newline="") as f:
        f.write("\n" + line + "\n")


# ---- R1. row-filter values are bound as literals, never spliced as SQL ------

@pytest.mark.parametrize("value", [
    "employee_id",                 # the confirmed exploit: IN (employee_id)
    "6, employee_id",
    "1) OR (1=1",
    "x' OR '1'='1",
    "payroll.employee_id",
    "(SELECT employee_id FROM payroll)",
])
def test_r1_gate_binds_attribute_as_literal(env, value):
    """Even with the admin bypassed (hand-edited files), the gate can only
    bind a value as literal(s): alice never sees more than her own row."""
    hand_edit_attrs(env, "alice", team_ids=value)
    hand_append_policy(env, "p2, employee, payroll, employee_id IN ({team_ids})")
    safe_sql = env.gate.authorize("alice", PAYSLIP_Q)
    assert "IN (payroll.employee_id)" not in safe_sql
    assert rows(env, "alice", PAYSLIP_Q) == ALICE_OWN_PAYSLIP


def test_r1_admin_rejects_identifier_value_before_it_goes_live(env):
    """The t2 exploit through the admin: C1 is harmless on its own, C2 (the
    template that would use it) is now rejected by the all-users check."""
    env.admin.apply(env.admin.propose_set_attribute("alice", "team_ids",
                                                    "employee_id"), "master")
    before = sha(env.policy)
    with pytest.raises(ValueError, match="alice.team_ids"):
        env.admin.propose_row_scope("employee", "payroll",
                                    "employee_id IN ({team_ids})")
    assert sha(env.policy) == before
    assert rows(env, "alice", PAYSLIP_Q) == ALICE_OWN_PAYSLIP


def test_r1_shipped_filters_render_equivalently(env):
    assert env.gate.authorize("alice", "SELECT sku FROM inventory").endswith(
        "WHERE inventory.warehouse_id = 'SG-01'")
    assert env.gate.authorize("bob", PAYSLIP_Q).split("WHERE ")[1].startswith(
        "payroll.employee_id = '1'")
    carol = env.gate.authorize("carol", PAYSLIP_Q)
    assert ("payroll.employee_id = '2' OR payroll.employee_id IN (1, 2, 3)"
            in carol)


@pytest.mark.parametrize("template", [
    "dept = 'x{dept}'",            # placeholder glued into a larger string
    "dept = '{dept}x'",
    "dept{dept} = 1",              # ... or into a name
    "dept = '__rbic_ph_dept__'",   # reserved sentinel text
])
def test_r1_placeholder_must_stand_alone(template):
    schema = json.loads((ROOT / "db_schema.json").read_text())
    with pytest.raises(FilterError):
        compile_row_filter("employees", template, schema)


# ---- R2. a reload mid-request can't mix old RBAC with new row filters -------

def revoke_payroll_by_hand(env):
    text = env.policy.read_text(encoding="utf-8")
    text = text.replace("p, employee, payroll.*, read", "").replace(
        "p2, employee, payroll, employee_id = '{employee_id}'", "")
    env.policy.write_text(text, encoding="utf-8")


def test_r2_reload_inside_request_uses_one_snapshot(env, monkeypatch):
    """t5: reload fires between the RBAC check and ABAC injection."""
    orig = env.gate._check_rbac

    def rbac_then_reload(*args):
        orig(*args)
        revoke_payroll_by_hand(env)
        env.gate._maybe_reload()

    monkeypatch.setattr(env.gate, "_check_rbac", rbac_then_reload)
    version = env.gate.policy_version
    safe_sql = env.gate.authorize("alice", PAYSLIP_Q)
    assert "payroll.employee_id = '6'" in safe_sql     # old snapshot's filter
    assert rows_for_sql(env, safe_sql) == ALICE_OWN_PAYSLIP
    assert env.gate.policy_version == version + 1      # the reload did happen
    monkeypatch.undo()
    with pytest.raises(AccessDenied):                  # next request: new policy
        env.gate.authorize("alice", PAYSLIP_Q)


def test_r2_concurrent_reload_from_another_thread(env, monkeypatch):
    """Two threads: A is paused mid-request while B reloads the policy."""
    in_rbac, resume = threading.Event(), threading.Event()
    orig = env.gate._check_rbac
    result = {}

    def paused_rbac(*args):
        orig(*args)
        in_rbac.set()
        assert resume.wait(10)

    monkeypatch.setattr(env.gate, "_check_rbac", paused_rbac)

    def worker():
        try:
            result["sql"] = env.gate.authorize("alice", PAYSLIP_Q)
        except Exception as err:  # noqa: BLE001
            result["err"] = err

    t = threading.Thread(target=worker)
    t.start()
    assert in_rbac.wait(10)
    revoke_payroll_by_hand(env)
    new_version = env.gate.refresh()                   # thread B's reload
    resume.set()
    t.join(10)
    assert "err" not in result, result.get("err")
    assert "payroll.employee_id = '6'" in result["sql"]
    assert rows_for_sql(env, result["sql"]) == ALICE_OWN_PAYSLIP
    assert env.gate.policy_version == new_version
    monkeypatch.undo()
    with pytest.raises(AccessDenied):
        env.gate.authorize("alice", PAYSLIP_Q)


def rows_for_sql(env, safe_sql):
    conn = sqlite3.connect(f"file:{env.db}?mode=ro", uri=True)
    try:
        return conn.execute(safe_sql).fetchall()
    finally:
        conn.close()


# ---- R3. stale pending changes, file lock, audit ordering ---------------------

def test_r3_second_pending_change_is_stale_after_first_applies(env):
    """t3 A: remove hr_staff's scope + move dave to hr_staff in one turn."""
    x = env.admin.propose_remove_row_scope("hr_staff", "employees", "dept = '{dept}'")
    y = env.admin.propose_assign_role("dave", "hr_staff")
    env.admin.apply(x, "master")
    attrs_before = sha(env.attrs)
    with pytest.raises(ValueError, match="Policy changed since this was proposed"):
        env.admin.apply(y, "master")
    assert sha(env.attrs) == attrs_before
    with pytest.raises(AccessDenied):
        env.gate.authorize("dave", "SELECT name, dept FROM employees")


@pytest.mark.parametrize("path_attr", ["schema", "model"])
def test_r3_any_input_change_makes_proposal_stale(env, path_attr):
    change = env.admin.propose_grant("hr_staff", "employees", "salary")
    path = getattr(env, path_attr)
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    before = sha(env.policy)
    with pytest.raises(ValueError, match="Policy changed since this was proposed"):
        env.admin.apply(change, "master")
    assert sha(env.policy) == before


def test_r3_apply_waits_for_lock_and_always_releases_it(env, monkeypatch):
    lock = env.policy.parent / ".policy.lock"
    change = env.admin.propose_grant("hr_staff", "employees", "salary")
    lock.write_text("other process\n")
    monkeypatch.setattr(policy_admin, "LOCK_TIMEOUT_S", 0.2)
    before = sha(env.policy)
    with pytest.raises(ValueError, match="Another policy change"):
        env.admin.apply(change, "master")
    assert sha(env.policy) == before and lock.exists()
    lock.unlink()
    env.admin.apply(change, "master")
    assert not lock.exists()
    failing = env.admin.propose_grant("hr_staff", "payroll", "*")
    with pytest.raises(ValueError, match="not a master"):
        env.admin.apply(failing, "bob")
    assert not lock.exists()


def test_r3_audit_record_written_before_file_replaced(env, monkeypatch):
    change = env.admin.propose_grant("hr_staff", "employees", "salary")
    real_replace = os.replace
    seen = {}

    def spy_replace(src, dst):
        records = [json.loads(l) for l in env.changelog.read_text().splitlines()]
        seen["at_replace"] = [(r["id"], r["status"]) for r in records]
        return real_replace(src, dst)

    monkeypatch.setattr(policy_admin.os, "replace", spy_replace)
    env.admin.apply(change, "master")
    assert seen["at_replace"] == [(change.id, "applying")]
    records = [json.loads(l) for l in env.changelog.read_text().splitlines()]
    assert [r["status"] for r in records] == ["applying", "applied"]
    assert [h["id"] for h in env.admin.history()] == [change.id]


def test_r3_failed_replace_is_audited_and_not_undoable(env, monkeypatch):
    change = env.admin.propose_grant("hr_staff", "employees", "salary")
    before = sha(env.policy)

    def broken_replace(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(policy_admin.os, "replace", broken_replace)
    with pytest.raises(OSError):
        env.admin.apply(change, "master")
    monkeypatch.undo()
    assert sha(env.policy) == before
    records = [json.loads(l) for l in env.changelog.read_text().splitlines()]
    assert [r["status"] for r in records] == [
        "applying", "failed: OSError: disk full"]
    assert env.admin.history() == []
    with pytest.raises(ValueError, match="Nothing to undo"):
        env.admin.propose_undo()
    assert not (env.policy.parent / ".policy.lock").exists()
    assert not list(env.policy.parent.glob(".tmp_*"))


# ---- R4. invisible/control characters and comments in templates ---------------

@pytest.mark.parametrize("template", [
    "employee_id = '{employee_id}' /* own payslip only */ OR employee_id > 0",
    "employee_id = '{employee_id}' OR employee_id > 0 -- hidden",
    "employee_id = '{employee_id}' # hidden",
    "employee_id = '{employee_id}' /*\x1b[8m*/ OR employee_id > 0 /*\x1b[0m*/",
    "employee_id = '{employee_id}'\x0cOR employee_id > 0",
    "employee_id = '{employee_id}' OR employee_id > 0",
    "employee_id = '‮0 < di_eeyolpme RO'",
    "employee_id = '{employee_id}'\rOR employee_id > 0",
])
def test_r4_template_must_be_printable_ascii_without_comments(env, template):
    before = sha(env.policy)
    with pytest.raises(ValueError):
        env.admin.propose_row_scope("hr_staff", "payroll", template)
    assert sha(env.policy) == before


def test_r4_line_editing_matches_casbin_line_splitting(env):
    """A hand-edited \\x0c template is one Casbin rule; the admin must see
    (and be able to remove) exactly that rule, and show it escaped."""
    template = "employee_id = '{employee_id}'\x0cOR employee_id > 0"
    hand_append_policy(env, f"p2, hr_staff, payroll, {template}")
    env.gate.refresh()
    assert ["hr_staff", "payroll", template] in \
        env.gate.enforcer.get_named_policy("p2")
    change = env.admin.propose_remove_row_scope("hr_staff", "payroll", template)
    assert "\x0c" not in change.diff() and "\\x0c" in change.diff()
    assert "\x0c" not in change.description
    env.admin.apply(change, "master")
    assert template not in env.policy.read_text(encoding="utf-8")


@pytest.mark.parametrize("call", [
    lambda a: a.propose_set_attribute("bob", "dept", "engineering\n"),
    lambda a: a.propose_set_attribute("bob", "dept\n", "x"),
    lambda a: a.propose_grant("hr_staff\n", "employees", "name"),
    lambda a: a.propose_assign_role("bob\n", "hr_staff"),
    lambda a: a.propose_set_attribute("bob", "dept", "café"),  # non-ASCII \w
])
def test_r4_names_and_values_use_fullmatch(env, call):
    with pytest.raises(ValueError):
        call(env.admin)


def test_r4_regexes_reject_trailing_newline():
    for regex, value in ((policy_admin.ROLE_RE, "abc\n"),
                         (policy_admin.ATTR_KEY_RE, "dept\n"),
                         (policy_admin.ATTR_VALUE_RE, "SG-01\n")):
        assert not regex.match(value) and not regex.fullmatch(value)


# ---- R5. always-true / non-restrictive filters ---------------------------------

@pytest.mark.parametrize("template", [
    "TRUE", "1", "employee_id", "(employee_id)", "NOT employee_id",
    "employee_id = employee_id",
    "employee_id IN (employee_id)",
    "employee_id >= employee_id + 0",
    "employee_id = '{employee_id}' OR 1 = 1",
    "employee_id = '{employee_id}' OR TRUE",
    "employee_id = '{employee_id}' OR (1 = 1 AND employee_id > 0)",
    "'{employee_id}' = '{employee_id}'",
    "CASE WHEN employee_id > 0 THEN 1 ELSE 1 END = 1",
])
def test_r5_non_restrictive_filters_rejected(env, template):
    with pytest.raises(ValueError):
        env.admin.propose_row_scope("hr_staff", "payroll", template)


@pytest.mark.parametrize("template", [
    "status IN ('unpaid', 'overdue')",
    "lower(status) = 'unpaid'",
    "NOT (status = 'paid')",
    "amount BETWEEN 0 AND 100",
    "due_date IS NOT NULL",
    "status = 'unpaid' OR (amount < 100 AND status <> 'paid')",
])
def test_r5_predicate_filters_still_accepted(env, template):
    change = env.admin.propose_row_scope("finance_analyst", "invoices", template)
    assert STATIC_FILTER_WARNING in change.description


def test_r5_placeholder_filter_has_no_static_warning(env):
    change = env.admin.propose_row_scope("hr_staff", "trainings", "dept = '{dept}'")
    assert STATIC_FILTER_WARNING not in change.description


# ---- R6. attribute undo is described and checked like a forward change ------

def test_r6_attribute_undo_describes_effects(env):
    env.admin.apply(env.admin.propose_assign_role("dave", "hr_staff"), "master")
    undo = env.admin.propose_undo()
    assert "no change to any role's effective access" not in undo.description
    assert "dave: gains read on invoices" in undo.description
    assert "dave: loses read on employees" in undo.description


def test_r6_attribute_undo_runs_value_and_scope_checks(env):
    # bob's old value is harmless until a hand-added template binds it
    # unquoted; undoing back to it must then be refused.
    hand_edit_attrs(env, "bob", team="abc")
    env.admin.apply(env.admin.propose_set_attribute("bob", "team", "5"), "master")
    hand_append_policy(env, "p2, hr_staff, trainings, id IN ({team})")
    with pytest.raises(ValueError, match="bob.team"):
        env.admin.propose_undo()


# ---- R7. tokenizer errors and bind parameters deny instead of crashing -------

@pytest.mark.parametrize("sql", [
    "SELECT 'abc FROM inventory",
    'SELECT sku FROM inventory WHERE sku = "x',
    "SELECT sku FROM inventory WHERE sku = ?",
    "SELECT sku FROM inventory WHERE sku = :a",
    "SELECT sku FROM inventory WHERE sku = @a",
    "SELECT sku FROM inventory WHERE sku = $1",
])
def test_r7_gate_denies_instead_of_raising(env, sql):
    with pytest.raises(AccessDenied):
        env.gate.authorize("alice", sql)


def test_r7_worker_chatbot_survives_tokenizer_error(env, monkeypatch, capsys):
    monkeypatch.setattr(chatbot, "DB_PATH", str(env.db))
    client = FakeClient([tool_use("run_sql", {"sql": "SELECT 'abc FROM inventory"})])
    script = iter(["what's in stock?", "exit"])
    chatbot.run_chatbot("alice", client=client, gate=env.gate,
                        input_fn=lambda _: next(script))
    assert DENY_MESSAGE in capsys.readouterr().out


# ---- R8. minor --------------------------------------------------------------------

def test_r8_row_scope_headline_warns_when_heirs_are_widened(env):
    # hr_staff inherits employee and already has a dept filter on employees,
    # so a new employee-level scope on employees WIDENS hr_staff.
    change = env.admin.propose_row_scope("employee", "employees",
                                         "id = '{employee_id}'")
    head = change.description.splitlines()[0]
    assert "WARNING" in head and "hr_staff" in head and "MORE rows" in head
    assert "hr_staff" not in head.split("WARNING")[0]
    assert "rows of employees WIDENED to" in change.description


def test_r8_broken_gate_clears_worker_history(env):
    history = [{"role": "user", "content": "hi"},
               {"role": "assistant", "content": "rows..."}]
    version = env.gate.policy_version
    env.policy.write_text(env.policy.read_text(encoding="utf-8")
                          + "p, broken), line, read\n", encoding="utf-8")
    role, prompt, new_version, reset = chatbot.refresh_session(
        env.gate, "alice", history, version)
    assert env.gate.broken and history == [] and new_version == version
