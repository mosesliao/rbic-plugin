"""The worker system prompt tells the model that results are already
row-limited (so it never asks who the user is or adds its own name/dept
filters), gives it the user's OWN employee_id and nothing else from the
attributes (so "my salary" picks the user's row out of team rows), and the
case-insensitive comparison it recommends passes the gate with the row
filter still ANDed in.

Live regressions: carol (hr_manager) asked for her team's salaries; the
model added `WHERE dept = 'Engineering'` (stored values are lowercase,
SQLite `=` is case-sensitive) and got 0 rows. carol asked "what is my
salary?", saw three payroll rows and picked Bob's with LIMIT 1 (or listed
all three, unable to tell which was hers).

Every test works on tmp_path copies; the repo's files are never touched.
"""

import json
import logging
import re
import sqlite3

import pytest

from types import SimpleNamespace as NS

from rbic import engine
from rbic.engine import RBICEngine
from rbic.gate import SQLGate
from rbic.identity import Identity

logging.disable(logging.CRITICAL)

DIALECTS = ("postgres", "sqlite")
WORKERS = ("alice", "bob", "carol", "dave")
OWN_IDS = {"alice": "6", "bob": "1", "carol": "2", "dave": "7"}

ROW_RULES = (
    "Every query result is already limited to the rows this user may see",
    "Do NOT add filters on the user's name, email, department or team.",
    "Never ask the user, or invite them, to provide their name, id, email or\n"
    "  any other identity detail (not even \"if you know your employee ID ...\").",
    "if their own employee_id is given under \"About\n"
    "  this user\" above, filter on it",
    "Only when it is NOT given, show all the\n  matching rows",
    "that you cannot tell which one is theirs. Never use LIMIT, ORDER BY or\n"
    "  a guess to pick one row.",
    "Choose the table whose columns answer the question.",
    "a payroll-style table, if one is listed",
    "LOWER(col) = LOWER('value')",
    "say that nothing was found in the data this\n  user can access",
    "do not tell the user to contact\n  HR or an administrator",
    "Never speculate about why records are missing or why results look\n"
    "  partial (e.g. \"hasn't been entered yet\"); just state what was found in\n"
    "  the data the user can access.",
)
KEPT_RULES = (
    "- Emit a single SQLite SELECT per tool call. No other statement types.",
    "- Only reference the tables and columns listed above.",
    "- After getting rows back, answer concisely in plain language.",
)


def self_line(own_id):
    return (f"About this user: their own employee_id is {own_id}. Use it only "
            f"to pick out the user's own row (e.g. WHERE employee_id = "
            f"{own_id} in a payroll-style table) when they ask about "
            "themselves alone; results already include everything else they "
            "may see.")


def make_gate(root, dialect):
    return SQLGate(
        model_path=str(root / "casbin" / "model.conf"),
        policy_path=str(root / "casbin" / "policy.csv"),
        schema_path=str(root / "db_schema.json"),
        attributes_path=str(root / "worker_attributes.json"),
        dialect=dialect,
    )


@pytest.fixture(params=DIALECTS)
def gate(request, demo_dir):
    return make_gate(demo_dir, request.param)


@pytest.fixture
def sgate(demo_dir):
    return make_gate(demo_dir, "sqlite")


def run(gate, demo_dir, username, sql):
    safe_sql = gate.authorize(username, sql)
    conn = sqlite3.connect(engine.readonly_uri(demo_dir / "company.db"),
                           uri=True)
    try:
        return safe_sql, conn.execute(safe_sql).fetchall()
    finally:
        conn.close()


# ---- the prompt ---------------------------------------------------------------

@pytest.mark.parametrize("username", WORKERS)
def test_prompt_says_rows_are_already_limited(sgate, username):
    role, prompt = engine.system_prompt_for(sgate, username)
    assert role
    for rule in ROW_RULES + KEPT_RULES:
        assert rule in prompt


def test_prompt_rules_also_for_a_worker_without_tables():
    prompt = engine.build_system_prompt(None, {}, {})
    for rule in ROW_RULES:
        assert rule in prompt
    assert "About this user" not in prompt


# ---- the user's own employee_id (SELF_IDENTITY_ATTRIBUTES) --------------------

def test_only_employee_id_may_reach_the_prompt():
    assert engine.SELF_IDENTITY_ATTRIBUTES == ("employee_id",)


@pytest.mark.parametrize("username", WORKERS)
def test_prompt_states_the_users_own_employee_id(sgate, username):
    _, prompt = engine.system_prompt_for(sgate, username)
    assert self_line(OWN_IDS[username]) in prompt
    assert prompt.count("About this user:") == 1
    # before the rules that refer to it as "above"
    assert prompt.index("About this user:") < prompt.index("Rules:")


def test_no_self_line_without_employee_id(demo_dir):
    attrs_path = demo_dir / "worker_attributes.json"
    attrs = json.loads(attrs_path.read_text(encoding="utf-8"))
    del attrs["dave"]["employee_id"]
    attrs_path.write_text(json.dumps(attrs, indent=2) + "\n", encoding="utf-8")
    role, prompt = engine.system_prompt_for(make_gate(demo_dir, "sqlite"),
                                            "dave")
    assert role == "finance_analyst"
    assert "About this user:" not in prompt
    assert not re.search(r"\b7\b", prompt)
    for rule in ROW_RULES:
        assert rule in prompt  # the "NOT given" branch is still there


@pytest.mark.parametrize("value", [
    "2a", "-1", -1, "1" * 21, 10 ** 20, " 2", "2 ", "2\n", "", "2.0", 2.0,
    True, False, None, [2], ["2"], {"id": 2}, "\uff12", "\u0662", "1, 2, 3",
    "2; DROP TABLE payroll", "{employee_id}", "2 OR 1=1",
])
def test_unusable_employee_id_is_left_out(value):
    worker = {"role": "hr_manager", "employee_id": value}
    assert engine.self_identity(worker) == {}
    prompt = engine.build_system_prompt("hr_manager", {}, {}, worker)
    assert "About this user:" not in prompt
    assert not re.search(r"employee_id (is (?!given)|= (?!<that id>))", prompt)


class _StrSub(str):
    def __str__(self):
        return "2 OR 1=1"


@pytest.mark.parametrize("value, shown", [
    (2, "2"), ("2", "2"), ("02", "02"), (0, "0"), ("1" * 20, "1" * 20),
])
def test_plain_ids_are_shown(value, shown):
    worker = {"role": "hr_manager", "employee_id": value}
    assert engine.self_identity(worker) == {"employee_id": shown}
    assert self_line(shown) in engine.build_system_prompt(
        "hr_manager", {}, {}, worker)


def test_str_subclass_is_left_out():
    worker = {"role": "hr_manager", "employee_id": _StrSub("2")}
    assert engine.self_identity(worker) == {}
    prompt = engine.build_system_prompt("hr_manager", {}, {}, worker)
    assert "About this user:" not in prompt and "1=1" not in prompt


@pytest.mark.parametrize("worker", [None, [], "2", 2, ("employee_id", 2)])
def test_non_mapping_worker_gives_no_line(worker):
    assert engine.self_identity(worker) == {}
    assert "About this user:" not in engine.build_system_prompt(
        "hr_manager", {}, {}, worker)


def test_no_other_attribute_reaches_the_prompt():
    worker = {
        "role": "hr_manager", "employee_id": 5,
        "email": "x9@example.test", "dept": "43210", "site": "77777",
        "self_and_subordinate_ids": "91, 92, 93", "manager_id": 88888,
        "username": "zed", "salary": "123456",
    }
    assert set(engine.self_identity(worker)) <= set(
        engine.SELF_IDENTITY_ATTRIBUTES)
    prompt = engine.build_system_prompt("hr_manager", {}, {}, worker)
    assert self_line("5") in prompt
    assert "@" not in prompt
    for value in ("x9", "43210", "77777", "91", "92", "93", "88888", "zed",
                  "123456"):
        assert value not in prompt, value


def test_prompt_uses_the_given_snapshot(demo_dir):
    gate = make_gate(demo_dir, "sqlite")
    snap = gate.refreshed_snapshot()
    attrs_path = demo_dir / "worker_attributes.json"
    attrs = json.loads(attrs_path.read_text(encoding="utf-8"))
    attrs["carol"]["employee_id"] = 9
    attrs_path.write_text(json.dumps(attrs, indent=2) + "\n", encoding="utf-8")
    _, old = engine.system_prompt_for(gate, "carol", snap)
    assert self_line("2") in old
    _, new = engine.system_prompt_for(gate, "carol")
    assert self_line("9") in new


class _OneShotClient:
    def __init__(self):
        self.calls = []
        self.messages = self

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return NS(stop_reason="end_turn",
                  content=[NS(type="text", text="ok")])


def test_ask_sends_the_self_line(demo_config):
    client = _OneShotClient()
    eng = RBICEngine(demo_config, client=client)
    result = eng.ask(Identity("openwebui", "sub-carol", "carol@example.test"),
                     [{"role": "user", "content": "what is my salary?"}])
    assert result.text == "ok" and not result.denied
    (call,) = client.calls
    assert self_line("2") in call["system"]
    assert "@" not in call["system"] and "1, 2, 3" not in call["system"]


@pytest.mark.parametrize("username", WORKERS)
def test_prompt_has_no_filters_attributes_or_emails(sgate, demo_dir, username):
    _, prompt = engine.system_prompt_for(sgate, username)
    attrs = json.loads(
        (demo_dir / "worker_attributes.json").read_text(encoding="utf-8"))
    assert "@" not in prompt
    # no attribute value of ANY worker (dept, site, ids, team list) except
    # the user's own employee_id
    for name, record in attrs.items():
        for key, value in record.items():
            if key == "role" or (name == username and key == "employee_id"):
                continue
            value = str(value)
            assert not re.search(rf"(?<![\w-]){re.escape(value)}(?![\w-])",
                                 prompt, re.IGNORECASE), (key, value)
    # no row-filter text or placeholder from policy.csv
    for line in (demo_dir / "casbin" / "policy.csv").read_text(
            encoding="utf-8").splitlines():
        fields = [f.strip() for f in line.split(",")]
        if fields[0] == "p2":
            assert fields[3] not in prompt
    assert "{" not in prompt and "}" not in prompt
    # never another worker's username
    for other in attrs:
        if other != username:
            assert not re.search(rf"\b{other}\b", prompt), other


# ---- the case-insensitive comparison passes the gate ---------------------------

def test_lower_equals_passes_gate_with_row_filter(gate):
    sql = gate.authorize(
        "carol", "SELECT name, salary FROM employees "
                 "WHERE LOWER(dept) = LOWER('Engineering')")
    low = sql.lower()
    assert "lower(" in low
    assert "dept = 'engineering'" in low  # hr_staff's dept scope, still ANDed


def test_lower_like_passes_gate_with_row_filter(gate):
    sql = gate.authorize(
        "bob", "SELECT id, name FROM employees WHERE LOWER(name) LIKE '%lim%'")
    low = sql.lower()
    assert "like '%lim%'" in low
    assert "dept = 'engineering'" in low


def test_lower_cannot_widen_rows(sgate, demo_dir):
    # carol's dept scope stays: asking for another dept case-insensitively
    # finds nothing, asking for her own finds the three engineering rows
    _, other = run(sgate, demo_dir, "carol",
                   "SELECT name FROM employees "
                   "WHERE LOWER(dept) = LOWER('Logistics')")
    assert other == []
    _, own = run(sgate, demo_dir, "carol",
                 "SELECT name, salary FROM employees "
                 "WHERE LOWER(dept) = LOWER('Engineering') ORDER BY id")
    assert own == [("Bob Tan", 78000), ("Carol Lim", 112000),
                   ("Erin Ng", 65000)]
    _, like = run(sgate, demo_dir, "bob",
                  "SELECT name FROM employees "
                  "WHERE LOWER(name) LIKE LOWER('%NG%') ORDER BY id")
    assert like == [("Erin Ng",)]  # Grace Koh / Alice Wong are other depts


def test_unfiltered_team_payroll_query_is_scoped(sgate, demo_dir):
    # what the prompt now asks for: query the table directly, no own filter
    sql, got = run(sgate, demo_dir, "carol",
                   "SELECT employee_id, salary FROM payroll ORDER BY employee_id")
    assert got == [(1, 78000), (2, 112000), (3, 65000)]
    assert "IN (1, 2, 3)" in sql
    _, bob = run(sgate, demo_dir, "bob",
                 "SELECT employee_id, salary FROM payroll")
    assert bob == [(1, 78000)]


def test_own_id_filter_picks_the_users_row(sgate, demo_dir):
    # what the self line asks for: carol's own payslip out of her team's
    sql, got = run(sgate, demo_dir, "carol",
                   "SELECT salary FROM payroll WHERE employee_id = 2")
    assert got == [(112000,)]
    assert "IN (1, 2, 3)" in sql  # the gate's row filter is still ANDed in


@pytest.mark.parametrize("username", ("bob", "alice", "dave"))
def test_id_filter_cannot_widen_rows(sgate, demo_dir, username):
    # someone else's id only narrows the user's own scope: no rows
    _, got = run(sgate, demo_dir, username,
                 "SELECT salary FROM payroll WHERE employee_id = 2")
    assert got == []


# ---- how each table's rows are limited ("rows:" lines, issue #10) -------------
# Live regression: carol asked "what about my team's salary?" and the model
# read employees (her department) instead of payroll (self + team). The
# prompt now says, per table, whose rows it holds - in plain words from the
# gate's own decide(), never the filter text or an attribute value.

DEMO_ROWS = {
    "alice": {"inventory": "your site", "shipments": "your site",
              "safety_incidents": "all rows", "payroll": "your own records"},
    "bob": {"payroll": "your own records", "employees": "your department",
            "leave_requests": "your department", "trainings": "all rows"},
    "carol": {"payroll": "your own records or you and your team",
              "employees": "your department",
              "leave_requests": "your department", "trainings": "all rows"},
    "dave": {"payroll": "your own records", "budgets": "all rows",
             "expenses": "your department", "invoices": "all rows"},
}
ROWS_RULE = ('For "my team ..." questions, query a table whose\n'
             '  rows include "you and your team"; for "my department ..." '
             'questions, one\n  whose rows are "your department"')
ROWS_LINE_RE = re.compile(r"^- (\w+)\((.*)\)\n  rows: (.*)$", re.M)


def rows_of(prompt) -> dict:
    """{table: rows text} of the regular table list (before the scopes)."""
    head = prompt.split("Row-limited scopes.")[0].split("Rules:")[0]
    return {t: r for t, _, r in ROWS_LINE_RE.findall(head)}


def write_policy(root, *lines):
    path = root / "casbin" / "policy.csv"
    with open(path, "a", encoding="utf-8", newline="") as f:
        f.write("".join(line + "\n" for line in lines))


def edit_attrs(root, **changes):
    path = root / "worker_attributes.json"
    attrs = json.loads(path.read_text(encoding="utf-8"))
    for user, values in changes.items():
        attrs[user].update(values)
    path.write_text(json.dumps(attrs, indent=2) + "\n", encoding="utf-8")


@pytest.mark.parametrize("username", WORKERS)
def test_every_demo_table_says_how_its_rows_are_limited(gate, username):
    _, prompt = engine.system_prompt_for(gate, username)
    assert rows_of(prompt) == DEMO_ROWS[username]
    assert ROWS_RULE in prompt
    # the new rule sits with the other rules, the old ones are unchanged
    assert prompt.index("Rules:") < prompt.index(ROWS_RULE)
    for rule in ROW_RULES + KEPT_RULES:
        assert rule in prompt


def test_carol_team_payroll_vs_department_employees(sgate):
    _, prompt = engine.system_prompt_for(sgate, "carol")
    assert ("- payroll(id, employee_id, salary, effective_date)\n"
            "  rows: your own records or you and your team\n") in prompt
    assert ("- employees(id, name, dept, start_date, salary)\n"
            "  rows: your department\n") in prompt


TEAM_RULE = ('Answer every team question, follow-ups such as "and what about my\n'
             '  team\'s salary?" included, from the table whose rows include "you and\n'
             '  your team", even if you queried it already.')


@pytest.mark.parametrize("username", WORKERS)
def test_team_rule_only_with_a_team_table(sgate, username):
    # live: after "show me my team payslip" (payroll), the follow-up "and
    # what about my team's salary?" went to employees (department rows)
    _, prompt = engine.system_prompt_for(sgate, username)
    assert (TEAM_RULE in prompt) == (username == "carol")
    if username == "carol":
        assert prompt.index("Rules:") < prompt.index(TEAM_RULE)
        assert 'do not query a table limited to "your\n  department"' in prompt


def test_alice_scoped_grant_says_own_records(sgate):
    _, prompt = engine.system_prompt_for(sgate, "alice")
    scopes = prompt.split("Row-limited scopes.")[1].split("Rules:")[0]
    assert "- employees(id, name, salary)\n  rows: your own records\n" in scopes


@pytest.mark.parametrize("username", WORKERS)
def test_rows_lines_hold_no_filter_text_or_values(sgate, demo_dir, username):
    _, prompt = engine.system_prompt_for(sgate, username)
    lines = re.findall(r"^  rows: (.*)$", prompt, re.M)
    assert lines
    for text in lines:
        # plain words only: no operators, quotes, digits, braces, emails
        assert re.fullmatch(r"[a-z_ ,;()]+", text), text
    tables = prompt.split("against these tables:")[1].split("About this user:")[0]
    for bad in ("=", "IN (", "'", "{", "}", "@", "<", ">", "LIKE"):
        assert bad not in tables, bad
    assert "{" not in prompt and "}" not in prompt and "@" not in prompt
    for line in (demo_dir / "casbin" / "policy.csv").read_text(
            encoding="utf-8").splitlines():
        fields = [f.strip() for f in line.split(",")]
        if fields[0] == "p2":
            assert fields[3] not in prompt


def test_team_differs_from_department(demo_dir):
    # carol's team spans departments: the prompt tells the two scopes apart,
    # and they really are different rows
    edit_attrs(demo_dir, carol={"self_and_subordinate_ids": "2, 4, 5"})
    gate = make_gate(demo_dir, "sqlite")
    _, prompt = engine.system_prompt_for(gate, "carol")
    rows = rows_of(prompt)
    assert rows["payroll"] == "your own records or you and your team"
    assert rows["employees"] == "your department"
    rest = prompt.replace(self_line("2"), "")
    for value in ("2", "4", "5", "2, 4, 5", "engineering"):
        assert not re.search(rf"(?<![\w-]){re.escape(value)}(?![\w-])",
                             rest), value
    _, team = run(gate, demo_dir, "carol",
                  "SELECT employee_id FROM payroll ORDER BY employee_id")
    _, dept = run(gate, demo_dir, "carol", "SELECT id FROM employees ORDER BY id")
    assert [r[0] for r in team] == [2, 4, 5]
    assert [r[0] for r in dept] == [1, 2, 3]


def test_unknown_attribute_and_static_filters(demo_dir):
    write_policy(demo_dir,
                 "p2, hr_staff, trainings, dept = '{cost_center}'",
                 "p2, finance_analyst, invoices, status = 'unpaid'")
    edit_attrs(demo_dir, bob={"cost_center": "cc-zz-9"},
               carol={"cost_center": "cc-zz-9"})
    gate = make_gate(demo_dir, "sqlite")
    _, bob = engine.system_prompt_for(gate, "bob")
    assert rows_of(bob)["trainings"] == "rows limited by your profile"
    # neither the unknown attribute's value nor its NAME reaches the prompt
    assert "cc-zz-9" not in bob
    assert "cost_center" not in bob and "cost" not in bob
    _, dave = engine.system_prompt_for(gate, "dave")
    assert rows_of(dave)["invoices"] == "a fixed subset"
    assert "unpaid" not in dave and "status =" not in dave


@pytest.mark.parametrize("name", ["is_executive", "clearance_level", "cohort",
                                  "region", "x"])
def test_unknown_attribute_names_never_reach_the_prompt(demo_dir, name):
    write_policy(demo_dir,
                 f"p2, hr_staff, trainings, title = '{{{name}}}'",
                 f"p2, employee, payroll, employee_id = {{{name}}}")
    edit_attrs(demo_dir, bob={name: "4"}, carol={name: "4"},
               alice={name: "4"}, dave={name: "4"})
    gate = make_gate(demo_dir, "sqlite")
    for username in WORKERS:
        _, prompt = engine.system_prompt_for(gate, username)
        assert not re.search(rf"\b{name}\b", prompt), (username, name)
        assert "rows limited by your profile" in rows_of(prompt)["payroll"]
    _, bob = engine.system_prompt_for(gate, "bob")
    assert rows_of(bob)["trainings"] == "rows limited by your profile"
    assert rows_of(bob)["payroll"] == (
        "your own records or rows limited by your profile")


def test_user_level_rows_are_described_per_column(demo_dir):
    # a personal grant with its own row scope: bob reads employees.salary
    # for his own row only, the other columns for his department
    write_policy(demo_dir, "p, user:bob, employees.salary, read",
                 "p2, user:bob, employees, id = '{employee_id}'")
    gate = make_gate(demo_dir, "sqlite")
    _, prompt = engine.system_prompt_for(gate, "bob")
    assert rows_of(prompt)["employees"] == (
        "your department (for id, name, dept, start_date); "
        "your own records (for salary)")


def test_personal_grant_without_row_filters_reads_all_rows(demo_dir):
    # dave's personal grant on a table no role of his filters: every row
    write_policy(demo_dir, "p, user:dave, trainings.title, read")
    gate = make_gate(demo_dir, "sqlite")
    _, prompt = engine.system_prompt_for(gate, "dave")
    assert rows_of(prompt)["trainings"] == "all rows"
    assert gate.snapshot.row_limits("dave", "trainings", ["title"]) == ()
    assert gate.snapshot.row_limits("dave", "trainings", ["dept"]) is None


@pytest.mark.parametrize("name, phrase", [
    ("employee_id", "your own records"),
    ("self_and_subordinate_ids", "you and your team"),
    ("subordinate_ids", "your team"),
    ("team_ids", "your team"),
    ("dept", "your department"),
    ("department", "your department"),
    ("home_dept", "your department"),
    ("site", "your site"),
    ("warehouse_id", "your site"),
    ("cost_center", "rows limited by your profile"),
    ("region", "rows limited by your profile"),
    ("is_executive", "rows limited by your profile"),
])
def test_attribute_phrases(name, phrase):
    assert engine.attribute_phrase(name) == phrase


@pytest.mark.parametrize("template, phrase", [
    ("dept = '{dept}'", "your department"),
    ("name = 'x'", "a fixed subset"),
    ("dept = '{dept}' AND name = '{site}'",
     "your department and your site"),
    ("dept = '{dept}' OR name = '{site}'",
     "your department or your site"),
    ("(dept = '{dept}' OR name = '{site}') AND id = {employee_id}",
     "a combination of your department and your site and your own records"),
    ("dept = '{dept}' AND name = '{region}'",
     "your department and rows limited by your profile"),
    ("name = '{region}' OR name = '{cohort}'", "rows limited by your profile"),
    ("dept = '{dept}' OR dept = '{home_dept}'", "your department"),
])
def test_filter_phrases(demo_dir, template, phrase):
    from rbic.gate import compile_row_filter
    schema = json.loads((demo_dir / "db_schema.json").read_text(encoding="utf-8"))
    for dialect in DIALECTS:
        rf = compile_row_filter("employees", template, schema, dialect=dialect)
        assert engine.row_limit_phrase((rf,)) == phrase
        assert engine.row_limit_phrase((rf, rf)) == phrase  # deduplicated
    assert engine.row_limit_phrase(()) == "all rows"
    assert engine.row_limit_phrase(None) is None


def test_no_rows_lines_or_rule_without_tables():
    prompt = engine.build_system_prompt(None, {}, {})
    assert "rows:" not in prompt and ROWS_RULE not in prompt
    # callers that pass no row descriptions get the old table lines
    prompt = engine.build_system_prompt("x", {"t": ["a"]}, {"t": [["a"]]})
    assert "- t(a)\n" in prompt and "rows:" not in prompt


def test_rows_come_from_the_given_snapshot(demo_dir):
    gate = make_gate(demo_dir, "sqlite")
    snap = gate.refreshed_snapshot()
    write_policy(demo_dir, "p2, hr_staff, trainings, dept = '{dept}'")
    _, old = engine.system_prompt_for(gate, "bob", snap)
    assert rows_of(old)["trainings"] == "all rows"
    _, new = engine.system_prompt_for(gate, "bob")
    assert rows_of(new)["trainings"] == "your department"
