"""The worker system prompt tells the model that results are already
row-limited (so it never self-identifies the user or adds its own
name/dept filters), and the case-insensitive comparison it recommends
passes the gate with the row filter still ANDed in.

Live regression: carol (hr_manager) asked for her team's salaries; the
model added `WHERE dept = 'Engineering'` (stored values are lowercase,
SQLite `=` is case-sensitive) and got 0 rows.

Every test works on tmp_path copies; the repo's files are never touched.
"""

import json
import logging
import re
import sqlite3

import pytest

from rbic import engine
from rbic.gate import SQLGate

logging.disable(logging.CRITICAL)

DIALECTS = ("postgres", "sqlite")
WORKERS = ("alice", "bob", "carol", "dave")

ROW_RULES = (
    "Every query result is already limited to the rows this user may see",
    "Do NOT add filters on the user's name, id, email, department\n"
    "  or team, and never ask the user who they are or for their id.",
    "you are not told which row is the user's\n  own.",
    "never use LIMIT, ORDER BY or\n  a guess to pick one row",
    "Choose the table whose columns answer the question.",
    "a payroll-style table, if one is listed",
    "LOWER(col) = LOWER('value')",
    "say that nothing was found in the data this\n  user can access",
    "do not tell the user to contact\n  HR or an administrator",
)
KEPT_RULES = (
    "- Emit a single SQLite SELECT per tool call. No other statement types.",
    "- Only reference the tables and columns listed above.",
    "- After getting rows back, answer concisely in plain language.",
)


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


@pytest.mark.parametrize("username", WORKERS)
def test_prompt_has_no_filters_attributes_or_emails(sgate, demo_dir, username):
    _, prompt = engine.system_prompt_for(sgate, username)
    attrs = json.loads(
        (demo_dir / "worker_attributes.json").read_text(encoding="utf-8"))
    assert "@" not in prompt
    # no attribute value of ANY worker (dept, site, ids, team list)
    for record in attrs.values():
        for key, value in record.items():
            if key == "role":
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
