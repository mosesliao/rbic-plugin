"""Acceptance: rbic-init reproduces the demo's hand-written policy.

The demo catalog is approved (every name-rule suggestion), roles.json is
built from the starter packs plus a few human edits (base roles inherit
`employee`; three pack scopes the shipped demo doesn't have are removed),
and policy.csv is replaced by ONLY the manual master-chatbot section
before compiling. The gate must then decide exactly as with the shipped
policy: the 15 gate-demo queries, every column/star/COUNT(*) query for
every user (decisions AND rows), and the salary-policy evolution.

Intentional differences (documented in CLAUDE.md):
- grants are named columns, never `table.*` (same columns for this schema);
- there is no `payroll_manager` role: hr_manager holds pay plus the team
  row filter itself (hr pack), and `employee` reads payroll through a
  scoped grant (staff_self_service pack) instead of p payroll.* + p2. The
  rows are identical; only the OR order of carol's payroll filter differs
  in the rewritten SQL.
- with the packs' defaults (no human edits) trainings, budgets and
  safety_incidents get row scopes the shipped demo lacks: stricter.
"""

import json
import logging
import shutil
import sqlite3

import pytest

from onboarding_demo import (DEMO_UNSCOPED, MANUAL_POLICY, build_roles,
                             compile_and_apply, config, load_state,
                             onboard_demo, save, approve_catalog)
from rbic.cli import gate_demo
from rbic.cli.gate_demo import DEMO_QUERIES
from rbic.gate import AccessDenied, SQLGate
from rbic.onboarding.block import BEGIN_MARKER, END_MARKER, find_block
from rbic.onboarding.roles import RowScope, add_scope, remove_scope, set_role

logging.disable(logging.CRITICAL)

PAYSLIP_Q = "SELECT employee_id, salary FROM payroll ORDER BY employee_id"


@pytest.fixture
def shipped(tmp_path_factory, demo_template):
    d = tmp_path_factory.mktemp("shipped")
    shutil.copytree(demo_template, d, dirs_exist_ok=True)
    return d


@pytest.fixture
def onboarded(demo_dir):
    onboard_demo(demo_dir)
    return demo_dir


def gate(d):
    return SQLGate.from_config(config(d))


def decide(g, d, user, sql):
    """(rewritten SQL or None, sorted rows or None)."""
    try:
        safe = g.authorize(user, sql)
    except AccessDenied:
        return None, None
    conn = sqlite3.connect(f"file:{d / 'company.db'}?mode=ro", uri=True)
    try:
        return safe, sorted(conn.execute(safe).fetchall(), key=repr)
    finally:
        conn.close()


def all_queries(d):
    schema = json.loads((d / "db_schema.json").read_text(encoding="utf-8"))
    users = json.loads((d / "worker_attributes.json").read_text(encoding="utf-8"))
    out = list(DEMO_QUERIES) + [(u, PAYSLIP_Q) for u in users]
    for user in users:
        for table, cols in schema.items():
            out += [(user, f"SELECT * FROM {table}"),
                    (user, f"SELECT COUNT(*) FROM {table}")]
            out += [(user, f"SELECT {c} FROM {table}") for c in cols]
    return out


# ---- the generated policy file --------------------------------------------------

def test_policy_is_generated_block_plus_manual_section(onboarded):
    text = (onboarded / "casbin" / "policy.csv").read_text(encoding="utf-8")
    begin, end = find_block(text)
    lines = text.split("\n")
    assert lines[begin] == BEGIN_MARKER and lines[end] == END_MARKER
    # outside the block: exactly the manual file, byte for byte
    assert "\n".join(lines[:begin] + lines[end + 1:]) == MANUAL_POLICY
    rules = [l for l in lines[begin:end] if l and not l.startswith("#")]
    assert not any(".*" in l for l in rules), "never table.* grants"
    assert "g, hr_manager, hr_staff" in rules
    assert "p, hr_staff, employees.dept, read" in rules
    assert "p, hr_staff, employees.salary, read" not in rules
    assert ("p2, employee, payroll, employee_id = '{employee_id}', "
            "id|employee_id|salary|effective_date") in rules


# ---- decisions match the shipped hand-written policy -----------------------------

def test_gate_demo_queries_match_shipped_policy(onboarded, shipped):
    new, old = gate(onboarded), gate(shipped)
    allowed = 0
    for user, sql in DEMO_QUERIES:
        a = decide(old, shipped, user, sql)
        b = decide(new, onboarded, user, sql)
        assert (a[0] is None) == (b[0] is None), (user, sql)
        assert a[1] == b[1], (user, sql)
        allowed += b[0] is not None
    assert (allowed, len(DEMO_QUERIES) - allowed) == (6, 9)


def test_every_user_column_and_table_matches_shipped_policy(onboarded, shipped):
    new, old = gate(onboarded), gate(shipped)
    text_differs = set()
    queries = all_queries(shipped)
    assert len(queries) > 300
    for user, sql in queries:
        a = decide(old, shipped, user, sql)
        b = decide(new, onboarded, user, sql)
        assert (a[0] is None) == (b[0] is None), (user, sql, a[0], b[0])
        assert a[1] == b[1], (user, sql)
        if a[0] != b[0]:
            text_differs.add((user, sql))
    # Only the OR order of carol's payroll filter (self OR team) differs.
    assert text_differs and all(u == "carol" and "payroll" in q
                                for u, q in text_differs)


def test_gate_demo_cli_on_generated_policy(onboarded, capsys):
    gate_demo.main(["--config-dir", str(onboarded)])
    out = capsys.readouterr().out
    assert out.count("-> ALLOW:") == 6 and out.count("-> DENY (") == 9


# ---- salary-policy evolution (tests/test_salary_policy_evolution.py) -------------

def test_stage2_scenarios_on_generated_policy(onboarded):
    g = gate(onboarded)
    assert decide(g, onboarded, "carol", PAYSLIP_Q)[1] == [
        (1, 78000), (2, 112000), (3, 65000)]
    assert decide(g, onboarded, "bob", PAYSLIP_Q)[1] == [(1, 78000)]
    assert decide(g, onboarded, "alice", PAYSLIP_Q)[1] == [(6, 42000)]
    assert decide(g, onboarded, "dave", PAYSLIP_Q)[1] == [(7, 52000)]
    with pytest.raises(AccessDenied):
        g.authorize("bob", "SELECT name, salary FROM employees")
    assert decide(g, onboarded, "bob", "SELECT name FROM employees")[1] == [
        ("Bob Tan",), ("Carol Lim",), ("Erin Ng",)]


def test_missing_scope_attribute_fails_closed(onboarded):
    path = onboarded / "worker_attributes.json"
    attrs = json.loads(path.read_text(encoding="utf-8"))
    attrs["mallory"] = {"role": "hr_manager", "dept": "engineering",
                        "employee_id": 99}
    path.write_text(json.dumps(attrs), encoding="utf-8")
    g = gate(onboarded)
    assert g.broken is None
    with pytest.raises(AccessDenied):
        g.authorize("mallory", PAYSLIP_Q)


def test_salary_policy_evolution_by_recompiling(demo_dir):
    """Stage 0 -> 1 -> 2 as roles.json edits + rbic-init compile."""
    policy = demo_dir / "casbin" / "policy.csv"
    approve_catalog(demo_dir)
    policy.write_text(MANUAL_POLICY, encoding="utf-8", newline="")
    # stage 0: HR/finance/warehouse packs, no self-service, no manager pay
    build_roles(demo_dir, packs=("hr", "finance", "warehouse"))
    schema, catalog, users, roles, sha = load_state(demo_dir)
    team = RowScope("payroll", "employee_id IN ({self_and_subordinate_ids})")
    roles, _ = set_role(roles, "hr_manager", categories=[])
    roles, _ = remove_scope(roles, "hr_manager", team)
    save(demo_dir, roles, sha)
    compile_and_apply(demo_dir)
    for user in ("alice", "bob", "carol", "dave"):
        with pytest.raises(AccessDenied):
            gate(demo_dir).authorize(user, PAYSLIP_Q)
    # stage 1: every base role inherits the self-service role
    build_roles(demo_dir, packs=("staff_self_service",), demo_exact=False)
    compile_and_apply(demo_dir)
    g = gate(demo_dir)
    assert decide(g, demo_dir, "bob", PAYSLIP_Q)[1] == [(1, 78000)]
    assert decide(g, demo_dir, "carol", PAYSLIP_Q)[1] == [(2, 112000)]
    # stage 2: managers additionally see their team
    schema, catalog, users, roles, sha = load_state(demo_dir)
    roles, _ = set_role(roles, "hr_manager", categories=["pay"])
    roles, _ = add_scope(roles, "hr_manager", team)
    save(demo_dir, roles, sha)
    compile_and_apply(demo_dir)
    g = gate(demo_dir)
    assert [r[0] for r in decide(g, demo_dir, "carol", PAYSLIP_Q)[1]] == [1, 2, 3]
    assert decide(g, demo_dir, "bob", PAYSLIP_Q)[1] == [(1, 78000)]
    # the manual section survived three recompiles byte for byte
    assert policy.read_text(encoding="utf-8").endswith(
        MANUAL_POLICY.split("\n\n", 1)[1])


# ---- pack defaults: stricter than the shipped demo ------------------------------

def test_pack_defaults_scope_more_tables_than_the_demo(demo_dir, shipped):
    onboard_demo(demo_dir, demo_exact=False)
    new, old = gate(demo_dir), gate(shipped)
    stricter = {"alice": "SELECT * FROM safety_incidents",
                "bob": "SELECT * FROM trainings",
                "dave": "SELECT * FROM budgets"}
    for user, sql in stricter.items():
        a, b = decide(old, shipped, user, sql), decide(new, demo_dir, user, sql)
        assert b[0] is not None and set(b[1]) < set(a[1]), (user, sql)
    assert len(DEMO_UNSCOPED) == len(stricter)
    for user, sql in DEMO_QUERIES:
        a, b = decide(old, shipped, user, sql), decide(new, demo_dir, user, sql)
        assert (a[0] is None) == (b[0] is None) and a[1] == b[1], (user, sql)
