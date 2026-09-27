"""The master's salary-policy evolution, as a test suite.

Stage 0  stringent  — nobody can read payroll through the bot (fail closed)
Stage 1  self-serve — workers may read their OWN payslip
Stage 2  managers   — hr_manager additionally sees subordinates' payslips

Stages 0 and 1 are derived from the shipped casbin/policy.csv by removing
the payroll policy blocks — proving the progression is pure policy-file
edits with zero code changes. Run: pytest -q
"""

import logging
import sqlite3
from pathlib import Path

import pytest

import seed_db
from sql_gate import AccessDenied, SQLGate

logging.disable(logging.CRITICAL)

ROOT = Path(__file__).parent
POLICY_LINES = (ROOT / "casbin" / "policy.csv").read_text().splitlines(keepends=True)

PAYSLIP_Q = "SELECT employee_id, salary FROM payroll ORDER BY employee_id"


@pytest.fixture(scope="session", autouse=True)
def seeded_db():
    seed_db.main()


def make_gate(tmp_path, exclude=()):
    """Gate with the shipped policy minus lines containing any exclude token."""
    lines = [l for l in POLICY_LINES if not any(tok in l for tok in exclude)]
    policy = tmp_path / "policy.csv"
    policy.write_text("".join(lines))
    return SQLGate(
        model_path=str(ROOT / "casbin" / "model.conf"),
        policy_path=str(policy),
        schema_path=str(ROOT / "db_schema.json"),
        attributes_path=str(ROOT / "worker_attributes.json"),
        dialect="sqlite",
    )


def rows(gate, username, sql):
    safe_sql = gate.authorize(username, sql)
    conn = sqlite3.connect(f"file:{ROOT / 'company.db'}?mode=ro", uri=True)
    try:
        return conn.execute(safe_sql).fetchall()
    finally:
        conn.close()


# ---- stage 0: stringent -------------------------------------------------

def test_stage0_nobody_reads_payroll(tmp_path):
    gate = make_gate(tmp_path, exclude=("payroll",))
    for user in ("alice", "bob", "carol", "dave"):
        with pytest.raises(AccessDenied):
            gate.authorize(user, PAYSLIP_Q)


# ---- stage 1: workers see their own payslip ------------------------------

def test_stage1_worker_sees_only_own_salary(tmp_path):
    gate = make_gate(tmp_path, exclude=("payroll_manager",))
    assert rows(gate, "bob", PAYSLIP_Q) == [(1, 78000)]
    assert rows(gate, "alice", PAYSLIP_Q) == [(6, 42000)]
    assert rows(gate, "dave", PAYSLIP_Q) == [(7, 52000)]


def test_stage1_manager_not_yet_widened(tmp_path):
    gate = make_gate(tmp_path, exclude=("payroll_manager",))
    assert rows(gate, "carol", PAYSLIP_Q) == [(2, 112000)]


# ---- stage 2: managers see self + subordinates ---------------------------

def test_stage2_manager_sees_team(tmp_path):
    gate = make_gate(tmp_path)  # full shipped policy
    assert rows(gate, "carol", PAYSLIP_Q) == [
        (1, 78000),   # Bob Tan (subordinate)
        (2, 112000),  # Carol Lim (self)
        (3, 65000),   # Erin Ng (subordinate)
    ]


def test_stage2_worker_scope_unchanged(tmp_path):
    gate = make_gate(tmp_path)
    assert rows(gate, "bob", PAYSLIP_Q) == [(1, 78000)]
    assert rows(gate, "alice", PAYSLIP_Q) == [(6, 42000)]


# ---- invariants that must survive the policy evolution -------------------

def test_employees_salary_column_still_denied_to_hr_staff(tmp_path):
    gate = make_gate(tmp_path)
    with pytest.raises(AccessDenied):
        gate.authorize("bob", "SELECT name, salary FROM employees")


def test_dept_filter_not_weakened_by_scope_union(tmp_path):
    # OR-union applies to same-table scopes only; single-scope tables
    # keep their filter — bob still sees engineering employees only.
    gate = make_gate(tmp_path)
    names = rows(gate, "bob", "SELECT name FROM employees ORDER BY id")
    assert names == [("Bob Tan",), ("Carol Lim",), ("Erin Ng",)]


def test_missing_scope_attribute_fails_closed(tmp_path):
    # A manager without self_and_subordinate_ids must be denied outright,
    # not silently narrowed to a scope that happens to render.
    gate = make_gate(tmp_path)
    gate.attributes["mallory"] = {"role": "hr_manager", "dept": "engineering",
                                  "employee_id": 99}
    with pytest.raises(AccessDenied):
        gate.authorize("mallory", PAYSLIP_Q)
