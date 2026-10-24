"""The master's salary-policy evolution, as a test suite.

Stage 0  stringent  — nobody can read payroll through the bot (fail closed)
Stage 1  self-serve — workers may read their OWN payslip
Stage 2  managers   — hr_manager additionally sees subordinates' payslips

Stages 0 and 1 are derived from the demo casbin/policy.csv by removing
the payroll policy blocks — proving the progression is pure policy-file
edits with zero code changes. Run: pytest -q
"""

import logging
import sqlite3

import pytest

from rbic.gate import AccessDenied, SQLGate

logging.disable(logging.CRITICAL)

PAYSLIP_Q = "SELECT employee_id, salary FROM payroll ORDER BY employee_id"


@pytest.fixture
def make_gate(demo_dir):
    """Gate with the demo policy minus lines containing any exclude token."""
    policy = demo_dir / "casbin" / "policy.csv"
    policy_lines = policy.read_text().splitlines(keepends=True)

    def make(exclude=()):
        lines = [l for l in policy_lines if not any(tok in l for tok in exclude)]
        policy.write_text("".join(lines))
        return SQLGate(
            model_path=str(demo_dir / "casbin" / "model.conf"),
            policy_path=str(policy),
            schema_path=str(demo_dir / "db_schema.json"),
            attributes_path=str(demo_dir / "worker_attributes.json"),
            dialect="sqlite",
        )
    return make


@pytest.fixture
def rows(demo_dir):
    def run(gate, username, sql):
        safe_sql = gate.authorize(username, sql)
        conn = sqlite3.connect(f"file:{demo_dir / 'company.db'}?mode=ro", uri=True)
        try:
            return conn.execute(safe_sql).fetchall()
        finally:
            conn.close()
    return run


# ---- stage 0: stringent -------------------------------------------------

def test_stage0_nobody_reads_payroll(make_gate):
    gate = make_gate(exclude=("payroll",))
    for user in ("alice", "bob", "carol", "dave"):
        with pytest.raises(AccessDenied):
            gate.authorize(user, PAYSLIP_Q)


# ---- stage 1: workers see their own payslip ------------------------------

def test_stage1_worker_sees_only_own_salary(make_gate, rows):
    gate = make_gate(exclude=("payroll_manager",))
    assert rows(gate, "bob", PAYSLIP_Q) == [(1, 78000)]
    assert rows(gate, "alice", PAYSLIP_Q) == [(6, 42000)]
    assert rows(gate, "dave", PAYSLIP_Q) == [(7, 52000)]


def test_stage1_manager_not_yet_widened(make_gate, rows):
    gate = make_gate(exclude=("payroll_manager",))
    assert rows(gate, "carol", PAYSLIP_Q) == [(2, 112000)]


# ---- stage 2: managers see self + subordinates ---------------------------

def test_stage2_manager_sees_team(make_gate, rows):
    gate = make_gate()  # full demo policy
    assert rows(gate, "carol", PAYSLIP_Q) == [
        (1, 78000),   # Bob Tan (subordinate)
        (2, 112000),  # Carol Lim (self)
        (3, 65000),   # Erin Ng (subordinate)
    ]


def test_stage2_worker_scope_unchanged(make_gate, rows):
    gate = make_gate()
    assert rows(gate, "bob", PAYSLIP_Q) == [(1, 78000)]
    assert rows(gate, "alice", PAYSLIP_Q) == [(6, 42000)]


# ---- invariants that must survive the policy evolution -------------------

def test_employees_salary_column_still_denied_to_hr_staff(make_gate):
    gate = make_gate()
    with pytest.raises(AccessDenied):
        gate.authorize("bob", "SELECT name, salary FROM employees")


def test_dept_filter_not_weakened_by_scope_union(make_gate, rows):
    # OR-union applies to same-table scopes only; single-scope tables
    # keep their filter — bob still sees engineering employees only.
    gate = make_gate()
    names = rows(gate, "bob", "SELECT name FROM employees ORDER BY id")
    assert names == [("Bob Tan",), ("Carol Lim",), ("Erin Ng",)]


def test_missing_scope_attribute_fails_closed(make_gate):
    # A manager without self_and_subordinate_ids must be denied outright,
    # not silently narrowed to a scope that happens to render.
    gate = make_gate()
    gate.attributes["mallory"] = {"role": "hr_manager", "dept": "engineering",
                                  "employee_id": 99}
    with pytest.raises(AccessDenied):
        gate.authorize("mallory", PAYSLIP_Q)
