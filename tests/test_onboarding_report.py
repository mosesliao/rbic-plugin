"""rbic.onboarding.report: built from the gate's snapshot (manual rules
included), plain-language rows, denies, hidden columns, warnings - and
never an email or any data/attribute value."""

import json
import sqlite3

import pytest

from onboarding_demo import config, onboard_demo
from rbic.config import resolve_config
from rbic.gate import SQLGate
from rbic.onboarding import catalog_path
from rbic.onboarding.catalog import load_catalog
from rbic.onboarding.report import access_report, plain_filter, report_from_bytes


def report(d, catalog=True):
    cfg = config(d)
    cat = None
    if catalog and catalog_path(d).exists():
        cat = load_catalog(catalog_path(d))[0]
    read = lambda p: p.read_bytes()  # noqa: E731
    return report_from_bytes(read(cfg.model_path), read(cfg.policy_path),
                             read(cfg.attributes_path), read(cfg.schema_path),
                             cat)


def section(text, role):
    start = text.index(f"### Role `{role}`")
    end = text.find("\n### ", start + 1)
    end = text.find("\n## ", start) if end == -1 else end
    return text[start:end]


@pytest.fixture
def onboarded(demo_dir):
    onboard_demo(demo_dir)
    return demo_dir


def test_plain_filter():
    assert plain_filter("dept = '{dept}'") == "dept = the user's dept"
    assert plain_filter("employee_id IN ({ids})") == \
        "employee_id IN (the user's ids)"
    assert plain_filter("status = 'open'") == "status = 'open'"


def test_report_on_the_onboarded_demo(onboarded):
    text = report(onboarded)
    hr = section(text, "hr_staff")
    assert "- Inherits: employee" in hr and "- Users: bob" in hr
    assert ("| employees | id (directory, low), name (directory, low), dept "
            "(directory, low), start_date (directory, low) | rows where dept "
            "= the user's dept |") in hr
    assert ("effective_date (pay, high) [scoped grant: only these columns] | "
            "rows where employee_id = the user's employee_id |") in hr  # own pay
    assert "| trainings |" in hr and "**ALL rows**" in hr
    mgr = section(text, "hr_manager")
    assert "rows where employee_id IN (the user's self_and_subordinate_ids)" in mgr
    # the manual master-bot rule shows up (warehouse_worker's scoped grant)
    ww = section(text, "warehouse_worker")
    assert "| employees | id (directory, low), name (directory, low), salary " \
           "(pay, high) [scoped grant: only these columns] | rows where id = " \
           "the user's employee_id |" in ww
    assert "## Hidden columns" in text
    assert "role hr_staff reads trainings on ALL rows" in text


def test_report_never_contains_emails_or_values(onboarded):
    text = report(onboarded)
    attrs = json.loads((onboarded / "worker_attributes.json").read_text(
        encoding="utf-8"))
    assert "@" not in text
    values = {v for r in attrs.values() for k, v in r.items()
              if k != "role" and isinstance(v, str)}
    assert {"SG-01", "engineering", "1, 2, 3"} <= values
    # (dave's dept "logistics" is also a category name, so it is skipped)
    for value in values - {"logistics"}:
        assert value not in text, value
    conn = sqlite3.connect(onboarded / "company.db")
    names = [r[0] for r in conn.execute("SELECT name FROM employees")]
    salaries = [str(r[0]) for r in conn.execute("SELECT salary FROM payroll")]
    conn.close()
    assert not any(v in text for v in names + salaries)


def test_report_follows_the_gate_not_the_sources(onboarded):
    """A p3 deny and a personal rule in the manual section are reported."""
    policy = onboarded / "casbin" / "policy.csv"
    policy.write_text(policy.read_text(encoding="utf-8")
                      + "p3, hr_staff, employees.dept, read\n"
                      + "p, user:bob, invoices.vendor, read\n"
                      + "p, finance_analyst, inventory.*, read\n",
                      encoding="utf-8")
    text = report(onboarded)
    hr = section(text, "hr_staff")
    assert "- column employees.dept denied (rule held by hr_staff)" in hr
    row = next(l for l in hr.splitlines() if l.startswith("| employees |"))
    assert "dept (" not in row
    # inherited by hr_manager too
    assert "employees.dept denied (rule held by hr_staff)" in \
        section(text, "hr_manager")
    assert "- **bob** (role hr_staff):" in text
    # invoices has no row filter at bob's role level: the personal grant
    # sees every row, and the report says so
    assert "personal grant invoices.vendor: **ALL rows**" in text
    # a wildcard grant made by hand reads everything the gate lets it read
    fin = section(text, "finance_analyst")
    assert "| inventory | id (inventory, low), sku" in fin


def test_hidden_and_unapproved_columns(demo_dir):
    onboard_demo(demo_dir)
    path = catalog_path(demo_dir)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["columns"]["trainings.title"]["status"] = "rejected"
    path.write_text(json.dumps(raw), encoding="utf-8")
    text = report(demo_dir)
    # still granted (policy not recompiled): readable but not approved
    assert "trainings.title is readable but not approved in catalog.json" in text
    assert "title (NOT APPROVED: rejected)" in text
    # nobody reads employees.salary once its p grant is removed
    policy = demo_dir / "casbin" / "policy.csv"
    policy.write_text(policy.read_text(encoding="utf-8").replace(
        "p, hr_manager, employees.salary, read\n", "").replace(
        ", id|name|salary\n", ", id|name\n"), encoding="utf-8")
    hidden = report(demo_dir).split("## Hidden columns", 1)[1]
    assert "- employees.salary (approved, pay)" in hidden


def test_missing_attribute_warning_names_no_value(onboarded):
    path = onboarded / "worker_attributes.json"
    attrs = json.loads(path.read_text(encoding="utf-8"))
    del attrs["carol"]["self_and_subordinate_ids"]
    path.write_text(json.dumps(attrs), encoding="utf-8")
    text = report(onboarded)
    assert ("user carol lacks attribute(s) self_and_subordinate_ids: queries "
            "covered by rules needing them are denied") in text


def test_report_on_the_shipped_hand_written_policy(demo_dir):
    text = report(demo_dir, catalog=False)
    assert "### Role `payroll_manager`" in text
    assert "| inventory | id, sku, qty, warehouse_id | rows where " \
           "warehouse_id = the user's site |" in text
    # the same report from the live gate's own snapshot
    gate = SQLGate.from_config(resolve_config(demo_dir, dialect="sqlite"))
    assert access_report(gate.snapshot) == text
