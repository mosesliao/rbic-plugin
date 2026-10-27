"""rbic-init drift (rbic.onboarding.drift) and the step-3 hardening: the
generated block's sources header and block_state (out of date / edited /
undone), `rbic-init status`, the all-rows acknowledgement end to end
(roles all-rows, compile refusal, block comment, access report), the
undo note, exit codes 0/1/2 and --json, no emails or values printed."""

import json
import logging
import sqlite3

import pytest

from onboarding_demo import (admin, compile_and_apply, compile_change, config,
                             load_state, onboard_demo, save)
from rbic.admin import SOURCES_NOT_REVERTED
from rbic.onboarding import catalog_path, roles_path
from rbic.onboarding.block import END_MARKER
from rbic.gate import STATIC_FILTER_WARNING
from rbic.onboarding.compile import (HEADER_PREFIX, CompileError,
                                     acknowledgements, block_header,
                                     compile_from_files)
from rbic.onboarding.drift import block_state, check_drift
from rbic.onboarding.report import report_from_bytes
from rbic.onboarding.roles import (RowScope, add_scope, remove_all_rows,
                                   remove_scope, set_all_rows, set_role)
from test_cli_init import audit_lines, run

logging.disable(logging.CRITICAL)
REASON = "auditors reconcile every payslip"


@pytest.fixture
def onboarded(demo_dir):
    onboard_demo(demo_dir)
    return demo_dir


def drift(d, *extra):
    try:
        code, out = run(["drift", "--config-dir", str(d), *extra])
    except SystemExit as exc:  # argparse errors
        return exc.code, []
    return code, out


def findings(report, name):
    return next(c for c in report.checks if c.name == name)


def policy_text(d):
    with open(d / "casbin" / "policy.csv", encoding="utf-8", newline="") as f:
        return f.read()


def write_policy(d, text):
    with open(d / "casbin" / "policy.csv", "w", encoding="utf-8",
              newline="") as f:
        f.write(text)


# ---- exit codes ------------------------------------------------------------------

def test_shipped_demo_is_clean(demo_dir):
    report = check_drift(config(demo_dir))
    assert report.status == "clean" and report.exit_code == 0
    assert findings(report, "catalog").status == "skipped"
    assert findings(report, "generated_block").status == "skipped"
    code, out = drift(demo_dir)
    assert code == 0 and out[-1] == "Result: clean (exit 0)"


def test_onboarded_demo_is_clean(onboarded):
    report = check_drift(config(onboarded))
    assert report.status == "clean", report.lines()
    assert "generated block matches its sources" in \
        findings(report, "generated_block").info


def test_schema_drift_exit_1_and_json(onboarded):
    conn = sqlite3.connect(onboarded / "company.db")
    conn.execute("ALTER TABLE inventory ADD COLUMN bin TEXT")
    conn.commit()
    conn.close()
    code, out = drift(onboarded, "--json")
    assert code == 1
    data = json.loads(out[0])
    assert data["status"] == "drift" and data["exit_code"] == 1
    schema = next(c for c in data["checks"] if c["name"] == "schema")
    assert schema["status"] == "drift"
    assert "db_schema.json vs database: inventory: new column(s) bin" in \
        schema["findings"]


def test_missing_database_exit_2(onboarded):
    code, out = drift(onboarded, "--db", str(onboarded / "nope.db"))
    assert code == 2
    assert out[-1] == "Result: error (exit 2)"
    code, out = drift(onboarded, "--db", str(onboarded / "nope.db"), "--json")
    assert code == 2 and json.loads(out[0])["status"] == "error"


def test_unexpected_failure_exit_2(onboarded, monkeypatch):
    from rbic.cli import init as init_cli

    def boom(*a, **k):
        raise RuntimeError("x")
    monkeypatch.setattr(init_cli, "check_drift", boom)
    code, out = drift(onboarded)
    assert code == 2 and out[0].startswith("Error: drift check failed")


# ---- catalog / roles / workers ---------------------------------------------------------

def test_catalog_coverage(onboarded):
    path = catalog_path(onboarded)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["columns"]["inventory.ghost"] = dict(raw["columns"]["inventory.sku"])
    entry = raw["columns"]["inventory.qty"]
    raw["columns"]["inventory.qty"] = {"category": entry["category"],
                                       "status": "suggested",
                                       "suggested_by": "human", "evidence": ""}
    raw["columns"]["shipments.eta"].update(status="rejected")
    del raw["columns"]["shipments.status"]
    path.write_text(json.dumps(raw), encoding="utf-8")
    c = findings(check_drift(config(onboarded)), "catalog")
    assert c.status == "drift"
    text = "\n".join(c.findings)
    assert "inventory.ghost: catalog entry for a column that no longer exists" \
        in text
    assert "inventory.qty: suggested (inventory), not approved - hidden" in text
    assert "shipments.status: unlabelled - hidden from everyone" in text
    assert "shipments.eta" not in text
    assert "rejected (hidden from everyone by decision): shipments.eta" in c.info


def test_roles_referencing_missing_things(onboarded):
    path = roles_path(onboarded)
    raw = json.loads(path.read_text(encoding="utf-8"))
    role = raw["roles"]["hr_staff"]
    role["categories"].append("nope")
    role["row_scopes"].append({"table": "ghost", "template": "id = 1"})
    role["row_scopes"].append({"table": "employees",
                               "template": "gone = '{dept}'"})
    role["row_scopes"].append({"table": "employees", "template": "id = 1",
                               "columns": ["id", "gone"]})
    role["all_rows"] = [{"table": "ghost", "reason": "why"}]
    role["inherits"].append("phantom")
    path.write_text(json.dumps(raw), encoding="utf-8")
    c = findings(check_drift(config(onboarded)), "roles")
    text = "\n".join(c.findings)
    assert "role hr_staff: category nope is not in catalog.json" in text
    assert "row scope on missing table ghost" in text
    assert "row scope on employees no longer compiles" in text
    assert "scoped grant names missing column employees.gone" in text
    assert "all-rows acknowledgement for missing table ghost" in text
    assert "inherits phantom, which roles.json does not define" in text


def test_workers_without_roles_and_roles_without_workers(demo_dir):
    attrs = json.loads((demo_dir / "worker_attributes.json").read_text(
        encoding="utf-8"))
    attrs["zed"] = {"email": "zed@example.test", "dept": "x"}
    attrs["yan"] = {"role": "ghost_role"}
    (demo_dir / "worker_attributes.json").write_text(json.dumps(attrs),
                                                     encoding="utf-8")
    write_policy(demo_dir, policy_text(demo_dir)
                 + "p, lonely, employees.name, read\n")
    report = check_drift(config(demo_dir))
    c = findings(report, "workers")
    assert c.findings == [
        "worker yan has role ghost_role, which no policy rule mentions (no "
        "data access)",
        "worker zed has no role (denied everything)",
        "role lonely has no workers (directly, by inheritance or as an extra "
        "role)"]
    code, out = drift(demo_dir)
    assert code == 1
    assert "zed@example.test" not in "\n".join(out)


def test_broken_policy_is_critical(demo_dir):
    write_policy(demo_dir, policy_text(demo_dir) + "p9, x, y, z\n")
    c = findings(check_drift(config(demo_dir)), "workers")
    assert c.findings[0].startswith("CRITICAL: the policy does not load")


def test_drift_never_prints_emails_or_values(onboarded):
    attrs = json.loads((onboarded / "worker_attributes.json").read_text(
        encoding="utf-8"))
    attrs["zed"] = {"email": "zed@example.test", "dept": "secret-dept"}
    (onboarded / "worker_attributes.json").write_text(json.dumps(attrs),
                                                      encoding="utf-8")
    for extra in ((), ("--json",)):
        _, out = drift(onboarded, *extra)
        text = "\n".join(out)
        assert "@example.test" not in text and "secret-dept" not in text
        assert "SG-01" not in text and "engineering" not in text


# ---- the generated block vs its sources ------------------------------------------------

def test_header_records_the_sources_fingerprint(onboarded):
    cfg = config(onboarded)
    gen = compile_from_files(onboarded, cfg.schema_path, cfg.attributes_path)
    assert gen.body[0].startswith(HEADER_PREFIX)
    fingerprint, version = block_header(policy_text(onboarded))
    assert fingerprint == gen.fingerprint and len(fingerprint) == 64
    import rbic
    assert version == rbic.__version__


def test_out_of_date_after_a_source_change(onboarded):
    schema, catalog, users, roles, sha = load_state(onboarded)
    roles, _ = set_role(roles, "hr_staff", description="changed")
    save(onboarded, roles, sha)
    state, messages = block_state(config(onboarded))
    assert state == "out_of_date"
    assert "generated block is out of date" in messages[0]
    code, out = run(["status", "--config-dir", str(onboarded)])
    assert "Generated block (policy.csv): OUT OF DATE" in out
    compile_and_apply(onboarded)
    assert block_state(config(onboarded))[0] == "in_sync"


def test_attribute_changes_do_not_make_the_block_stale(onboarded):
    a = admin(onboarded)
    a.apply(a.propose_set_attribute("bob", "dept", "logistics", actor="master"),
            actor="master")
    assert block_state(config(onboarded))[0] == "in_sync"


def test_edited_block(onboarded):
    text = policy_text(onboarded)
    write_policy(onboarded, text.replace("p, hr_staff, employees.name, read\n",
                                         ""))
    state, messages = block_state(config(onboarded))
    assert state == "edited" and "was edited" in messages[0]
    lines = [l for l in text.split("\n") if not l.startswith(HEADER_PREFIX)]
    write_policy(onboarded, "\n".join(lines))
    state, messages = block_state(config(onboarded))
    assert state == "edited" and "no sources header" in messages[0]


def test_undone_block_and_undo_note(onboarded):
    a = admin(onboarded)
    undo = a.propose_undo(actor="master")
    assert SOURCES_NOT_REVERTED in undo.description
    assert "were NOT reverted" in undo.description
    a.apply(undo, actor="master")
    state, messages = block_state(config(onboarded))
    assert state == "undone"
    assert "was undone; the onboarding sources were not reverted" in messages[0]
    c = findings(check_drift(config(onboarded)), "generated_block")
    assert c.status == "drift" and c.findings[0].startswith("undone:")


def test_malformed_block(onboarded):
    write_policy(onboarded, policy_text(onboarded).replace(END_MARKER, ""))
    assert block_state(config(onboarded))[0] == "malformed"


def test_not_onboarded(demo_dir):
    state, _ = block_state(config(demo_dir))
    assert state == "not_onboarded"
    code, out = run(["status", "--config-dir", str(demo_dir)])
    assert "Generated block (policy.csv): not generated yet" in out


# ---- high sensitivity on ALL rows, end to end ------------------------------------------

def _auditor(d, ack=True):
    schema, catalog, users, roles, sha = load_state(d)
    roles, _ = set_role(roles, "auditor", categories=["pay"])
    if ack:
        for table in ("payroll", "employees"):
            roles, _ = set_all_rows(roles, "auditor", table, REASON)
    save(d, roles, sha)


AUDITOR_STATIC = (("payroll", "employee_id > 0"), ("employees", "id <> -1"))


def _static_auditor(d, scopes=AUDITOR_STATIC, ack=()):
    schema, catalog, users, roles, sha = load_state(d)
    roles, _ = set_role(roles, "auditor", categories=["pay"])
    for table, template in scopes:
        roles, lines = add_scope(roles, "auditor", RowScope(table, template))
        assert any(STATIC_FILTER_WARNING in line for line in lines)
    for table in ack:
        roles, _ = set_all_rows(roles, "auditor", table, REASON)
    save(d, roles, sha)


def test_static_scopes_do_not_count_as_a_row_limit(onboarded, capsys):
    # Review finding: `employee_id > 0` / `id <> -1` (the same rows for every
    # user) passed the all-rows refusal for high-sensitivity columns.
    _static_auditor(onboarded)
    with pytest.raises(SystemExit) as exc:
        run(["compile", "--config-dir", str(onboarded), "--actor", "master"])
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert ("role auditor would read high-sensitivity column(s) payroll.(id, "
            "employee_id, salary, effective_date) on ALL rows (only STATIC row "
            "scope(s) in its role level: employee_id > 0") in err
    assert "role auditor would read high-sensitivity column(s) " \
        "employees.(salary) on ALL rows (only STATIC" in err


def test_static_scope_with_acknowledgement_compiles_with_warnings(onboarded):
    _static_auditor(onboarded, ack=("payroll", "employees"))
    gen, change = compile_change(onboarded)
    assert any("role auditor: row scope on payroll (employee_id > 0): "
               + STATIC_FILTER_WARNING == w for w in gen.warnings)
    assert ("compile: role auditor reads high-sensitivity column(s) "
            "payroll.(id, employee_id, salary, effective_date) on ALL rows "
            "(only STATIC row scope(s)") in change.description
    assert f"acknowledged in roles.json: {REASON}" in change.description
    admin(onboarded).apply(change, actor="master")
    cfg = config(onboarded)
    schema, catalog, *_ = load_state(onboarded)
    report = report_from_bytes(
        cfg.model_path.read_bytes(), cfg.policy_path.read_bytes(),
        cfg.attributes_path.read_bytes(), cfg.schema_path.read_bytes(),
        catalog)
    assert ("rows where employee_id > 0 (STATIC: the same rows for every "
            f"user) (acknowledged: {REASON})") in report
    assert ("role auditor reads payroll on ALL rows (only static row filters "
            "in its role level: STATIC: the same rows for every user), "
            "including high-sensitivity id, employee_id, salary, "
            f"effective_date - acknowledged in roles.json: {REASON}") in report


def test_static_status_filter_is_static_too(onboarded):
    # a constant comparison on any column is static: `status = 'unpaid'`
    schema, catalog, users, roles, sha = load_state(onboarded)
    roles, _ = set_role(roles, "payslip_clerk", categories=["pay"])
    roles, lines = add_scope(roles, "payslip_clerk",
                             RowScope("payroll", "effective_date > '2000-01-01'"))
    save(onboarded, roles, sha)
    with pytest.raises(CompileError, match="payslip_clerk would read "
                                           "high-sensitivity"):
        compile_from_files(onboarded, config(onboarded).schema_path,
                           config(onboarded).attributes_path)


def test_static_scoped_grant_of_high_columns_needs_acknowledgement(onboarded):
    schema, catalog, users, roles, sha = load_state(onboarded)
    roles, _ = set_role(roles, "auditor", categories=[])
    roles, lines = add_scope(roles, "auditor", RowScope(
        "payroll", "employee_id > 0", ("employee_id", "salary")))
    assert any(STATIC_FILTER_WARNING in line for line in lines)
    save(onboarded, roles, sha)
    cfg = config(onboarded)
    with pytest.raises(CompileError, match=r"role auditor would read "
                       r"high-sensitivity column\(s\) payroll.\(employee_id, "
                       r"salary\) on ALL rows \(through a STATIC scoped grant"):
        compile_from_files(onboarded, cfg.schema_path, cfg.attributes_path)
    schema, catalog, users, roles, sha = load_state(onboarded)
    roles, _ = set_all_rows(roles, "auditor", "payroll", REASON)
    save(onboarded, roles, sha)
    gen = compile_from_files(onboarded, cfg.schema_path, cfg.attributes_path)
    assert f"# all_rows auditor payroll: {REASON}" in gen.body
    # a scoped grant bound from the user's attributes needs none
    schema, catalog, users, roles, sha = load_state(onboarded)
    roles, _ = remove_all_rows(roles, "auditor", "payroll")
    roles, _ = remove_scope(roles, "auditor", RowScope(
        "payroll", "employee_id > 0", ("employee_id", "salary")))
    roles, lines = add_scope(roles, "auditor", RowScope(
        "payroll", "employee_id = '{employee_id}'", ("employee_id", "salary")))
    assert not any(STATIC_FILTER_WARNING in line for line in lines)
    save(onboarded, roles, sha)
    compile_from_files(onboarded, cfg.schema_path, cfg.attributes_path)


def test_cli_roles_scope_shows_the_static_warning(onboarded):
    code, out = run(["roles", "scope", "hr_staff", "employees", "id > 0",
                     "--config-dir", str(onboarded), "--actor", "master"],
                    ("no",))
    assert code == 0
    assert any(STATIC_FILTER_WARNING in line for line in out)


def test_compile_refuses_unacknowledged_high_sensitivity(onboarded, capsys):
    _auditor(onboarded, ack=False)
    with pytest.raises(SystemExit) as exc:
        run(["compile", "--config-dir", str(onboarded), "--actor", "master"])
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "refused - high-sensitivity data on ALL rows" in err
    assert "role auditor would read high-sensitivity column(s) " \
        "payroll.(id, employee_id, salary, effective_date)" in err


def test_acknowledged_reason_reaches_block_report_and_summary(onboarded):
    _auditor(onboarded)
    gen, change = compile_change(onboarded)
    assert f"compile: role auditor reads high-sensitivity column(s) " \
        f"payroll.(id, employee_id, salary, effective_date) on ALL rows - " \
        f"acknowledged in roles.json: {REASON}" in change.description
    admin(onboarded).apply(change, actor="master")
    text = policy_text(onboarded)
    assert f"# all_rows auditor payroll: {REASON}" in text
    assert acknowledgements(text) == {("auditor", "payroll"): REASON,
                                      ("auditor", "employees"): REASON}
    cfg = config(onboarded)
    schema, catalog, *_ = load_state(onboarded)
    report = report_from_bytes(
        cfg.model_path.read_bytes(), cfg.policy_path.read_bytes(),
        cfg.attributes_path.read_bytes(), cfg.schema_path.read_bytes(),
        catalog)
    assert f"**ALL rows** (acknowledged: {REASON})" in report
    assert f"role auditor reads payroll on ALL rows (no row filter in its role " \
        f"level), including high-sensitivity id, employee_id, salary, " \
        f"effective_date - acknowledged in roles.json: {REASON}" in report


def test_acknowledgement_comment_outside_the_block_counts_for_nothing():
    text = f"# all_rows auditor payroll: {REASON}\n"
    assert acknowledgements(text) == {}


def test_cli_roles_all_rows(onboarded, audit_on):
    _auditor(onboarded, ack=False)
    code, out = run(["roles", "all-rows", "auditor", "payroll", "--reason",
                     REASON, "--config-dir", str(onboarded), "--actor",
                     "master", "--audit-log", str(onboarded / "a.jsonl")],
                    ["yes"])
    assert code == 0 and "APPLIED" in out[-1]
    assert any("reads payroll on ALL rows" in l for l in out)
    roles = json.loads(roles_path(onboarded).read_text(encoding="utf-8"))
    assert roles["roles"]["auditor"]["all_rows"] == [
        {"table": "payroll", "reason": REASON}]
    assert any(l.startswith("ROLES_CHANGE actor=master action=all-rows")
               for l in audit_lines(onboarded / "a.jsonl"))
    code, out = run(["roles", "all-rows", "auditor", "payroll", "--remove",
                     "--config-dir", str(onboarded), "--actor", "master"],
                    ["yes"])
    assert code == 0
    assert "all_rows" not in json.loads(roles_path(onboarded).read_text(
        encoding="utf-8"))["roles"]["auditor"]


@pytest.mark.parametrize("extra, message", [
    ((), "give --reason TEXT to acknowledge, or --remove"),
    (("--reason", "x", "--remove"), "give --reason TEXT"),
    (("--reason", "café"), "printable ASCII"),
])
def test_cli_roles_all_rows_refusals(onboarded, capsys, extra, message):
    _auditor(onboarded, ack=False)
    with pytest.raises(SystemExit):
        run(["roles", "all-rows", "auditor", "payroll", *extra,
             "--config-dir", str(onboarded), "--actor", "master"], ["yes"])
    assert message in capsys.readouterr().err
