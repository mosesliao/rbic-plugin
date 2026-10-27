"""rbic-init (rbic.cli.init) end to end with injected I/O on tmp copies:
schema dry run / write with yes-no confirmation, suggest, status,
approve/reject, actor checks, audit lines and --help everywhere."""

import json
import logging
import sqlite3
import subprocess
import sys

import pytest

from rbic import audit
from rbic.cli import init as init_cli
from rbic.onboarding import catalog_path

SUBCOMMANDS = ("schema", "suggest", "status", "approve", "reject")


@pytest.fixture
def audit_on():
    previous = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    yield
    logging.disable(previous)
    audit.unconfigure()


def run(argv, answers=()):
    out = []
    answers = list(answers)

    def input_fn(prompt):
        out.append(prompt)
        if not answers:
            raise EOFError
        item = answers.pop(0)
        if isinstance(item, type) and issubclass(item, BaseException):
            raise item
        return item

    code = init_cli.main(argv, input_fn=input_fn, output=out.append)
    return code, out


def add_column(db, table="inventory", column="bin"):
    conn = sqlite3.connect(db)
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT")
    conn.commit()
    conn.close()


def audit_lines(path):
    return [json.loads(l)["message"] for l in
            path.read_text(encoding="utf-8").splitlines()]


# ---- help ----------------------------------------------------------------------

@pytest.mark.parametrize("argv", [["--help"], *([c, "--help"] for c in SUBCOMMANDS)])
def test_help(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        init_cli.main(argv)
    assert exc.value.code == 0
    assert "usage: rbic-init" in capsys.readouterr().out


def test_runs_as_module(demo_dir):
    proc = subprocess.run([sys.executable, "-m", "rbic.cli.init", "status",
                           "--config-dir", str(demo_dir)],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert "unlabelled: 47" in proc.stdout


def test_missing_config_dir_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        init_cli.main(["status"])
    assert exc.value.code == 2
    assert "RBIC_CONFIG_DIR" in capsys.readouterr().err


# ---- schema ----------------------------------------------------------------------

def test_schema_up_to_date(demo_dir):
    code, out = run(["schema", "--config-dir", str(demo_dir)])
    assert code == 0
    assert "Introspected 10 table(s)/view(s), 47 column(s)." in out
    assert "db_schema.json is up to date." in out


def test_schema_dry_run_writes_nothing(demo_dir):
    add_column(demo_dir / "company.db")
    before = (demo_dir / "db_schema.json").read_bytes()
    code, out = run(["schema", "--config-dir", str(demo_dir)])
    assert "  - inventory: new column(s) bin" in out
    assert any("dry run" in l for l in out)
    assert (demo_dir / "db_schema.json").read_bytes() == before


@pytest.mark.parametrize("answers, applied, reasks", [
    (["y"], True, 0), (["YES"], True, 0), (["n"], False, 0),
    (["No"], False, 0), (["maybe", "", "y"], True, 2), ([EOFError], False, 0),
    ([KeyboardInterrupt], False, 0),
])
def test_schema_write_confirmation(demo_dir, tmp_path, audit_on, answers,
                                   applied, reasks):
    add_column(demo_dir / "company.db")
    log = tmp_path / "audit.jsonl"
    code, out = run(["schema", "--config-dir", str(demo_dir), "--write",
                     "--actor", "master", "--audit-log", str(log)], answers)
    assert code == 0
    text = "\n".join(out)
    assert "WARNING: warehouse_worker [users: alice] can read inventory.(bin)" \
        in text
    assert out.count("Please type yes or no.") == reasks
    schema = json.loads((demo_dir / "db_schema.json").read_text(encoding="utf-8"))
    assert ("bin" in schema["inventory"]) is applied
    messages = audit_lines(log)
    confirms = [m for m in messages if m.startswith("POLICY_CONFIRM")]
    assert len(confirms) == 1
    assert confirms[0].endswith("confirmed" if applied else "declined")
    assert any(m.startswith("POLICY_CHANGE ") for m in messages) is applied
    changelog = demo_dir / "policy_changes.jsonl"
    assert changelog.exists() is applied


def test_schema_write_refuses_a_breaking_change(demo_dir, capsys):
    conn = sqlite3.connect(demo_dir / "company.db")
    conn.execute("ALTER TABLE employees DROP COLUMN salary")
    conn.commit()
    conn.close()
    before = (demo_dir / "db_schema.json").read_bytes()
    with pytest.raises(SystemExit) as exc:
        run(["schema", "--config-dir", str(demo_dir), "--write", "--actor",
             "master"], ["y"])
    assert exc.value.code == 1
    assert "employees.salary" in capsys.readouterr().err
    assert (demo_dir / "db_schema.json").read_bytes() == before


@pytest.mark.parametrize("actor", [None, "alice", "nobody"])
def test_schema_write_needs_a_master_actor(demo_dir, capsys, actor):
    add_column(demo_dir / "company.db")
    argv = ["schema", "--config-dir", str(demo_dir), "--write"]
    if actor:
        argv += ["--actor", actor]
    with pytest.raises(SystemExit) as exc:
        run(argv, ["y"])
    assert exc.value.code == 1
    assert "master" in capsys.readouterr().err


def test_schema_missing_db(demo_dir, capsys):
    with pytest.raises(SystemExit) as exc:
        run(["schema", "--config-dir", str(demo_dir), "--db",
             str(demo_dir / "nope.db")])
    assert exc.value.code == 1
    assert "does not exist" in capsys.readouterr().err


# ---- suggest / status / approve / reject ------------------------------------------

def test_suggest_then_status(demo_dir):
    code, out = run(["suggest", "--config-dir", str(demo_dir)])
    assert code == 0
    assert out[0].split() == ["COLUMN", "STATUS", "CATEGORY", "CONF",
                              "EVIDENCE"]
    row = next(l for l in out if l.startswith("payroll.salary "))
    assert row.split()[:3] == ["payroll.salary", "suggested", "pay"]
    assert any("47 added, 0 updated, 0 human decision(s) kept" in l
               for l in out)
    assert any(l.startswith("47 column(s) not approved: hidden from everyone "
                            "until approved") for l in out)
    _, out = run(["status", "--config-dir", str(demo_dir)])
    assert "  suggested:  47 (awaiting approval)" in out
    assert "Fully approved tables: none" in out
    # suggesting again changes nothing
    _, out = run(["suggest", "--config-dir", str(demo_dir), "--no-values"])
    assert any("0 added, 0 updated, 0 human decision(s) kept" in l
               for l in out)


def test_status_without_catalog(demo_dir):
    _, out = run(["status", "--config-dir", str(demo_dir)])
    assert out[0].startswith("No catalog yet")
    assert "  unlabelled: 47" in out


@pytest.mark.parametrize("answers, applied", [
    (["y"], True), (["n"], False), (["?", "yes"], True), ([EOFError], False),
])
def test_approve_confirmation(demo_dir, tmp_path, audit_on, answers, applied):
    run(["suggest", "--config-dir", str(demo_dir), "--no-values"])
    log = tmp_path / "audit.jsonl"
    code, out = run(["approve", "--config-dir", str(demo_dir), "--actor",
                     "master", "--audit-log", str(log), "payroll.salary"],
                    answers)
    assert code == 0
    assert "  - payroll.salary: suggested pay -> approve as pay" in out
    entry = json.loads(catalog_path(demo_dir).read_text(encoding="utf-8")
                       )["columns"]["payroll.salary"]
    assert (entry["status"] == "approved") is applied
    if applied:
        assert entry["approved_by"] == "master" and entry["approved_at"]
    messages = audit_lines(log)
    assert [m for m in messages if m.startswith("CATALOG_CONFIRM")][0].endswith(
        "confirmed" if applied else "declined")
    assert any(m.startswith("CATALOG_CHANGE") for m in messages) is applied


def test_approve_all_then_suggest_keeps_decisions(demo_dir):
    run(["suggest", "--config-dir", str(demo_dir), "--no-values"])
    run(["approve", "--config-dir", str(demo_dir), "--actor", "master",
         "employees.name", "contact"], ["y"])
    run(["reject", "--config-dir", str(demo_dir), "--actor", "master",
         "payroll.id"], ["y"])
    code, out = run(["approve", "--config-dir", str(demo_dir), "--actor",
                     "master", "--all-suggested"], ["y"])
    assert any(l.startswith("Proposed approve of 45 column(s)") for l in out)
    _, out = run(["suggest", "--config-dir", str(demo_dir)])
    assert any("0 added, 0 updated, 47 human decision(s) kept" in l
               for l in out)
    columns = json.loads(catalog_path(demo_dir).read_text(encoding="utf-8")
                         )["columns"]
    assert columns["employees.name"]["category"] == "contact"
    assert columns["employees.name"]["suggested_by"] == "human"
    assert columns["payroll.id"]["status"] == "rejected"
    _, out = run(["status", "--config-dir", str(demo_dir)])
    assert "  approved:   46" in out and "  rejected:   1" in out
    assert "Not fully approved: payroll (3/4)" in out


@pytest.mark.parametrize("argv, message", [
    (["approve", "--actor", "alice", "payroll.salary"], "not a master user"),
    (["approve", "--actor", "master"], "--all-suggested"),
    (["approve", "--actor", "master", "payroll.bonus", "pay"], "Unknown column"),
    (["approve", "--actor", "master", "payroll.salary", "perks"],
     "Unknown category"),
    (["reject", "--actor", "master", "nope.x"], "Unknown column"),
])
def test_approve_refusals(demo_dir, capsys, argv, message):
    run(["suggest", "--config-dir", str(demo_dir), "--no-values"])
    before = catalog_path(demo_dir).read_bytes()
    with pytest.raises(SystemExit) as exc:
        run([*argv, "--config-dir", str(demo_dir)], ["y"])
    assert exc.value.code == 1
    assert message in capsys.readouterr().err
    assert catalog_path(demo_dir).read_bytes() == before


def test_invalid_catalog_is_reported(demo_dir, capsys):
    path = catalog_path(demo_dir)
    path.parent.mkdir()
    path.write_text('{"version": 1, "categories": {}, "columns": '
                    '{"payroll.bonus": {}}}', encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        run(["status", "--config-dir", str(demo_dir)])
    assert exc.value.code == 1
    assert "catalog.json" in capsys.readouterr().err
