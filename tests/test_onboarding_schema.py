"""rbic.onboarding.schema and PolicyAdmin.propose_schema_update: database
introspection, schema diffs, and the validated db_schema.json write path
(gate loader in both dialects, rule references, lock, changelog, undo)."""

import json
import os
import sqlite3

import pytest

from rbic.admin import LOCK_NAME, PolicyAdmin
from rbic.gate import AccessDenied, SQLGate
from rbic.onboarding.schema import (diff_schema, introspect_sqlite,
                                    normalize_type, ordered_like)
from conftest import DEMO_SOURCE


@pytest.fixture
def admin(demo_config):
    return PolicyAdmin.from_config(demo_config)


def shipped_schema():
    return json.loads((DEMO_SOURCE / "db_schema.json").read_text(encoding="utf-8"))


# ---- introspection -----------------------------------------------------------

def test_introspected_demo_db_equals_shipped_schema(seeded_db):
    notes = []
    found = introspect_sqlite(seeded_db, notes)
    assert found == shipped_schema()
    assert notes == []
    # tables sorted by name, columns in declared order
    assert list(found) == sorted(found)
    assert list(found["employees"]) == ["id", "name", "dept", "start_date",
                                        "salary"]


def test_writing_introspected_demo_schema_is_a_no_op(admin, seeded_db):
    found = ordered_like(admin.schema(), introspect_sqlite(seeded_db))
    assert diff_schema(admin.schema(), found).empty
    with pytest.raises(ValueError, match="already matches"):
        admin.propose_schema_update(found)


@pytest.mark.parametrize("declared, expected, noted", [
    ("INTEGER", "int", False), ("BIGINT", "int", False),
    ("UNSIGNED BIG INT", "int", False), ("TEXT", "text", False),
    ("VARCHAR(20)", "text", False), ("CLOB", "text", False),
    ("NUMERIC", "numeric", False), ("DECIMAL(10,2)", "numeric", False),
    ("REAL", "numeric", False), ("DOUBLE PRECISION", "numeric", False),
    ("BOOLEAN", "numeric", False), ("DATE", "date", False),
    ("DATETIME", "timestamp", False), ("TIMESTAMP", "timestamp", False),
    ("", "text", True), ("BLOB", "text", True), ("GEOMETRY", "text", True),
])
def test_normalize_type(declared, expected, noted):
    typ, note = normalize_type(declared)
    assert typ == expected
    assert (note is not None) is noted


def test_introspection_skips_internal_and_unaddressable_names(tmp_path):
    db = tmp_path / "x.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, ref,
                             "Total Amount" NUMERIC, note BLOB);
        CREATE TABLE "Customers" (id INTEGER);
        CREATE TABLE "a.b" (id INTEGER);
        CREATE VIEW order_refs AS SELECT id, ref FROM orders;
        INSERT INTO orders (ref) VALUES ('x');
    """)
    conn.close()
    before = db.read_bytes()
    notes = []
    found = introspect_sqlite(db, notes)
    # sqlite_sequence (AUTOINCREMENT) is internal; mixed-case / dotted names
    # can't be addressed through the gate.
    assert found == {"order_refs": {"id": "int", "ref": "text"},
                     "orders": {"id": "int", "ref": "text", "note": "text"}}
    text = "\n".join(notes)
    assert "'Customers' skipped" in text and "'a.b' skipped" in text
    assert "orders.'Total Amount' skipped" in text
    assert "orders.ref: no declared type" in text
    assert "orders.note: unknown declared type 'BLOB'" in text
    assert db.read_bytes() == before  # read-only


def test_introspection_missing_db_is_refused(tmp_path):
    with pytest.raises(FileNotFoundError):
        introspect_sqlite(tmp_path / "nope.db")
    assert not (tmp_path / "nope.db").exists()  # mode=ro never creates it


def test_diff_schema_and_ordered_like():
    old = {"a": {"id": "int", "x": "text"}, "b": {"id": "int"}}
    new = {"c": {"id": "int"}, "a": {"y": "int", "x": "date", "id": "int"}}
    d = diff_schema(old, new)
    assert d.added_tables == ["c"] and d.removed_tables == ["b"]
    assert d.added_columns == {"a": ["y"]}
    assert d.type_changes == {"a": [("x", "text", "date")]}
    assert not d.empty and diff_schema(new, new).empty
    assert "new table c (id)" in d.lines(new)
    merged = ordered_like(old, new)
    assert list(merged) == ["a", "c"]
    assert list(merged["a"]) == ["id", "x", "y"]
    assert merged["a"]["x"] == "date"


# ---- validated write path ----------------------------------------------------

def test_removing_a_granted_column_is_refused(admin):
    schema = admin.schema()
    del schema["employees"]["salary"]  # p, hr_manager, employees.salary, read
    with pytest.raises(ValueError, match="employees.salary"):
        admin.propose_schema_update(schema)


def test_removing_a_filtered_column_is_refused(admin):
    schema = admin.schema()
    del schema["inventory"]["warehouse_id"]  # p2 ... warehouse_id = '{site}'
    with pytest.raises(ValueError, match="would not load in the SQL gate"):
        admin.propose_schema_update(schema)


def test_removing_a_filtered_table_is_refused(admin):
    schema = admin.schema()
    del schema["shipments"]
    with pytest.raises(ValueError, match="shipments"):
        admin.propose_schema_update(schema)


def test_malformed_schema_is_refused(admin):
    with pytest.raises(ValueError, match="Invalid schema"):
        admin.propose_schema_update({"t": {}})


def test_safe_change_applies_with_changelog_and_reaches_the_gate(
        admin, demo_config):
    before = demo_config.schema_path.read_bytes().decode("utf-8")
    schema = admin.schema()
    schema["inventory"]["bin"] = "text"
    schema["audit_trail"] = {"id": "int", "event": "text"}
    change = admin.propose_schema_update(schema, actor="master")
    assert change.kind == "schema_update"
    assert "new table audit_trail (id, event)" in change.description
    assert "inventory: new column(s) bin" in change.description
    # inventory.* is granted to warehouse_worker: the new column is
    # readable at once, and the proposal says so.
    assert ("WARNING: warehouse_worker [users: alice] can read "
            "inventory.(bin) immediately") in change.description
    assert '"bin": "text"' in change.diff()
    assert demo_config.schema_path.read_bytes().decode("utf-8") == before

    admin.apply(change, actor="master")
    assert json.loads(demo_config.schema_path.read_text(encoding="utf-8")) == schema
    assert not (demo_config.policy_path.parent / LOCK_NAME).exists()
    log = [json.loads(l) for l in (demo_config.config_dir /
                                   "policy_changes.jsonl").read_text(
        encoding="utf-8").splitlines()]
    assert [e["status"] for e in log] == ["applying", "applied"]
    assert log[-1]["kind"] == "schema_update"
    assert log[-1]["before_text"] == before
    assert admin.history()[-1]["kind"] == "schema_update"

    gate = SQLGate.from_config(demo_config)
    assert "bin" in gate.authorize("alice", "SELECT sku, bin FROM inventory")
    with pytest.raises(AccessDenied):
        gate.authorize("alice", "SELECT event FROM audit_trail")  # no grant


def test_apply_needs_a_master_and_unchanged_inputs(admin, demo_config):
    schema = admin.schema()
    schema["audit_trail"] = {"id": "int"}
    change = admin.propose_schema_update(schema)
    with pytest.raises(ValueError, match="not a master"):
        admin.apply(change, actor="alice")
    with open(demo_config.policy_path, "a", encoding="utf-8") as f:
        f.write("\n# touched\n")
    with pytest.raises(ValueError, match="Policy changed since"):
        admin.apply(change, actor="master")
    assert "audit_trail" not in admin.schema()


def test_apply_waits_for_the_policy_lock(admin, demo_config, monkeypatch):
    from rbic import admin as admin_module
    monkeypatch.setattr(admin_module, "LOCK_TIMEOUT_S", 0.2)
    schema = admin.schema()
    schema["audit_trail"] = {"id": "int"}
    change = admin.propose_schema_update(schema)
    lock = demo_config.policy_path.parent / LOCK_NAME
    lock.write_text("123\n")
    with pytest.raises(ValueError, match="Another policy change"):
        admin.apply(change, actor="master")
    assert lock.exists()  # someone else's lock is left alone
    lock.unlink()
    assert "audit_trail" not in admin.schema()
    admin.apply(change, actor="master")
    assert "audit_trail" in admin.schema()


def test_dangling_rule_coming_back_to_life_is_flagged(admin, demo_config):
    with open(demo_config.policy_path, "a", encoding="utf-8") as f:
        f.write("p, hr_staff, employees.badge, read\n")
    schema = admin.schema()
    schema["employees"]["badge"] = "text"
    change = admin.propose_schema_update(schema)
    assert ("the existing rule 'p, hr_staff, employees.badge, read' names "
            "employees.badge, which did not exist before") in change.description


def test_schema_change_can_be_undone(admin, demo_config):
    original = demo_config.schema_path.read_bytes()
    schema = admin.schema()
    schema["audit_trail"] = {"id": "int"}
    admin.apply(admin.propose_schema_update(schema), actor="master")
    undo = admin.propose_undo()
    assert undo.target == os.fspath(demo_config.schema_path)
    assert "table audit_trail removed" in undo.description
    admin.apply(undo, actor="master")
    assert demo_config.schema_path.read_bytes() == original
