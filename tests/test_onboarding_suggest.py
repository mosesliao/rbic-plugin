"""rbic.onboarding.suggest: local name and value rules. Value rules must
never let a data value out - not in suggestions, evidence, the catalog,
the audit log or CLI output."""

import json
import logging
import sqlite3

import pytest

from rbic import audit
from rbic.cli import init as init_cli
from rbic.onboarding import catalog_path
from rbic.onboarding.suggest import (NAME_RULES, VALUE_RULES, _is_birth_date,
                                     _is_card, suggest_categories, tokens)
from conftest import DEMO_SOURCE

DEMO_SCHEMA = json.loads((DEMO_SOURCE / "db_schema.json").read_text(
    encoding="utf-8"))

EMAILS = [f"person{i}@corp.test" for i in range(8)]
NRICS = ["S1234567D", "T7654321A", "F1111111K", "G2222222X", "M3333333L",
         "S4444444E", "T5555555B", "S6666666C"]
PHONES = ["+65 9123 4567", "81234567", "6123-4567", "+6591234568",
          "9876 5432", "+44 20 7946 0958", "87654321", "+1 415 555 0100"]
CARDS = ["4111 1111 1111 1111", "5500-0000-0000-0004", "340000000000009",
         "6011000000000004", "4012888888881881", "4222222222222",
         "5105105105105100", "4111111111111111"]
SECRET_VALUES = EMAILS + NRICS + PHONES + CARDS


def by_column(suggestions):
    return {s.column: s for s in suggestions}


# ---- name rules ----------------------------------------------------------------

def test_tokens():
    assert tokens("employee_id") == ["employee", "id"]
    assert tokens("startDate") == ["start", "date"]
    assert tokens("addr2Line") == ["addr", "2", "line"]


def test_rule_ids_are_unique():
    ids = [r.id for r in NAME_RULES] + [r.id for r in VALUE_RULES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("column, category", [
    ("payroll.salary", "pay"),
    ("payroll.employee_id", "pay"),          # id inherits the table
    ("employees.name", "directory"),
    ("employees.start_date", "directory"),
    ("employees.salary", "pay"),             # more sensitive than directory
    ("inventory.qty", "inventory"),
    ("inventory.warehouse_id", "inventory"),
    ("shipments.eta", "logistics"),
    ("invoices.vendor", "finance"),
    ("budgets.amount", "finance"),
    ("expenses.dept", "finance"),            # table context beats directory
    ("safety_incidents.severity", "safety"),
    ("leave_requests.status", "leave"),
    ("trainings.title", "training"),
])
def test_demo_schema_name_suggestions(column, category):
    s = by_column(suggest_categories(DEMO_SCHEMA, use_values=False))[column]
    assert s.category == category
    assert s.suggested_by.startswith("name-rule:")
    assert 0 < s.confidence <= 1


def test_demo_schema_every_column_gets_a_category(seeded_db):
    names = suggest_categories(DEMO_SCHEMA, use_values=False)
    assert len(names) == sum(map(len, DEMO_SCHEMA.values()))
    assert all(s.category for s in names)
    # no value rule fires on the demo data: sampling changes nothing
    with_values = suggest_categories(DEMO_SCHEMA, db_path=seeded_db)
    assert with_values == names


@pytest.mark.parametrize("table, column, category, rule", [
    ("people", "national_id", "personal_identifier", "national_id"),
    ("people", "nric", "personal_identifier", "national_id"),
    ("people", "customer_email", "contact", "contact"),
    ("people", "dob", "personal_identifier", "birth"),
    ("misc", "beta", None, "none"),          # 'eta' only matches a whole token
    ("misc", "id", "other", "id_column"),
    ("misc", "paid_on", None, "none"),       # not 'pay', not an id
    ("bonuses", "note", "pay", "pay"),       # plural table name
])
def test_name_rule_cases(table, column, category, rule):
    s = by_column(suggest_categories({table: {"id": "int", column: "text"}},
                                     use_values=False))[f"{table}.{column}"]
    assert s.category == category
    assert s.suggested_by == f"name-rule:{rule}"


# ---- value rules -----------------------------------------------------------------

def test_card_and_birth_date_helpers():
    assert _is_card("4111 1111 1111 1111")
    assert not _is_card("4111 1111 1111 1112")  # Luhn fails
    assert not _is_card("0000000000000000")
    assert _is_birth_date("1980-05-17")
    assert not _is_birth_date("2024-01-01")


def make_db(path, rows=8):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE contacts (id INTEGER, ref TEXT, ident TEXT, "
                 "reach TEXT, card TEXT, salary TEXT, born TEXT)")
    for i in range(rows):
        conn.execute("INSERT INTO contacts VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (i, EMAILS[i % 8], NRICS[i % 8], PHONES[i % 8],
                      CARDS[i % 8], "91234567", "1980-05-17"))
    conn.commit()
    conn.close()


CONTACTS = {"contacts": {"id": "int", "ref": "text", "ident": "text",
                         "reach": "text", "card": "text", "salary": "text",
                         "born": "text"}}


def test_value_rules_detect_without_leaking(tmp_path):
    db = tmp_path / "c.db"
    make_db(db)
    notes = []
    result = by_column(suggest_categories(CONTACTS, db_path=db, notes=notes))
    assert result["contacts.ref"].category == "contact"  # name says nothing
    assert result["contacts.ref"].suggested_by == "value-rule:email"
    assert result["contacts.ref"].evidence == \
        "value-rule:email matched 8/8 sampled values"
    assert result["contacts.ident"].suggested_by == "value-rule:sg_nric"
    assert result["contacts.ident"].category == "personal_identifier"
    assert result["contacts.reach"].suggested_by == "value-rule:phone"
    assert result["contacts.card"].suggested_by == "value-rule:card_number"
    assert result["contacts.born"].suggested_by == "value-rule:birth_date"
    # a phone-looking salary stays pay: values never lower sensitivity
    salary = result["contacts.salary"]
    assert salary.category == "pay" and salary.suggested_by == "name-rule:pay"
    assert "value-rule:phone matched 8/8" in salary.evidence
    assert "ignored" in salary.evidence
    text = repr(list(result.values())) + repr(notes)
    assert not [v for v in SECRET_VALUES + ["91234567", "1980-05-17"]
                if v in text]


def test_sample_rows_caps_reads(tmp_path):
    db = tmp_path / "c.db"
    make_db(db, rows=40)
    s = by_column(suggest_categories(CONTACTS, db_path=db, sample_rows=10))
    assert s["contacts.ref"].evidence == \
        "value-rule:email matched 10/10 sampled values"
    with pytest.raises(ValueError, match="sample_rows"):
        suggest_categories(CONTACTS, db_path=db, sample_rows=0)


def test_no_values_never_opens_the_database(tmp_path, monkeypatch):
    db = tmp_path / "c.db"
    make_db(db)

    def refuse(*a, **k):
        raise AssertionError("database opened")

    monkeypatch.setattr("rbic.onboarding.suggest.sqlite3.connect", refuse)
    s = by_column(suggest_categories(CONTACTS, db_path=db, use_values=False))
    assert s["contacts.ref"].category is None
    assert s["contacts.salary"].category == "pay"


def test_sampling_reads_only(tmp_path):
    db = tmp_path / "c.db"
    make_db(db)
    before = db.read_bytes()
    suggest_categories(CONTACTS, db_path=db)
    assert db.read_bytes() == before


def test_columns_missing_from_the_database_are_not_sampled(tmp_path):
    db = tmp_path / "c.db"
    make_db(db)
    notes = []
    # SQLite would read "missing" as a string literal: it must not be queried
    schema = {"contacts": {"id": "int", "ref": "text", "missing": "text"},
              "ghost": {"id": "int"}}
    s = by_column(suggest_categories(schema, db_path=db, notes=notes))
    assert s["contacts.missing"].category is None
    assert notes == ["contacts.missing: not in the database; value rules "
                     "skipped", "ghost: not in the database; value rules "
                     "skipped"]


def test_sampling_errors_report_class_only(tmp_path, monkeypatch):
    db = tmp_path / "c.db"
    make_db(db)
    notes = []

    def boom(*a):
        raise sqlite3.OperationalError("near 'S1234567D': syntax error")

    monkeypatch.setattr("rbic.onboarding.suggest._value_counts", boom)
    suggest_categories({"contacts": {"ref": "text"}}, db_path=db, notes=notes)
    assert notes == ["contacts.ref: value sampling failed (OperationalError)"]


def test_missing_database_skips_value_rules(tmp_path):
    notes = []
    suggest_categories(CONTACTS, db_path=tmp_path / "nope.db", notes=notes)
    assert notes == ["database not found; value rules skipped"]
    assert not (tmp_path / "nope.db").exists()


# ---- end to end through the CLI: nothing leaks into catalog, log or output ---

@pytest.fixture
def audit_on():
    previous = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    yield
    logging.disable(previous)
    audit.unconfigure()


def test_cli_suggest_leaks_no_values(demo_dir, tmp_path, capsys, audit_on):
    make_db(demo_dir / "company.db")  # adds the contacts table to the demo db
    schema = json.loads((demo_dir / "db_schema.json").read_text(encoding="utf-8"))
    schema.update(CONTACTS)
    (demo_dir / "db_schema.json").write_text(json.dumps(schema, indent=2),
                                             encoding="utf-8")
    log = tmp_path / "audit.jsonl"
    out = []
    assert init_cli.main(["suggest", "--config-dir", str(demo_dir),
                          "--audit-log", str(log)], output=out.append) == 0
    printed = "\n".join(out)
    assert "contacts.ref" in printed and "value-rule:email" in printed
    assert "not granted by the generated policy until approved" in printed
    assert "contacts.ref" not in next(l for l in out if l.startswith("WARNING"))
    catalog = catalog_path(demo_dir).read_text(encoding="utf-8")
    assert json.loads(catalog)["columns"]["contacts.ident"]["category"] == \
        "personal_identifier"
    audit_text = log.read_text(encoding="utf-8")
    assert "CATALOG_SUGGEST" in audit_text
    captured = capsys.readouterr()
    everything = printed + catalog + audit_text + captured.out + captured.err
    assert not [v for v in SECRET_VALUES if v in everything]
