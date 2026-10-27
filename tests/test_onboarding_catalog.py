"""rbic.onboarding.catalog: catalog.json validation, merging (never over a
human decision), approvals/rejections, status and safe saving."""

import json
from datetime import datetime, timezone

import pytest

from rbic.onboarding import ONBOARDING_LOCK
from rbic.onboarding.catalog import (
    CatalogError, ColumnEntry, apply_decisions, catalog_status,
    load_catalog, merge_suggestions, new_catalog, parse_catalog,
    plan_approvals, plan_rejections, save_catalog)
from rbic.onboarding.suggest import Suggestion

SCHEMA = {"payroll": {"id": "int", "salary": "numeric"},
          "employees": {"id": "int", "name": "text"}}
NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)


def sug(column, category, by="name-rule:pay", evidence="rule fired",
        confidence=0.9):
    return Suggestion(column, category, confidence, by, evidence)


def catalog_json(**columns):
    c = new_catalog().to_json()
    c["columns"] = columns
    return json.dumps(c)


def entry(**over):
    e = {"category": "pay", "status": "suggested",
         "suggested_by": "name-rule:pay", "evidence": "x",
         "approved_by": None, "approved_at": None}
    e.update(over)
    return e


# ---- validation --------------------------------------------------------------

def test_round_trip_and_defaults():
    c = new_catalog()
    assert {"directory", "contact", "pay", "personal_identifier", "leave",
            "training", "inventory", "logistics", "finance", "safety",
            "other"} == set(c.categories)
    assert c.categories["pay"]["sensitivity"] == "high"
    assert parse_catalog(c.to_text()).to_json() == c.to_json()


@pytest.mark.parametrize("columns, message", [
    ({"payroll.bonus": entry()}, "does not have: payroll.bonus"),
    ({"Payroll.salary": entry()}, "invalid column key"),
    ({"payroll.salary": entry(category="Pay")}, "invalid category name"),
    ({"payroll.salary": entry(category="perks")}, "not defined"),
    ({"payroll.salary": entry(status="maybe")}, "status must be"),
    ({"payroll.salary": entry(suggested_by="gpt")}, "suggested_by"),
    ({"payroll.salary": entry(evidence="78000 é")}, "printable ASCII"),
    ({"payroll.salary": entry(evidence="x" * 201)}, "at most 200"),
    ({"payroll.salary": entry(confidence=1.5)}, "confidence"),
    ({"payroll.salary": entry(status="approved")}, "needs approved_by"),
    ({"payroll.salary": entry(status="approved", approved_by="master",
                              approved_at="yesterday")}, "ISO 8601"),
    ({"payroll.salary": entry(status="approved", category=None,
                              approved_by="master",
                              approved_at=NOW.isoformat())}, "needs a category"),
    ({"payroll.salary": entry(approved_by="master")}, "suggested column has no"),
    ({"payroll.salary": dict(entry(), value="78000")}, "unknown field"),
])
def test_invalid_columns_are_refused(columns, message):
    with pytest.raises(CatalogError, match=message):
        parse_catalog(catalog_json(**columns), SCHEMA)


@pytest.mark.parametrize("mutate, message", [
    (lambda c: c["categories"].update({"9bad": {"description": "x",
                                                "sensitivity": "low"}}),
     "invalid category name"),
    (lambda c: c["categories"]["pay"].update(sensitivity="secret"),
     "sensitivity must be"),
    (lambda c: c.update(version=2), "version must be 1"),
    (lambda c: c.update(extra=1), "unknown field"),
])
def test_invalid_catalog_shape_is_refused(mutate, message):
    c = new_catalog().to_json()
    mutate(c)
    with pytest.raises(CatalogError, match=message):
        parse_catalog(json.dumps(c))


def test_not_json_is_refused():
    with pytest.raises(CatalogError, match="not valid JSON"):
        parse_catalog("{")


# ---- merging -----------------------------------------------------------------

def test_merge_never_overwrites_human_decisions():
    c = new_catalog()
    c.columns["payroll.salary"] = ColumnEntry(
        "pay", "approved", "name-rule:pay", "x", 0.9, "master", NOW.isoformat())
    c.columns["payroll.id"] = ColumnEntry(
        "pay", "rejected", "name-rule:id_column", "x", 0.4, "master",
        NOW.isoformat())
    c.columns["employees.id"] = ColumnEntry("other", "suggested", "human", "x")
    c.columns["employees.name"] = ColumnEntry("other", "suggested",
                                              "name-rule:none", "x")
    merged, result = merge_suggestions(c, [
        sug("payroll.salary", "contact", "value-rule:email"),
        sug("payroll.id", "pay"),
        sug("employees.id", "directory"),
        sug("employees.name", "directory", "name-rule:directory"),
    ])
    assert merged.columns["payroll.salary"] == c.columns["payroll.salary"]
    assert merged.columns["payroll.id"] == c.columns["payroll.id"]
    assert merged.columns["employees.id"] == c.columns["employees.id"]
    assert merged.columns["employees.name"].category == "directory"
    assert sorted(result.kept) == ["employees.id", "payroll.id",
                                   "payroll.salary"]
    assert result.updated == ["employees.name"] and result.added == []
    assert c.columns["employees.name"].category == "other"  # input unchanged


def test_merge_adds_missing_default_category():
    c = new_catalog()
    del c.categories["pay"]
    merged, result = merge_suggestions(c, [sug("payroll.salary", "pay")])
    assert merged.categories["pay"]["sensitivity"] == "high"
    assert result.added == ["payroll.salary"]


# ---- decisions ---------------------------------------------------------------

def suggested_catalog():
    c, _ = merge_suggestions(new_catalog(), [
        sug("payroll.salary", "pay"), sug("payroll.id", "pay"),
        sug("employees.name", "directory"),
        sug("employees.id", None, "name-rule:none", "no name rule matched", 0)])
    return c


def test_approve_suggested_category_and_override():
    c = suggested_catalog()
    plan = plan_approvals(c, SCHEMA, {"payroll.salary": None,
                                      "employees.name": "contact"})
    out = apply_decisions(c, plan, "master", NOW)
    s = out.columns["payroll.salary"]
    assert (s.status, s.category, s.suggested_by, s.approved_by) == (
        "approved", "pay", "name-rule:pay", "master")
    assert s.approved_at == NOW.isoformat()
    n = out.columns["employees.name"]
    assert (n.category, n.suggested_by) == ("contact", "human")
    assert c.columns["payroll.salary"].status == "suggested"  # pure


def test_approve_all_suggested_skips_uncategorized():
    c = suggested_catalog()
    plan = plan_approvals(c, SCHEMA, all_suggested=True)
    assert [d.column for d in plan] == ["employees.name", "payroll.id",
                                        "payroll.salary"]


@pytest.mark.parametrize("columns, message", [
    ({"employees.id": None}, "no suggested category"),
    ({"payroll.salary": "perks"}, "Unknown category"),
    ({"payroll.bonus": "pay"}, "Unknown column"),
    ({}, "Nothing to approve"),
])
def test_approve_refusals(columns, message):
    with pytest.raises(CatalogError, match=message):
        plan_approvals(suggested_catalog(), SCHEMA, columns)


def test_already_approved_and_reject():
    c = apply_decisions(suggested_catalog(), plan_approvals(
        suggested_catalog(), SCHEMA, {"payroll.salary": None}), "master", NOW)
    with pytest.raises(CatalogError, match="already approved"):
        plan_approvals(c, SCHEMA, {"payroll.salary": "pay"})
    out = apply_decisions(c, plan_rejections(c, SCHEMA, ["payroll.salary",
                                                         "employees.id"]),
                          "master", NOW)
    assert out.columns["payroll.salary"].status == "rejected"
    assert out.columns["employees.id"].status == "rejected"
    with pytest.raises(CatalogError, match="already rejected"):
        plan_rejections(out, SCHEMA, ["payroll.salary"])
    with pytest.raises(CatalogError, match="Invalid actor"):
        apply_decisions(c, [], "bad actor!", NOW)


def test_status_counts():
    c = suggested_catalog()
    c = apply_decisions(c, plan_approvals(
        c, SCHEMA, {"payroll.salary": None, "payroll.id": None}), "master", NOW)
    st = catalog_status(c, SCHEMA)
    assert (st.approved, st.suggested, st.rejected, st.unlabelled) == (2, 1, 0, 1)
    assert st.approved_tables == ["payroll"]
    assert st.partial_tables == {"employees": (0, 2)}
    assert st.unlabelled_columns == ["employees.id"]
    assert st.hidden == 2


# ---- saving ------------------------------------------------------------------

def test_save_is_atomic_and_refuses_stale(tmp_path):
    path = tmp_path / "onboarding" / "catalog.json"
    c, sha = load_catalog(path, SCHEMA)
    assert sha is None and c.columns == {}
    sha = save_catalog(path, suggested_catalog(), None)
    loaded, sha2 = load_catalog(path, SCHEMA)
    assert sha2 == sha and loaded.to_json() == suggested_catalog().to_json()
    with pytest.raises(CatalogError, match="changed since"):
        save_catalog(path, new_catalog(), None)
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(CatalogError, match="changed since"):
        save_catalog(path, new_catalog(), sha)
    assert not (path.parent / ONBOARDING_LOCK).exists()
    assert [p.name for p in path.parent.iterdir()] == ["catalog.json"]


def test_save_waits_for_the_lock(tmp_path, monkeypatch):
    from rbic import admin
    monkeypatch.setattr(admin, "LOCK_TIMEOUT_S", 0.2)
    path = tmp_path / "catalog.json"
    (tmp_path / ONBOARDING_LOCK).write_text("1\n")
    with pytest.raises(ValueError, match="Another catalog change"):
        save_catalog(path, new_catalog(), None)
    assert not path.exists()
