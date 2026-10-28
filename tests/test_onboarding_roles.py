"""rbic.onboarding.roles: roles.json validation, edits, safe saving, and
the starter packs (shipped, instantiated by column name, merged without
overwriting human edits)."""

import json
from datetime import datetime, timezone

import pytest

from rbic.onboarding import ONBOARDING_LOCK, roles_path
from rbic.onboarding.catalog import (ColumnEntry, merge_suggestions,
                                     new_catalog, plan_approvals)
from rbic.onboarding.catalog import apply_decisions as decide
from rbic.onboarding.suggest import suggest_categories
from rbic.onboarding.roles import (
    RoleDef, Roles, RolesError, RowScope, add_scope, instantiate_pack,
    list_packs, load_pack, load_roles, merge_pack, parse_pack, parse_roles,
    remove_role, remove_scope, save_roles, set_role)

SCHEMA = {
    "employees": {"id": "int", "name": "text", "dept": "text", "salary": "numeric"},
    "payroll": {"id": "int", "employee_id": "int", "salary": "numeric"},
    "bonuses": {"id": "int", "staff_no": "int", "amount": "numeric"},
    "trainings": {"id": "int", "title": "text"},
}
USERS = ("alice", "bob", "master")
NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)


def catalog(**columns):
    c = new_catalog()
    for key, (cat, status) in columns.items():
        c.columns[key.replace("__", ".")] = ColumnEntry(
            cat, status, "human", "",
            approved_by="master" if status != "suggested" else None,
            approved_at="2026-10-27T00:00:00+00:00" if status != "suggested"
            else None)
    return c


CAT = catalog(employees__id=("directory", "approved"),
              employees__name=("directory", "approved"),
              employees__dept=("directory", "approved"),
              employees__salary=("pay", "approved"),
              payroll__id=("pay", "approved"),
              payroll__employee_id=("pay", "approved"),
              payroll__salary=("pay", "approved"),
              bonuses__id=("pay", "approved"),
              bonuses__staff_no=("pay", "approved"),
              bonuses__amount=("pay", "suggested"),
              trainings__id=("training", "approved"),
              trainings__title=("training", "rejected"))


def doc(roles, packs=()):
    return json.dumps({"version": 1, "roles": roles, "packs": list(packs)})


def parse(roles, packs=()):
    return parse_roles(doc(roles, packs), catalog=CAT, schema=SCHEMA,
                       usernames=USERS)


GOOD = {"description": "HR staff", "categories": ["directory"],
        "inherits": [], "source": "human",
        "row_scopes": [{"table": "employees", "template": "dept = '{dept}'"},
                       {"table": "payroll",
                        "template": "employee_id = '{employee_id}'",
                        "columns": ["employee_id", "salary"]}]}


def test_parse_and_round_trip():
    roles = parse({"hr_staff": GOOD}, ["hr@1"])
    role = roles.roles["hr_staff"]
    assert role.row_scopes == [
        RowScope("employees", "dept = '{dept}'"),
        RowScope("payroll", "employee_id = '{employee_id}'",
                 ("employee_id", "salary"))]
    again = parse_roles(roles.to_text(), catalog=CAT, schema=SCHEMA)
    assert again.to_json() == roles.to_json()


@pytest.mark.parametrize("roles, message", [
    ({"master": {}}, "master"),
    ({"user:alice": {}}, "user subject"),
    ({"alice": {}}, "username"),
    ({"HR": {}}, "invalid role name"),
    ({"a": {}}, "invalid role name"),
    ({"hr": {"color": "red"}}, "unknown field"),
    ({"hr": {"inherits": ["ghost"]}}, "does not define"),
    ({"hr": {"inherits": ["hr"]}}, "itself"),
    ({"aa": {"inherits": ["bb"]}, "bb": {"inherits": ["aa"]}}, "cycle"),
    ({"hr": {"inherits": ["master"]}}, "master"),
    ({"hr": {"categories": ["perks"]}}, "unknown category"),
    ({"hr": {"categories": ["pay", "pay"]}}, "duplicates"),
    ({"hr": {"source": "llm"}}, "source"),
    ({"hr": {"description": "tab\there"}}, "printable"),
    ({"hr": {"row_scopes": [{"table": "ghost", "template": "id = 1"}]}},
     "unknown table"),
    ({"hr": {"row_scopes": [{"table": "employees", "template": "nope = 1"}]}},
     "nope"),
    ({"hr": {"row_scopes": [{"table": "employees",
                             "template": "id IN (SELECT id FROM payroll)"}]}},
     "subqueries"),
    ({"hr": {"row_scopes": [{"table": "employees",
                             "template": "dept = '{dept}' -- x"}]}}, "comment"),
    ({"hr": {"row_scopes": [{"table": "employees", "template": "id = id"}]}},
     "always true"),
    ({"hr": {"row_scopes": [{"table": "employees", "template": "1 = 1"}]}},
     "compare"),
    ({"hr": {"row_scopes": [{"table": "employees", "template": "id = 1",
                             "columns": ["bonus"]}]}}, "bonus"),
    ({"hr": {"row_scopes": [{"table": "employees", "template": "id = 1",
                             "columns": []}]}}, "must not be empty"),
    ({"hr": {"row_scopes": [{"table": "employees", "template": "id = 1"},
                            {"table": "employees", "template": "id = 1"}]}},
     "duplicates"),
])
def test_validation_refusals(roles, message):
    with pytest.raises(RolesError, match=message):
        parse(roles)


@pytest.mark.parametrize("text, message", [
    ('{"version": 2, "roles": {}}', "version"),
    ('{"version": 1, "roles": {}, "extra": 1}', "unknown field"),
    ('{"version": 1, "roles": {}, "packs": ["hr"]}', "name@version"),
    ('{"version": 1, "roles": {}, "packs": ["hr@1", "hr@2"]}', "twice"),
    ('[]', "object"), ('{', "JSON"),
])
def test_document_refusals(text, message):
    with pytest.raises(RolesError, match=message):
        parse_roles(text)


# ---- edits --------------------------------------------------------------------------

def test_edits_make_a_role_human_owned():
    roles = Roles({"hr": RoleDef("x", ["directory"], [], [], "pack:hr")})
    with pytest.raises(RolesError, match="--categories"):
        set_role(roles, "new")
    new, lines = set_role(roles, "hr", inherits=[])
    assert lines[0] == "update role hr (was pack:hr)" and new.roles["hr"].source == "human"
    roles2, _ = add_scope(roles, "hr", RowScope("employees", "dept = '{dept}'"))
    assert roles2.roles["hr"].source == "human"
    assert roles.roles["hr"].source == "pack:hr"  # pure: input untouched
    with pytest.raises(RolesError, match="already has"):
        add_scope(roles2, "hr", RowScope("employees", "dept = '{dept}'"))
    roles3, lines = remove_scope(roles2, "hr", RowScope("employees",
                                                        "dept = '{dept}'"))
    assert any("ALL rows" in l for l in lines)
    with pytest.raises(RolesError, match="has no"):
        remove_scope(roles3, "hr", RowScope("employees", "dept = '{dept}'"))
    base = Roles({"hr": RoleDef(categories=["directory"]),
                  "mgr": RoleDef(inherits=["hr"])})
    with pytest.raises(RolesError, match="inherited by mgr"):
        remove_role(base, "hr")
    assert "mgr" not in remove_role(base, "mgr")[0].roles


def test_save_is_stale_safe_and_validated(tmp_path):
    path = tmp_path / "onboarding" / "roles.json"
    roles = parse({"hr_staff": GOOD})
    sha = save_roles(path, roles, None, catalog=CAT, schema=SCHEMA)
    loaded, sha2 = load_roles(path, catalog=CAT, schema=SCHEMA)
    assert sha2 == sha and loaded.to_json() == roles.to_json()
    before = path.read_bytes()
    with pytest.raises(RolesError, match="changed since"):
        save_roles(path, Roles(), None)
    bad = roles.copy()
    bad.roles["hr_staff"].categories = ["perks"]
    with pytest.raises(RolesError, match="unknown category"):
        save_roles(path, bad, sha, catalog=CAT, schema=SCHEMA)
    assert path.read_bytes() == before
    assert sorted(p.name for p in path.parent.iterdir()) == ["roles.json"]
    assert not (path.parent / ONBOARDING_LOCK).exists()


# ---- starter packs ----------------------------------------------------------------

def test_shipped_packs():
    assert list_packs() == ["finance", "hr", "people_manager",
                            "staff_self_service", "warehouse"]
    defaults = set(new_catalog().categories)
    for name in list_packs():
        pack = load_pack(name)
        assert pack.ref == f"{name}@1"
        for role in pack.roles.values():
            assert set(role.categories) <= defaults
            for rule in role.scopes:
                assert set(rule.grant_categories or ()) <= defaults
    assert load_pack("hr").roles["hr_manager"].inherits == ["hr_staff"]
    with pytest.raises(RolesError, match="unknown starter pack"):
        load_pack("../hr")


@pytest.mark.parametrize("text, message", [
    ('{"format": 2, "name": "x1", "version": "1", "roles": {"r1": {}}}', "format"),
    ('{"format": 1, "name": "x1", "version": "1", "roles": {"r1": '
     '{"inherits": ["zz"]}}}', "does not define"),
    ('{"format": 1, "name": "x1", "version": "1", "roles": {"r1": '
     '{"row_scopes": [{"ownership_columns": ["dept"], "template": "dept = 1"}]}}}',
     "\\$column"),
    ('{"format": 1, "name": "x1", "version": "1", "roles": {"master": {}}}',
     "master"),
])
def test_pack_validation(text, message):
    with pytest.raises(RolesError, match=message):
        parse_pack(text, "x1")


def test_pack_skips_tables_without_the_ownership_column():
    roles, notes = instantiate_pack(load_pack("hr"), CAT, SCHEMA)
    staff, mgr = roles["hr_staff"], roles["hr_manager"]
    # employees has dept; trainings (training) has no dept column
    assert staff.row_scopes == [RowScope("employees", "dept = '{dept}'")]
    assert any("hr_staff: no row scope on trainings" in n and "ALL rows" in n
               for n in notes)
    # pay lives in employees (no employee_id), payroll (yes), bonuses (no)
    assert mgr.row_scopes == [RowScope(
        "payroll", "employee_id IN ({self_and_subordinate_ids})")]
    assert any("hr_manager: no row scope on bonuses" in n for n in notes)
    assert any("hr_manager: no row scope on employees" in n for n in notes)
    assert mgr.source == "pack:hr"


def test_self_service_is_a_scoped_grant_on_owned_tables_only():
    roles, notes = instantiate_pack(load_pack("staff_self_service"), CAT, SCHEMA)
    # columns of the pay category (not rejected) of payroll only
    assert roles["employee"].row_scopes == [RowScope(
        "payroll", "employee_id = '{employee_id}'",
        ("id", "employee_id", "salary"))]
    assert roles["employee"].categories == []
    assert {n.split(" - ")[0] for n in notes} == {
        "employee: no self-service grant on employees",
        "employee: no self-service grant on bonuses"}


def test_every_pack_scope_uses_an_existing_ownership_column(demo_dir):
    schema = json.loads((demo_dir / "db_schema.json").read_text(encoding="utf-8"))
    merged, _ = merge_suggestions(new_catalog(), suggest_categories(
        schema, use_values=False))
    catalog = decide(merged, plan_approvals(merged, schema, all_suggested=True),
                     "master", NOW)
    for name in list_packs():
        pack = load_pack(name)
        roles, _ = instantiate_pack(pack, catalog, schema)
        for rname, role in roles.items():
            owners = {c for r in pack.roles[rname].scopes
                      for c in r.ownership_columns}
            for scope in role.row_scopes:
                assert owners & set(schema[scope.table]), (name, scope)


def test_pack_with_unknown_category_is_refused():
    c = new_catalog()
    del c.categories["pay"]
    with pytest.raises(RolesError, match="pay"):
        instantiate_pack(load_pack("hr"), c, SCHEMA)


def test_merge_never_overwrites_human_or_other_pack_roles():
    roles, result = merge_pack(Roles(), load_pack("hr"), CAT, SCHEMA, USERS)
    assert sorted(result.added) == ["hr_manager", "hr_staff"]
    assert roles.packs == ["hr@1"]
    # re-adding the same pack: unchanged
    again, result = merge_pack(roles, load_pack("hr"), CAT, SCHEMA, USERS)
    assert sorted(result.unchanged) == ["hr_manager", "hr_staff"]
    # a human edit is kept and reported
    edited, _ = set_role(roles, "hr_staff", categories=["directory"])
    merged, result = merge_pack(edited, load_pack("hr"), CAT, SCHEMA, USERS)
    assert [n for n, _ in result.conflicts] == ["hr_staff"]
    assert merged.roles["hr_staff"].categories == ["directory"]
    assert merged.roles["hr_staff"].source == "human"
    # a pack-owned role is refreshed when the catalog changed
    cat2 = catalog(**{k.replace(".", "__"): (e.category, e.status)
                      for k, e in CAT.columns.items()},
                   trainings__dept=("training", "approved"))
    schema2 = dict(SCHEMA, trainings={"id": "int", "title": "text",
                                      "dept": "text"})
    refreshed, result = merge_pack(roles, load_pack("hr"), cat2, schema2, USERS)
    assert result.updated == ["hr_staff"]
    assert RowScope("trainings", "dept = '{dept}'") in \
        refreshed.roles["hr_staff"].row_scopes


def test_merge_refuses_a_role_named_like_a_user():
    with pytest.raises(RolesError, match="username"):
        merge_pack(Roles(), load_pack("people_manager"), CAT, SCHEMA,
                   ("manager",))


def test_roles_file_lives_in_onboarding(demo_dir):
    assert roles_path(demo_dir) == demo_dir / "onboarding" / "roles.json"
