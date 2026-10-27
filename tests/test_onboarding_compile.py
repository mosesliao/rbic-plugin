"""rbic.onboarding.compile + the rbic-init block + PolicyAdmin's
generated_policy proposals: only approved columns, never table.*, block
replacement that keeps every outside line, malformed markers refused,
the master bot never edits generated lines, stale sources refused at
proposal and apply time, gate-load and filter-binding refusals, undo."""

import json
import logging
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from onboarding_demo import (MANUAL_POLICY, admin, approve_catalog, build_roles,
                             compile_change, config, load_state, onboard_demo,
                             save)
from rbic.admin import CHANGES_HEADER, STALE_MESSAGE
from rbic.onboarding import catalog_path, roles_path
from rbic.onboarding.block import (BEGIN_MARKER, END_MARKER,
                                   GENERATED_RULE_MESSAGE, BlockError,
                                   find_block, outside_lines,
                                   replace_block)
from rbic.onboarding.catalog import (apply_decisions, load_catalog,
                                     plan_rejections, save_catalog)
from rbic.onboarding.compile import (CompileError, GeneratedPolicy, _line,
                                     build_policy_text, compile_from_files,
                                     compile_policy)
from rbic.onboarding.roles import RowScope, add_scope, set_role
from test_onboarding_roles import CAT, SCHEMA, parse

logging.disable(logging.CRITICAL)


def rules_of(gen):
    return [", ".join(r) for r in gen.rules]


# ---- compile_policy ------------------------------------------------------------

def test_only_approved_columns_and_never_table_star():
    roles = parse({
        "hr_staff": {"categories": ["directory", "training"],
                     "row_scopes": [{"table": "employees",
                                     "template": "dept = '{dept}'"}]},
        "payroll_clerk": {"categories": ["pay"], "inherits": ["hr_staff"],
                          "row_scopes": [{"table": "payroll",
                                          "template": "id = 1"}]}})
    gen = compile_policy(CAT, roles, SCHEMA)
    rules = rules_of(gen)
    assert not any(".*" in r for r in rules)
    assert "p, hr_staff, employees.name, read" in rules
    assert "p, hr_staff, trainings.id, read" in rules
    assert "p, hr_staff, trainings.title, read" not in rules     # rejected
    assert "p, payroll_clerk, bonuses.staff_no, read" in rules
    assert "p, payroll_clerk, bonuses.amount, read" not in rules  # suggested
    assert "g, payroll_clerk, hr_staff" in rules
    assert "p2, hr_staff, employees, dept = '{dept}'" in rules
    assert {"trainings.title (rejected)", "bonuses.amount (suggested)"} <= \
        set(gen.hidden)
    # deterministic, role by role: comment, g, p (schema order), p2
    assert gen.body[0] == "# role hr_staff (human)"
    assert compile_policy(CAT, roles, SCHEMA).body == gen.body


def test_scoped_grants_keep_approved_columns_only():
    roles = parse({"employee": {"row_scopes": [
        {"table": "bonuses", "template": "staff_no = '{employee_id}'",
         "columns": ["staff_no", "amount"]},
        {"table": "trainings", "template": "id = 1", "columns": ["title"]}]}})
    gen = compile_policy(CAT, roles, SCHEMA)
    assert rules_of(gen) == [
        "p2, employee, bonuses, staff_no = '{employee_id}', staff_no"]
    text = "\n".join(gen.warnings)
    assert "leaves out not-approved column(s) amount" in text
    assert "scoped grant on trainings has no approved column and is skipped" \
        in text


def test_warnings():
    roles = parse({
        "a_reader": {"categories": ["pay", "finance"]},
        "b_scoped": {"categories": ["pay"],
                     "row_scopes": [{"table": "payroll",
                                     "template": "employee_id = '{eid}'"}]}})
    text = "\n".join(compile_policy(CAT, roles, SCHEMA).warnings)
    assert "role a_reader: category finance has no approved column" in text
    assert ("role a_reader reads payroll on ALL rows (no row scope in its "
            "role level), while b_scoped has a row scope on payroll") in text
    assert ("role a_reader reads high-sensitivity column(s) "
            "payroll.(id, employee_id, salary) on ALL rows") in text
    # b_scoped's payroll is scoped; its employees.salary is not
    assert "role b_scoped reads high-sensitivity column(s) employees.(salary)" \
        in text
    assert "role b_scoped reads high-sensitivity column(s) payroll" not in text


def test_inherited_scope_counts_for_the_role_level():
    roles = parse({
        "base": {"categories": ["directory"],
                 "row_scopes": [{"table": "employees",
                                 "template": "dept = '{dept}'"}]},
        "mgr": {"categories": ["pay"], "inherits": ["base"]}})
    text = "\n".join(compile_policy(CAT, roles, SCHEMA).warnings)
    assert "mgr reads high-sensitivity column(s) employees" not in text
    assert "mgr reads high-sensitivity column(s) payroll" in text


def test_role_named_like_a_user_is_refused():
    with pytest.raises(CompileError, match="username"):
        compile_policy(CAT, parse({"hr": {}}), SCHEMA, usernames=["hr"])


def test_rules_must_round_trip_casbins_tokenizer():
    assert _line(["p2", "r1", "t", "id IN (1, 2)"]) == "p2, r1, t, id IN (1, 2)"
    with pytest.raises(CompileError, match="round-trip"):
        _line(["p2", "r1", "t", "a = 1, b = 2"])


# ---- the block -----------------------------------------------------------------

OUTSIDE = ("# head comment\r\n"
           "p, hr_staff, employees.id, read\r\n"
           "\r\n"
           f"{CHANGES_HEADER}\r\n"
           "p3, hr_staff, employees.dept, read\r\n")


def test_insert_before_master_section_then_replace_keeps_outside_bytes():
    first = replace_block(OUTSIDE, ["p, a1, t.c, read"],
                          before_header=CHANGES_HEADER)
    assert first == ("# head comment\r\np, hr_staff, employees.id, read\r\n\r\n"
                     f"{BEGIN_MARKER}\r\np, a1, t.c, read\r\n{END_MARKER}\r\n"
                     f"{CHANGES_HEADER}\r\np3, hr_staff, employees.dept, read\r\n")
    second = replace_block(first, ["p, b2, t.d, read", "p, b2, t.e, read"])
    assert "".join(outside_lines(second)) == OUTSIDE
    begin, end = find_block(second)
    assert second.split("\n")[begin + 1:end] == ["p, b2, t.d, read\r",
                                                 "p, b2, t.e, read\r"]


def test_insert_at_end_without_master_section():
    assert replace_block("p, x1, t.c, read", ["p, a1, t.c, read"]) == (
        f"p, x1, t.c, read\n{BEGIN_MARKER}\np, a1, t.c, read\n{END_MARKER}\n")
    assert replace_block("", []) == f"{BEGIN_MARKER}\n{END_MARKER}\n"


@pytest.mark.parametrize("text, message", [
    (f"{BEGIN_MARKER}\n{BEGIN_MARKER}\n{END_MARKER}\n", "at most one"),
    (f"{BEGIN_MARKER}\n", "at most one"),
    (f"{END_MARKER}\n", "at most one"),
    (f"{END_MARKER}\n{BEGIN_MARKER}\n", "before its BEGIN"),
    ("# ---- BEGIN rbic init (generated) ----\n", "malformed"),
    ("#  ----  END  rbic init ----\n", "malformed"),
])
def test_malformed_markers_are_refused(text, message):
    with pytest.raises(BlockError, match=message):
        find_block(text)
    with pytest.raises(BlockError):
        build_policy_text(text, GeneratedPolicy(["p, a1, t.c, read"], []))


def test_duplicate_of_an_outside_rule_stays_outside():
    gen = GeneratedPolicy(["# role hr_staff (human)",
                           "p, hr_staff, employees.id, read",
                           "p, hr_staff, employees.name, read"], [])
    text, notes = build_policy_text(OUTSIDE, gen)
    begin, end = find_block(text)
    block = text.split("\n")[begin:end + 1]
    assert "p, hr_staff, employees.name, read\r" in block
    assert "p, hr_staff, employees.id, read\r" not in block
    assert notes == ["rule 'p, hr_staff, employees.id, read' already exists in "
                     "policy.csv outside the rbic-init block; kept there and "
                     "left out of the block"]


# ---- PolicyAdmin: proposals, staleness, apply, undo -----------------------------

@pytest.fixture
def onboarded(demo_dir):
    onboard_demo(demo_dir)
    return demo_dir


def test_generated_change_records_every_source(demo_dir):
    approve_catalog(demo_dir)
    build_roles(demo_dir)
    gen, change = compile_change(demo_dir)
    assert change.kind == "generated_policy"
    assert set(change.input_hashes) == {"policy", "attributes", "schema", "model",
                                        "extra:catalog", "extra:roles"}
    assert set(gen.sources) == {"catalog", "roles", "schema", "attributes"}
    assert "Effects:" in change.description
    assert "warehouse_worker [users: alice]:" in change.description
    # the shipped hand-written rules are duplicates: kept outside the block
    assert "already exists in policy.csv outside the rbic-init block" \
        in change.description


@pytest.mark.parametrize("touch", ["catalog", "roles"])
def test_source_changed_after_proposal_is_refused_at_apply(demo_dir, touch):
    approve_catalog(demo_dir)
    build_roles(demo_dir)
    _, change = compile_change(demo_dir)
    path = catalog_path(demo_dir) if touch == "catalog" else roles_path(demo_dir)
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    before = (demo_dir / "casbin" / "policy.csv").read_bytes()
    with pytest.raises(ValueError, match=STALE_MESSAGE):
        admin(demo_dir).apply(change, actor="master")
    assert (demo_dir / "casbin" / "policy.csv").read_bytes() == before


@pytest.mark.parametrize("touch", ["catalog", "roles", "db_schema.json",
                                   "worker_attributes.json"])
def test_source_changed_after_compile_is_refused_at_proposal(demo_dir, touch):
    approve_catalog(demo_dir)
    build_roles(demo_dir)
    cfg = config(demo_dir)
    gen = compile_from_files(demo_dir, cfg.schema_path, cfg.attributes_path)
    path = {"catalog": catalog_path(demo_dir),
            "roles": roles_path(demo_dir)}.get(touch, demo_dir / touch)
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="changed since this policy was compiled"):
        admin(demo_dir).propose_generated_policy(gen, actor="master")


def test_result_that_the_gate_refuses_is_refused(demo_dir):
    approve_catalog(demo_dir)
    build_roles(demo_dir)
    cfg = config(demo_dir)
    gen = compile_from_files(demo_dir, cfg.schema_path, cfg.attributes_path)
    bad = replace(gen, body=[*gen.body,
                             "p2, hr_staff, employees, id IN (SELECT 1)"])
    with pytest.raises(ValueError, match="would not load in the SQL gate"):
        admin(demo_dir).propose_generated_policy(bad, actor="master")


def test_every_users_filters_are_bound_against_the_result(demo_dir):
    approve_catalog(demo_dir)
    build_roles(demo_dir)
    schema, catalog, users, roles, sha = load_state(demo_dir)
    # bob's dept ("engineering") can't bind into an unquoted placeholder
    roles, _ = add_scope(roles, "hr_staff",
                         RowScope("leave_requests", "employee_id IN ({dept})"))
    save(demo_dir, roles, sha)
    with pytest.raises(ValueError, match="unquoted placeholder needs a number"):
        compile_change(demo_dir)


def test_nothing_to_change_and_undo(onboarded):
    policy = onboarded / "casbin" / "policy.csv"
    with pytest.raises(ValueError, match="already holds exactly"):
        compile_change(onboarded)
    a = admin(onboarded)
    undo = a.propose_undo(actor="master")
    a.apply(undo, actor="master")
    assert policy.read_text(encoding="utf-8") == MANUAL_POLICY
    kinds = [json.loads(l)["kind"] for l in
             (onboarded / "policy_changes.jsonl").read_text(
                 encoding="utf-8").splitlines()]
    assert kinds == ["generated_policy", "generated_policy", "undo", "undo"]


def test_recompile_after_catalog_change_hides_rejected_column(onboarded):
    schema, *_ = load_state(onboarded)
    catalog, sha = load_catalog(catalog_path(onboarded), schema)
    plan = plan_rejections(catalog, schema, ["employees.start_date"])
    save_catalog(catalog_path(onboarded),
                 apply_decisions(catalog, plan, "master",
                                 datetime.now(timezone.utc)), sha)
    gen, change = compile_change(onboarded)
    assert "p, hr_staff, employees.start_date, read" not in rules_of(gen)
    assert "loses read on employees.(start_date)" in change.description
    assert "employees.start_date (rejected)" in gen.hidden


# ---- the master bot and the block -----------------------------------------------

@pytest.mark.parametrize("call", [
    lambda a: a.propose_revoke(role="hr_staff", table="employees",
                               column="name", actor="master"),
    lambda a: a.propose_remove_row_scope(role="hr_staff", table="employees",
                                         filter_template="dept = '{dept}'",
                                         actor="master"),
    lambda a: a.propose_remove_inherit("hr_manager", "hr_staff", actor="master"),
    lambda a: a.propose_remove_row_scope(
        role="employee", table="payroll",
        filter_template="employee_id = '{employee_id}'",
        columns="id|employee_id|salary|effective_date", actor="master"),
])
def test_master_bot_refuses_to_edit_generated_rules(onboarded, call):
    before = (onboarded / "casbin" / "policy.csv").read_bytes()
    with pytest.raises(ValueError) as err:
        call(admin(onboarded))
    assert GENERATED_RULE_MESSAGE in str(err.value)
    assert (onboarded / "casbin" / "policy.csv").read_bytes() == before


def test_master_bot_additions_go_to_the_master_section(onboarded):
    a = admin(onboarded)
    change = a.propose_deny(role="hr_staff", table="employees", column="dept",
                            actor="master")
    a.apply(change, actor="master")
    text = (onboarded / "casbin" / "policy.csv").read_text(encoding="utf-8")
    begin, end = find_block(text)
    lines = text.split("\n")
    assert "p3, hr_staff, employees.dept, read" in lines[end + 1:]
    assert lines.index(CHANGES_HEADER) > end
    # and a master-bot rule outside the block can still be removed
    a = admin(onboarded)
    a.apply(a.propose_remove_deny(role="hr_staff", table="employees",
                                  column="dept", actor="master"), actor="master")
    # a recompile keeps the master section
    schema, catalog, users, roles, sha = load_state(onboarded)
    roles, _ = set_role(roles, "hr_staff", description="changed")
    save(onboarded, roles, sha)
    with pytest.raises(ValueError, match="already holds exactly"):
        compile_change(onboarded)  # a description is not a rule


def test_master_bot_refuses_with_malformed_markers(onboarded):
    policy = onboarded / "casbin" / "policy.csv"
    policy.write_text(policy.read_text(encoding="utf-8").replace(END_MARKER, ""),
                      encoding="utf-8")
    a = admin(onboarded)
    with pytest.raises(ValueError, match="rbic-init markers"):
        a.propose_grant(role="hr_staff", table="employees", column="salary",
                        actor="master")
    with pytest.raises(ValueError, match="markers"):
        compile_change(onboarded)


def test_master_system_prompt_explains_the_block(onboarded):
    from rbic.master import build_system_prompt
    prompt = build_system_prompt(admin(onboarded))
    assert "rbic-init block are generated" in prompt
    assert "rbic-init compile" in prompt
