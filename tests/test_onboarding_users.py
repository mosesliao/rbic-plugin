"""rbic-init import-users (rbic.onboarding.users + PolicyAdmin's user_import
change + the CLI): the HR / IdP channel that may set emails. CSV rules,
group map, derived team ids, masters untouched, fail-closed refusals with
row numbers and no values, stale apply, yes/no, undo, and no email ever
in the output or the audit log."""

import json
import logging
import shutil
from pathlib import Path

import pytest

from rbic import DENY_MESSAGE, Identity, RBICEngine
from rbic.admin import STALE_MESSAGE, PolicyAdmin
from rbic.config import resolve_config
from rbic.onboarding.users import (UserImportError, group_map_path,
                                   load_group_map, parse_csv, parse_group_map,
                                   plan_import, user_rules)
from test_cli_init import audit_lines, run

logging.disable(logging.CRITICAL)

DEMO_CSV = (
    "username,email,groups,employee_id,manager,dept,site\n"
    "alice,alice@example.test,Warehouse SG,6,,,SG-01\n"
    "bob,bob@example.test,HR Staff,1,carol,engineering,\n"
    "carol,carol@example.test,HR Staff;HR Managers,2,,engineering,\n"
    "dave,dave@example.test,Finance,7,,logistics,\n"
    "erin,erin@example.test,,3,carol,engineering,\n")
GROUP_MAP = {"version": 1, "map": [
    {"group": "HR Managers", "role": "hr_manager"},
    {"group": "HR Staff", "role": "hr_staff"},
    {"group": "Finance", "role": "finance_analyst"},
    {"group": "Warehouse SG", "role": "warehouse_worker"}]}
ROLES = {"hr_manager", "hr_staff", "finance_analyst", "warehouse_worker",
         "employee", "payroll_manager"}
DEMO_SOURCE_SAMPLE = (Path(__file__).resolve().parent.parent / "examples"
                      / "demo" / "onboarding-sample")
EMAILS = ("alice@example.test", "bob@example.test", "carol@example.test",
          "dave@example.test", "erin@example.test")


def cfg(d):
    return resolve_config(d, dialect="sqlite")


def admin(d):
    return PolicyAdmin.from_config(cfg(d))


def attrs(d):
    return json.loads((d / "worker_attributes.json").read_text(encoding="utf-8"))


def write_attrs(d, data):
    (d / "worker_attributes.json").write_text(json.dumps(data, indent=2) + "\n",
                                              encoding="utf-8")


@pytest.fixture
def fresh(demo_dir):
    """The demo with no workers but master, and the sample group map."""
    write_attrs(demo_dir, {"master": {"role": "master"}})
    path = group_map_path(demo_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(GROUP_MAP), encoding="utf-8")
    return demo_dir


def plan(d, text=DEMO_CSV, **kwargs):
    a = admin(d)
    parsed = parse_csv(text.encode("utf-8"))
    gm = parse_group_map(json.dumps(kwargs.pop("group_map", GROUP_MAP)),
                         known_roles=ROLES)
    return plan_import(attrs(d), parsed, gm, known_roles=ROLES,
                       rules_by_user=user_rules(a._enforcer()), **kwargs)


def import_(d, text=DEMO_CSV, **kwargs):
    p = plan(d, text, **kwargs)
    a = admin(d)
    change = a.propose_user_import(p.attributes, actor="master",
                                   headline=p.headline(), extra_notes=p.notes)
    a.apply(change, actor="master")
    return p, change


def refused(d, text, match, **kwargs):
    with pytest.raises(UserImportError, match=match) as err:
        plan(d, text, **kwargs)
    return str(err.value)


# ---- happy path ------------------------------------------------------------------

def test_csv_recreates_the_demo_users(fresh, demo_template):
    p, change = import_(fresh)
    got = attrs(fresh)
    shipped = json.loads((demo_template / "worker_attributes.json")
                         .read_text(encoding="utf-8"))
    for user in ("alice", "bob", "carol", "dave"):
        assert {k: v for k, v in got[user].items()
                if k != "self_and_subordinate_ids"} == \
            {k: v for k, v in shipped[user].items()
             if k != "self_and_subordinate_ids"}
    assert got["carol"]["self_and_subordinate_ids"] == "1, 2, 3"
    assert got["bob"]["self_and_subordinate_ids"] == "1"
    assert got["master"] == {"role": "master"}
    assert "role" not in got["erin"]
    assert p.added == ["alice", "bob", "carol", "dave", "erin"]
    assert p.unmapped == ["erin"]
    assert change.kind == "user_import"
    assert "carol (role hr_manager; also mapped: hr_staff)" in change.description
    assert "carol: new worker, role hr_manager; <email set>" in change.description
    for email in EMAILS:
        assert email not in change.description
    for value in ("SG-01", "engineering", "logistics"):
        assert value not in change.description
    # the gate serves the imported users
    from rbic.gate import SQLGate
    gate = SQLGate.from_config(cfg(fresh))
    assert "IN (1, 2, 3)" in gate.authorize(
        "carol", "SELECT employee_id, salary FROM payroll")


def test_shipped_sample_imports(fresh):
    sample = DEMO_SOURCE_SAMPLE
    shutil.copy(sample / "group_map.json", group_map_path(fresh))
    gm = load_group_map(group_map_path(fresh), known_roles=ROLES)
    parsed = parse_csv((sample / "hr_export.csv").read_bytes())
    p = plan_import(attrs(fresh), parsed, gm, known_roles=ROLES)
    assert p.attributes["carol"]["self_and_subordinate_ids"] == "1, 2, 3"
    assert all(r.email.endswith("@example.test") for r in parsed.rows)


def test_reimport_is_unchanged_and_keeps_uncovered_keys(fresh):
    import_(fresh)
    data = attrs(fresh)
    data["dave"]["clearance"] = "basic"   # set by the master bot, say
    write_attrs(fresh, data)
    p = plan(fresh)
    assert p.unchanged == ["alice", "bob", "carol", "dave", "erin"]
    assert p.attributes["dave"]["clearance"] == "basic"
    with pytest.raises(ValueError, match="already matches this import"):
        admin(fresh).propose_user_import(p.attributes, actor="master")


def test_updates_are_summarized_without_values(fresh):
    import_(fresh)
    text = (DEMO_CSV.replace("dave@example.test", "dave.chua@example.test")
            .replace("Finance,7,,logistics", "Finance,7,,finance"))
    p = plan(fresh, text)
    assert p.updated == ["dave"]
    change = admin(fresh).propose_user_import(p.attributes, actor="master")
    assert "dave: <email changed>; attributes changed: dept" in change.description
    assert "dave.chua" not in change.description
    assert "finance," not in change.description


def test_team_depth_all_is_transitive(fresh):
    text = DEMO_CSV.replace("dave,dave@example.test,Finance,7,,",
                            "dave,dave@example.test,Finance,7,bob,")
    assert plan(fresh, text).attributes["carol"]["self_and_subordinate_ids"] \
        == "1, 2, 3"
    deep = plan(fresh, text, team_depth="all").attributes
    assert deep["carol"]["self_and_subordinate_ids"] == "1, 2, 3, 7"
    assert deep["bob"]["self_and_subordinate_ids"] == "1, 7"


def test_semicolon_delimiter_with_pipe_groups_and_bom(fresh):
    text = "﻿" + DEMO_CSV.replace(",", ";").replace("HR Staff;HR Managers",
                                                         "HR Staff|HR Managers")
    p = plan(fresh, text)
    assert p.attributes["carol"]["role"] == "hr_manager"
    assert p.attributes["bob"]["role"] == "hr_staff"


def test_formula_like_values_are_plain_data(fresh):
    text = ("username,email,groups,note\n"
            "bob,bob@example.test,HR Staff,-5\n"
            "dave,dave@example.test,Finance,@team\n")
    p = plan(fresh, text)
    assert p.attributes["bob"]["note"] == "-5"
    assert p.attributes["dave"]["note"] == "@team"


# ---- refusals (row numbers, usernames, never values) ------------------------------

@pytest.mark.parametrize("value", ["=1+2", "+SUM(A1)", "=HYPERLINK(x)",
                                   "a;b", "tab\x0bvalue", "café"])
def test_invalid_values_are_refused_without_the_value(fresh, value):
    text = f"username,email,groups,note\nbob,bob@example.test,HR Staff,{value}\n"
    message = refused(fresh, text, r"row 2 \(bob\): column 'note' has an "
                                   "invalid value")
    assert value not in message


@pytest.mark.parametrize("header, message", [
    ("username,email,Dept-Name", "row 1 .header.: column 3 is not a valid"),
    ("username,email,dept,DEPT", "duplicate column"),
    ("username,groups", "required column 'email' is missing"),
    ("username,email,role", "a 'role' column is not allowed"),
    ("username,email,manager,self_and_subordinate_ids", "is derived"),
    ("username;email,dept", "cannot tell the delimiter"),
    ("username email", "cannot tell the delimiter"),
])
def test_invalid_headers_are_refused(fresh, header, message):
    refused(fresh, header + "\nbob,bob@example.test" + "," * 4 + "\n", message)


@pytest.mark.parametrize("email", [
    "carol@example.teſt",      # long s: casefolds onto "s"
    "bob@exämple.test",
    "аlice@example.test",      # Cyrillic a
    "dave@example.test ",      # NBSP is not stripped
    "not-an-email", ""])
def test_lookalike_and_invalid_emails_are_refused(fresh, email):
    text = f"username,email\nbob,{email}\n"
    message = refused(fresh, text, r"row 2 \(bob\): invalid or empty email")
    assert email.strip() == "" or email not in message


def test_duplicates_are_refused(fresh):
    text = ("username,email,employee_id\n"
            "bob,bob@example.test,1\n"
            "carol,BOB@example.test,2\n"
            "Bob,bob2@example.test,1\n")
    message = refused(fresh, text, "the import was refused")
    assert "row 3 (carol): email already used by row 2 (bob)" in message
    assert "row 4 (Bob): duplicate username (also row 2" in message
    assert "@" not in message.replace("row", "")


def test_duplicate_employee_ids_are_refused(fresh):
    text = "username,email,employee_id\nbob,b@example.test,1\ncarol,c@example.test,1\n"
    refused(fresh, text, r"row 3 \(carol\): employee_id already used by row 2")


def test_master_rows_are_refused(fresh):
    text = "username,email\nmaster,boss@example.test\nbob,bob@example.test\n"
    refused(fresh, text, r"row 2 \(master\): is a master user")
    text = "username,email\nMASTER,boss@example.test\n"
    refused(fresh, text, "is a master user")


def test_masters_are_kept_untouched_and_cannot_be_removed(fresh):
    p = plan(fresh, remove_missing=True)
    assert p.attributes["master"] == {"role": "master"}
    assert "master" not in p.removed


def test_username_equal_to_a_role_is_refused(fresh):
    refused(fresh, "username,email\nhr_staff,x@example.test\n",
            "also a role name")


def test_bad_rows_are_all_reported(fresh):
    text = ("username,email,employee_id\n"
            "bad name!,x@example.test,1\n"
            "bob,bob@example.test,12a\n"
            "carol,carol@example.test\n")
    message = refused(fresh, text, "the import was refused")
    assert "row 2: invalid or empty username" in message
    assert "bad name" not in message
    assert "row 3 (bob): employee_id must be digits only" in message
    assert "12a" not in message
    assert "row 4: has 2 field(s), the header has 3" in message


def test_not_utf8_is_refused(fresh):
    with pytest.raises(UserImportError, match="not UTF-8"):
        parse_csv("username,email\nb\xf6b,bob@example.test\n".encode("latin-1"))


@pytest.mark.parametrize("manager_col, message", [
    (("carol", "bob"), "manager cycle"),
    (("bob", ""), "manager cycle"),           # bob manages himself
    (("nobody", ""), "manager is not a username in this export"),
])
def test_manager_problems_are_refused(fresh, manager_col, message):
    text = ("username,email,employee_id,manager\n"
            f"bob,bob@example.test,1,{manager_col[0]}\n"
            f"carol,carol@example.test,2,{manager_col[1]}\n")
    refused(fresh, text, message)


def test_too_many_team_ids_are_refused(fresh):
    rows = ["boss,boss@example.test,1,"]
    rows += [f"w{i},w{i}@example.test,{100000 + i},boss" for i in range(40)]
    text = "username,email,employee_id,manager\n" + "\n".join(rows) + "\n"
    refused(fresh, text, r"\(boss\): self_and_subordinate_ids would list 41 ids")


@pytest.mark.parametrize("entry, message", [
    ({"group": "X", "role": "master"}, "master role cannot be assigned"),
    ({"group": "X", "role": "user:bob"}, "user subject"),
    ({"group": "X", "role": "ghost_role"}, "unknown role"),
    ({"group": "a;b", "role": "hr_staff"}, "no ';' or '|'"),
    ({"group": "", "role": "hr_staff"}, "printable name"),
    ({"group": "X"}, "exactly group and role"),
])
def test_group_map_is_validated(entry, message):
    with pytest.raises(UserImportError, match=message):
        parse_group_map(json.dumps({"version": 1, "map": [entry]}),
                        known_roles=ROLES)


def test_group_map_duplicates_and_shape():
    with pytest.raises(UserImportError, match="listed twice"):
        parse_group_map(json.dumps({"version": 1, "map": [
            {"group": "X", "role": "hr_staff"},
            {"group": "X", "role": "employee"}]}), known_roles=ROLES)
    with pytest.raises(UserImportError, match="version"):
        parse_group_map(json.dumps({"version": 2, "map": []}), known_roles=ROLES)
    with pytest.raises(UserImportError, match="is a username"):
        parse_group_map(json.dumps({"version": 1, "map": [
            {"group": "X", "role": "bobby"}]}), known_roles={"bobby"},
            usernames=["bobby"])


# ---- existing workers --------------------------------------------------------------

def test_missing_workers_are_kept_unless_remove_missing(demo_dir):
    text = "username,email,groups\nbob,bob@example.test,HR Staff\n"
    p = plan(demo_dir, text)
    assert p.kept_missing == ["alice", "carol", "dave"]
    assert set(p.attributes) == {"alice", "bob", "carol", "dave", "master"}
    removed = plan(demo_dir, text, remove_missing=True)
    assert removed.removed == ["alice", "carol", "dave"]
    assert set(removed.attributes) == {"bob", "master"}


def test_email_of_a_kept_worker_is_refused(demo_dir):
    text = "username,email,groups\nerin,carol@example.test,HR Staff\n"
    refused(demo_dir, text, "email already belongs to carol")


def test_remove_missing_refuses_workers_with_personal_rules(demo_dir):
    a = admin(demo_dir)
    a.apply(a.propose_grant(username="dave", table="employees", column="name",
                            actor="master"), actor="master")
    text = ("username,email,groups\nbob,bob@example.test,HR Staff\n"
            "alice,alice@example.test,Warehouse SG\n"
            "carol,carol@example.test,HR Managers\n")
    message = refused(demo_dir, text, "cannot remove dave", remove_missing=True)
    assert "p, user:dave, employees.name, read" in message


def test_unmapped_worker_has_no_role_and_is_denied(fresh):
    import_(fresh)
    engine = RBICEngine(cfg(fresh), client=object())
    result = engine.ask(Identity("openwebui", "sub-erin", "erin@example.test"),
                        [{"role": "user", "content": "show payslips"}])
    assert result.denied and result.text == DENY_MESSAGE
    assert result.reason == "identity: worker has no role"


def test_existing_worker_losing_every_group_loses_the_role(demo_dir):
    text = ("username,email,groups,employee_id,site\n"
            "alice,alice@example.test,,6,SG-01\n")
    p = plan(demo_dir, text)
    change = admin(demo_dir).propose_user_import(p.attributes, actor="master")
    assert "alice: role warehouse_worker -> NONE" in change.description
    assert "loses read on inventory" in change.description


# ---- PolicyAdmin machinery ------------------------------------------------------------

def test_stale_apply_is_refused(fresh):
    p = plan(fresh)
    a = admin(fresh)
    change = a.propose_user_import(p.attributes, actor="master")
    path = fresh / "worker_attributes.json"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match=STALE_MESSAGE):
        a.apply(change, actor="master")
    assert "carol" not in attrs(fresh)


def test_change_records_all_input_hashes(fresh):
    change = admin(fresh).propose_user_import(plan(fresh).attributes,
                                              actor="master")
    assert set(change.input_hashes) == {"policy", "attributes", "schema", "model"}


def test_proposal_refuses_what_the_gate_refuses(fresh):
    p = plan(fresh)
    bad = json.loads(json.dumps(p.attributes))
    bad["bob"]["email"] = "carol@example.test"    # duplicate email
    with pytest.raises(ValueError, match="share the same email"):
        admin(fresh).propose_user_import(bad, actor="master")
    bad = json.loads(json.dumps(p.attributes))
    bad["master"]["email"] = "boss@example.test"
    with pytest.raises(ValueError, match="Master users cannot be"):
        admin(fresh).propose_user_import(bad, actor="master")
    bad = json.loads(json.dumps(p.attributes))
    bad["carol"]["self_and_subordinate_ids"] = "1; 2"
    with pytest.raises(ValueError, match="carol.self_and_subordinate_ids: "
                                         "invalid attribute value") as err:
        admin(fresh).propose_user_import(bad, actor="master")
    assert "1; 2" not in str(err.value)
    bad["carol"]["self_and_subordinate_ids"] = "1, x"   # valid text, not ids
    with pytest.raises(ValueError, match="carol: an attribute value cannot "
                                         "be used in a row filter") as err:
        admin(fresh).propose_user_import(bad, actor="master")
    assert "1, x" not in str(err.value)


def test_row_filters_are_rebound_for_every_user(demo_dir):
    # dept is bound into an unquoted IN placeholder by this hand-made rule
    policy = demo_dir / "casbin" / "policy.csv"
    policy.write_text(policy.read_text(encoding="utf-8")
                      + "p2, hr_staff, leave_requests, employee_id IN "
                        "({employee_id})\n", encoding="utf-8")
    text = ("username,email,groups,employee_id,dept\n"
            "bob,bob@example.test,HR Staff,,engineering\n")
    p = plan(demo_dir, text)
    # bob without employee_id: the gate denies those queries (missing
    # attribute), which is allowed; a non-number would not be
    p.attributes["bob"]["employee_id"] = "1x"
    with pytest.raises(ValueError, match="bob: an attribute value cannot be "
                                         "used in a row filter") as err:
        admin(demo_dir).propose_user_import(p.attributes, actor="master")
    assert "1x" not in str(err.value)


def test_master_bot_cannot_undo_an_import_that_changed_emails(fresh):
    import_(fresh)
    with pytest.raises(ValueError, match="only that channel may do"):
        admin(fresh).propose_undo(actor="master")
    undo = admin(fresh).propose_undo(actor="master", identity_channel=True)
    assert "@" not in undo.description.replace("rbic-init", "")
    admin(fresh).apply(undo, actor="master")
    assert attrs(fresh) == {"master": {"role": "master"}}


def test_master_bot_may_undo_an_import_without_email_changes(demo_dir):
    text = ("username,email,groups,employee_id,site\n"
            "alice,alice@example.test,Finance,6,SG-01\n")
    import_(demo_dir, text)
    undo = admin(demo_dir).propose_undo(actor="master")
    assert "alice: role finance_analyst -> warehouse_worker" in undo.description
    admin(demo_dir).apply(undo, actor="master")
    assert attrs(demo_dir)["alice"]["role"] == "warehouse_worker"


def test_identity_channel_undo_only_undoes_imports(demo_dir):
    a = admin(demo_dir)
    a.apply(a.propose_assign_role("bob", "hr_manager", actor="master"),
            actor="master")
    with pytest.raises(ValueError, match="is not a user import"):
        admin(demo_dir).propose_undo(actor="master", identity_channel=True)


# ---- CLI ------------------------------------------------------------------------------

def cli(d, csv_text=DEMO_CSV, extra=(), answers=("yes",)):
    path = d / "export.csv"
    path.write_text(csv_text, encoding="utf-8")
    return run(["import-users", "--config-dir", str(d), "--csv", str(path),
                "--actor", "master", "--audit-log", str(d / "audit.jsonl"),
                *extra], answers)


def test_cli_import_yes_applies_and_never_shows_emails(fresh, audit_on, capsys):
    code, out = cli(fresh, answers=("maybe", "YES"))
    assert code == 0
    text = "\n".join(out)
    assert out.count("Apply? [yes/no]: ") == 2          # "maybe" re-asks
    assert "APPLIED" in text
    assert "carol: new worker, role hr_manager; <email set>" in text
    lines = audit_lines(fresh / "audit.jsonl")
    assert any(l.startswith("POLICY_CONFIRM") and "decision=confirmed" in l
               for l in lines)
    assert any(l.startswith("POLICY_CHANGE") and "kind=user_import" in l
               for l in lines)
    everything = text + capsys.readouterr().err + \
        (fresh / "audit.jsonl").read_text(encoding="utf-8")
    for email in EMAILS:
        assert email not in everything
    for value in ("SG-01", "engineering"):
        assert value not in everything
    assert attrs(fresh)["carol"]["email"] == "carol@example.test"


@pytest.mark.parametrize("answers", [("no",), ("N",), ()])
def test_cli_import_no_or_eof_declines(fresh, answers, audit_on):
    before = (fresh / "worker_attributes.json").read_bytes()
    code, out = cli(fresh, answers=answers)
    assert code == 0 and "declined; nothing was written" in out[-1]
    assert (fresh / "worker_attributes.json").read_bytes() == before
    assert any("decision=declined" in l
               for l in audit_lines(fresh / "audit.jsonl"))


def test_cli_import_needs_a_master_and_a_group_map(fresh, capsys):
    with pytest.raises(SystemExit):
        run(["import-users", "--config-dir", str(fresh), "--csv", "x.csv",
             "--actor", "bob"])
    assert "not a master user" in capsys.readouterr().err
    group_map_path(fresh).unlink()
    with pytest.raises(SystemExit):
        cli(fresh)
    assert "group_map.json does not exist" in capsys.readouterr().err


def test_cli_refusal_shows_rows_not_values(fresh, capsys):
    with pytest.raises(SystemExit) as exc:
        cli(fresh, DEMO_CSV + "zed,=cmd|' /C calc'!A0,HR Staff,9,,x,\n")
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "row 7 (zed): invalid or empty email" in err
    assert "calc" not in err


def test_cli_undo(fresh):
    cli(fresh)
    code, out = run(["import-users", "--config-dir", str(fresh), "--undo",
                     "--actor", "master"], ["yes"])
    assert code == 0 and "APPLIED" in out[-1]
    assert attrs(fresh) == {"master": {"role": "master"}}


def test_cli_group_map_option(fresh):
    other = fresh / "gm.json"
    other.write_text(json.dumps({"version": 1, "map": [
        {"group": "Finance", "role": "employee"}]}), encoding="utf-8")
    group_map_path(fresh).unlink()
    code, _ = cli(fresh, extra=("--group-map", str(other)))
    assert code == 0
    assert attrs(fresh)["dave"]["role"] == "employee"
    assert "role" not in attrs(fresh)["carol"]
