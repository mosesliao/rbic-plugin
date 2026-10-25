"""PolicyAdmin validates with the gate's own loader (rbic.gate.load_snapshot).

Whatever a proposal would write must load in the SQL gate byte for byte as
the gate loads it: the bytes-based Casbin load, the lone-CR and
unknown-ptype refusal (check_policy_bytes), compile_snapshot, and the
email and user-subject checks. Otherwise the gate would deny everyone, so
the admin refuses before writing anything.
"""

import json
import logging

import pytest

from rbic import gate as gate_module
from test_master_policy import env, sha  # noqa: F401 - fixture

logging.disable(logging.CRITICAL)

GATE_REFUSES = "would not load in the SQL gate"


def append_policy(env, data: bytes) -> None:
    with open(env.policy, "ab") as f:
        f.write(data)


def files_unchanged(env, before: dict) -> bool:
    return {p: sha(p) for p in before} == before


def snapshot_files(env) -> dict:
    return {p: sha(p) for p in (env.policy, env.attrs)}


@pytest.mark.parametrize("bad, why", [
    (b"# temporary note\rp3, hr_staff, employees.name, read\n",
     "lone carriage return"),
    (b"p5, hr_staff, employees.salary, read\n", "unknown rule type"),
])
def test_policy_proposal_on_top_of_bad_line_is_refused(env, bad, why):
    append_policy(env, bad)
    env.gate.refresh()
    assert env.gate.broken and why in env.gate.broken  # the gate refuses it
    before = snapshot_files(env)
    with pytest.raises(ValueError) as exc:
        env.admin.propose_grant("hr_staff", "employees", "salary",
                                actor="master")
    assert GATE_REFUSES in str(exc.value) and why in str(exc.value)
    assert files_unchanged(env, before)
    assert not env.changelog.exists()


@pytest.mark.parametrize("bad", [
    b"# temporary note\rp3, hr_staff, employees.name, read\n",
    b"p5, hr_staff, employees.salary, read\n",
])
def test_attribute_proposal_on_top_of_bad_policy_is_refused(env, bad):
    append_policy(env, bad)
    before = snapshot_files(env)
    with pytest.raises(ValueError, match=GATE_REFUSES):
        env.admin.propose_set_attribute("bob", "dept", "logistics",
                                        actor="master")
    assert files_unchanged(env, before)


def test_proposal_with_duplicate_email_is_refused(env):
    attrs = json.loads(env.attrs.read_text(encoding="utf-8"))
    attrs["dave"]["email"] = "BOB@example.test"  # casefolds to bob's
    env.attrs.write_text(json.dumps(attrs, indent=2) + "\n", encoding="utf-8")
    env.gate.refresh()
    assert "share the same email" in env.gate.broken
    before = snapshot_files(env)
    for propose in (
        lambda: env.admin.propose_grant("hr_staff", "employees", "salary",
                                        actor="master"),
        lambda: env.admin.propose_set_attribute("bob", "dept", "logistics",
                                                actor="master"),
        lambda: env.admin.propose_assign_role("bob", "hr_manager",
                                              actor="master"),
    ):
        with pytest.raises(ValueError, match="share the same email"):
            propose()
    assert files_unchanged(env, before)


def test_admin_runs_the_gates_loader(env, monkeypatch):
    calls = []
    real = gate_module.check_policy_bytes

    def spy(data):
        calls.append(data)
        return real(data)

    monkeypatch.setattr(gate_module, "check_policy_bytes", spy)
    change = env.admin.propose_grant("hr_staff", "employees", "salary",
                                     actor="master")
    assert change.after_text.encode("utf-8") in calls

    monkeypatch.setattr(gate_module, "check_policy_bytes",
                        lambda data: (_ for _ in ()).throw(ValueError("sentinel")))
    with pytest.raises(ValueError, match="sentinel"):
        env.admin.propose_grant("hr_staff", "employees", "salary",
                                actor="master")


def test_apply_revalidates_with_the_gates_loader(env, monkeypatch):
    change = env.admin.propose_grant("hr_staff", "employees", "salary",
                                     actor="master")
    before = snapshot_files(env)
    monkeypatch.setattr(gate_module, "check_policy_bytes",
                        lambda data: (_ for _ in ()).throw(ValueError("sentinel")))
    with pytest.raises(ValueError, match="sentinel"):
        env.admin.apply(change, actor="master")
    assert files_unchanged(env, before)
    assert not env.changelog.exists()  # refused before the audit record
    monkeypatch.undo()
    env.admin.apply(change, actor="master")
    assert "p, hr_staff, employees.salary, read" in env.policy.read_text(
        encoding="utf-8")


def test_valid_proposals_still_apply_and_load(env):
    for change in (
        env.admin.propose_grant("hr_staff", "employees", "salary",
                                actor="master"),
    ):
        env.admin.apply(change, actor="master")
    env.admin.apply(env.admin.propose_set_attribute(
        "bob", "dept", "logistics", actor="master"), actor="master")
    env.gate.refresh()
    assert env.gate.broken is None
