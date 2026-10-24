"""Master bot confirmation prompt: yes/no parsing, re-ask, fail-closed, audit.

Works on tmp_path copies via the `env` fixture from test_master_policy; the
repo's real policy files are never touched. Run: pytest -q
"""

import json
import logging

import pytest

from rbic.cli import master as master_cli
from rbic import master as master_bot
from test_master_policy import (  # noqa: F401 - fixtures
    GRANT_CALL, SALARY_Q, FakeClient, end_turn, env, rows, sha,
    tool_use,
)


@pytest.fixture
def audit_log(caplog):
    # test_master_policy disables logging globally at import; undo for here.
    logging.disable(logging.NOTSET)
    caplog.set_level(logging.INFO, logger="rbic.audit")
    yield caplog
    logging.disable(logging.CRITICAL)


def run_confirm(env, answers):
    """Propose the hr_staff salary grant and answer the prompt with `answers`."""
    change = env.admin.propose_grant("hr_staff", "employees", "salary",
                                     actor="master")
    pending, history, out, prompts = {change.id: change}, [], [], []
    script = iter(answers)

    def input_fn(prompt):
        prompts.append(prompt)
        item = next(script)
        if isinstance(item, type) and issubclass(item, BaseException):
            raise item
        return item

    master_bot.confirm_pending(env.admin, "master", pending, history,
                               input_fn, out.append)
    assert pending == {}
    note = json.dumps(history)
    return change, note, out, prompts


def applied(env):
    return "p, hr_staff, employees.salary, read" in env.policy.read_text(
        encoding="utf-8")


@pytest.mark.parametrize("answer", ["yes", "Yes", "YES", "y", "Y", " yes ",
                                    "yes\n"])
def test_yes_variants_apply(env, answer):
    change, note, out, prompts = run_confirm(env, [answer])
    assert applied(env)
    assert rows(env, "bob", SALARY_Q)
    assert f"Change {change.id} was APPLIED" in note
    assert prompts == [f"Apply change {change.id}? [yes/no]: "]


@pytest.mark.parametrize("answer", ["no", "No", "n", "N", " no "])
def test_no_variants_decline(env, answer):
    original = sha(env.policy)
    change, note, out, _ = run_confirm(env, [answer])
    assert sha(env.policy) == original
    assert not env.changelog.exists()
    assert "DECLINED by the human" in note
    assert any("declined by you" in o for o in out)


@pytest.mark.parametrize("first", ["yes please", "apply", "", "   ", "ok",
                                   "yess"])
def test_unclear_answer_reasks_then_yes(env, first):
    change, note, out, prompts = run_confirm(env, [first, "yes"])
    assert applied(env)
    assert out.count(master_bot.REASK) == 1
    assert len(prompts) == 2
    assert "APPLIED" in note


def test_garbage_then_no_declines(env):
    original = sha(env.policy)
    _, note, out, prompts = run_confirm(env, ["sure", "maybe", "no"])
    assert sha(env.policy) == original
    assert out.count(master_bot.REASK) == 2 and len(prompts) == 3
    assert "DECLINED" in note


@pytest.mark.parametrize("exc", [EOFError, KeyboardInterrupt])
def test_eof_or_interrupt_declines(env, exc):
    original = sha(env.policy)
    _, note, _, _ = run_confirm(env, [exc])
    assert sha(env.policy) == original
    assert not env.changelog.exists()
    assert "DECLINED" in note


def test_eof_after_garbage_declines(env):
    original = sha(env.policy)
    run_confirm(env, ["hmm", EOFError])
    assert sha(env.policy) == original


def test_audit_log_records_confirm_and_decline(env, audit_log):
    change, *_ = run_confirm(env, ["Y"])
    msgs = [r.getMessage() for r in audit_log.records
            if r.name == "rbic.audit" and "POLICY_CONFIRM" in r.getMessage()]
    assert f"POLICY_CONFIRM change={change.id} actor=master decision=confirmed" \
        in msgs

    audit_log.clear()
    change2 = env.admin.propose_revoke("hr_staff", "employees", "salary",
                                       actor="master")
    pending = {change2.id: change2}
    master_bot.confirm_pending(env.admin, "master", pending, [],
                               lambda _: "No", lambda *_: None)
    msgs = [r.getMessage() for r in audit_log.records if r.name == "rbic.audit"]
    assert f"POLICY_CONFIRM change={change2.id} actor=master decision=declined" \
        in msgs
    assert applied(env)  # the revoke was declined, the grant stays


def test_stale_change_error_still_surfaced(env):
    change = env.admin.propose_grant("hr_staff", "employees", "salary",
                                     actor="master")
    env.policy.write_text(env.policy.read_text(encoding="utf-8")
                          + "# touched\n", encoding="utf-8")
    history, out = [], []
    pending = {change.id: change}
    master_bot.confirm_pending(env.admin, "master", pending, history,
                               lambda _: "yes", out.append)
    assert pending == {}
    assert any("NOT applied" in o for o in out)
    assert "could NOT be applied" in json.dumps(history)


def test_full_bot_yes_capitalised_applies(env):
    client = FakeClient([tool_use("propose_grant", GRANT_CALL),
                         end_turn("Proposed.")])
    inputs = iter(["let hr_staff see salaries", "yes please", "Yes", "exit"])
    out = []
    master_cli.run_master_bot("master", client=client,
                              input_fn=lambda _: next(inputs),
                              output=out.append, admin=env.admin)
    assert applied(env)
    assert master_bot.REASK in out


def test_system_prompt_has_confirm_rule(env):
    prompt = master_bot.build_system_prompt(env.admin)
    assert master_bot.CONFIRM_RULE in prompt
    assert "type yes or no" in prompt
    assert "cannot apply changes yourself" in prompt
