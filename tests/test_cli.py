"""rbic.cli: the terminal entry points, run with injected I/O and fake clients.

No real API calls; every test works on tmp_path copies of examples/demo.
The master confirmation semantics themselves are covered in
test_master_confirm.py (library) and here end to end through the CLI loop.
"""

import json
import logging
import os
import subprocess
import sys

import pytest

from rbic import DENY_MESSAGE
from rbic.cli import chat as chat_cli
from rbic.cli import gate_demo, seed as seed_cli
from rbic.cli import init as init_cli
from rbic.cli import master as master_cli
from rbic.gate import SQLGate
from test_engine import SALARY_Q, A, FakeClient, U, end_turn, tool_use
from test_master_policy import GRANT_CALL, env  # noqa: F401 - fixture
from test_master_policy import FakeClient as MasterFakeClient
from test_master_policy import end_turn as master_end_turn
from test_master_policy import tool_use as master_tool_use

logging.disable(logging.CRITICAL)

CLI_MODULES = [("rbic-chat", chat_cli), ("rbic-master", master_cli),
               ("rbic-gate-demo", gate_demo), ("rbic-seed", seed_cli),
               ("rbic-init", init_cli)]


# ---- rbic-chat ---------------------------------------------------------------

def test_chat_denied_question_prints_deny_message(demo_config):
    client = FakeClient([tool_use(SALARY_Q), end_turn("hi bob")])
    script = iter(["salaries?", "hello", "exit"])
    out = []
    chat_cli.run_chatbot("bob", client=client, config=demo_config,
                         input_fn=lambda _: next(script), output=out.append)
    text = "\n".join(out)
    assert f"Assistant: {DENY_MESSAGE}" in text and "hi bob" in text
    # the denied turn left only text in the history the engine was given
    assert client.calls[1]["messages"] == [U("salaries?"), A(DENY_MESSAGE),
                                           U("hello")]


def test_chat_eof_ends_session(demo_config):
    def eof(_):
        raise EOFError
    out = []
    chat_cli.run_chatbot("alice", client=FakeClient([]), config=demo_config,
                         input_fn=eof, output=out.append)
    assert any("Worker Chatbot" in o for o in out)


def test_chat_unknown_worker_exits(demo_config):
    with pytest.raises(SystemExit) as exc:
        chat_cli.run_chatbot("nobody", client=FakeClient([]), config=demo_config,
                             input_fn=lambda _: "exit", output=lambda *_: None)
    assert exc.value.code not in (0, None)


def test_run_chatbot_does_not_load_dotenv(demo_config, monkeypatch):
    import dotenv
    called = []
    monkeypatch.setattr(dotenv, "load_dotenv", lambda *a, **k: called.append(1))
    chat_cli.run_chatbot("alice", client=FakeClient([]), config=demo_config,
                         input_fn=lambda _: "exit", output=lambda *_: None)
    assert called == []


# ---- rbic-master -------------------------------------------------------------

def run_master(env, answers, responses):
    script = iter(answers)

    def input_fn(_prompt):
        item = next(script)
        if isinstance(item, type) and issubclass(item, BaseException):
            raise item
        return item

    out = []
    client = MasterFakeClient(responses)
    master_cli.run_master_bot("master", client=client, input_fn=input_fn,
                              output=out.append, admin=env.admin)
    return out, client


def granted(env):
    return "p, hr_staff, employees.salary, read" in env.policy.read_text(
        encoding="utf-8")


@pytest.mark.parametrize("answers, applied", [
    (["Y"], True),
    (["yes"], True),
    (["n"], False),
    (["NO"], False),
    (["maybe", "", "y"], True),      # anything else re-asks
    ([EOFError], False),             # EOF at the prompt declines
])
def test_master_cli_confirm_semantics(env, caplog, answers, applied):
    logging.disable(logging.NOTSET)
    try:
        with caplog.at_level(logging.INFO, logger="rbic.audit"):
            out, _ = run_master(env, ["let hr_staff see salaries", *answers,
                                      "exit"],
                                [master_tool_use("propose_grant", GRANT_CALL),
                                 master_end_turn("Proposed.")])
    finally:
        logging.disable(logging.CRITICAL)
    assert granted(env) is applied
    assert out.count("Please type yes or no.") == sum(
        1 for a in answers if isinstance(a, str) and a.strip().lower()
        not in ("y", "yes", "n", "no"))
    decisions = [r.getMessage() for r in caplog.records
                 if r.getMessage().startswith("POLICY_CONFIRM")]
    assert len(decisions) == 1
    assert decisions[0].endswith("confirmed" if applied else "declined")


def test_master_cli_refuses_non_master(env):
    with pytest.raises(SystemExit) as exc:
        master_cli.run_master_bot("bob", client=MasterFakeClient([]),
                                  input_fn=lambda _: "exit",
                                  output=lambda *_: None, admin=env.admin)
    assert "not a master user" in str(exc.value.code)


def test_master_cli_tool_results_carry_no_email(env):
    _, client = run_master(env, ["who is carol?", "exit"], [
        master_tool_use("describe_user", {"username": "carol"}),
        master_end_turn("Carol is an HR manager."),
    ])
    sent = json.dumps(client.calls[1]["messages"], default=str)
    assert "carol@example.test" not in sent
    assert "<set>" in sent


# ---- rbic-gate-demo ----------------------------------------------------------

def test_gate_demo_outcomes(demo_config):
    gate = SQLGate.from_config(demo_config)
    out = []
    results = gate_demo.run_demo(gate, output=out.append)
    allowed = [r for r in results if r[2] is not None]
    assert (len(allowed), len(results) - len(allowed)) == (6, 9)
    text = "\n".join(out)
    assert text.count("-> ALLOW:") == 6 and text.count("-> DENY (") == 9


def test_gate_demo_main(demo_dir, capsys):
    gate_demo.main(["--config-dir", str(demo_dir)])
    out = capsys.readouterr().out
    assert out.count("-> ALLOW:") == 6 and out.count("-> DENY (") == 9


def test_gate_demo_as_module_without_runpy_warning(demo_dir):
    env = {k: v for k, v in os.environ.items() if not k.startswith("RBIC_")}
    proc = subprocess.run(
        [sys.executable, "-W", "error::RuntimeWarning", "-m",
         "rbic.cli.gate_demo", "--config-dir", str(demo_dir)],
        capture_output=True, text=True, timeout=120, env=env,
        cwd=demo_dir)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.count("-> ALLOW:") == 6
    assert "RuntimeWarning" not in proc.stderr
    assert "ALLOW user=alice" in proc.stderr  # the CLI logs audit to stderr


def test_gate_demo_audit_log_option(demo_dir, tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    from rbic import audit
    logging.disable(logging.NOTSET)
    try:
        gate_demo.main(["--config-dir", str(demo_dir), "--audit-log", str(path)])
        records = [json.loads(line) for line in
                   path.read_text(encoding="utf-8").splitlines()]
    finally:
        audit.unconfigure()
        logging.disable(logging.CRITICAL)
    events = [r["event"] for r in records]
    assert events.count("ALLOW") == 6 and events.count("DENY") == 9


# ---- rbic-seed ---------------------------------------------------------------

def test_seed_main(tmp_path, capsys):
    db = tmp_path / "x.db"
    seed_cli.main(["--db", str(db)])
    assert db.is_file()
    assert "across 10 tables" in capsys.readouterr().out


# ---- every entry point -------------------------------------------------------

@pytest.mark.parametrize("prog, module", CLI_MODULES)
def test_help(prog, module, capsys):
    with pytest.raises(SystemExit) as exc:
        module.main(["--help"])
    assert exc.value.code == 0
    assert f"usage: {prog}" in capsys.readouterr().out


@pytest.mark.parametrize("prog, module", CLI_MODULES[:3])
def test_missing_config_dir_is_a_usage_error(prog, module, capsys, monkeypatch):
    if hasattr(module, "load_env"):  # never read the developer's .env here
        monkeypatch.setattr(module, "load_env", lambda: None)
    argv = [] if module is gate_demo else ["someone"]
    with pytest.raises(SystemExit) as exc:
        module.main(argv)
    assert exc.value.code == 2
    assert "RBIC_CONFIG_DIR" in capsys.readouterr().err
