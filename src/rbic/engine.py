"""Worker-facing chatbot: NL question -> LLM text-to-SQL -> SQL gate -> SQLite -> answer.

The LLM is untrusted. Every SQL statement it emits goes through
SQLGate.authorize() (parse -> RBAC -> ABAC rewrite) before touching the
database, and the database connection itself is opened read-only as
defense in depth. On AccessDenied the fixed DENY_MESSAGE is printed from
code — the model never generates the refusal.
"""

import argparse
import json
import logging
import os
import sqlite3
import sys

import anthropic
from dotenv import load_dotenv

from .config import DEFAULT_MODEL, ConfigError, EngineConfig, resolve_config
from .gate import DENY_MESSAGE, AccessDenied, SQLGate

MODEL = DEFAULT_MODEL
EXECUTOR_DIALECT = "sqlite"
MAX_TOOL_TURNS = 5
MAX_ROWS_TO_MODEL = 50

RUN_SQL_TOOL = {
    "name": "run_sql",
    "description": (
        "Run a single read-only SQL SELECT against the company database and "
        "get the matching rows back as JSON. Use it whenever the worker's "
        "question needs data."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "sql": {
                "type": "string",
                "description": "Exactly one SQLite SELECT statement.",
            }
        },
        "required": ["sql"],
    },
}


def allowed_schema(gate: SQLGate, username: str, snapshot=None) -> dict:
    """Subset of the schema this worker may read through plain grants,
    after precedence (user deny > user allow > role deny > role allow),
    so a denied column is never advertised.

    Shown to the LLM so it doesn't write doomed queries — purely UX.
    The gate still enforces every query regardless of what the model saw.
    """
    snapshot = snapshot or gate.snapshot
    return snapshot.effective_columns(username, gate.schema)


def scoped_schema(gate: SQLGate, username: str, snapshot=None) -> dict:
    """table -> [[columns], ...] of the worker's scoped grants (4-field p2
    rows, role- or user-level): columns readable only for certain rows and
    only together, minus any column a deny takes away.

    UX only, like allowed_schema; the filter itself is not shown.
    """
    snapshot = snapshot or gate.snapshot
    out = {}
    for table, grants in snapshot.scoped_columns(username).items():
        if table not in gate.schema:
            continue
        out[table] = [list(cols) for _, cols in grants]
    return out


def build_system_prompt(role: str, schema: dict, scoped: dict = None) -> str:
    tables = "\n".join(f"- {t}({', '.join(cols)})" for t, cols in schema.items())
    scoped_lines = "\n".join(
        f"- {t}({', '.join(cols)})"
        for t, grants in (scoped or {}).items() for cols in grants)
    if scoped_lines:
        scoped_lines = f"""
Row-limited scopes. Each line below lists columns of a table you may read
only for a limited set of rows (the limit is applied automatically). A query
that uses any column of such a table beyond its regular list above must use
ONLY the columns of one of these lines, nothing else from that table:
{scoped_lines}
"""
    return f"""You are a company data assistant for a {role}.

Answer the worker's questions using the run_sql tool against these tables:
{tables}
{scoped_lines}
Rules:
- Emit a single SQLite SELECT per tool call. No other statement types.
- Only reference the tables and columns listed above.
- After getting rows back, answer concisely in plain language.
- If a question needs no company data, answer directly without the tool.
"""


def execute(sql: str, db_path) -> list:
    """Run gated SQL against a read-only connection (defense in depth)."""
    conn = sqlite3.connect(f"file:{os.fspath(db_path)}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql).fetchall()]
    finally:
        conn.close()


def complete_turn(client, gate, username, system_prompt, history, *,
                  db_path, model: str = MODEL) -> str:
    """Drive one user turn to completion, including tool round-trips.

    Raises AccessDenied the moment any generated SQL fails the gate.
    """
    for _ in range(MAX_TOOL_TURNS):
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=system_prompt,
            tools=[RUN_SQL_TOOL],
            messages=history,
        )
        history.append({"role": "assistant", "content": response.content})

        if response.stop_reason != "tool_use":
            return "".join(b.text for b in response.content if b.type == "text")

        results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            safe_sql = gate.authorize(username, block.input["sql"])  # may raise
            rows = execute(safe_sql, db_path)
            results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps(rows[:MAX_ROWS_TO_MODEL], default=str),
            })
        history.append({"role": "user", "content": results})

    return "Sorry, I couldn't complete that request — please rephrase."


POLICY_RESET_NOTICE = "(Access policy was updated — conversation reset.)"


def refresh_session(gate, username, history, seen_version):
    """Pick up live policy changes before a turn.

    Returns (role, system_prompt, version, reset). On a policy change the
    history is cleared: rows fetched under the old policy must not linger
    in the model's context after a revocation. While the gate is in its
    fail-closed (broken) state the history is cleared too, so the model
    can't answer from rows fetched before the failed reload. The role is
    re-read every turn because the master can reassign it on the fly.
    """
    gate.refresh()
    snap = gate.snapshot  # one consistent view of version/attributes/policy
    version = snap.version
    reset = version != seen_version
    if reset or snap.broken:
        history.clear()
    subj = snap.subjects_for(username)
    role = subj.role if subj else None
    schema = allowed_schema(gate, username, snap) if subj else {}
    scoped = scoped_schema(gate, username, snap) if subj else {}
    return role, build_system_prompt(role, schema, scoped), version, reset


def run_chatbot(username: str, client=None, gate=None, input_fn=input, *,
                config: EngineConfig):
    if config.dialect != EXECUTOR_DIALECT:
        raise ConfigError(f"The worker chatbot executes on SQLite; the gate's "
                          f"dialect must be {EXECUTOR_DIALECT!r}, not "
                          f"{config.dialect!r}.")
    load_dotenv()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    gate = gate or SQLGate.from_config(config)
    worker = gate.attributes.get(username)
    if worker is None:
        sys.exit(f"Unknown worker {username!r} — add them to worker_attributes.json")
    role = worker["role"]

    client = client or anthropic.Anthropic()
    seen_version = gate.policy_version
    history = []

    print(f"\n=== Worker Chatbot | user: {username} | role: {role} ===")
    print("Type 'exit' to quit.\n")

    while True:
        try:
            user_input = input_fn("You: ").strip()
        except EOFError:
            break
        if user_input.lower() == "exit":
            break
        if not user_input:
            continue

        role, system_prompt, seen_version, reset = refresh_session(
            gate, username, history, seen_version
        )
        if reset:
            print(POLICY_RESET_NOTICE)

        history.append({"role": "user", "content": user_input})
        checkpoint = len(history)
        try:
            if role is None:
                raise AccessDenied("worker no longer exists")
            reply = complete_turn(client, gate, username, system_prompt,
                                  history, db_path=config.db_path,
                                  model=config.model)
        except AccessDenied:
            # Roll back any dangling tool_use turns, then answer from CODE —
            # the model does not generate the refusal.
            del history[checkpoint:]
            reply = DENY_MESSAGE
            history.append({"role": "assistant", "content": reply})

        print(f"\nAssistant: {reply}\n")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        prog="rbic-chat", description="Chat with company data as a worker.")
    parser.add_argument("username", help="worker username (worker_attributes.json)")
    parser.add_argument("--config-dir",
                        help="policy/config directory (default: $RBIC_CONFIG_DIR)")
    parser.add_argument("--db", help="SQLite database (default: $RBIC_DB_PATH "
                                     "or <config-dir>/company.db)")
    parser.add_argument("--model", help=f"LLM model (default: $RBIC_MODEL or {MODEL})")
    args = parser.parse_args(argv)
    try:
        cfg = resolve_config(args.config_dir, db_path=args.db, model=args.model)
        run_chatbot(args.username, config=cfg)
    except ConfigError as err:
        parser.error(str(err))


if __name__ == "__main__":
    main()
