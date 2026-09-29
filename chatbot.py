"""Worker-facing chatbot: NL question -> LLM text-to-SQL -> SQL gate -> SQLite -> answer.

The LLM is untrusted. Every SQL statement it emits goes through
SQLGate.authorize() (parse -> RBAC -> ABAC rewrite) before touching the
database, and the database connection itself is opened read-only as
defense in depth. On AccessDenied the fixed DENY_MESSAGE is printed from
code — the model never generates the refusal.
"""

import json
import logging
import sqlite3
import sys

import anthropic
from dotenv import load_dotenv

from sql_gate import DENY_MESSAGE, AccessDenied, SQLGate

MODEL = "claude-sonnet-4-6"
DB_PATH = "company.db"
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


def allowed_schema(gate: SQLGate, role: str, enforcer=None) -> dict:
    """Subset of the schema this role may read.

    Shown to the LLM so it doesn't write doomed queries — purely UX.
    The gate still enforces every query regardless of what the model saw.
    """
    enforcer = enforcer or gate.enforcer
    out = {}
    for table, cols in gate.schema.items():
        allowed = [
            c for c in cols if enforcer.enforce(role, f"{table}.{c}", "read")
        ]
        if allowed:
            out[table] = allowed
    return out


def build_system_prompt(role: str, schema: dict) -> str:
    tables = "\n".join(f"- {t}({', '.join(cols)})" for t, cols in schema.items())
    return f"""You are a company data assistant for a {role}.

Answer the worker's questions using the run_sql tool against these tables:
{tables}

Rules:
- Emit a single SQLite SELECT per tool call. No other statement types.
- Only reference the tables and columns listed above.
- After getting rows back, answer concisely in plain language.
- If a question needs no company data, answer directly without the tool.
"""


def execute(sql: str) -> list:
    """Run gated SQL against a read-only connection (defense in depth)."""
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql).fetchall()]
    finally:
        conn.close()


def complete_turn(client, gate, username, system_prompt, history) -> str:
    """Drive one user turn to completion, including tool round-trips.

    Raises AccessDenied the moment any generated SQL fails the gate.
    """
    for _ in range(MAX_TOOL_TURNS):
        response = client.messages.create(
            model=MODEL,
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
            rows = execute(safe_sql)
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
    worker = snap.attributes.get(username)
    role = worker.get("role") if isinstance(worker, dict) else None
    if not isinstance(role, str):
        role = None
    schema = allowed_schema(gate, role, snap.enforcer) if role else {}
    return role, build_system_prompt(role, schema), version, reset


def run_chatbot(username: str, client=None, gate=None, input_fn=input):
    load_dotenv()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    gate = gate or SQLGate(dialect="sqlite")
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
            reply = complete_turn(client, gate, username, system_prompt, history)
        except AccessDenied:
            # Roll back any dangling tool_use turns, then answer from CODE —
            # the model does not generate the refusal.
            del history[checkpoint:]
            reply = DENY_MESSAGE
            history.append({"role": "assistant", "content": reply})

        print(f"\nAssistant: {reply}\n")


if __name__ == "__main__":
    run_chatbot(sys.argv[1] if len(sys.argv) > 1 else "alice")
