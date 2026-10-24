"""rbic-chat: chat with company data as a worker, in the terminal.

    rbic-chat --config-dir examples/demo alice
    python -m rbic.cli.chat --config-dir examples/demo alice
"""

import argparse
import sys
import uuid

from ..config import ConfigError, EngineConfig, resolve_config
from ..engine import MODEL, RBICEngine
from ..identity import Identity, LocalProvider
from . import add_audit_log_argument, load_env, setup_logging


def run_chatbot(username: str, client=None, gate=None, input_fn=input,
                output=print, *, config: EngineConfig) -> None:
    """Local terminal chat as `username`, on RBICEngine.ask().

    LocalProvider (subject = worker key) is for this CLI only: whoever runs
    it can be any worker, which is fine for a local demo and never for a
    web host.
    """
    engine = RBICEngine(config, gate=gate, client=client,
                        attribute_provider=LocalProvider())
    record = engine.gate.attributes.get(username)
    if not isinstance(record, dict):
        sys.exit(f"Unknown worker {username!r} — add them to worker_attributes.json")
    identity = Identity("local", username)
    conversation_id = uuid.uuid4().hex
    history = []  # text only: what the user typed and what was shown

    output(f"\n=== Worker Chatbot | user: {username} | role: {record.get('role')} ===")
    output("Type 'exit' to quit.\n")

    while True:
        try:
            user_input = input_fn("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if user_input.lower() == "exit":
            break
        if not user_input:
            continue

        history.append({"role": "user", "content": user_input})
        result = engine.ask(identity, history, conversation_id=conversation_id)
        if result.reset:
            del history[:-1]  # earlier turns belong to the old policy
        history.append({"role": "assistant", "content": result.text})
        output(f"\nAssistant: {result.text}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rbic-chat", description="Chat with company data as a worker.")
    parser.add_argument("username", help="worker username (worker_attributes.json)")
    parser.add_argument("--config-dir",
                        help="policy/config directory (default: $RBIC_CONFIG_DIR)")
    parser.add_argument("--db", help="SQLite database (default: $RBIC_DB_PATH "
                                     "or <config-dir>/company.db)")
    parser.add_argument("--model", help=f"LLM model (default: $RBIC_MODEL or {MODEL})")
    add_audit_log_argument(parser)
    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    load_env()
    setup_logging(args.audit_log)
    try:
        cfg = resolve_config(args.config_dir, db_path=args.db, model=args.model)
        run_chatbot(args.username, config=cfg)
    except ConfigError as err:
        parser.error(str(err))


if __name__ == "__main__":
    main()
