"""rbic-master: change access policy by chatting; every change needs a yes.

    rbic-master --config-dir examples/demo master
    python -m rbic.cli.master --config-dir examples/demo master

The tools, the system prompt and the confirmation semantics live in
rbic.master (with injected I/O); this module wires them to the terminal.
"""

import argparse
import sys
from typing import Optional

import anthropic

from ..admin import PolicyAdmin
from ..config import ConfigError, EngineConfig, resolve_config
from ..master import (MODEL, NotMasterError, add_user_text, build_system_prompt,
                      complete_turn, confirm_pending, require_master)
from . import add_audit_log_argument, load_env, setup_logging


def _require_master(admin, username) -> None:
    try:
        require_master(admin, username)
    except NotMasterError as err:
        sys.exit(str(err))


def run_master_bot(username, client=None, input_fn=input, output=print,
                   admin=None, *, config: Optional[EngineConfig] = None) -> None:
    """Interactive master session. After each model turn every proposed
    change is shown and applied only on yes/y (any case); no/n declines,
    anything else re-asks, EOF/Ctrl-C declines, and each decision is
    audited (rbic.master.confirm_pending)."""
    if admin is None:
        if config is None:
            raise ConfigError("run_master_bot needs a PolicyAdmin or an EngineConfig.")
        admin = PolicyAdmin.from_config(config)
    model = config.model if config is not None else MODEL
    _require_master(admin, username)
    client = client or anthropic.Anthropic()
    history, pending = [], {}

    output(f"\n=== Master Chatbot | user: {username} ===")
    output("Ask about or change access policy. Type 'exit' to quit.\n")

    while True:
        try:
            user_input = input_fn("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if user_input.lower() == "exit":
            break
        if not user_input:
            continue
        _require_master(admin, username)

        add_user_text(history, user_input)
        reply = complete_turn(client, admin, username, build_system_prompt(admin),
                              history, pending, model)
        output(f"\nMaster: {reply}\n")
        confirm_pending(admin, username, pending, history, input_fn, output)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rbic-master",
        description="Change access policy by chatting; every change needs "
                    "your yes/no.")
    parser.add_argument("username", help="master username (worker_attributes.json)")
    parser.add_argument("--config-dir",
                        help="policy/config directory (default: $RBIC_CONFIG_DIR)")
    parser.add_argument("--model", help=f"LLM model (default: $RBIC_MODEL or {MODEL})")
    add_audit_log_argument(parser)
    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cfg = resolve_config(args.config_dir, model=args.model)
    except ConfigError as err:
        parser.error(str(err))
    load_env()
    setup_logging(args.audit_log)
    run_master_bot(args.username, config=cfg)


if __name__ == "__main__":
    main()
