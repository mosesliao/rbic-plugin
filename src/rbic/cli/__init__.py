"""Command-line entry points: the only place rbic does terminal I/O.

rbic-chat (rbic.cli.chat), rbic-master (rbic.cli.master), rbic-gate-demo
(rbic.cli.gate_demo) and rbic-seed (rbic.cli.seed). Code here may print,
read stdin, exit, load .env and configure logging; the library modules
never do (tests/test_library_hygiene.py enforces it).
"""

import logging
import sys

from .. import audit

LOG_FORMAT = "%(levelname)s %(message)s"


def setup_logging(audit_log=None, *, level=logging.INFO) -> None:
    """Audit lines to stderr ("LEVEL message"), plus a JSON-lines file when
    `audit_log` is given. Casbin's own INFO chatter is silenced (every
    policy load and proposal would log it)."""
    logging.basicConfig(level=level, format=LOG_FORMAT, stream=sys.stderr)
    logging.getLogger("casbin").setLevel(logging.WARNING)
    if audit_log:
        audit.configure(audit_log, level=level)


def load_env() -> None:
    """Read .env from the current directory (or a parent) into os.environ:
    the CLI's way to get ANTHROPIC_API_KEY. Library code never does this."""
    from dotenv import load_dotenv
    load_dotenv()


def add_audit_log_argument(parser) -> None:
    parser.add_argument("--audit-log", metavar="PATH",
                        help="also append audit records to PATH as JSON lines "
                             "(rbic.audit.configure)")
