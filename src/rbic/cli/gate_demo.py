"""rbic-gate-demo: the SQL gate's decision for a fixed set of demo queries.

    rbic-gate-demo --config-dir examples/demo

No API key and no database needed: the gate only parses, checks and
rewrites.
"""

import argparse

from ..config import ConfigError, resolve_config
from ..gate import DENY_MESSAGE, AccessDenied, SQLGate
from . import add_audit_log_argument, setup_logging

# (user, LLM-generated SQL). Against examples/demo: 6 ALLOW, 9 DENY.
DEMO_QUERIES = [
    ("alice", "SELECT sku, qty FROM inventory WHERE qty < 10"),
    ("alice", "SELECT * FROM inventory"),
    ("bob", "SELECT name, dept FROM employees"),
    ("bob", "SELECT name, salary FROM employees"),      # salary -> deny
    ("bob", "SELECT * FROM employees"),                 # * expands to salary -> deny
    ("carol", "SELECT name, salary FROM employees"),    # hr_manager inherits + salary
    ("dave", "SELECT vendor, amount FROM invoices"),
    ("dave", "SELECT name FROM employees"),             # finance can't read HR -> deny
    ("alice", "DROP TABLE inventory"),                  # not a SELECT -> deny
    ("alice", "SELECT secret FROM classified"),         # unknown table -> deny
    # personal scoped grant (p2, user:alice, employees, id = 2, id|name|salary):
    # alice alone reads Carol's name+salary (plus her own row via her role)
    ("alice", "SELECT name, salary FROM employees WHERE name LIKE '%Carol%'"),
    ("alice", "SELECT name, dept FROM employees"),      # dept not in scope -> deny
    ("alice", "SELECT * FROM employees"),               # star beyond scope -> deny
    # whole-row reference (Postgres) is not a Column -> unsupported -> deny
    ("bob", "SELECT name FROM employees e WHERE (e).salary > 100000"),
    # a column-less query still needs a grant on the table -> deny
    ("dave", "SELECT COUNT(*) FROM employees"),
]


def run_demo(gate: SQLGate, output=print, queries=DEMO_QUERIES) -> list:
    """Show each decision; return [(user, sql, rewritten SQL or None)]."""
    results = []
    for user, sql in queries:
        output(f"{user}: {sql}")
        try:
            safe = gate.authorize(user, sql)
        except AccessDenied as e:
            output(f"  -> DENY ({e})")
            output(f"     bot says: {DENY_MESSAGE}\n")
            results.append((user, sql, None))
        else:
            output(f"  -> ALLOW: {safe}\n")
            results.append((user, sql, safe))
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rbic-gate-demo",
        description="Run the SQL gate over a fixed set of demo queries "
                    "(no API key needed).")
    parser.add_argument("--config-dir",
                        help="policy/config directory (default: $RBIC_CONFIG_DIR)")
    parser.add_argument("--dialect",
                        help="SQL dialect (default: $RBIC_DIALECT or sqlite)")
    add_audit_log_argument(parser)
    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cfg = resolve_config(args.config_dir, dialect=args.dialect)
    except ConfigError as err:
        parser.error(str(err))
    setup_logging(args.audit_log)
    run_demo(SQLGate.from_config(cfg))


if __name__ == "__main__":
    main()
