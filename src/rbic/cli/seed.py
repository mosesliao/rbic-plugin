"""rbic-seed: (re)create the demo SQLite database.

    rbic-seed --config-dir examples/demo     # writes examples/demo/company.db
    rbic-seed --db path/to/company.db
"""

import argparse
import os

from ..config import ConfigError, resolve_config
from ..demo.seed import DATA, seed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rbic-seed", description="Create and seed the demo SQLite database.")
    parser.add_argument("--db", help="database file to (re)create")
    parser.add_argument("--config-dir",
                        help="config directory whose db path to use when --db "
                             "is omitted (default: $RBIC_CONFIG_DIR)")
    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.db:
        db_path = os.path.abspath(args.db)
    else:
        try:
            db_path = os.fspath(resolve_config(args.config_dir).db_path)
        except ConfigError as err:
            parser.error(f"pass --db PATH or a config directory. {err}")
    count = seed(db_path)
    print(f"Seeded {db_path} with {count} rows across {len(DATA)} tables.")


if __name__ == "__main__":
    main()
