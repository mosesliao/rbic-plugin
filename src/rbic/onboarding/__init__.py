"""Onboarding toolkit (rbic-init): generate an organization's policy sources.

The toolkit PROPOSES; the organization's policy owner (a master user)
APPROVES. Its human-editable sources live in <config_dir>/onboarding/
(catalog.json: column -> data category; later roles.json). Nothing here
grants access by itself: unapproved columns grant nothing, db_schema.json
is only written through PolicyAdmin (validated with the gate's own loader,
locked, changelogged before replace, after an explicit yes), and no data
value is ever returned, stored, logged or sent to an LLM.

Library code: no terminal I/O (the CLI is rbic.cli.init).
"""

from pathlib import Path

ONBOARDING_DIR = Path("onboarding")
CATALOG_FILE = ONBOARDING_DIR / "catalog.json"


def catalog_path(config_dir) -> Path:
    return Path(config_dir) / CATALOG_FILE
