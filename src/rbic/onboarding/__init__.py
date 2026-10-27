"""Onboarding toolkit (rbic-init): generate an organization's policy sources.

The toolkit PROPOSES; the organization's policy owner (a master user)
APPROVES. Its human-editable sources live in <config_dir>/onboarding/:
catalog.json (column -> data category) and roles.json (roles x
categories grid, inheritance, row ownership, starter packs used).
`rbic-init compile` turns APPROVED columns only into the rbic-init block
of policy.csv (rbic.onboarding.block), applied through PolicyAdmin
(validated with the gate's own loader, locked, changelogged before
replace) after an explicit yes. Nothing here grants access by itself, and
no data value is ever returned, stored, logged or sent to an LLM.

Library code: no terminal I/O (the CLI is rbic.cli.init).
"""

from pathlib import Path

ONBOARDING_DIR = Path("onboarding")
CATALOG_FILE = ONBOARDING_DIR / "catalog.json"
ROLES_FILE = ONBOARDING_DIR / "roles.json"
REPORT_FILE = ONBOARDING_DIR / "access-report.md"
# One lock for every onboarding source (catalog.json, roles.json).
ONBOARDING_LOCK = ".onboarding.lock"


def catalog_path(config_dir) -> Path:
    return Path(config_dir) / CATALOG_FILE


def roles_path(config_dir) -> Path:
    return Path(config_dir) / ROLES_FILE


def report_path(config_dir) -> Path:
    return Path(config_dir) / REPORT_FILE
