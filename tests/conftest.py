"""Shared fixtures: every test works on a tmp_path copy of examples/demo.

examples/demo is read exactly once per session (into a session tmp dir,
together with a freshly seeded company.db); tests copy from that pristine
template, so no test reads or mutates the repository's files or depends on
the current directory.
"""

import logging
import shutil
from pathlib import Path

import pytest

from rbic import audit
from rbic.config import (ATTRIBUTES_FILE, ENV_CONFIG_DIR, ENV_DB_PATH,
                         ENV_DIALECT, ENV_MODEL, MODEL_FILE, POLICY_FILE,
                         SCHEMA_FILE, resolve_config)
from rbic.demo.seed import seed

DEMO_SOURCE = Path(__file__).resolve().parent.parent / "examples" / "demo"
CONFIG_FILES = (MODEL_FILE, POLICY_FILE, SCHEMA_FILE, ATTRIBUTES_FILE)


@pytest.fixture(autouse=True)
def _no_rbic_env(monkeypatch):
    """The caller's RBIC_* variables must not leak into any test."""
    for name in (ENV_CONFIG_DIR, ENV_DB_PATH, ENV_MODEL, ENV_DIALECT):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(scope="session")
def demo_template(tmp_path_factory) -> Path:
    """Read-only template: the demo config files plus a seeded company.db.
    Copy it (demo_dir) before changing anything."""
    root = tmp_path_factory.mktemp("demo_template")
    for rel in CONFIG_FILES:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(DEMO_SOURCE / rel, root / rel)
    seed(root / "company.db")
    return root


@pytest.fixture(scope="session")
def seeded_db(demo_template) -> Path:
    return demo_template / "company.db"


@pytest.fixture
def demo_dir(tmp_path, demo_template) -> Path:
    """A writable copy of the demo config and database in tmp_path."""
    shutil.copytree(demo_template, tmp_path, dirs_exist_ok=True)
    return tmp_path


@pytest.fixture
def demo_config(demo_dir):
    """EngineConfig over demo_dir (sqlite dialect)."""
    return resolve_config(demo_dir, dialect="sqlite")


@pytest.fixture
def audit_on():
    """Re-enable logging (many test modules disable it) for audit checks."""
    previous = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    yield
    logging.disable(previous)
    audit.unconfigure()
