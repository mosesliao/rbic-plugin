"""Configuration resolution: explicit arguments > environment > defaults.

There is no default configuration directory and nothing falls back to the
current working directory. A relative path that is passed in explicitly
(argument or environment variable) is made absolute once, here.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

ENV_CONFIG_DIR = "RBIC_CONFIG_DIR"
ENV_DB_PATH = "RBIC_DB_PATH"
ENV_MODEL = "RBIC_MODEL"
ENV_DIALECT = "RBIC_DIALECT"

DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_DIALECT = "sqlite"
SUPPORTED_DIALECTS = ("sqlite", "postgres")

MODEL_FILE = Path("casbin", "model.conf")
POLICY_FILE = Path("casbin", "policy.csv")
SCHEMA_FILE = Path("db_schema.json")
ATTRIBUTES_FILE = Path("worker_attributes.json")
DB_FILE = Path("company.db")


class ConfigError(Exception):
    """The configuration is missing or invalid; nothing was started."""


@dataclass(frozen=True)
class EngineConfig:
    config_dir: Path
    model_path: Path
    policy_path: Path
    schema_path: Path
    attributes_path: Path
    db_path: Path
    model: str
    dialect: str


def _pick(explicit, env_name: str) -> Optional[str]:
    """Explicit value, else the environment variable; empty counts as unset
    (an empty path would otherwise mean the current directory)."""
    if explicit is not None and str(explicit) != "":
        return explicit
    value = os.environ.get(env_name, "")
    return value or None


def resolve_config(config_dir=None, *, db_path=None, model=None,
                   dialect=None) -> EngineConfig:
    raw_dir = _pick(config_dir, ENV_CONFIG_DIR)
    if raw_dir is None:
        raise ConfigError(
            f"No configuration directory: pass --config-dir (or config_dir=) "
            f"or set {ENV_CONFIG_DIR}. It must contain {MODEL_FILE.as_posix()}, "
            f"{POLICY_FILE.as_posix()}, {SCHEMA_FILE} and {ATTRIBUTES_FILE}.")
    root = Path(raw_dir).expanduser().absolute()
    if not root.is_dir():
        raise ConfigError(f"Configuration directory {str(root)!r} does not exist "
                          "or is not a directory.")

    paths = {}
    for name, rel in (("model_path", MODEL_FILE), ("policy_path", POLICY_FILE),
                      ("schema_path", SCHEMA_FILE),
                      ("attributes_path", ATTRIBUTES_FILE)):
        path = root / rel
        if not path.is_file():
            raise ConfigError(f"Configuration file {str(path)!r} is missing.")
        paths[name] = path

    raw_db = _pick(db_path, ENV_DB_PATH)
    db = Path(raw_db).expanduser().absolute() if raw_db else root / DB_FILE

    model_name = _pick(model, ENV_MODEL) or DEFAULT_MODEL
    dialect_name = _pick(dialect, ENV_DIALECT) or DEFAULT_DIALECT
    if dialect_name not in SUPPORTED_DIALECTS:
        raise ConfigError(f"Unsupported SQL dialect {dialect_name!r}; expected "
                          f"one of {', '.join(SUPPORTED_DIALECTS)}.")

    return EngineConfig(config_dir=root, db_path=db, model=str(model_name),
                        dialect=dialect_name, **paths)
