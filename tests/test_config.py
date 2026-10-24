"""Configuration resolution: explicit args > RBIC_* environment > defaults;
no default config dir, no fallback to the current directory."""

import logging
import os

import pytest

from rbic.admin import PolicyAdmin
from rbic.config import (DEFAULT_DIALECT, DEFAULT_MODEL, ConfigError,
                         EngineConfig, resolve_config)
from rbic.gate import AccessDenied, SQLGate

logging.disable(logging.CRITICAL)


def test_defaults(demo_dir):
    cfg = resolve_config(demo_dir)
    assert isinstance(cfg, EngineConfig)
    assert cfg.config_dir == demo_dir
    assert cfg.model_path == demo_dir / "casbin" / "model.conf"
    assert cfg.policy_path == demo_dir / "casbin" / "policy.csv"
    assert cfg.schema_path == demo_dir / "db_schema.json"
    assert cfg.attributes_path == demo_dir / "worker_attributes.json"
    assert cfg.db_path == demo_dir / "company.db"
    assert cfg.model == DEFAULT_MODEL == "claude-sonnet-4-6"
    assert cfg.dialect == DEFAULT_DIALECT == "sqlite"
    assert all(p.is_absolute() for p in (cfg.config_dir, cfg.model_path,
                                          cfg.policy_path, cfg.schema_path,
                                          cfg.attributes_path, cfg.db_path))


def test_env_overrides_defaults(demo_dir, tmp_path_factory, monkeypatch):
    db = tmp_path_factory.mktemp("db") / "other.db"
    monkeypatch.setenv("RBIC_CONFIG_DIR", str(demo_dir))
    monkeypatch.setenv("RBIC_DB_PATH", str(db))
    monkeypatch.setenv("RBIC_MODEL", "env-model")
    monkeypatch.setenv("RBIC_DIALECT", "postgres")
    cfg = resolve_config()
    assert (cfg.config_dir, cfg.db_path, cfg.model, cfg.dialect) == (
        demo_dir, db, "env-model", "postgres")


def test_args_override_env(demo_dir, tmp_path_factory, monkeypatch):
    other = tmp_path_factory.mktemp("other")   # not a config dir at all
    db = tmp_path_factory.mktemp("db") / "arg.db"
    monkeypatch.setenv("RBIC_CONFIG_DIR", str(other))
    monkeypatch.setenv("RBIC_DB_PATH", str(other / "env.db"))
    monkeypatch.setenv("RBIC_MODEL", "env-model")
    monkeypatch.setenv("RBIC_DIALECT", "postgres")
    cfg = resolve_config(demo_dir, db_path=db, model="arg-model",
                         dialect="sqlite")
    assert (cfg.config_dir, cfg.db_path, cfg.model, cfg.dialect) == (
        demo_dir, db, "arg-model", "sqlite")


def test_config_is_frozen(demo_config):
    with pytest.raises(AttributeError):
        demo_config.dialect = "postgres"


def test_missing_config_dir_is_an_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigError, match="RBIC_CONFIG_DIR"):
        resolve_config()


def test_empty_env_is_not_the_current_directory(demo_dir, monkeypatch):
    # demo_dir is a valid config dir; an empty variable must not mean "here".
    monkeypatch.chdir(demo_dir)
    monkeypatch.setenv("RBIC_CONFIG_DIR", "")
    with pytest.raises(ConfigError):
        resolve_config()
    with pytest.raises(ConfigError):
        resolve_config("")


def test_nonexistent_config_dir_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="does not exist"):
        resolve_config(tmp_path / "nope")


@pytest.mark.parametrize("rel", ["casbin/model.conf", "casbin/policy.csv",
                                 "db_schema.json", "worker_attributes.json"])
def test_missing_file_is_an_error(demo_dir, rel):
    os.remove(demo_dir / rel)
    with pytest.raises(ConfigError, match="missing"):
        resolve_config(demo_dir)


def test_unsupported_dialect_is_an_error(demo_dir):
    with pytest.raises(ConfigError, match="dialect"):
        resolve_config(demo_dir, dialect="mysql")


def test_gate_requires_explicit_dialect(demo_config):
    with pytest.raises(TypeError):
        SQLGate(demo_config.model_path, demo_config.policy_path,
                demo_config.schema_path, demo_config.attributes_path)


def test_policy_admin_changelog_defaults_to_config_dir(demo_config, tmp_path):
    admin = PolicyAdmin.from_config(demo_config)
    assert admin.changelog_path == os.fspath(
        demo_config.config_dir / "policy_changes.jsonl")
    other = tmp_path / "elsewhere.jsonl"
    assert PolicyAdmin.from_config(demo_config, other).changelog_path == \
        os.fspath(other)


def test_works_from_an_unrelated_cwd(demo_dir, tmp_path_factory, monkeypatch):
    elsewhere = tmp_path_factory.mktemp("elsewhere")
    monkeypatch.chdir(elsewhere)
    cfg = resolve_config(demo_dir)
    gate = SQLGate.from_config(cfg)
    admin = PolicyAdmin.from_config(cfg)
    assert gate.dialect == "sqlite"
    assert gate.authorize("bob", "SELECT name FROM employees").endswith(
        "WHERE employees.dept = 'engineering'")
    with pytest.raises(AccessDenied):
        gate.authorize("bob", "SELECT name, salary FROM employees")
    admin.apply(admin.propose_revoke("hr_staff", "employees", "name"),
                actor="master")
    with pytest.raises(AccessDenied):
        gate.authorize("bob", "SELECT name FROM employees")
    assert (demo_dir / "policy_changes.jsonl").exists()
    assert os.listdir(elsewhere) == []
