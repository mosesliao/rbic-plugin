"""Library hygiene: rbic (outside rbic.cli) does no terminal I/O, never
exits the process, never configures logging and never reads .env; the
audit logger follows the library convention (NullHandler) and
rbic.audit.configure() is the supported way for hosts to keep records.
"""

import ast
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from rbic import audit

SRC = Path(__file__).resolve().parent.parent / "src" / "rbic"
CLI = SRC / "cli"
LIBRARY_FILES = sorted(p for p in SRC.rglob("*.py") if CLI not in p.parents)

FORBIDDEN_NAMES = {"print", "input", "exit", "quit"}
FORBIDDEN_ATTRIBUTES = {("sys", "exit"), ("logging", "basicConfig")}


def _label(path: Path) -> str:
    try:
        return path.relative_to(SRC.parent).as_posix()
    except ValueError:
        return path.name


def _violations(path: Path) -> list:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = []
    for node in ast.walk(tree):
        where = f"{_label(path)}:{getattr(node, 'lineno', '?')}"
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            found.append(f"{where} uses {node.id}")
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                and (node.value.id, node.attr) in FORBIDDEN_ATTRIBUTES:
            found.append(f"{where} uses {node.value.id}.{node.attr}")
        elif isinstance(node, ast.Import):
            found += [f"{where} imports {a.name}" for a in node.names
                      if a.name.split(".")[0] == "dotenv"]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] == "dotenv":
                found.append(f"{where} imports from {node.module}")
            # from sys import exit / from logging import basicConfig
            for a in node.names:
                if (node.module, a.name) in FORBIDDEN_ATTRIBUTES:
                    found.append(f"{where} imports {node.module}.{a.name}")
        elif isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) \
                and node.left.id == "__name__":
            found.append(f"{where} has an `if __name__ == ...` block")
    return found


def test_scan_covers_the_library():
    names = {p.relative_to(SRC).as_posix() for p in LIBRARY_FILES}
    assert {"__init__.py", "audit.py", "admin.py", "engine.py", "gate.py",
            "master.py", "identity.py", "history.py", "config.py",
            "demo/seed.py", "onboarding/__init__.py", "onboarding/catalog.py",
            "onboarding/schema.py", "onboarding/suggest.py",
            "onboarding/block.py", "onboarding/compile.py",
            "onboarding/report.py", "onboarding/roles.py",
            "onboarding/store.py"} <= names
    assert not any(n.startswith("cli/") for n in names)


@pytest.mark.parametrize("path", LIBRARY_FILES,
                         ids=lambda p: p.relative_to(SRC).as_posix())
def test_no_terminal_io_exit_logging_config_or_dotenv(path):
    assert _violations(path) == []


def test_scanner_catches_violations(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("import sys, logging\nfrom dotenv import load_dotenv\n"
                   "import dotenv.main\n"
                   "def f():\n    print('x'); input(); sys.exit(1); exit()\n"
                   "    logging.basicConfig()\n"
                   "out = print\n"
                   "if __name__ == '__main__':\n    f()\n", encoding="utf-8")
    text = "\n".join(_violations(bad))
    for what in ("uses print", "uses input", "uses sys.exit", "uses exit",
                 "uses logging.basicConfig", "imports from dotenv",
                 "imports dotenv.main", "__name__"):
        assert what in text, what
    assert text.count("uses print") == 2


def _fresh_python(code: str, cwd, *args) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items()
           if k not in ("ANTHROPIC_API_KEY", "RBIC_DOTENV_SENTINEL")
           and not k.startswith("RBIC_")}
    return subprocess.run([sys.executable, "-c", code, *map(str, args)],
                          cwd=cwd, env=env, capture_output=True, text=True,
                          timeout=120)


def test_import_adds_no_root_handlers_and_reads_no_dotenv(tmp_path):
    (tmp_path / ".env").write_text(
        "RBIC_DOTENV_SENTINEL=1\nANTHROPIC_API_KEY=sk-from-dotenv\n")
    code = (
        "import logging, os, json\n"
        "root = logging.getLogger()\n"
        "before = list(root.handlers), root.level\n"
        "import rbic, rbic.engine, rbic.gate, rbic.admin, rbic.master, "
        "rbic.identity, rbic.history, rbic.config, rbic.demo.seed\n"
        "a = logging.getLogger('rbic.audit')\n"
        "print(json.dumps({\n"
        "  'root_unchanged': (list(root.handlers), root.level) == before,\n"
        "  'root_handlers': len(root.handlers),\n"
        "  'audit_handlers': [type(h).__name__ for h in a.handlers],\n"
        "  'audit_level': a.level,\n"
        "  'dotenv_loaded': 'RBIC_DOTENV_SENTINEL' in os.environ,\n"
        "  'key_from_dotenv': os.environ.get('ANTHROPIC_API_KEY') == 'sk-from-dotenv',\n"
        "  'dotenv_imported': 'dotenv' in __import__('sys').modules,\n"
        "  'cli_imported': any(m.startswith('rbic.cli') for m in __import__('sys').modules),\n"
        "}))\n"
    )
    proc = _fresh_python(code, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == {
        "root_unchanged": True, "root_handlers": 0,
        "audit_handlers": ["NullHandler"], "audit_level": 0,
        "dotenv_loaded": False, "key_from_dotenv": False,
        "dotenv_imported": False, "cli_imported": False,
    }


def test_engine_use_reads_no_dotenv(demo_config, tmp_path):
    (tmp_path / "envdir").mkdir()
    (tmp_path / "envdir" / ".env").write_text(
        "RBIC_DOTENV_SENTINEL=1\nANTHROPIC_API_KEY=sk-from-dotenv\n")
    code = (
        "import os, sys, warnings\n"
        "warnings.simplefilter('ignore')\n"
        "from rbic import RBICEngine, Identity\n"
        "e = RBICEngine.from_config_dir(sys.argv[1])\n"
        "e.reload()\n"
        "e.ask(Identity('x', 'y', 'nobody@example.test'), "
        "[{'role': 'user', 'content': 'hi'}])\n"
        "print('RBIC_DOTENV_SENTINEL' in os.environ, "
        "os.environ.get('ANTHROPIC_API_KEY') == 'sk-from-dotenv')\n"
    )
    proc = _fresh_python(code, tmp_path / "envdir", demo_config.config_dir)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "False False"


# ---- audit.configure / NullHandler decision -----------------------------------

@pytest.fixture
def clean_audit():
    logging.disable(logging.NOTSET)
    level = audit.logger.level
    audit.unconfigure()
    yield audit
    audit.unconfigure()
    audit.logger.setLevel(level)
    logging.disable(logging.CRITICAL)


def test_configure_writes_json_lines(clean_audit, tmp_path):
    path = tmp_path / "audit.jsonl"
    handler = audit.configure(path)
    audit.logger.info("ALLOW user=%s sql=%r", "bob", "SELECT 1")
    audit.logger.warning("DENY user=bob reason=x sql='SELECT salary'")
    handler.flush()
    lines = path.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]
    assert [r["event"] for r in records] == ["ALLOW", "DENY"]
    assert [r["level"] for r in records] == ["INFO", "WARNING"]
    assert records[0]["message"] == "ALLOW user=bob sql='SELECT 1'"
    assert records[0]["ts"].endswith("+00:00")  # UTC ISO 8601


def test_configure_is_idempotent_and_replaces_its_own_handler(clean_audit, tmp_path):
    first = audit.configure(tmp_path / "a.jsonl")
    assert audit.configure(tmp_path / "a.jsonl") is first
    assert audit.configure(str(tmp_path / "a.jsonl"), level=logging.WARNING) is first
    assert first.level == logging.WARNING
    ours = [h for h in audit.logger.handlers if isinstance(h, logging.FileHandler)]
    assert ours == [first]
    second = audit.configure(tmp_path / "b.jsonl")
    ours = [h for h in audit.logger.handlers if isinstance(h, logging.FileHandler)]
    assert ours == [second] and second is not first
    host = logging.NullHandler()
    audit.logger.addHandler(host)
    try:
        audit.configure(tmp_path / "c.jsonl")
        assert host in audit.logger.handlers  # host handlers are left alone
    finally:
        audit.logger.removeHandler(host)


def test_configure_with_owner_keeps_another_owners_file(clean_audit, tmp_path):
    a = audit.configure(tmp_path / "a.jsonl", owner="pipe-a")
    # another owner, or a host call without an owner, never swaps a's file
    assert audit.configure(tmp_path / "b.jsonl", owner="pipe-b") is a
    assert a.baseFilename == str(tmp_path / "a.jsonl")
    assert audit.configure(tmp_path / "a.jsonl", owner="pipe-b") is a  # same file
    # the owner itself may move its file (e.g. its setting changed)
    c = audit.configure(tmp_path / "c.jsonl", owner="pipe-a")
    assert c is not a and c.baseFilename == str(tmp_path / "c.jsonl")
    ours = [h for h in audit.logger.handlers if isinstance(h, logging.FileHandler)]
    assert ours == [c]
    # a host handler without owner is kept against an owner-tagged call ...
    audit.unconfigure()
    host = audit.configure(tmp_path / "host.jsonl")
    assert audit.configure(tmp_path / "d.jsonl", owner="pipe-a") is host
    # ... and the classic call without owner still replaces (unchanged API)
    assert audit.configure(tmp_path / "e.jsonl") is not host


def test_unconfigured_engine_warns_once(demo_config, tmp_path):
    code = (
        "import sys, warnings, json\n"
        "from rbic import RBICEngine, audit\n"
        "with warnings.catch_warnings(record=True) as w:\n"
        "    warnings.simplefilter('always')\n"
        "    RBICEngine.from_config_dir(sys.argv[1])\n"
        "    RBICEngine.from_config_dir(sys.argv[1])\n"
        "unconfigured = [str(x.message) for x in w "
        "if issubclass(x.category, audit.AuditNotConfiguredWarning)]\n"
        "audit.configure(sys.argv[2])\n"
        "with warnings.catch_warnings(record=True) as w2:\n"
        "    warnings.simplefilter('always')\n"
        "    RBICEngine.from_config_dir(sys.argv[1])\n"
        "print(json.dumps([len(unconfigured), audit.is_configured(), len(w2)]))\n"
    )
    proc = _fresh_python(code, tmp_path, demo_config.config_dir,
                         tmp_path / "audit.jsonl")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == [1, True, 0]


def test_host_handler_counts_as_configured(tmp_path, demo_config):
    code = (
        "import logging, sys, warnings\n"
        "logging.basicConfig()\n"
        "from rbic import RBICEngine, audit\n"
        "with warnings.catch_warnings(record=True) as w:\n"
        "    warnings.simplefilter('always')\n"
        "    RBICEngine.from_config_dir(sys.argv[1])\n"
        "print(audit.is_configured(), len(w))\n"
    )
    proc = _fresh_python(code, tmp_path, demo_config.config_dir)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["True", "0"]
