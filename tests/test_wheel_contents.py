"""The wheel ships the rbic package and its metadata, nothing else.

No demo configuration, database, tests, .env, changelog or lock file may
end up in it (examples/demo is for the repository and the sdist only).
The build takes about a second with --no-isolation (hatchling installed);
an isolated build needs network access to fetch hatchling.
"""

import importlib.util
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

import rbic

ROOT = Path(__file__).resolve().parent.parent
CLI_MODULES = ("chat", "master", "gate_demo", "seed", "init")
PACK_DIR = "rbic/onboarding/packs/"
PACKS = ("finance", "hr", "people_manager", "staff_self_service", "warehouse")


def _has(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def _build_commands(out: Path) -> list:
    no_isolation = _has("hatchling")
    cmds = []
    if _has("build"):
        cmds.append([sys.executable, "-m", "build", "--wheel", "--outdir",
                     str(out), *(["--no-isolation"] if no_isolation else []),
                     str(ROOT)])
    cmds.append([sys.executable, "-m", "pip", "wheel", str(ROOT), "--no-deps",
                 "--quiet", "-w", str(out),
                 *(["--no-build-isolation"] if no_isolation else [])])
    return cmds


@pytest.fixture(scope="module")
def wheel(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("wheel")
    errors = []
    for cmd in _build_commands(out):
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        wheels = sorted(out.glob("rbic_plugin-*.whl"))
        if proc.returncode == 0 and wheels:
            return wheels[-1]
        errors.append(f"{' '.join(cmd[1:4])}: exit {proc.returncode}: "
                      f"{(proc.stderr or proc.stdout).strip()[-300:]}")
    pytest.skip("could not build a wheel (offline without hatchling "
                "installed?): " + " | ".join(errors))


def test_wheel_contains_only_the_package_and_metadata(wheel):
    names = zipfile.ZipFile(wheel).namelist()
    dist_info = f"rbic_plugin-{rbic.__version__}.dist-info/"
    stray = [n for n in names
             if not (n.startswith("rbic/") or n.startswith(dist_info))]
    assert stray == []
    forbidden = ("examples/", "tests/", "company.db", ".env",
                 "policy_changes.jsonl", ".policy.lock", "worker_attributes.json",
                 "policy.csv", "model.conf", "db_schema.json", "conftest",
                 "catalog.json", "roles.json", "access-report.md",
                 ".onboarding.lock")
    assert [n for n in names if any(f in n for f in forbidden)] == []
    # Python modules, plus the starter packs (package data, JSON).
    data = [n for n in names if n.startswith("rbic/") and not n.endswith(".py")]
    assert data and all(n.startswith(PACK_DIR) and n.endswith(".json")
                        for n in data), data


def test_wheel_has_every_module_and_cli_entry_points(wheel):
    z = zipfile.ZipFile(wheel)
    names = set(z.namelist())
    for module in ("__init__", "admin", "audit", "config", "engine", "gate",
                   "history", "identity", "master", "demo/__init__",
                   "demo/seed", "onboarding/__init__", "onboarding/catalog",
                   "onboarding/schema", "onboarding/suggest",
                   "onboarding/block", "onboarding/compile", "onboarding/report",
                   "onboarding/roles", "onboarding/store", "cli/__init__",
                   *(f"cli/{m}" for m in CLI_MODULES)):
        assert f"rbic/{module}.py" in names, module
    for pack in PACKS:
        assert f"{PACK_DIR}{pack}.json" in names, pack
    entry_points = z.read(
        f"rbic_plugin-{rbic.__version__}.dist-info/entry_points.txt").decode()
    for script, module in (("rbic-chat", "chat"), ("rbic-master", "master"),
                           ("rbic-gate-demo", "gate_demo"), ("rbic-seed", "seed"),
                           ("rbic-init", "init")):
        assert f"{script} = rbic.cli.{module}:main" in entry_points
