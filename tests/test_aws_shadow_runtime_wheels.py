"""Offline-only audit of Flop-specific pip wheel installer. Never executes installer."""
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import subprocess
import sys
import tomllib
from urllib.parse import urlsplit
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging/aws/install-shadow-pinned-runtime.py"


def load():
    spec = importlib.util.spec_from_file_location("flop_pinned_wheels", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_compiles_no_side_effects():
    compile(SCRIPT.read_text(), str(SCRIPT), "exec")


def test_wheel_plan_matches_exact_locked_runtime_closed_dependencies():
    m = load()
    assert m.RELEASE_SHA == "3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e"
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    plan = m.wheel_plan(lock)
    assert len(plan) == 10
    assert len({row[0] for row in plan}) == 10
    assert {row[0] for row in plan} == set(m.CORE)
    assert all(len(row[4]) == 64 for row in plan)
    assert all("files.pythonhosted.org" == urlsplit(row[3]).hostname for row in plan)
    assert all(row[2].endswith(".whl") for row in plan)
    assert sum(row[5] for row in plan) < 50 * 1024 * 1024
    expected = {"cryptography":"50.0.1", "httpx":"0.28.1",
                "anyio":"4.14.2", "cffi":"2.1.1"}
    for name, version in expected.items():
        assert next(x[1] for x in plan if x[0] == name) == version
    assert "-cp312-cp312-manylinux2014_x86_64." in next(
        x[2] for x in plan if x[0] == "cffi")
    assert "-cp311-abi3-manylinux2014_x86_64." in next(
        x[2] for x in plan if x[0] == "cryptography")


def test_reject_unpinned_registry_and_missing_checksum():
    m = load()
    original = tomllib.loads((ROOT / "uv.lock").read_text())
    def p(name): return next(x for x in original["package"] if x["name"] == name)
    p("httpx")["source"] = {"registry": "https://attacker.example/simple"}
    with pytest.raises(m.Stop, match="LOCK_UNTRUSTED_REGISTRY_STOP"):
        m.wheel_plan(original)
    p("httpx")["source"] = {"registry": "https://pypi.org/simple"}
    p("httpx")["wheels"][0]["hash"] = "sha256:000"
    with pytest.raises(m.Stop, match="WHEEL_SHA_MISSING_STOP"):
        m.wheel_plan(original)


def test_reject_unpinned_dependency_added_to_cryptography():
    m = load()
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    name = next(x for x in lock["package"] if x["name"] == "cryptography")
    name["dependencies"].append({"name": "other-project"})
    with pytest.raises(m.Stop, match="LOCK_DEP_OUTSIDE_CORE_STOP"):
        m.wheel_plan(lock)


@pytest.mark.parametrize("minute,allowed", [
    (0, False), (2, False), (4, False), (5, False), (6, True),
    (25, True), (52, True), (53, False), (59, False)
])
def test_k137_safe_window_boundaries(minute, allowed):
    m = load()
    assert m.slot_now(datetime(2026, 10, 12, 4, minute, tzinfo=timezone.utc)) is allowed


def test_k137_public_service_must_not_run_on_install(monkeypatch):
    m = load()
    monkeypatch.setattr(m, "k137",
                        lambda unit: ("active", "static") if unit == m.K137_SVC else ("active", "enabled"))
    with pytest.raises(m.Stop, match="K137_UNIT_STATE_STOP"):
        m.k137_snapshot()


def test_no_cross_project_or_unsafe_tools():
    data = SCRIPT.read_text()
    for pattern in ("systemctl stop", "systemctl enable", "systemctl restart",
                    "sudo ", "oci.auth", "SIGN_SEED", "wallet",
                    "flop_agent.resident_daemon", "apt install",
                    "package-manager", "chmod 777", "npx "):
        assert pattern not in data
    assert "/var/lib/flop-shadow/venv" in data
    assert "ensurepip" in data
    assert "--no-index" in data
    assert "--no-deps" in data
    assert "FLOP_SHADOW_PINNED_RUNTIME_DEPS_STAGE_PASS" in data
    assert "FLOP_SHADOW_PINNED_WHEELS_SHA256_PASS" in data
