"""Offline-only fail-closed K137 natural Type=oneshot lifecycle tests.

No AWS connection, systemctl changes, bot runtime, or package installation.
"""
import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "packaging/aws/install-shadow-pinned-wheels-k137-transient.py"


def load():
    spec = importlib.util.spec_from_file_location("flop_shadow_transient", SRC)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.mark.parametrize("state", ["inactive", "active", "activating", "deactivating"])
def test_observer_tolerates_normal_oneshot_transition_without_starting(state, monkeypatch):
    m = load()
    monkeypatch.setattr(
        m, "k137",
        lambda unit: (state, "static") if unit == m.K137_SVC
        else ("active", "enabled")
    )
    assert m.k137_snapshot(allow_active=True) == (
        (state, "static"), ("active", "enabled")
    )
    if state != "inactive":
        with pytest.raises(m.Stop, match="K137_UNIT_STATE_STOP"):
            m.k137_snapshot()
    else:
        assert m.k137_snapshot() == (("inactive", "static"), ("active", "enabled"))


@pytest.mark.parametrize("state", ["failed", "reloading", "maintenance", "unknown"])
def test_unexpected_public_service_state_stops_even_in_observer(state, monkeypatch):
    m = load()
    monkeypatch.setattr(
        m, "k137",
        lambda unit: (state, "static") if unit == m.K137_SVC
        else ("active", "enabled")
    )
    with pytest.raises(m.Stop, match="K137_UNIT_STATE_STOP"):
        m.k137_snapshot(allow_active=True)


@pytest.mark.parametrize("unitfile", ["enabled", "masked", "not-found", "generated"])
def test_unexpected_public_service_unitfile_stops(unitfile, monkeypatch):
    m = load()
    monkeypatch.setattr(
        m, "k137",
        lambda unit: ("activating", unitfile) if unit == m.K137_SVC
        else ("active", "enabled")
    )
    with pytest.raises(m.Stop, match="K137_UNIT_STATE_STOP"):
        m.k137_snapshot(allow_active=True)


@pytest.mark.parametrize("timer_state", [
    ("inactive", "enabled"), ("active", "disabled"),
    ("failed", "enabled"), ("inactive", "not-found")
])
def test_unexpected_timer_state_stops(timer_state, monkeypatch):
    m = load()
    monkeypatch.setattr(
        m, "k137",
        lambda unit: ("activating", "static") if unit == m.K137_SVC else timer_state
    )
    with pytest.raises(m.Stop, match="K137_UNIT_STATE_STOP"):
        m.k137_snapshot(allow_active=True)


def test_foreground_wait_survives_natural_oneshot_activation_and_exit(monkeypatch):
    m = load()
    states = iter(["activating", "deactivating", "inactive"])
    current = ["activating"]
    def fake_k137(unit):
        if unit == m.K137_SVC:
            current[0] = next(states, "inactive")
            return (current[0], "static")
        return ("active", "enabled")

    class Clock:
        @staticmethod
        def now(tz):
            return datetime(2026, 10, 12, 5, 10, tzinfo=timezone.utc)

    monkeypatch.setattr(m, "k137", fake_k137)
    monkeypatch.setattr(m.datetime, "datetime", Clock)
    monkeypatch.setattr(m.time, "sleep", lambda seconds: None)
    assert m.await_quiet() == (("inactive", "static"), ("active", "enabled"))


def test_timer_change_during_wait_stops_without_mutation(monkeypatch):
    m = load()
    states = iter([("active", "enabled"), ("inactive", "disabled")])
    def fake_k137(unit):
        if unit == m.K137_SVC:
            return ("activating", "static")
        return next(states, ("inactive", "disabled"))
    monkeypatch.setattr(m, "k137", fake_k137)
    monkeypatch.setattr(m.time, "sleep", lambda seconds: None)
    with pytest.raises(m.Stop, match="K137_TIMER_DRIFT_STOP"):
        m.await_quiet()


def test_source_only_new_one_shot_still_disarmed():
    s = SRC.read_text()
    compile(s, str(SRC), "exec")
    assert 'observed_states = ("inactive", "active", "activating", "deactivating")' in s
    assert 'allowed_states = observed_states if allow_active else ("inactive",)' in s
    assert 'if svc[0] == "inactive" and slot_now(' in s
    assert "deadline = time.monotonic() + 900" in s
    assert 'WHEELS = CACHE / "runtime-wheel-cache-v2"' in s
    assert "K137_SERVICE_TIMER_CHANGED_STOP" in s
    assert "FLOP_SHADOW_PINNED_RUNTIME_DEPS_STAGE_PASS" in s
    for prohibited in ("systemctl start", "systemctl stop", "systemctl restart",
                       "systemctl enable", "apt install", "sudo ",
                       "flop_agent.resident_daemon", "oci.auth"):
        assert prohibited not in s
