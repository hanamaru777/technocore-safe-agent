"""No AWS access: offline regression for source-only shadow interpreter verification."""
import importlib.util
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "packaging/aws/verify-shadow-interpreter.py"


def load():
    spec = importlib.util.spec_from_file_location("flop_shadow_venv", SOURCE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_syntax_and_fixed_isolated_paths():
    compile(SOURCE.read_text(), str(SOURCE), "exec")
    m = load()
    assert m.SOURCE_SHA == "3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e"
    assert str(m.VENV) == "/var/lib/flop-shadow/venv"
    assert str(m.RELEASE).startswith("/opt/flop-shadow/releases/")
    assert m.TIMER == "k137q-public-k58.timer"


def test_offline_syntax_and_lock_actual_repository():
    m = load()
    result = subprocess.run(
        [sys.executable, "-I", "-c", m.SMOKE, str(REPO)],
        capture_output=True, text=True, timeout=10, check=False
    )
    assert result.returncode == 0, result.stderr
    assert "FLOP_SHADOW_SOURCE_SYNTAX_PASS" in result.stdout
    assert "FLOP_SHADOW_DEPENDENCY_MANIFEST_STATIC_PASS count=36" in result.stdout


@pytest.mark.parametrize("state,accept", [
    (("inactive", "disabled"), True),
    (("active", "enabled"), True),
    (("active", "disabled"), False),
    (("inactive", "enabled"), False),
    (("failed", "enabled"), False),
])
def test_k137_timer_states_fail_closed(monkeypatch, state, accept):
    m = load()
    monkeypatch.setattr(m, "k137_status",
        lambda unit: ("inactive", "disabled") if unit.endswith(".service") else state)
    if accept:
        assert m.snapshot()[1] == state
    else:
        with pytest.raises(m.Stop, match="K137_RUNNING_OR_UNEXPECTED_STATE_STOP"):
            m.snapshot()


def test_any_active_k137_service_blocks(monkeypatch):
    m = load()
    monkeypatch.setattr(m, "k137_status",
        lambda unit: ("active", "static") if unit.endswith(".service") else ("active", "enabled"))
    with pytest.raises(m.Stop, match="K137_RUNNING_OR_UNEXPECTED_STATE_STOP"):
        m.snapshot()


def test_no_network_or_application_execute_on_host():
    s = SOURCE.read_text()
    for forbidden in ("urllib", "urlopen", "httpx", "requests.get",
                      "socket.connect", "pip install", "uv sync", "apt install",
                      "systemctl start", "systemctl stop", "systemctl restart",
                      "systemctl enable", "flop_agent.resident_daemon",
                      "oracle_signer.main", "wallet", "sudo "):
        assert forbidden not in s
    assert '["runuser", "-u", "flop-shadow"' in s
    assert "env\", \"-i\"" in s
    assert "--without-pip" in s
    assert "FLOP_SHADOW_OFFLINE_INTERPRETER_STAGE_PASS" in s


@pytest.mark.parametrize("minute,expected", [
    (0, False), (1, False), (2, False), (3, False),
    (5, False), (6, True), (9, True), (44, True),
    (57, True), (58, False), (59, False),
])
def test_k137_quiet_slot_boundaries(minute, expected):
    from datetime import datetime, timezone
    m = load()
    assert m.safe_slot(datetime(2026, 10, 12, 4, minute, tzinfo=timezone.utc)) is expected


def test_k137_active_natural_service_waits_without_mutation(monkeypatch):
    m = load()
    from datetime import datetime, timezone
    calls = []
    service = [("active", "static"), ("inactive", "static")]
    def fake_status(unit):
        if unit.endswith(".timer"):
            return ("active", "enabled")
        calls.append(unit)
        return service[min(len(calls) - 1, len(service) - 1)]
    monkeypatch.setattr(m, "k137_status", fake_status)
    monkeypatch.setattr(m, "snapshot",
                        lambda: (("inactive", "static"), ("active", "enabled")))
    class Clock:
        @staticmethod
        def now(tz):
            return datetime(2026, 10, 12, 4, 16, tzinfo=timezone.utc)
    monkeypatch.setattr(m.datetime, "datetime", Clock)
    monkeypatch.setattr(m.time, "sleep", lambda duration: None)
    assert m.await_k137_idle(timeout_seconds=100, interval_seconds=1) == (
        ("inactive", "static"), ("active", "enabled"))
    assert len(calls) == 2


def test_k137_timer_state_drift_during_wait_stops(monkeypatch):
    m = load()
    from datetime import datetime, timezone
    timer_states = [("active", "enabled"), ("inactive", "disabled")]
    reads = []
    def fake_status(unit):
        if unit.endswith(".service"):
            return ("inactive", "disabled")
        reads.append(unit)
        return timer_states[min(len(reads) - 1, 1)]
    monkeypatch.setattr(m, "k137_status", fake_status)
    class Clock:
        @staticmethod
        def now(tz):
            return datetime(2026, 10, 12, 4, 2, tzinfo=timezone.utc)
    monkeypatch.setattr(m.datetime, "datetime", Clock)
    monkeypatch.setattr(m.time, "sleep", lambda duration: None)
    with pytest.raises(m.Stop, match="K137_TIMER_CHANGED_DURING_WAIT_STOP"):
        m.await_k137_idle(timeout_seconds=100, interval_seconds=1)


def test_k137_wait_timeout_stops_not_retries(monkeypatch):
    m = load()
    from datetime import datetime, timezone
    monkeypatch.setattr(m, "k137_status",
                        lambda unit: ("inactive", "disabled") if unit.endswith(".service") else ("active", "enabled"))
    class Clock:
        @staticmethod
        def now(tz):
            return datetime(2026, 10, 12, 4, 2, tzinfo=timezone.utc)
    monkeypatch.setattr(m.datetime, "datetime", Clock)
    monotonic_values = iter([0, 1, 512])
    monkeypatch.setattr(m.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(m.time, "sleep", lambda duration: None)
    with pytest.raises(m.Stop, match="K137_WINDOW_WAIT_TIMEOUT_STOP"):
        m.await_k137_idle(timeout_seconds=510)


def test_real_timing_wait_is_bounded_and_nonpersistent():
    s = SOURCE.read_text()
    assert "timeout_seconds=510" in s
    assert "time.sleep(min(interval_seconds, remaining))" in s
    assert "systemctl start" not in s
    assert "systemctl disable" not in s
    assert "timer in ((\"active\", \"enabled\"), (\"inactive\", \"disabled\"))" in s
