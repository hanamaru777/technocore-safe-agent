from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import sonnet_mitsuri_contact_fast as fast


def safety(*, health="degraded", age=10, core=(117, 5_083_155)):
    return {
        "schema_version": 1,
        "updated_at": (datetime.now(UTC) - timedelta(seconds=age)).isoformat(),
        "health": health,
        "unrecoverable_core_gap_events": core[0],
        "unrecoverable_core_gap_messages": core[1],
    }


def test_fast_contact_allows_fresh_degraded(monkeypatch):
    monkeypatch.setattr(fast.registration, "load_safety_snapshot", lambda: safety())
    result = fast.require_nonbinding_safety()
    assert result["health"] == "degraded"
    assert result["core"] == (117, 5_083_155)


def test_fast_contact_rejects_stale(monkeypatch):
    monkeypatch.setattr(
        fast.registration,
        "load_safety_snapshot",
        lambda: safety(age=fast.MAX_AGE_SECONDS + 1),
    )
    with pytest.raises(fast.FastContactError, match="nonbinding_safety_stale"):
        fast.require_nonbinding_safety()


def test_fast_contact_rejects_core_change(monkeypatch):
    monkeypatch.setattr(
        fast.registration,
        "load_safety_snapshot",
        lambda: safety(core=(118, 5_083_155)),
    )
    with pytest.raises(fast.FastContactError, match="protected_core_baseline_changed"):
        fast.require_nonbinding_safety()


def test_run_replaces_only_health_and_calls_bounded_lane(monkeypatch):
    called = []
    monkeypatch.setattr(
        fast.lane,
        "run_once",
        lambda: called.append("lane") or {"status": "posted"},
    )
    marker = lambda: None
    monkeypatch.setattr(fast, "require_nonbinding_safety", marker)
    result = fast.run_once()
    assert fast.lane.require_health is marker
    assert called == ["lane"]
    assert result == {"status": "posted"}


def test_runner_is_bounded_and_does_not_restart_long_lived_services():
    text = (
        fast.registration.core.ROOT
        / "packaging/oracle/run-mitsuri-fast-contact.sh"
    ).read_text("utf-8")
    assert "TimeoutStartSec=75s" in text
    assert "timeout 5s python3" in text
    assert "0 <= age <= 900" in text
    assert fast.MAX_AGE_SECONDS == 900
    assert "lobby-capture-service.sqlite3" not in text
    assert "sonnet_mitsuri_contact_v2" not in text
    assert "/export" not in text
    assert "systemctl restart technocore-safe-agent-resident" not in text
    assert "systemctl restart technocore-safe-agent-lobby-capture" not in text
    assert "systemctl restart technocore-safe-agent-signer" not in text
    assert "MITSURI_FAST=PASS" in text
    assert "DO_NOT_RERUN=YES" in text
