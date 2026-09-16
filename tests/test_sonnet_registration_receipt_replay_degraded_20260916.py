from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import sonnet_registration_receipt_replay_degraded_20260916 as adapter


def _snapshot(*, health="degraded", age=10, events=117, messages=5_083_155):
    return {
        "schema_version": 1,
        "updated_at": (datetime.now(UTC) - timedelta(seconds=age)).isoformat(),
        "health": health,
        "unrecoverable_core_gap_events": events,
        "unrecoverable_core_gap_messages": messages,
    }


def test_allows_only_fresh_ok_or_degraded_with_exact_core(monkeypatch):
    monkeypatch.setattr(adapter.registration, "load_safety_snapshot", lambda: _snapshot())
    result = adapter.require_replay_health()
    assert result["health"] == "degraded"
    assert result["protected_core_gap_events"] == 117
    assert result["protected_core_gap_messages"] == 5_083_155

    monkeypatch.setattr(adapter.registration, "load_safety_snapshot", lambda: _snapshot(health="ok"))
    assert adapter.require_replay_health()["health"] == "ok"


@pytest.mark.parametrize(
    ("snapshot", "error"),
    [
        (_snapshot(health="critical"), "replay_safety_invalid_health"),
        (_snapshot(age=301), "replay_safety_stale"),
        (_snapshot(events=118), "protected_core_baseline_changed"),
        (_snapshot(messages=5_083_156), "protected_core_baseline_changed"),
    ],
)
def test_replay_safety_fails_closed(monkeypatch, snapshot, error):
    monkeypatch.setattr(adapter.registration, "load_safety_snapshot", lambda: snapshot)
    with pytest.raises(adapter.ReplaySafetyError, match=error):
        adapter.require_replay_health()


def test_main_patches_only_isolated_replay_process_and_restores(monkeypatch):
    original = adapter.replay.registration.require_health
    seen = []

    def fake_main():
        seen.append(adapter.replay.registration.require_health is adapter.require_replay_health)

    monkeypatch.setattr(adapter.replay, "main", fake_main)
    adapter.main()

    assert seen == [True]
    assert adapter.replay.registration.require_health is original


def test_underlying_replay_remains_exact_and_non_generic():
    assert adapter.replay.REQUEST_ID == "32c15433c6d73af1cea5d6467dece016"
    assert adapter.replay.PAYLOAD == {
        "type": "sonnet.register.v1",
        "contest_id": "sonnet-2",
        "role": "writer",
        "x_account_url": "https://x.com/MinerMaru73",
        "request_id": "32c15433c6d73af1cea5d6467dece016",
    }
