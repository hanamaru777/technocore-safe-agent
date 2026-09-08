from __future__ import annotations

import asyncio

from flop_agent import (
    observer,
    observer_lobby_capture as capture,
    observer_lobby_spool_recovery as spool,
    observer_resilience as resilience,
)


class _UnusedBudget:
    async def acquire(self):
        raise AssertionError("network budget must not be used for complete local spool recovery")


class _UnusedClient:
    async def get(self, *args, **kwargs):
        raise AssertionError("network must not be used for complete local spool recovery")


def _config():
    return {
        **observer.DEFAULT_CONFIG,
        "read_budget_per_minute": 300,
        "discovery_sample_limit": 1,
        "long_poll_seconds": 10,
    }


def test_complete_local_spool_closes_live_gap_without_export(tmp_path, monkeypatch):
    path = tmp_path / "capture.sqlite3"
    monkeypatch.setattr(capture, "capture_path", lambda: path)
    connection = capture._connect(path)
    try:
        capture.store_rows(
            connection,
            [
                {"seq": 2, "text": "two", "from": "did:key:test2"},
                {"seq": 3, "text": "three", "from": "did:key:test3"},
            ],
        )
    finally:
        connection.close()

    state = resilience.default_state()
    state["cursors"]["lobby"] = 1
    payload = {"messages": [{"seq": 4, "text": "four", "from": "did:key:test4"}]}

    changed, _ = asyncio.run(
        spool.process_live_payload_with_recovery(
            _UnusedClient(),
            _UnusedBudget(),
            state,
            _config(),
            "lobby",
            payload,
            None,
            None,
            bootstrap=False,
        )
    )

    assert changed is True
    assert state["cursors"]["lobby"] == 4
    metrics = state["metrics"]
    assert metrics.get("lobby_spool_recovery_events") == 1
    assert metrics.get("lobby_spool_recovered_messages") == 2
    assert metrics.get("unrecoverable_core_gap_events", 0) == 0


def test_incomplete_local_spool_refuses_partial_claim(tmp_path, monkeypatch):
    path = tmp_path / "capture.sqlite3"
    monkeypatch.setattr(capture, "capture_path", lambda: path)
    connection = capture._connect(path)
    try:
        capture.store_rows(connection, [{"seq": 3, "text": "three"}])
    finally:
        connection.close()

    state = resilience.default_state()
    state["cursors"]["lobby"] = 1

    changed, recovered = asyncio.run(
        spool._drain_complete_spool_range(
            state,
            _config(),
            2,
            3,
            None,
            None,
        )
    )

    assert changed is False
    assert recovered == 0
    assert state["cursors"]["lobby"] == 1


def test_exact_gap_waits_for_capture_commit_before_server_fallback(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["lobby"] = 1
    payload = {"messages": [{"seq": 4, "text": "four", "from": "did:key:test4"}]}
    calls = []

    async def fake_prefix(*args, **kwargs):
        calls.append("prefix")
        if len(calls) == 1:
            return False, 0
        state["cursors"]["lobby"] = 3
        return True, 2

    async def fake_base(*args, **kwargs):
        calls.append(("base", state["cursors"]["lobby"]))
        assert state["cursors"]["lobby"] == 3
        state["cursors"]["lobby"] = 4
        return True, False

    monkeypatch.setattr(spool, "_drain_spool_prefix", fake_prefix)
    monkeypatch.setattr(spool, "_BASE_PROCESS_LIVE", fake_base)
    monkeypatch.setattr(spool, "SPOOL_CATCHUP_WAIT_SECONDS", 1.0)
    monkeypatch.setattr(spool, "SPOOL_CATCHUP_POLL_SECONDS", 0.001)

    changed, _ = asyncio.run(
        spool.process_live_payload_with_recovery(
            object(),
            object(),
            state,
            _config(),
            "lobby",
            payload,
            None,
            None,
            bootstrap=False,
        )
    )

    assert changed is True
    assert state["cursors"]["lobby"] == 4
    assert calls[-1] == ("base", 3)
    metrics = state["metrics"]
    assert metrics["lobby_spool_catchup_waits"] == 1
    assert metrics["lobby_spool_catchup_successes"] == 1
    assert metrics["lobby_spool_catchup_timeouts"] == 0
    assert metrics["lobby_spool_recovery_events"] == 1
    assert metrics["lobby_spool_recovered_messages"] == 2
    assert metrics["unrecoverable_core_gap_events"] == 0


def test_partial_spool_prefix_is_preserved_before_fallback(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["lobby"] = 1
    payload = {"messages": [{"seq": 4, "text": "four", "from": "did:key:test4"}]}
    prefix_calls = 0
    base_seen = []

    async def fake_prefix(*args, **kwargs):
        nonlocal prefix_calls
        prefix_calls += 1
        if prefix_calls == 1:
            state["cursors"]["lobby"] = 2
            return True, 1
        return False, 0

    async def fake_base(*args, **kwargs):
        base_seen.append(state["cursors"]["lobby"])
        return True, False

    monkeypatch.setattr(spool, "_drain_spool_prefix", fake_prefix)
    monkeypatch.setattr(spool, "_BASE_PROCESS_LIVE", fake_base)
    monkeypatch.setattr(spool, "SPOOL_CATCHUP_WAIT_SECONDS", 0.0)

    changed, _ = asyncio.run(
        spool.process_live_payload_with_recovery(
            object(),
            object(),
            state,
            _config(),
            "lobby",
            payload,
            None,
            None,
            bootstrap=False,
        )
    )

    assert changed is True
    assert base_seen == [2]
    metrics = state["metrics"]
    assert metrics["lobby_spool_catchup_timeouts"] == 1
    assert metrics["lobby_spool_recovery_events"] == 1
    assert metrics["lobby_spool_recovered_messages"] == 1
    assert metrics["lobby_spool_partial_recovery_messages"] == 1


def test_install_patches_only_resilience_recovery_surface(monkeypatch):
    monkeypatch.setattr(spool, "_INSTALLED", False)
    original_process = resilience.process_live_payload_with_recovery
    original_error = resilience.recover_after_live_error
    try:
        spool.install()
        assert resilience.process_live_payload_with_recovery is spool.process_live_payload_with_recovery
        assert resilience.recover_after_live_error is spool.recover_after_live_error
    finally:
        resilience.process_live_payload_with_recovery = original_process
        resilience.recover_after_live_error = original_error
        spool._INSTALLED = False
