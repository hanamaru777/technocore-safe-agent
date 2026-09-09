from __future__ import annotations

import asyncio

from flop_agent import (
    core,
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
    assert metrics["lobby_spool_catchup_timeouts"] == 0
    assert metrics["lobby_spool_recovery_events"] == 1
    assert metrics["lobby_spool_recovered_messages"] == 1
    assert metrics["lobby_spool_partial_recovery_messages"] == 1


def test_large_local_backlog_recovers_cooperatively_without_live_fallback(tmp_path, monkeypatch):
    """Each room cycle advances one exact slice and lets other tasks run."""
    path = tmp_path / "capture.sqlite3"
    monkeypatch.setattr(capture, "capture_path", lambda: path)
    connection = capture._connect(path)
    try:
        capture.store_rows(connection, [{"seq": seq, "text": f"row {seq}", "from": f"did:key:test{seq}"} for seq in range(2, 252)])
    finally:
        connection.close()

    state = resilience.default_state(); state["cursors"]["lobby"] = 1
    payload = {"messages": [{"seq": 252, "text": "newer live", "from": "did:key:live"}]}
    fallback_calls, events_ran = [], []

    async def no_fallback(*args, **kwargs):
        fallback_calls.append(True)
        raise AssertionError("fresh local suffix must not use network fallback")

    async def event_worker():
        await asyncio.sleep(0)
        events_ran.append(True)

    monkeypatch.setattr(spool, "_BASE_PROCESS_LIVE", no_fallback)

    async def run():
        event_task = asyncio.create_task(event_worker())
        changed, drain = await spool.process_live_payload_with_recovery(object(), object(), state, _config(), "lobby", payload, None, None, bootstrap=False)
        await event_task
        return changed, drain

    changed, drain = asyncio.run(run())
    assert changed is True and drain is False
    assert state["cursors"]["lobby"] == spool.SPOOL_CHUNK_MESSAGES + 1
    assert events_ran == [True] and fallback_calls == []
    assert state["metrics"].get("unrecoverable_core_gap_events", 0) == 0

    # Exact cursor progress persists; a later cycle resumes rather than replaying.
    asyncio.run(spool.process_live_payload_with_recovery(object(), object(), state, _config(), "lobby", payload, None, None, bootstrap=False))
    assert state["cursors"]["lobby"] == 1 + 2 * spool.SPOOL_CHUNK_MESSAGES
    assert fallback_calls == []


def test_agent_cap_backlog_uses_one_eviction_index_and_yields_scheduler(tmp_path, monkeypatch):
    """A production-shaped hot lobby backlog must not scan 5k Agents per row."""
    path = tmp_path / "capture.sqlite3"
    monkeypatch.setattr(capture, "capture_path", lambda: path)
    monkeypatch.setattr(core, "did_note_location", lambda did: ("", "", did.rsplit(":", 1)[-1]))
    connection = capture._connect(path)
    try:
        capture.store_rows(
            connection,
            [
                {"seq": seq, "text": "ordinary lobby message", "from": f"did:key:new-{seq}"}
                for seq in range(2, 302)
            ],
        )
    finally:
        connection.close()

    state = resilience.default_state()
    state["cursors"]["lobby"] = 1
    for number in range(5000):
        fingerprint = f"retained-{number:04d}"
        state["agents"][fingerprint] = {
            "did": f"did:key:{fingerprint}",
            "fingerprint": fingerprint,
            "facts": {
                "first_seen": "2026-01-01T00:00:00+00:00",
                "last_seen": "2026-01-01T00:00:00+00:00",
                "last_encounter_at": "2026-01-01T00:00:00+00:00",
                "seen_count": 1,
                "rooms": [], "message_refs": [], "recent_messages": [],
                "signed_count": 1, "unsigned_count": 0,
                "interaction_with_us": number == 4999,
            },
            "inferences": {"contribution_url_candidates": [], "role_candidates": [], "repeat_seen": False},
        }

    rebuilds = 0
    original_rebuild = observer._rebuild_agent_eviction_index

    def counted_rebuild(indexed_state):
        nonlocal rebuilds
        rebuilds += 1
        return original_rebuild(indexed_state)

    base_calls, scheduler_turns = [], []

    async def scheduler_turn(label):
        scheduler_turns.append(label)

    async def consume_newer_live(*args, **kwargs):
        base_calls.append(state["cursors"]["lobby"])
        assert state["cursors"]["lobby"] == 301
        return False, False

    monkeypatch.setattr(observer, "_rebuild_agent_eviction_index", counted_rebuild)
    monkeypatch.setattr(spool, "_BASE_PROCESS_LIVE", consume_newer_live)
    payload = {"messages": [{"seq": 302, "text": "newer live", "from": "did:key:live"}]}

    async def run():
        for label in ("events", "writer", "events"):
            task = asyncio.create_task(scheduler_turn(label))
            await spool.process_live_payload_with_recovery(
                object(), object(), state, _config(), "lobby", payload, None, None, bootstrap=False
            )
            assert task.done(), "each bounded recovery slice must release the scheduler"

    asyncio.run(run())

    assert rebuilds == 1
    assert len(state["agents"]) == 5000
    assert "retained-4999" in state["agents"]  # tier-3 interaction survives weak eviction
    assert state["cursors"]["lobby"] == 301
    assert base_calls == [301]  # only after every exact protected local row
    assert scheduler_turns == ["events", "writer", "events"]
    assert state["metrics"].get("unrecoverable_core_gap_events", 0) == 0


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
