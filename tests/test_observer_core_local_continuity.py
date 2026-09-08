from __future__ import annotations

import asyncio
import json

from flop_agent import (
    observer,
    observer_core_local_continuity as final,
    observer_resilience as resilience,
)


def message(seq: int):
    return {
        "seq": seq,
        "from": "did:key:z6MkAgent",
        "text": "hello",
        "ts": "2026-09-08T00:00:00Z",
    }


class Budget:
    def __init__(self):
        self.calls = 0

    async def acquire(self):
        self.calls += 1


class Writer:
    def __init__(self):
        self.dirty = 0

    def mark_dirty(self):
        self.dirty += 1


class Stop:
    def __init__(self, value=False):
        self.value = value

    def is_set(self):
        return self.value

    async def wait(self):
        while not self.value:
            await asyncio.sleep(1)


class FakeResponse:
    status_code = 200
    headers = {}

    def __init__(self, rows):
        self.rows = rows

    def raise_for_status(self):
        return None

    async def aiter_lines(self):
        for row in self.rows:
            yield json.dumps(row, separators=(",", ":"))


class FakeContext:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeClient:
    def __init__(self, rows):
        self.response = FakeResponse(rows)

    def stream(self, method, url, **kwargs):
        return FakeContext(self.response)


def config():
    return {**observer.DEFAULT_CONFIG, "read_budget_per_minute": 600}


def test_exact_events_snapshot_recovers_prefix_and_accounts_only_absent_suffix(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["events"] = 50
    resilience.set_error(
        state,
        "events",
        "startup_live_probe_gap",
        "cursor=50;first_unseen=60",
    )
    budget = Budget()
    monkeypatch.setattr(final, "_BASE_EVENTS_STARTUP_STREAM", object())

    recovered, retry, error = asyncio.run(
        final.stream_events_startup_export(
            FakeClient([message(seq) for seq in range(45, 56)] + [message(60)]),
            budget,
            state,
            config(),
            "events",
            None,
            None,
        )
    )

    assert retry is None
    assert error is None
    assert recovered == 5
    assert state["cursors"]["events"] == 59
    assert state["metrics"]["unrecoverable_core_gap_events"] == 1
    assert state["metrics"]["unrecoverable_core_gap_messages"] == 4
    assert state["last_unrecoverable_gap"]["missing_from"] == 56
    assert state["last_unrecoverable_gap"]["missing_to"] == 59
    assert state["last_unrecoverable_gap"]["recovery_reason"] == "not_in_retained_export"
    assert state["metrics"]["events_startup_snapshot_unrecoverable_events"] == 1
    assert state["metrics"]["events_startup_snapshot_unrecoverable_messages"] == 4
    assert state["health"]["rooms"]["events"]["status"] == "ok"
    assert budget.calls == 1


def test_exact_events_snapshot_present_never_counts_unrecoverable(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["events"] = 50
    resilience.set_error(
        state,
        "events",
        "startup_live_probe_gap",
        "cursor=50;first_unseen=60",
    )
    monkeypatch.setattr(final, "_BASE_EVENTS_STARTUP_STREAM", object())

    recovered, retry, error = asyncio.run(
        final.stream_events_startup_export(
            FakeClient([message(seq) for seq in range(45, 80)]),
            Budget(),
            state,
            config(),
            "events",
            None,
            None,
        )
    )

    assert retry is None
    assert error is None
    assert recovered == 9
    assert state["cursors"]["events"] == 59
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0
    assert state["metrics"]["events_startup_snapshot_unrecoverable_events"] == 0
    assert state["health"]["rooms"]["events"]["status"] == "ok"


def test_lobby_live_gap_stays_pending_while_fresh_capture_is_still_behind(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["lobby"] = 1
    payload = {"messages": [message(4)]}

    async def incomplete(*args, **kwargs):
        return False, 0, False

    async def forbidden(*args, **kwargs):
        raise AssertionError("moving server fallback must not run while capture is still behind")

    monkeypatch.setattr(final.spool, "_recover_exact_spool_range_with_grace", incomplete)
    monkeypatch.setattr(final.capture, "status", lambda: {"capture_cursor": 2, "last_error": "", "last_success_at": "now"})
    monkeypatch.setattr(final, "_capture_fresh", lambda *args, **kwargs: True)
    monkeypatch.setattr(final, "_BASE_PROCESS_LIVE", forbidden)

    changed, drain = asyncio.run(
        final.process_live_payload_with_recovery(
            object(),
            object(),
            state,
            config(),
            "lobby",
            payload,
            None,
            None,
            bootstrap=False,
        )
    )

    assert changed is True
    assert drain is False
    assert state["cursors"]["lobby"] == 1
    assert state["health"]["rooms"]["lobby"]["kind"] == "gap_recovery_lobby_capture_pending"
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0
    assert state["metrics"]["lobby_capture_pending_cycles"] == 1


def test_lobby_live_gap_delegates_only_after_capture_has_crossed_gap(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["lobby"] = 1
    payload = {"messages": [message(4)]}
    calls = []

    async def incomplete(*args, **kwargs):
        return False, 0, False

    async def base(*args, **kwargs):
        calls.append("base")
        return True, False

    monkeypatch.setattr(final.spool, "_recover_exact_spool_range_with_grace", incomplete)
    monkeypatch.setattr(final.capture, "status", lambda: {"capture_cursor": 4, "last_error": "", "last_success_at": "now"})
    monkeypatch.setattr(final, "_capture_fresh", lambda *args, **kwargs: True)
    monkeypatch.setattr(final, "_BASE_PROCESS_LIVE", base)

    changed, drain = asyncio.run(
        final.process_live_payload_with_recovery(
            object(),
            object(),
            state,
            config(),
            "lobby",
            payload,
            None,
            None,
            bootstrap=False,
        )
    )

    assert changed is True
    assert drain is False
    assert calls == ["base"]
    assert state["metrics"].get("lobby_capture_pending_cycles", 0) == 0


def test_lobby_startup_fresh_capture_can_satisfy_continuity_without_server(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["lobby"] = 10
    writer = Writer()

    monkeypatch.setattr(final.capture, "status", lambda: {"capture_cursor": 15, "last_error": "", "last_success_at": "now"})
    monkeypatch.setattr(final.capture, "contiguous_end", lambda start: 15)
    monkeypatch.setattr(final, "_capture_fresh", lambda *args, **kwargs: True)

    async def drain(state, config, start, end, own_did, mailbox):
        assert (start, end) == (11, 15)
        state["cursors"]["lobby"] = 15
        return True, 5

    async def forbidden(*args, **kwargs):
        raise AssertionError("fresh complete local startup evidence must avoid server export")

    monkeypatch.setattr(final.spool, "_drain_complete_spool_range", drain)
    monkeypatch.setattr(final, "_BASE_STARTUP_CATCHUP", forbidden)

    asyncio.run(
        final.startup_catchup(
            object(), object(), state, config(), "lobby", None, None, Stop(), writer
        )
    )

    assert state["cursors"]["lobby"] == 15
    assert state["health"]["rooms"]["lobby"]["status"] == "ok"
    assert state["metrics"]["lobby_startup_capture_shortcuts"] == 1
    assert state["metrics"]["lobby_startup_capture_messages"] == 5
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0


def test_lobby_live_error_waits_for_fresh_capture_before_server_export(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["lobby"] = 10

    monkeypatch.setattr(final.capture, "contiguous_end", lambda start: start - 1)
    monkeypatch.setattr(final.capture, "status", lambda: {"capture_cursor": 10, "last_error": "", "last_success_at": "now"})
    monkeypatch.setattr(final, "_capture_fresh", lambda *args, **kwargs: True)

    async def forbidden(*args, **kwargs):
        raise AssertionError("server fallback must not race a healthy capture lane")

    monkeypatch.setattr(final, "_BASE_RECOVER_AFTER_ERROR", forbidden)

    changed, recovered, retry, error = asyncio.run(
        final.recover_after_live_error(
            object(), object(), state, config(), "lobby", None, None
        )
    )

    assert changed is True
    assert recovered == 0
    assert retry is None
    assert error == "capture_pending"
    assert state["cursors"]["lobby"] == 10
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0
    assert state["metrics"]["lobby_live_error_capture_pending_cycles"] == 1
