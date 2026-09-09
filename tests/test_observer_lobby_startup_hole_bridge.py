from __future__ import annotations

import asyncio
import json

from flop_agent import (
    observer,
    observer_core_local_continuity as local,
    observer_lobby_capture as capture,
    observer_lobby_spool_recovery as spool,
    observer_lobby_startup_hole_bridge as bridge,
    observer_resilience as resilience,
    observer_startup_resilience as startup,
)


def msg(seq: int) -> dict:
    return {
        "seq": seq,
        "from": f"did:key:test{seq}",
        "text": f"row {seq}",
        "ts": "2026-09-09T00:00:00Z",
    }


class Budget:
    def __init__(self):
        self.calls = 0

    async def acquire(self):
        self.calls += 1


class Stop:
    def is_set(self):
        return False

    async def wait(self):
        await asyncio.sleep(3600)


class Response:
    status_code = 200
    headers = {}

    def __init__(self, rows):
        self.rows = rows

    def raise_for_status(self):
        return None

    async def aiter_lines(self):
        for row in self.rows:
            yield json.dumps(row, separators=(",", ":"))


class Context:
    def __init__(self, rows):
        self.response = Response(rows)

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class Client:
    def __init__(self, rows):
        self.rows = rows

    def stream(self, *args, **kwargs):
        return Context(self.rows)


class FailingContext:
    async def __aenter__(self):
        raise observer.httpx.ConnectTimeout("boom")

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FailingClient:
    def stream(self, *args, **kwargs):
        return FailingContext()


def cfg():
    return {**observer.DEFAULT_CONFIG, "read_budget_per_minute": 300}


def test_startup_streams_one_hole_then_returns_to_exact_local_suffix(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["lobby"] = 10
    budget = Budget()
    base_calls = []

    monkeypatch.setattr(local, "_capture_fresh", lambda *args, **kwargs: True)
    monkeypatch.setattr(capture, "status", lambda: {"capture_cursor": 20, "last_error": "", "last_success_at": "now"})

    def fake_read_range(start, end, path=None):
        if start == end and 12 <= start <= 20:
            return [msg(start)]
        return []

    def fake_contiguous_end(start, path=None):
        return 20 if 12 <= start <= 20 else start - 1

    async def fake_local_drain(state, config, start, end, own_did, mailbox, **kwargs):
        assert (start, end) == (12, 20)
        state["cursors"]["lobby"] = 20
        return True, 9

    async def forbidden_base(*args, **kwargs):
        base_calls.append(True)
        raise AssertionError("fresh local suffix must not fall into full startup export")

    monkeypatch.setattr(capture, "read_range", fake_read_range)
    monkeypatch.setattr(capture, "contiguous_end", fake_contiguous_end)
    monkeypatch.setattr(spool, "_drain_complete_spool_range", fake_local_drain)
    monkeypatch.setattr(bridge, "_BASE_STARTUP_CATCHUP", forbidden_base)

    asyncio.run(
        bridge.startup_catchup(
            Client([msg(11)]), budget, state, cfg(), "lobby", None, None, Stop()
        )
    )

    assert state["cursors"]["lobby"] == 20
    assert budget.calls == 1
    assert base_calls == []
    assert state["metrics"]["lobby_startup_bridge_successes"] == 1
    assert state["metrics"]["lobby_startup_bridge_messages"] == 1
    assert state["metrics"].get("unrecoverable_core_gap_events", 0) == 0


def test_snapshot_proven_missing_prefix_is_accounted_exactly_once(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["lobby"] = 10
    budget = Budget()

    def fake_read_range(start, end, path=None):
        if start == end and start >= 13:
            return [msg(start)]
        return []

    monkeypatch.setattr(capture, "read_range", fake_read_range)

    recovered, retry, error, local_resume = asyncio.run(
        bridge._stream_until_local_resume(
            Client([msg(13)]), budget, state, cfg(), None, None, Stop()
        )
    )

    assert (recovered, retry, error, local_resume) == (0, None, None, True)
    assert state["cursors"]["lobby"] == 12
    assert state["metrics"]["unrecoverable_core_gap_events"] == 1
    assert state["metrics"]["unrecoverable_core_gap_messages"] == 2
    assert state["last_unrecoverable_gap"]["missing_from"] == 11
    assert state["last_unrecoverable_gap"]["missing_to"] == 12
    assert state["last_unrecoverable_gap"]["recovery_reason"] == "not_in_retained_export"


def test_bridge_transport_error_never_invents_cursor_progress(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["lobby"] = 10
    budget = Budget()
    monkeypatch.setattr(capture, "read_range", lambda *args, **kwargs: [])

    recovered, retry, error, local_resume = asyncio.run(
        bridge._stream_until_local_resume(
            FailingClient(), budget, state, cfg(), None, None, Stop()
        )
    )

    assert recovered == 0
    assert retry is None
    assert error == "ConnectTimeout"
    assert local_resume is False
    assert state["cursors"]["lobby"] == 10
    assert state["metrics"].get("unrecoverable_core_gap_events", 0) == 0


def test_install_patches_only_startup_surface(monkeypatch):
    original = startup.startup_catchup
    monkeypatch.setattr(bridge, "_INSTALLED", False)
    monkeypatch.setattr(bridge, "_BASE_STARTUP_CATCHUP", None)
    try:
        bridge.install()
        assert startup.startup_catchup is bridge.startup_catchup
        assert bridge._BASE_STARTUP_CATCHUP is original
    finally:
        startup.startup_catchup = original
        bridge._INSTALLED = False
        bridge._BASE_STARTUP_CATCHUP = None
