from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from flop_agent import (
    observer_core_local_continuity as local,
    observer_lobby_capture as capture,
    observer_lobby_startup_hole_bridge as bridge,
    observer_lobby_startup_local_liveness as liveness,
    observer_resilience as resilience,
)


def msg(seq: int) -> dict:
    return {
        "seq": seq,
        "from": f"did:key:test{seq}",
        "text": f"row {seq}",
        "ts": "2026-09-09T00:00:00Z",
    }


class Stop:
    def is_set(self) -> bool:
        return False

    async def wait(self) -> None:
        await asyncio.sleep(3600)


class Writer:
    def __init__(self) -> None:
        self.marks = 0

    def mark_dirty(self) -> None:
        self.marks += 1


async def _fake_drain(
    state,
    config,
    room,
    exported,
    own_did,
    mailbox,
    *,
    gap_end=None,
    event_message=None,
):
    del config, own_did, mailbox, event_message
    if not exported:
        return False, 0
    end = int(gap_end if gap_end is not None else exported[-1]["seq"])
    state.setdefault("cursors", {})[room] = end
    return True, len(exported)


def _state(cursor: int) -> dict:
    return {
        "cursors": {"lobby": cursor},
        "metrics": {},
        "health": {"current": "degraded", "rooms": {}},
    }


def test_startup_uses_exact_local_rows_when_steady_freshness_would_reject(monkeypatch):
    now = datetime.now(UTC)
    monkeypatch.setattr(local, "_BOOT_AT", now - timedelta(seconds=40))
    monkeypatch.setattr(
        capture,
        "status",
        lambda: {
            "capture_cursor": 110,
            "last_success_at": (now - timedelta(seconds=30)).isoformat(),
            "last_error": "",
        },
    )
    monkeypatch.setattr(
        capture,
        "read_range",
        lambda start, end: [msg(seq) for seq in range(start, end + 1)]
        if 101 <= start <= end <= 110
        else [],
    )
    monkeypatch.setattr(resilience, "_drain_export_snapshot", _fake_drain)
    monkeypatch.setattr(resilience, "set_success", lambda state, room: True)

    async def fail_bridge(*args, **kwargs):
        raise AssertionError("streaming bridge must not run while exact local rows exist")

    async def fail_base(*args, **kwargs):
        raise AssertionError("legacy startup fallback must not run for healthy local evidence")

    monkeypatch.setattr(bridge, "_stream_until_local_resume", fail_bridge)
    monkeypatch.setattr(liveness, "_BASE_STARTUP_CATCHUP", fail_base)

    state = _state(100)
    writer = Writer()
    asyncio.run(
        liveness.startup_catchup(
            object(), object(), state, {}, "lobby", None, None, Stop(), writer
        )
    )

    assert state["cursors"]["lobby"] == 110
    assert state["metrics"]["lobby_startup_local_liveness_messages"] == 10
    assert state["metrics"]["lobby_startup_local_liveness_bridge_attempts"] == 0
    assert writer.marks >= 1


def test_startup_bridges_only_the_actual_local_hole(monkeypatch):
    now = datetime.now(UTC)
    monkeypatch.setattr(local, "_BOOT_AT", now - timedelta(seconds=10))
    monkeypatch.setattr(
        capture,
        "status",
        lambda: {
            "capture_cursor": 105,
            "last_success_at": now.isoformat(),
            "last_error": "",
        },
    )
    present = {101, 102, 104, 105}

    def read_range(start: int, end: int):
        if all(seq in present for seq in range(start, end + 1)):
            return [msg(seq) for seq in range(start, end + 1)]
        return []

    monkeypatch.setattr(capture, "read_range", read_range)
    monkeypatch.setattr(resilience, "_drain_export_snapshot", _fake_drain)
    monkeypatch.setattr(resilience, "set_success", lambda state, room: True)

    bridge_calls = []

    async def fake_bridge(client, budget, state, config, own_did, mailbox, stop, writer=None):
        del client, budget, config, own_did, mailbox, stop
        bridge_calls.append(int(state["cursors"]["lobby"]))
        assert state["cursors"]["lobby"] == 102
        state["cursors"]["lobby"] = 103
        if writer:
            writer.mark_dirty()
        return 1, None, None, True

    async def fail_base(*args, **kwargs):
        raise AssertionError("legacy full export must not run for a fresh isolated hole")

    monkeypatch.setattr(bridge, "_stream_until_local_resume", fake_bridge)
    monkeypatch.setattr(liveness, "_BASE_STARTUP_CATCHUP", fail_base)

    state = _state(100)
    asyncio.run(
        liveness.startup_catchup(
            object(), object(), state, {}, "lobby", None, None, Stop(), Writer()
        )
    )

    assert state["cursors"]["lobby"] == 105
    assert bridge_calls == [102]
    assert state["metrics"]["lobby_startup_local_liveness_bridge_attempts"] == 1
    assert state["metrics"]["lobby_startup_local_liveness_messages"] == 4


def test_startup_delegates_when_capture_has_no_exact_rows_and_is_stale(monkeypatch):
    now = datetime.now(UTC)
    monkeypatch.setattr(local, "_BOOT_AT", now - timedelta(seconds=180))
    monkeypatch.setattr(
        capture,
        "status",
        lambda: {
            "capture_cursor": 150,
            "last_success_at": (now - timedelta(seconds=120)).isoformat(),
            "last_error": "",
        },
    )
    monkeypatch.setattr(capture, "read_range", lambda start, end: [])

    called = []

    async def base(*args, **kwargs):
        called.append(True)

    async def fail_bridge(*args, **kwargs):
        raise AssertionError("stale capture must delegate instead of bridging")

    monkeypatch.setattr(liveness, "_BASE_STARTUP_CATCHUP", base)
    monkeypatch.setattr(bridge, "_stream_until_local_resume", fail_bridge)

    state = _state(100)
    asyncio.run(
        liveness.startup_catchup(
            object(), object(), state, {}, "lobby", None, None, Stop(), Writer()
        )
    )

    assert called == [True]
    assert state["metrics"]["lobby_startup_local_liveness_delegations"] == 1
