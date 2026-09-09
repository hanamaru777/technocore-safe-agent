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


class StopAfterWait:
    def __init__(self) -> None:
        self.set = False
        self.waits = 0

    def is_set(self) -> bool:
        return self.set

    async def wait(self) -> None:
        self.waits += 1
        self.set = True


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
    stop = StopAfterWait()
    asyncio.run(
        liveness.startup_catchup(
            object(), object(), state, {}, "lobby", None, None, stop, writer
        )
    )

    assert state["cursors"]["lobby"] == 110
    assert state["metrics"]["lobby_startup_local_liveness_messages"] == 10
    assert state["metrics"]["lobby_startup_local_liveness_bridge_attempts"] == 0
    assert state["metrics"]["lobby_startup_local_liveness_caught_up_waits"] == 1
    assert stop.waits == 1
    assert writer.marks >= 1


def test_caught_up_lobby_stays_local_and_consumes_new_capture_rows(monkeypatch):
    now = datetime.now(UTC)
    monkeypatch.setattr(local, "_BOOT_AT", now - timedelta(seconds=10))
    status = {
        "capture_cursor": 102,
        "last_success_at": now.isoformat(),
        "last_error": "",
    }
    present = {101, 102}

    monkeypatch.setattr(capture, "status", lambda: dict(status))

    def read_range(start: int, end: int):
        if all(seq in present for seq in range(start, end + 1)):
            return [msg(seq) for seq in range(start, end + 1)]
        return []

    monkeypatch.setattr(capture, "read_range", read_range)
    monkeypatch.setattr(resilience, "_drain_export_snapshot", _fake_drain)
    monkeypatch.setattr(resilience, "set_success", lambda state, room: True)

    async def fail_bridge(*args, **kwargs):
        raise AssertionError("bridge must not run while exact local rows exist")

    async def fail_base(*args, **kwargs):
        raise AssertionError("caught-up lobby must not hand back to legacy live worker")

    monkeypatch.setattr(bridge, "_stream_until_local_resume", fail_bridge)
    monkeypatch.setattr(liveness, "_BASE_STARTUP_CATCHUP", fail_base)

    class AdvanceThenStop:
        def __init__(self) -> None:
            self.waits = 0
            self.set = False

        def is_set(self) -> bool:
            return self.set

        async def wait(self) -> None:
            self.waits += 1
            if self.waits == 1:
                present.add(103)
                status["capture_cursor"] = 103
                status["last_success_at"] = datetime.now(UTC).isoformat()
                return
            self.set = True

    stop = AdvanceThenStop()
    state = _state(100)
    asyncio.run(
        liveness.startup_catchup(
            object(), object(), state, {}, "lobby", None, None, stop, Writer()
        )
    )

    assert state["cursors"]["lobby"] == 103
    assert state["metrics"]["lobby_startup_local_liveness_messages"] == 3
    assert state["metrics"]["lobby_startup_local_liveness_caught_up_waits"] == 2
    assert stop.waits == 2


def test_caught_up_capture_timeout_waits_locally_then_recovers(monkeypatch):
    now = datetime.now(UTC)
    monkeypatch.setattr(local, "_BOOT_AT", now - timedelta(seconds=10))
    status = {
        "capture_cursor": 100,
        "last_success_at": (now - timedelta(seconds=120)).isoformat(),
        "last_error": "ReadTimeout",
    }
    present: set[int] = set()

    monkeypatch.setattr(capture, "status", lambda: dict(status))

    def read_range(start: int, end: int):
        if all(seq in present for seq in range(start, end + 1)):
            return [msg(seq) for seq in range(start, end + 1)]
        return []

    monkeypatch.setattr(capture, "read_range", read_range)
    monkeypatch.setattr(resilience, "_drain_export_snapshot", _fake_drain)

    def set_error(state, room, kind, detail=""):
        state["health"]["current"] = "degraded"
        state["health"]["rooms"][room] = {
            "status": "error",
            "kind": kind,
            "detail": detail,
        }
        return True

    def set_success(state, room):
        state["health"]["rooms"][room] = {"status": "ok"}
        state["health"]["current"] = "ok"
        return True

    monkeypatch.setattr(resilience, "set_error", set_error)
    monkeypatch.setattr(resilience, "set_success", set_success)

    async def fail_bridge(*args, **kwargs):
        raise AssertionError("caught-up capture timeout is not a proven local hole")

    async def fail_base(*args, **kwargs):
        raise AssertionError("capture timeout must stay in the local follower")

    monkeypatch.setattr(bridge, "_stream_until_local_resume", fail_bridge)
    monkeypatch.setattr(liveness, "_BASE_STARTUP_CATCHUP", fail_base)

    class RecoverThenStop:
        def __init__(self) -> None:
            self.waits = 0
            self.set = False

        def is_set(self) -> bool:
            return self.set

        async def wait(self) -> None:
            self.waits += 1
            if self.waits == 1:
                present.add(101)
                status["capture_cursor"] = 101
                status["last_success_at"] = datetime.now(UTC).isoformat()
                status["last_error"] = ""
                return
            self.set = True

    stop = RecoverThenStop()
    state = _state(100)
    asyncio.run(
        liveness.startup_catchup(
            object(), object(), state, {}, "lobby", None, None, stop, Writer()
        )
    )

    assert state["cursors"]["lobby"] == 101
    assert state["metrics"]["lobby_startup_local_liveness_messages"] == 1
    assert state["metrics"]["lobby_startup_local_liveness_bridge_attempts"] == 0
    assert state["metrics"]["lobby_startup_local_liveness_capture_stall_waits"] == 1
    assert state["metrics"]["lobby_startup_local_liveness_caught_up_waits"] == 2
    assert state["health"]["rooms"]["lobby"]["status"] == "ok"
    assert stop.waits == 2


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
    stop = StopAfterWait()
    asyncio.run(
        liveness.startup_catchup(
            object(), object(), state, {}, "lobby", None, None, stop, Writer()
        )
    )

    assert state["cursors"]["lobby"] == 105
    assert bridge_calls == [102]
    assert state["metrics"]["lobby_startup_local_liveness_bridge_attempts"] == 1
    assert state["metrics"]["lobby_startup_local_liveness_messages"] == 4
    assert state["metrics"]["lobby_startup_local_liveness_caught_up_waits"] == 1


def test_startup_streams_when_capture_is_stale_instead_of_full_export(monkeypatch):
    now = datetime.now(UTC)
    monkeypatch.setattr(local, "_BOOT_AT", now - timedelta(seconds=180))
    status = {
        "capture_cursor": 150,
        "last_success_at": (now - timedelta(seconds=120)).isoformat(),
        "last_error": "ReadTimeout",
    }
    monkeypatch.setattr(capture, "status", lambda: dict(status))
    monkeypatch.setattr(capture, "read_range", lambda start, end: [])
    monkeypatch.setattr(resilience, "set_success", lambda state, room: True)

    bridge_calls = []

    async def fake_bridge(client, budget, state, config, own_did, mailbox, stop, writer=None):
        del client, budget, config, own_did, mailbox, stop
        bridge_calls.append(int(state["cursors"]["lobby"]))
        assert state["cursors"]["lobby"] == 100
        state["cursors"]["lobby"] = 150
        status["last_success_at"] = datetime.now(UTC).isoformat()
        status["last_error"] = ""
        if writer:
            writer.mark_dirty()
        return 50, None, None, True

    async def fail_base(*args, **kwargs):
        raise AssertionError("stale capture must not re-enter legacy full export")

    monkeypatch.setattr(liveness, "_BASE_STARTUP_CATCHUP", fail_base)
    monkeypatch.setattr(bridge, "_stream_until_local_resume", fake_bridge)

    state = _state(100)
    stop = StopAfterWait()
    asyncio.run(
        liveness.startup_catchup(
            object(), object(), state, {}, "lobby", None, None, stop, Writer()
        )
    )

    assert bridge_calls == [100]
    assert state["cursors"]["lobby"] == 150
    assert state["metrics"]["lobby_startup_local_liveness_bridge_attempts"] == 1
    assert state["metrics"]["lobby_startup_local_liveness_stale_bridge_attempts"] == 1
    assert state["metrics"]["lobby_startup_local_liveness_delegations"] == 0
    assert state["metrics"]["lobby_startup_local_liveness_caught_up_waits"] == 1
