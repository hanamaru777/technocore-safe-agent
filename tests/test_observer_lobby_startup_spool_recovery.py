from __future__ import annotations

import asyncio

from flop_agent import (
    observer_lobby_startup_spool_recovery as startup_spool,
    observer_resilience as resilience,
)


class Stop:
    def __init__(self, value=False):
        self.value = value

    def is_set(self):
        return self.value


class Writer:
    def __init__(self):
        self.dirty = 0

    def mark_dirty(self):
        self.dirty += 1


def test_lobby_startup_drains_persisted_spool_before_server_path(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["lobby"] = 10
    order = []
    writer = Writer()

    monkeypatch.setattr(startup_spool.capture, "contiguous_end", lambda start: 15)

    async def fake_drain(state, config, start, end, own_did, mailbox):
        order.append(("spool", start, end))
        assert start == 11
        assert end == 15
        state["cursors"]["lobby"] = 15
        return True, 5

    async def fake_base(client, budget, state, config, room, own_did, mailbox, stop, writer=None):
        order.append(("base", state["cursors"]["lobby"]))
        assert state["cursors"]["lobby"] == 15

    monkeypatch.setattr(startup_spool.spool, "_drain_complete_spool_range", fake_drain)
    monkeypatch.setattr(startup_spool, "_BASE_STARTUP_CATCHUP", fake_base)

    asyncio.run(
        startup_spool.startup_catchup(
            object(), object(), state, {}, "lobby", None, None, Stop(), writer
        )
    )

    assert order == [("spool", 11, 15), ("base", 15)]
    assert writer.dirty == 1
    metrics = state["metrics"]
    assert metrics["lobby_startup_spool_attempts"] == 1
    assert metrics["lobby_startup_spool_recoveries"] == 1
    assert metrics["lobby_startup_spool_messages"] == 5
    assert metrics.get("unrecoverable_core_gap_events", 0) == 0


def test_non_lobby_startup_delegates_without_spool(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["events"] = 10
    calls = []

    def forbidden(*args, **kwargs):
        raise AssertionError("non-lobby startup must not inspect lobby spool")

    async def fake_base(client, budget, state, config, room, own_did, mailbox, stop, writer=None):
        calls.append(room)

    monkeypatch.setattr(startup_spool.capture, "contiguous_end", forbidden)
    monkeypatch.setattr(startup_spool, "_BASE_STARTUP_CATCHUP", fake_base)

    asyncio.run(
        startup_spool.startup_catchup(
            object(), object(), state, {}, "events", None, None, Stop()
        )
    )

    assert calls == ["events"]
    assert "lobby_startup_spool_attempts" not in state["metrics"]


def test_install_patches_startup_surface_only(monkeypatch):
    original = startup_spool.startup.startup_catchup
    monkeypatch.setattr(startup_spool, "_INSTALLED", False)
    monkeypatch.setattr(startup_spool, "_BASE_STARTUP_CATCHUP", None)
    try:
        startup_spool.install()
        assert startup_spool.startup.startup_catchup is startup_spool.startup_catchup
        assert startup_spool._BASE_STARTUP_CATCHUP is original
    finally:
        startup_spool.startup.startup_catchup = original
        startup_spool._INSTALLED = False
        startup_spool._BASE_STARTUP_CATCHUP = None
