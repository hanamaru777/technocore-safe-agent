import asyncio

from flop_agent import (
    observer_events_startup_transport_fallback as fallback,
    observer_resilience as resilience,
)


class Writer:
    def __init__(self):
        self.dirty = 0

    def mark_dirty(self):
        self.dirty += 1


def make_state():
    state = resilience.default_state()
    state["cursors"]["events"] = 50
    return state


async def noop_base(*args, **kwargs):
    raise AssertionError("events path must not delegate to base startup catchup")


async def no_wait(stop, delay):
    return None


def test_transient_export_failure_reprobes_live_and_recovers(monkeypatch):
    state = make_state()
    stop = asyncio.Event()
    writer = Writer()
    live_calls = 0
    export_calls = 0

    async def fake_live(*args, **kwargs):
        nonlocal live_calls
        live_calls += 1
        if live_calls == 1:
            return "export", None
        state["cursors"]["events"] = 51
        resilience.set_success(state, "events")
        return "success", None

    async def fake_export(*args, **kwargs):
        nonlocal export_calls
        export_calls += 1
        assert state["cursors"]["events"] == 50
        return 0, None, "ConnectTimeout"

    monkeypatch.setattr(fallback, "_BASE_STARTUP_CATCHUP", noop_base)
    monkeypatch.setattr(fallback.startup, "_try_events_live_probe", fake_live)
    monkeypatch.setattr(fallback.startup, "_stream_events_startup_export", fake_export)
    monkeypatch.setattr(fallback.startup, "_wait_or_stop", no_wait)

    asyncio.run(
        fallback.startup_catchup(
            object(), object(), state, {}, "events", None, None, stop, writer
        )
    )

    assert live_calls == 2
    assert export_calls == 1
    assert state["cursors"]["events"] == 51
    assert state["health"]["rooms"]["events"]["status"] == "ok"
    assert state["metrics"]["events_startup_export_reprobes"] == 1
    assert state["metrics"]["events_startup_export_reprobe_successes"] == 1
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0


def test_rate_limit_stays_in_export_mode_without_live_reprobe(monkeypatch):
    state = make_state()
    stop = asyncio.Event()
    live_calls = 0
    export_calls = 0

    async def fake_live(*args, **kwargs):
        nonlocal live_calls
        live_calls += 1
        return "export", None

    async def fake_export(*args, **kwargs):
        nonlocal export_calls
        export_calls += 1
        return 0, 5.0, "rate_limited"

    async def stop_after_wait(stop_event, delay):
        assert delay == 5.0
        stop_event.set()

    monkeypatch.setattr(fallback, "_BASE_STARTUP_CATCHUP", noop_base)
    monkeypatch.setattr(fallback.startup, "_try_events_live_probe", fake_live)
    monkeypatch.setattr(fallback.startup, "_stream_events_startup_export", fake_export)
    monkeypatch.setattr(fallback.startup, "_wait_or_stop", stop_after_wait)

    asyncio.run(
        fallback.startup_catchup(
            object(), object(), state, {}, "events", None, None, stop
        )
    )

    assert live_calls == 1
    assert export_calls == 1
    assert state["cursors"]["events"] == 50
    assert state["metrics"].get("events_startup_export_reprobes", 0) == 0
    assert state["health"]["rooms"]["events"]["kind"] == "startup_stream_export_rate_limited"


def test_integrity_error_retries_export_without_live_reprobe(monkeypatch):
    state = make_state()
    stop = asyncio.Event()
    live_calls = 0
    export_calls = 0

    async def fake_live(*args, **kwargs):
        nonlocal live_calls
        live_calls += 1
        return "export", None

    async def fake_export(*args, **kwargs):
        nonlocal export_calls
        export_calls += 1
        if export_calls == 1:
            return 0, None, "invalid_export"
        resilience.set_success(state, "events")
        return 0, None, None

    monkeypatch.setattr(fallback, "_BASE_STARTUP_CATCHUP", noop_base)
    monkeypatch.setattr(fallback.startup, "_try_events_live_probe", fake_live)
    monkeypatch.setattr(fallback.startup, "_stream_events_startup_export", fake_export)
    monkeypatch.setattr(fallback.startup, "_wait_or_stop", no_wait)

    asyncio.run(
        fallback.startup_catchup(
            object(), object(), state, {}, "events", None, None, stop
        )
    )

    assert live_calls == 1
    assert export_calls == 2
    assert state["metrics"].get("events_startup_export_reprobes", 0) == 0
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0


def test_reprobe_that_proves_real_gap_returns_to_export_without_skipping(monkeypatch):
    state = make_state()
    stop = asyncio.Event()
    live_calls = 0
    export_calls = 0

    async def fake_live(*args, **kwargs):
        nonlocal live_calls
        live_calls += 1
        if live_calls == 1:
            # Initial escalation was transport-driven, not gap-driven.
            return "export", None
        resilience.set_error(
            state,
            "events",
            "startup_live_probe_gap",
            "cursor=50;first_unseen=60",
        )
        return "export", None

    async def fake_export(*args, **kwargs):
        nonlocal export_calls
        export_calls += 1
        if export_calls == 1:
            assert state["cursors"]["events"] == 50
            return 0, None, "ReadTimeout"
        record = state["health"]["rooms"]["events"]
        assert record["kind"] == "startup_live_probe_gap"
        state["cursors"]["events"] = 59
        resilience.set_success(state, "events")
        return 9, None, None

    monkeypatch.setattr(fallback, "_BASE_STARTUP_CATCHUP", noop_base)
    monkeypatch.setattr(fallback.startup, "_try_events_live_probe", fake_live)
    monkeypatch.setattr(fallback.startup, "_stream_events_startup_export", fake_export)
    monkeypatch.setattr(fallback.startup, "_wait_or_stop", no_wait)

    asyncio.run(
        fallback.startup_catchup(
            object(), object(), state, {}, "events", None, None, stop
        )
    )

    assert live_calls == 2
    assert export_calls == 2
    assert state["cursors"]["events"] == 59
    assert state["metrics"]["events_startup_export_reprobes"] == 1
    assert state["metrics"].get("events_startup_export_reprobe_successes", 0) == 0
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0
