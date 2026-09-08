import asyncio

from flop_agent import core, observer, observer_resilience, observer_startup_resilience


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    config = {**observer.DEFAULT_CONFIG, "read_budget_per_minute": 600}
    observer.atomic_json_write(observer.config_path(), config)
    return config


def message(seq, text="hello", did="did:key:z6MkAgent"):
    return {
        "seq": seq,
        "from": did,
        "text": text,
        "ts": "2026-09-07T00:00:00Z",
    }


class CountingBudget:
    def __init__(self):
        self.calls = 0

    async def acquire(self):
        self.calls += 1


class Writer:
    def __init__(self):
        self.dirty = 0

    def mark_dirty(self):
        self.dirty += 1


def test_startup_catchup_drains_before_live_worker(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["lobby"] = 100
    stop = asyncio.Event()
    budget = CountingBudget()
    writer = Writer()
    order = []

    async def fake_export(*args, **kwargs):
        order.append("export")
        return [message(101), message(102), message(103)], None, None

    async def fake_base(*args, **kwargs):
        order.append("live")
        stop.set()

    monkeypatch.setattr(observer_resilience, "read_room_export", fake_export)
    monkeypatch.setattr(observer_startup_resilience, "_BASE_ROOM_WORKER", fake_base)

    asyncio.run(
        observer_startup_resilience.room_worker(
            object(), budget, state, config, "lobby", None, None, stop, writer
        )
    )

    assert order == ["export", "live"]
    assert budget.calls == 1
    assert state["cursors"]["lobby"] == 103
    assert state["metrics"]["startup_export_attempts"] == 1
    assert state["metrics"]["startup_export_successes"] == 1
    assert state["metrics"]["startup_export_messages"] == 3
    assert state["metrics"]["startup_export_failures"] == 0
    assert state["metrics"]["startup_live_probe_attempts"] == 0
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0
    assert writer.dirty >= 1


def test_events_empty_live_probe_bypasses_full_export(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["events"] = 50
    stop = asyncio.Event()
    budget = CountingBudget()
    writer = Writer()

    async def fake_live(*args, **kwargs):
        return {"messages": []}, None, None

    async def forbidden_export(*args, **kwargs):
        raise AssertionError("contiguous events startup must not export")

    monkeypatch.setattr(observer_resilience, "read_room_live", fake_live)
    monkeypatch.setattr(observer_resilience, "read_room_export", forbidden_export)

    asyncio.run(
        observer_startup_resilience.startup_catchup(
            object(), budget, state, config, "events", None, None, stop, writer
        )
    )

    assert budget.calls == 1
    assert state["cursors"]["events"] == 50
    assert state["health"]["rooms"]["events"]["status"] == "ok"
    assert state["metrics"]["startup_live_probe_attempts"] == 1
    assert state["metrics"]["startup_live_probe_successes"] == 1
    assert state["metrics"]["startup_live_probe_messages"] == 0
    assert state["metrics"]["startup_live_probe_fallbacks"] == 0
    assert state["metrics"]["startup_live_probe_failures"] == 0
    assert state["metrics"]["startup_export_attempts"] == 0
    assert writer.dirty >= 1


def test_events_contiguous_live_probe_processes_bounded_slice_without_export(
    monkeypatch, tmp_path
):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["events"] = 50
    stop = asyncio.Event()
    budget = CountingBudget()
    writer = Writer()

    async def fake_live(*args, **kwargs):
        return {"messages": [message(51), message(52)]}, None, None

    async def forbidden_export(*args, **kwargs):
        raise AssertionError("contiguous events startup must not export")

    monkeypatch.setattr(observer_resilience, "read_room_live", fake_live)
    monkeypatch.setattr(observer_resilience, "read_room_export", forbidden_export)

    asyncio.run(
        observer_startup_resilience.startup_catchup(
            object(), budget, state, config, "events", None, None, stop, writer
        )
    )

    assert budget.calls == 1
    assert state["cursors"]["events"] == 52
    assert state["metrics"]["startup_live_probe_attempts"] == 1
    assert state["metrics"]["startup_live_probe_successes"] == 1
    assert state["metrics"]["startup_live_probe_messages"] == 2
    assert state["metrics"]["startup_live_probe_fallbacks"] == 0
    assert state["metrics"]["startup_export_attempts"] == 0
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0


def test_events_live_probe_transport_error_retries_live_without_export(
    monkeypatch, tmp_path
):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["events"] = 50
    stop = asyncio.Event()
    budget = CountingBudget()
    writer = Writer()
    calls = 0

    async def fake_live(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return None, None, "ConnectTimeout"
        return {"messages": [message(51), message(52)]}, None, None

    async def forbidden_export(*args, **kwargs):
        raise AssertionError("transient events live error must not force full export")

    async def no_wait(stop_event, delay):
        return None

    monkeypatch.setattr(observer_resilience, "read_room_live", fake_live)
    monkeypatch.setattr(observer_resilience, "read_room_export", forbidden_export)
    monkeypatch.setattr(observer_startup_resilience, "_wait_or_stop", no_wait)

    asyncio.run(
        observer_startup_resilience.startup_catchup(
            object(), budget, state, config, "events", None, None, stop, writer
        )
    )

    assert calls == 2
    assert budget.calls == 2
    assert state["cursors"]["events"] == 52
    assert state["health"]["rooms"]["events"]["status"] == "ok"
    assert state["metrics"]["startup_live_probe_attempts"] == 2
    assert state["metrics"]["startup_live_probe_failures"] == 1
    assert state["metrics"]["startup_live_probe_successes"] == 1
    assert state["metrics"]["startup_live_probe_fallbacks"] == 0
    assert state["metrics"]["startup_export_attempts"] == 0
    assert writer.dirty >= 2


def test_events_live_probe_error_stays_fail_closed_when_stopped(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["events"] = 50
    stop = asyncio.Event()
    budget = CountingBudget()
    writer = Writer()

    async def fake_live(*args, **kwargs):
        return None, None, "ConnectTimeout"

    async def forbidden_export(*args, **kwargs):
        raise AssertionError("transport uncertainty must not escalate to export")

    async def stop_after_error(stop_event, delay):
        stop_event.set()

    monkeypatch.setattr(observer_resilience, "read_room_live", fake_live)
    monkeypatch.setattr(observer_resilience, "read_room_export", forbidden_export)
    monkeypatch.setattr(observer_startup_resilience, "_wait_or_stop", stop_after_error)

    asyncio.run(
        observer_startup_resilience.startup_catchup(
            object(), budget, state, config, "events", None, None, stop, writer
        )
    )

    assert budget.calls == 1
    assert state["cursors"]["events"] == 50
    assert state["health"]["rooms"]["events"]["status"] == "error"
    assert state["health"]["rooms"]["events"]["kind"] == "startup_live_probe_ConnectTimeout"
    assert state["metrics"]["startup_live_probe_attempts"] == 1
    assert state["metrics"]["startup_live_probe_failures"] == 1
    assert state["metrics"]["startup_live_probe_successes"] == 0
    assert state["metrics"]["startup_live_probe_fallbacks"] == 0
    assert state["metrics"]["startup_export_attempts"] == 0
    assert writer.dirty >= 1


def test_events_live_probe_gap_falls_back_to_export_without_skipping(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["events"] = 50
    stop = asyncio.Event()
    budget = CountingBudget()
    writer = Writer()

    async def fake_live(*args, **kwargs):
        return {"messages": [message(60)]}, None, None

    async def fake_export(*args, **kwargs):
        record = state["health"]["rooms"]["events"]
        assert record["status"] == "error"
        assert record["kind"] == "startup_live_probe_gap"
        return [message(seq) for seq in range(51, 61)], None, None

    monkeypatch.setattr(observer_resilience, "read_room_live", fake_live)
    monkeypatch.setattr(observer_resilience, "read_room_export", fake_export)

    asyncio.run(
        observer_startup_resilience.startup_catchup(
            object(), budget, state, config, "events", None, None, stop, writer
        )
    )

    assert budget.calls == 2
    assert state["cursors"]["events"] == 60
    assert state["health"]["rooms"]["events"]["status"] == "ok"
    assert state["metrics"]["startup_live_probe_attempts"] == 1
    assert state["metrics"]["startup_live_probe_successes"] == 0
    assert state["metrics"]["startup_live_probe_fallbacks"] == 1
    assert state["metrics"]["startup_export_attempts"] == 1
    assert state["metrics"]["startup_export_successes"] == 1
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0


def test_startup_export_failure_retries_without_cursor_advance(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["lobby"] = 50
    stop = asyncio.Event()
    budget = CountingBudget()
    writer = Writer()
    calls = 0

    async def fake_export(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            assert state["cursors"]["lobby"] == 50
            return None, None, "ConnectTimeout"
        assert state["cursors"]["lobby"] == 50
        return [message(51), message(52)], None, None

    async def no_wait(stop_event, delay):
        return None

    monkeypatch.setattr(observer_resilience, "read_room_export", fake_export)
    monkeypatch.setattr(observer_startup_resilience, "_wait_or_stop", no_wait)

    asyncio.run(
        observer_startup_resilience.startup_catchup(
            object(), budget, state, config, "lobby", None, None, stop, writer
        )
    )

    assert calls == 2
    assert budget.calls == 2
    assert state["cursors"]["lobby"] == 52
    assert state["metrics"]["startup_live_probe_attempts"] == 0
    assert state["metrics"]["startup_export_attempts"] == 2
    assert state["metrics"]["startup_export_successes"] == 1
    assert state["metrics"]["startup_export_failures"] == 1
    assert state["metrics"]["startup_export_messages"] == 2


def test_startup_catchup_accounts_evicted_prefix_exactly(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["lobby"] = 100
    stop = asyncio.Event()
    budget = CountingBudget()

    async def fake_export(*args, **kwargs):
        return [message(110), message(111)], None, None

    monkeypatch.setattr(observer_resilience, "read_room_export", fake_export)

    asyncio.run(
        observer_startup_resilience.startup_catchup(
            object(), budget, state, config, "lobby", None, None, stop
        )
    )

    assert state["cursors"]["lobby"] == 111
    assert state["metrics"]["unrecoverable_core_gap_events"] == 1
    assert state["metrics"]["unrecoverable_core_gap_messages"] == 9
    assert state["last_unrecoverable_gap"]["missing_from"] == 101
    assert state["last_unrecoverable_gap"]["missing_to"] == 109
    assert state["last_unrecoverable_gap"]["recovery_reason"] == "retained_ring_start"
    assert state["metrics"]["startup_export_messages"] == 2


def test_optional_and_untracked_rooms_skip_startup_export(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)

    for room in ("tclk-offers", "project-watch-room"):
        state = observer_resilience.default_state()
        state["cursors"][room] = 100
        stop = asyncio.Event()
        budget = CountingBudget()

        async def forbidden_export(*args, **kwargs):
            raise AssertionError("non-core startup must not export")

        monkeypatch.setattr(observer_resilience, "read_room_export", forbidden_export)

        asyncio.run(
            observer_startup_resilience.startup_catchup(
                object(), budget, state, config, room, None, None, stop
            )
        )

        assert budget.calls == 0
        assert state["cursors"][room] == 100
        assert "startup_export_attempts" not in state["metrics"]


def test_new_core_room_without_persisted_cursor_skips_startup_export(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    stop = asyncio.Event()
    budget = CountingBudget()

    async def forbidden_export(*args, **kwargs):
        raise AssertionError("bootstrap room without cursor must not export")

    monkeypatch.setattr(observer_resilience, "read_room_export", forbidden_export)

    asyncio.run(
        observer_startup_resilience.startup_catchup(
            object(), budget, state, config, "lobby", None, None, stop
        )
    )

    assert budget.calls == 0
    assert "lobby" not in state["cursors"]


def test_startup_guard_is_get_only(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["lobby"] = 5
    stop = asyncio.Event()
    budget = CountingBudget()

    monkeypatch.setattr(
        core,
        "post_signed",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("startup catch-up must never write")
        ),
    )

    async def fake_export(*args, **kwargs):
        return [message(6)], None, None

    monkeypatch.setattr(observer_resilience, "read_room_export", fake_export)

    asyncio.run(
        observer_startup_resilience.startup_catchup(
            object(), budget, state, config, "lobby", None, None, stop
        )
    )

    assert state["cursors"]["lobby"] == 6
    assert state["metrics"]["startup_export_successes"] == 1
