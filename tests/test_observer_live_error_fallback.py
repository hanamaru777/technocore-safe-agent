import asyncio

from flop_agent import core, observer, observer_resilience


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
        "ts": "2026-09-06T00:00:00Z",
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


def run_worker(monkeypatch, tmp_path, *, room, live_result, export_result=None):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"][room] = 100
    stop = asyncio.Event()
    budget = CountingBudget()
    writer = Writer()
    calls = {"live": 0, "export": 0}

    async def fake_live(*args, **kwargs):
        calls["live"] += 1
        payload, retry, error = live_result
        if error == "rate_limited" or room not in observer_resilience.CORE_FALLBACK_ROOMS:
            stop.set()
        return payload, retry, error

    async def fake_export(*args, **kwargs):
        calls["export"] += 1
        stop.set()
        if export_result is None:
            raise AssertionError("export fallback must not run")
        return export_result

    monkeypatch.setattr(observer_resilience, "read_room_live", fake_live)
    monkeypatch.setattr(observer_resilience, "read_room_export", fake_export)

    asyncio.run(
        observer_resilience.room_worker(
            object(),
            budget,
            state,
            config,
            room,
            None,
            None,
            stop,
            writer,
        )
    )
    return state, budget, writer, calls


def test_default_state_has_live_error_fallback_metrics(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()

    assert state["metrics"]["live_error_export_fallback_attempts"] == 0
    assert state["metrics"]["live_error_export_fallback_successes"] == 0
    assert state["metrics"]["live_error_export_fallback_messages"] == 0
    assert state["metrics"]["live_error_export_fallback_failures"] == 0


def test_core_live_error_immediately_falls_back_to_export_and_drains(monkeypatch, tmp_path):
    monkeypatch.setattr(
        core,
        "post_signed",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("live-error fallback must never write")
        ),
    )

    state, budget, writer, calls = run_worker(
        monkeypatch,
        tmp_path,
        room="lobby",
        live_result=(None, None, "ConnectTimeout"),
        export_result=([message(101), message(102), message(103)], None, None),
    )

    assert calls == {"live": 1, "export": 1}
    assert budget.calls == 2
    assert writer.dirty == 1
    assert state["cursors"]["lobby"] == 103
    assert state["metrics"]["live_error_export_fallback_attempts"] == 1
    assert state["metrics"]["live_error_export_fallback_successes"] == 1
    assert state["metrics"]["live_error_export_fallback_messages"] == 3
    assert state["metrics"]["live_error_export_fallback_failures"] == 0
    assert state["metrics"]["gap_recovered_messages"] == 3
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0
    assert state["health"]["current"] == "degraded"
    assert state["health"]["rooms"]["lobby"]["kind"] == "ConnectTimeout"


def test_core_live_error_fallback_marks_missing_prefix_exactly(monkeypatch, tmp_path):
    state, budget, _, calls = run_worker(
        monkeypatch,
        tmp_path,
        room="lobby",
        live_result=(None, None, "ReadError"),
        export_result=([message(200), message(201), message(202)], None, None),
    )

    assert calls == {"live": 1, "export": 1}
    assert budget.calls == 2
    assert state["cursors"]["lobby"] == 202
    assert state["metrics"]["live_error_export_fallback_messages"] == 3
    assert state["metrics"]["unrecoverable_core_gap_events"] == 1
    assert state["metrics"]["unrecoverable_core_gap_messages"] == 99
    assert state["last_unrecoverable_gap"]["room"] == "lobby"
    assert state["last_unrecoverable_gap"]["missing_from"] == 101
    assert state["last_unrecoverable_gap"]["missing_to"] == 199
    assert state["last_unrecoverable_gap"]["recovery_reason"] == "retained_ring_start"


def test_fallback_export_failure_never_advances_cursor(monkeypatch, tmp_path):
    state, budget, _, calls = run_worker(
        monkeypatch,
        tmp_path,
        room="lobby",
        live_result=(None, None, "ConnectTimeout"),
        export_result=(None, None, "ReadTimeout"),
    )

    assert calls == {"live": 1, "export": 1}
    assert budget.calls == 2
    assert state["cursors"]["lobby"] == 100
    assert state["metrics"]["live_error_export_fallback_attempts"] == 1
    assert state["metrics"]["live_error_export_fallback_successes"] == 0
    assert state["metrics"]["live_error_export_fallback_messages"] == 0
    assert state["metrics"]["live_error_export_fallback_failures"] == 1
    assert state["metrics"]["message_gaps"] == 0
    assert state["health"]["rooms"]["lobby"]["kind"] == "ConnectTimeout"


def test_live_429_does_not_trigger_export_fallback(monkeypatch, tmp_path):
    state, budget, _, calls = run_worker(
        monkeypatch,
        tmp_path,
        room="lobby",
        live_result=(None, 17.0, "rate_limited"),
    )

    assert calls == {"live": 1, "export": 0}
    assert budget.calls == 1
    assert state["cursors"]["lobby"] == 100
    assert state["metrics"]["live_error_export_fallback_attempts"] == 0
    assert state["health"]["rooms"]["lobby"]["kind"] == "rate_limited"


def test_optional_lane_live_error_does_not_trigger_core_fallback(monkeypatch, tmp_path):
    state, budget, _, calls = run_worker(
        monkeypatch,
        tmp_path,
        room="tclk-offers",
        live_result=(None, None, "ConnectTimeout"),
    )

    assert calls == {"live": 1, "export": 0}
    assert budget.calls == 1
    assert state["cursors"]["tclk-offers"] == 100
    assert state["metrics"]["live_error_export_fallback_attempts"] == 0
    assert state["health"]["current"] == "ok"
    assert state["health"]["rooms"]["tclk-offers"]["optional"] is True


def test_unrelated_watch_room_does_not_trigger_core_fallback(monkeypatch, tmp_path):
    state, budget, _, calls = run_worker(
        monkeypatch,
        tmp_path,
        room="project-watch-room",
        live_result=(None, None, "ConnectTimeout"),
    )

    assert calls == {"live": 1, "export": 0}
    assert budget.calls == 1
    assert state["cursors"]["project-watch-room"] == 100
    assert state["metrics"]["live_error_export_fallback_attempts"] == 0
