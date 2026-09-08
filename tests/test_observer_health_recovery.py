import asyncio

from flop_agent import observer_health_recovery, observer_resilience


def _state_with_room_error(kind: str) -> dict:
    state = observer_resilience.default_state()
    state["health"]["current"] = "degraded"
    state["health"]["rooms"]["events"] = {
        "status": "error",
        "room": "events",
        "kind": kind,
        "at": "old-error",
        "detail": "",
    }
    return state


def _run(monkeypatch, state: dict, base):
    monkeypatch.setattr(observer_health_recovery, "_BASE_PROCESS_LIVE", base)
    return asyncio.run(
        observer_health_recovery.process_live_payload_with_recovery(
            None,
            None,
            state,
            {},
            "events",
            {"messages": []},
            None,
            None,
            bootstrap=False,
        )
    )


def test_successful_live_cycle_clears_unchanged_stale_gap_recovery_error(monkeypatch):
    state = _state_with_room_error("gap_recovery_TotalTimeout")

    async def successful_cycle(*args, **kwargs):
        return False, False

    changed, drain = _run(monkeypatch, state, successful_cycle)

    assert changed is True
    assert drain is False
    assert state["health"]["rooms"]["events"]["status"] == "ok"
    assert state["health"]["current"] == "ok"


def test_fresh_gap_recovery_failure_from_current_cycle_remains_degraded(monkeypatch):
    state = _state_with_room_error("gap_recovery_TotalTimeout")

    async def failing_cycle(*args, **kwargs):
        target_state = args[2]
        room = args[4]
        observer_resilience.set_error(
            target_state,
            room,
            "gap_recovery_TotalTimeout",
            "",
        )
        return True, False

    changed, drain = _run(monkeypatch, state, failing_cycle)

    assert changed is True
    assert drain is False
    record = state["health"]["rooms"]["events"]
    assert record["status"] == "error"
    assert record["kind"] == "gap_recovery_TotalTimeout"
    assert record["at"] != "old-error"
    assert state["health"]["current"] == "degraded"


def test_successful_live_cycle_does_not_hide_other_core_error(monkeypatch):
    state = _state_with_room_error("TotalTimeout")

    async def successful_cycle(*args, **kwargs):
        return False, False

    changed, drain = _run(monkeypatch, state, successful_cycle)

    assert changed is False
    assert drain is False
    assert state["health"]["rooms"]["events"]["status"] == "error"
    assert state["health"]["rooms"]["events"]["kind"] == "TotalTimeout"
    assert state["health"]["current"] == "degraded"
