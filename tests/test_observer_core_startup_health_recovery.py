import asyncio

from flop_agent import (
    observer_events_startup_transport_fallback as events_fallback,
    observer_lobby_fallback_health as lobby_health,
    observer_resilience as resilience,
)


async def _call_events(state, room="events"):
    return await events_fallback.try_events_live_probe(
        object(), object(), state, {}, room, None, None, None
    )


def test_events_second_non_rate_limit_transport_failure_escalates_to_stream(monkeypatch):
    state = resilience.default_state()

    async def fake_base(*args, **kwargs):
        return "retry", None

    monkeypatch.setattr(events_fallback, "_BASE_TRY_LIVE_PROBE", fake_base)

    first = asyncio.run(_call_events(state))
    second = asyncio.run(_call_events(state))

    assert first == ("retry", None)
    assert second == ("export", None)
    assert state["metrics"]["events_startup_transport_streak"] == 0
    assert state["metrics"]["events_startup_transport_escalations"] == 1


def test_events_rate_limit_never_escalates_to_export(monkeypatch):
    state = resilience.default_state()

    async def fake_base(*args, **kwargs):
        return "retry", 3.0

    monkeypatch.setattr(events_fallback, "_BASE_TRY_LIVE_PROBE", fake_base)

    for _ in range(4):
        assert asyncio.run(_call_events(state)) == ("retry", 3.0)

    assert state["metrics"]["events_startup_transport_streak"] == 0
    assert state["metrics"]["events_startup_transport_escalations"] == 0


def test_events_success_resets_transport_streak(monkeypatch):
    state = resilience.default_state()
    outcomes = iter([("retry", None), ("success", None)])

    async def fake_base(*args, **kwargs):
        return next(outcomes)

    monkeypatch.setattr(events_fallback, "_BASE_TRY_LIVE_PROBE", fake_base)

    assert asyncio.run(_call_events(state)) == ("retry", None)
    assert state["metrics"]["events_startup_transport_streak"] == 1
    assert asyncio.run(_call_events(state)) == ("success", None)
    assert state["metrics"]["events_startup_transport_streak"] == 0
    assert state["metrics"]["events_startup_transport_escalations"] == 0


def test_lobby_successful_fallback_clears_stale_live_error(monkeypatch):
    state = resilience.default_state()
    resilience.set_error(state, "lobby", "HTTPStatusError", "")

    async def fake_base(*args, **kwargs):
        return True, 0, None, None

    monkeypatch.setattr(lobby_health, "_BASE_RECOVER_AFTER_ERROR", fake_base)

    changed, recovered, retry, error = asyncio.run(
        lobby_health.recover_after_live_error(
            object(), object(), state, {}, "lobby", None, None
        )
    )

    assert changed is True
    assert recovered == 0
    assert retry is None
    assert error is None
    assert state["health"]["rooms"]["lobby"]["status"] == "ok"
    assert state["metrics"]["lobby_fallback_health_recoveries"] == 1


def test_lobby_failed_fallback_stays_red(monkeypatch):
    state = resilience.default_state()
    resilience.set_error(state, "lobby", "HTTPStatusError", "")

    async def fake_base(*args, **kwargs):
        return True, 0, None, "ConnectTimeout"

    monkeypatch.setattr(lobby_health, "_BASE_RECOVER_AFTER_ERROR", fake_base)

    _changed, _recovered, _retry, error = asyncio.run(
        lobby_health.recover_after_live_error(
            object(), object(), state, {}, "lobby", None, None
        )
    )

    assert error == "ConnectTimeout"
    assert state["health"]["rooms"]["lobby"]["status"] == "error"
    assert state["health"]["rooms"]["lobby"]["kind"] == "HTTPStatusError"
    assert state["metrics"].get("lobby_fallback_health_recoveries", 0) == 0


def test_non_lobby_success_does_not_reclassify_health(monkeypatch):
    state = resilience.default_state()
    resilience.set_error(state, "events", "TotalTimeout", "")

    async def fake_base(*args, **kwargs):
        return True, 5, None, None

    monkeypatch.setattr(lobby_health, "_BASE_RECOVER_AFTER_ERROR", fake_base)

    asyncio.run(
        lobby_health.recover_after_live_error(
            object(), object(), state, {}, "events", None, None
        )
    )

    assert state["health"]["rooms"]["events"]["status"] == "error"
    assert state["health"]["rooms"]["events"]["kind"] == "TotalTimeout"
    assert state["metrics"].get("lobby_fallback_health_recoveries", 0) == 0
