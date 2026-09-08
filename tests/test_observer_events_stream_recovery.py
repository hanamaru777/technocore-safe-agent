import asyncio

from flop_agent import (
    observer_events_stream_recovery as steady,
    observer_resilience as resilience,
    observer_startup_resilience as startup,
)


def message(seq):
    return {
        "seq": seq,
        "from": "did:key:z6MkAgent",
        "text": "hello",
        "ts": "2026-09-08T00:00:00Z",
    }


async def _forbidden(*args, **kwargs):
    raise AssertionError("forbidden buffered/base recovery path")


def test_events_live_gap_uses_stream_then_base_without_buffered_gap(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["events"] = 50
    calls = []

    async def fake_stream(*args, **kwargs):
        calls.append("stream")
        state["cursors"]["events"] = 59
        return 9, None, None

    async def fake_base(*args, **kwargs):
        calls.append("base")
        assert state["cursors"]["events"] == 59
        state["cursors"]["events"] = 60
        return True, False

    monkeypatch.setattr(startup, "_stream_events_startup_export", fake_stream)
    monkeypatch.setattr(steady, "_BASE_PROCESS_LIVE", fake_base)

    changed, drain = asyncio.run(
        steady.process_live_payload_with_recovery(
            object(), object(), state, {}, "events", {"messages": [message(60)]}, None, None,
            bootstrap=False,
        )
    )

    assert changed is True
    assert drain is False
    assert calls == ["stream", "base"]
    assert state["cursors"]["events"] == 60
    assert state["metrics"]["gap_recovery_attempts"] == 1
    assert state["metrics"]["events_steady_stream_gap_attempts"] == 1
    assert state["metrics"]["events_steady_stream_attempts"] == 1
    assert state["metrics"]["events_steady_stream_successes"] == 1
    assert state["metrics"]["events_steady_stream_messages"] == 9
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0


def test_events_clean_stream_eof_accounts_remaining_gap_without_buffered_retry(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["events"] = 50

    async def fake_stream(*args, **kwargs):
        return 0, None, None

    async def fake_base(*args, **kwargs):
        assert state["cursors"]["events"] == 59
        state["cursors"]["events"] = 60
        return True, False

    monkeypatch.setattr(startup, "_stream_events_startup_export", fake_stream)
    monkeypatch.setattr(steady, "_BASE_PROCESS_LIVE", fake_base)

    asyncio.run(
        steady.process_live_payload_with_recovery(
            object(), object(), state, {}, "events", {"messages": [message(60)]}, None, None,
            bootstrap=False,
        )
    )

    assert state["metrics"]["unrecoverable_core_gap_events"] == 1
    assert state["metrics"]["unrecoverable_core_gap_messages"] == 9
    assert state["last_unrecoverable_gap"]["room"] == "events"
    assert state["last_unrecoverable_gap"]["missing_from"] == 51
    assert state["last_unrecoverable_gap"]["missing_to"] == 59
    assert state["last_unrecoverable_gap"]["recovery_reason"] == "not_in_retained_export"


def test_events_stream_error_stays_fail_closed_and_does_not_process_live(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["events"] = 50

    async def fake_stream(*args, **kwargs):
        state["cursors"]["events"] = 52
        return 2, None, "ReadTimeout"

    monkeypatch.setattr(startup, "_stream_events_startup_export", fake_stream)
    monkeypatch.setattr(steady, "_BASE_PROCESS_LIVE", _forbidden)

    changed, drain = asyncio.run(
        steady.process_live_payload_with_recovery(
            object(), object(), state, {}, "events", {"messages": [message(60)]}, None, None,
            bootstrap=False,
        )
    )

    assert changed is True
    assert drain is False
    assert state["cursors"]["events"] == 52
    assert state["health"]["rooms"]["events"]["status"] == "error"
    assert state["health"]["rooms"]["events"]["kind"] == "gap_recovery_ReadTimeout"
    assert state["metrics"]["events_steady_stream_failures"] == 1
    assert state["metrics"]["events_steady_stream_messages"] == 2
    assert state["metrics"]["unrecoverable_core_gap_events"] == 0


def test_events_live_error_fallback_uses_streaming_helper(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["events"] = 100

    async def fake_stream(*args, **kwargs):
        state["cursors"]["events"] = 103
        return 3, None, None

    monkeypatch.setattr(startup, "_stream_events_startup_export", fake_stream)
    monkeypatch.setattr(steady, "_BASE_RECOVER_AFTER_ERROR", _forbidden)

    changed, recovered, retry, error = asyncio.run(
        steady.recover_after_live_error(
            object(), object(), state, {}, "events", None, None
        )
    )

    assert changed is True
    assert recovered == 3
    assert retry is None
    assert error is None
    assert state["cursors"]["events"] == 103
    assert state["metrics"]["live_error_export_fallback_attempts"] == 1
    assert state["metrics"]["live_error_export_fallback_successes"] == 1
    assert state["metrics"]["live_error_export_fallback_messages"] == 3
    assert state["metrics"]["events_steady_stream_live_error_attempts"] == 1


def test_non_events_delegates_to_existing_overlay_chain(monkeypatch):
    state = resilience.default_state()
    calls = []

    async def fake_process(*args, **kwargs):
        calls.append("process")
        return False, False

    async def fake_recover(*args, **kwargs):
        calls.append("recover")
        return False, 0, None, None

    monkeypatch.setattr(steady, "_BASE_PROCESS_LIVE", fake_process)
    monkeypatch.setattr(steady, "_BASE_RECOVER_AFTER_ERROR", fake_recover)

    asyncio.run(
        steady.process_live_payload_with_recovery(
            object(), object(), state, {}, "lobby", {"messages": []}, None, None,
            bootstrap=False,
        )
    )
    asyncio.run(
        steady.recover_after_live_error(
            object(), object(), state, {}, "lobby", None, None
        )
    )

    assert calls == ["process", "recover"]


def test_install_captures_already_installed_lobby_chain(monkeypatch):
    async def process(*args, **kwargs):
        return False, False

    async def recover(*args, **kwargs):
        return False, 0, None, None

    monkeypatch.setattr(steady, "_INSTALLED", False)
    monkeypatch.setattr(steady, "_BASE_PROCESS_LIVE", None)
    monkeypatch.setattr(steady, "_BASE_RECOVER_AFTER_ERROR", None)
    monkeypatch.setattr(resilience, "process_live_payload_with_recovery", process)
    monkeypatch.setattr(resilience, "recover_after_live_error", recover)

    steady.install()

    assert steady._BASE_PROCESS_LIVE is process
    assert steady._BASE_RECOVER_AFTER_ERROR is recover
    assert resilience.process_live_payload_with_recovery is steady.process_live_payload_with_recovery
    assert resilience.recover_after_live_error is steady.recover_after_live_error
