import asyncio

from flop_agent import (
    observer_lobby_capture_health_proof as proof,
    observer_resilience as resilience,
)


def test_fresh_same_cursor_capture_clears_rich_live_error(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["lobby"] = 10
    resilience.set_error(state, "lobby", "ConnectTimeout", "")

    monkeypatch.setattr(
        proof.capture,
        "status",
        lambda: {"capture_cursor": 10, "last_error": "", "last_success_at": "now"},
    )
    monkeypatch.setattr(proof.local, "_capture_fresh", lambda *args, **kwargs: True)

    async def forbidden(*args, **kwargs):
        raise AssertionError("fresh same-cursor capture proof must avoid server fallback")

    monkeypatch.setattr(proof, "_BASE_RECOVER_AFTER_ERROR", forbidden)

    changed, recovered, retry, error = asyncio.run(
        proof.recover_after_live_error(
            object(), object(), state, {}, "lobby", None, None
        )
    )

    assert changed is True
    assert recovered == 0
    assert retry is None
    assert error is None
    assert state["health"]["rooms"]["lobby"]["status"] == "ok"
    assert state["metrics"]["lobby_capture_health_proofs"] == 1


def test_capture_behind_rich_cursor_delegates(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["lobby"] = 10
    calls = []

    monkeypatch.setattr(
        proof.capture,
        "status",
        lambda: {"capture_cursor": 9, "last_error": "", "last_success_at": "now"},
    )
    monkeypatch.setattr(proof.local, "_capture_fresh", lambda *args, **kwargs: True)

    async def base(*args, **kwargs):
        calls.append("base")
        return True, 0, None, "capture_pending"

    monkeypatch.setattr(proof, "_BASE_RECOVER_AFTER_ERROR", base)

    result = asyncio.run(
        proof.recover_after_live_error(
            object(), object(), state, {}, "lobby", None, None
        )
    )

    assert calls == ["base"]
    assert result == (True, 0, None, "capture_pending")
    assert state["metrics"].get("lobby_capture_health_proofs", 0) == 0


def test_non_lobby_never_uses_capture_health_proof(monkeypatch):
    state = resilience.default_state()
    state["cursors"]["events"] = 10
    calls = []

    def forbidden():
        raise AssertionError("non-lobby recovery must not inspect lobby capture")

    async def base(*args, **kwargs):
        calls.append("base")
        return False, 0, None, "retry_live"

    monkeypatch.setattr(proof.capture, "status", forbidden)
    monkeypatch.setattr(proof, "_BASE_RECOVER_AFTER_ERROR", base)

    result = asyncio.run(
        proof.recover_after_live_error(
            object(), object(), state, {}, "events", None, None
        )
    )

    assert calls == ["base"]
    assert result == (False, 0, None, "retry_live")
