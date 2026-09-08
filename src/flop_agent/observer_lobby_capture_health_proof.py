"""Treat a fresh independent lobby capture poll as read-side health evidence.

If the rich lobby live GET fails but the supervised capture lane has just completed
a successful poll at exactly the same cursor, there is no continuity gap to recover.
Keeping the room red in that case only reflects transport-path redundancy, not lost
observation. This wrapper clears lobby health only for that exact fresh-cursor proof.
It adds no network request and never advances a cursor.
"""
from __future__ import annotations

from . import observer_core_local_continuity as local
from . import observer_lobby_capture as capture
from . import observer_resilience as resilience

LOBBY_ROOM = "lobby"
_INSTALLED = False
_BASE_RECOVER_AFTER_ERROR = None


def _metrics(state: dict) -> dict:
    metrics = state.setdefault("metrics", {})
    metrics.setdefault("lobby_capture_health_proofs", 0)
    return metrics


async def recover_after_live_error(
    client,
    budget,
    state: dict,
    config: dict,
    room: str,
    own_did: str | None,
    mailbox: str | None,
):
    if _BASE_RECOVER_AFTER_ERROR is None:  # pragma: no cover
        raise RuntimeError("lobby capture health proof is not installed")

    if room == LOBBY_ROOM:
        since = int(state.get("cursors", {}).get(room, 0) or 0)
        status = capture.status()
        capture_cursor = int(status.get("capture_cursor", 0) or 0)
        if local._capture_fresh(status) and capture_cursor == since:
            changed = resilience.set_success(state, room)
            _metrics(state)["lobby_capture_health_proofs"] += 1
            return changed or True, 0, None, None

    return await _BASE_RECOVER_AFTER_ERROR(
        client,
        budget,
        state,
        config,
        room,
        own_did,
        mailbox,
    )


def install() -> None:
    global _INSTALLED, _BASE_RECOVER_AFTER_ERROR
    if _INSTALLED:
        return
    _BASE_RECOVER_AFTER_ERROR = resilience.recover_after_live_error
    resilience.recover_after_live_error = recover_after_live_error
    _INSTALLED = True
