"""Clear stale lobby live-read health only after fallback continuity succeeds.

A lobby live GET can fail while the independent local capture spool (or the
existing retained-ring fallback behind it) still proves continuity.  The base
room worker records the live error before invoking recovery, but historically a
successful fallback did not replace that red health record.  Production showed
exactly this shape: stale lobby ``HTTPStatusError`` while capture remained healthy
and advancing and core loss counters did not move.

This overlay changes health only after the already-installed lobby recovery chain
returns success (``error is None``).  Failed or uncertain fallback remains red.
It adds no network request and changes no cursor or gap accounting.
"""
from __future__ import annotations

from . import observer_resilience as resilience

LOBBY_ROOM = "lobby"
_INSTALLED = False
_BASE_RECOVER_AFTER_ERROR = None


def _metrics(state: dict) -> dict:
    metrics = state.setdefault("metrics", {})
    metrics.setdefault("lobby_fallback_health_recoveries", 0)
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
    if _BASE_RECOVER_AFTER_ERROR is None:  # pragma: no cover - install contract guard
        raise RuntimeError("lobby fallback health overlay is not installed")

    changed, recovered, retry, error = await _BASE_RECOVER_AFTER_ERROR(
        client,
        budget,
        state,
        config,
        room,
        own_did,
        mailbox,
    )

    if room == LOBBY_ROOM and error is None:
        health_changed = resilience.set_success(state, room)
        if health_changed:
            _metrics(state)["lobby_fallback_health_recoveries"] += 1
        changed = health_changed or changed

    return changed, recovered, retry, error


def install() -> None:
    """Install after the complete lobby/events recovery chain."""
    global _INSTALLED, _BASE_RECOVER_AFTER_ERROR
    if _INSTALLED:
        return
    _BASE_RECOVER_AFTER_ERROR = resilience.recover_after_live_error
    resilience.recover_after_live_error = recover_after_live_error
    _INSTALLED = True
