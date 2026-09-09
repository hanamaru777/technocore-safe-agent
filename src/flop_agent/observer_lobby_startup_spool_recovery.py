"""Use persisted local lobby capture before server export during Resident startup.

The lobby shock absorber is durable SQLite state. On Resident restart, the startup
catch-up wrapper previously went straight to the moving server retained-ring export
before the normal lobby spool overlay could run. That left a restart-only path where
rows already captured locally could be ignored and classified unrecoverable if the
server ring had compacted.

This overlay drains exact persisted lobby rows before startup catch-up falls back to
the moving server ring. If the independent capture service advances while Rich
Observer is draining a large backlog, the wrapper keeps consuming the newly available
local suffix until there is no exact next local row at that instant. It performs no
Technocore write, signing, shell execution, URL following, or secret access.
"""
from __future__ import annotations

import asyncio

from . import observer_lobby_capture as capture
from . import observer_lobby_spool_recovery as spool
from . import observer_startup_resilience as startup

_INSTALLED = False
_BASE_STARTUP_CATCHUP = None


def _metrics(state: dict) -> dict:
    metrics = state.setdefault("metrics", {})
    for key in (
        "lobby_startup_spool_attempts",
        "lobby_startup_spool_recoveries",
        "lobby_startup_spool_messages",
    ):
        metrics.setdefault(key, 0)
    return metrics


async def startup_catchup(
    client,
    budget,
    state: dict,
    config: dict,
    room: str,
    own_did: str | None,
    mailbox: str | None,
    stop,
    writer=None,
) -> None:
    if _BASE_STARTUP_CATCHUP is None:  # pragma: no cover - install contract guard
        raise RuntimeError("lobby startup spool overlay is not installed")

    if room == capture.ROOM and not stop.is_set():
        cursor = int(state.get("cursors", {}).get(room, 0) or 0)
        if cursor > 0:
            metrics = _metrics(state)
            metrics["lobby_startup_spool_attempts"] += 1

            while not stop.is_set():
                current = int(state.get("cursors", {}).get(room, 0) or 0)
                start = current + 1
                end = capture.contiguous_end(start)
                if end < start:
                    break

                changed, recovered = await spool._drain_complete_spool_range(
                    state,
                    config,
                    start,
                    end,
                    own_did,
                    mailbox,
                )
                if recovered:
                    metrics["lobby_startup_spool_recoveries"] += 1
                    metrics["lobby_startup_spool_messages"] += recovered
                if writer and changed:
                    writer.mark_dirty()

                new_current = int(state.get("cursors", {}).get(room, current) or current)
                if recovered <= 0 or new_current < end:
                    break

                # Capture has its own process and may advance while this startup
                # worker drains a large exact range. Give sibling tasks a turn, then
                # re-check the next exact local prefix before considering server
                # fallback. This prevents a moving local suffix from being ignored.
                await asyncio.sleep(0)

    await _BASE_STARTUP_CATCHUP(
        client,
        budget,
        state,
        config,
        room,
        own_did,
        mailbox,
        stop,
        writer,
    )


def install() -> None:
    """Patch startup catch-up after the durable lobby spool overlay is installed."""
    global _INSTALLED, _BASE_STARTUP_CATCHUP
    if _INSTALLED:
        return
    _BASE_STARTUP_CATCHUP = startup.startup_catchup
    startup.startup_catchup = startup_catchup
    _INSTALLED = True
