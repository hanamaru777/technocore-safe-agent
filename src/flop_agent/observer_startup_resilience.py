"""Startup catch-up guard for the read-only Technocore Observer.

A Resident restart can leave an existing cursor behind a hot room. Before the
first post-restart live tail is allowed to run, protected core rooms snapshot the
official retained-ring export and drain everything newer than the persisted
cursor. This closes the startup window that PR #72's live-error fallback cannot
cover because that fallback only activates after a live read actually fails.

This module performs no Technocore writes, signing, command execution, URL
following, or secret access.
"""
from __future__ import annotations

import asyncio

from . import observer, observer_resilience

CORE_STARTUP_ROOMS = frozenset({"lobby", "events"})
STARTUP_RETRY_SECONDS = 1.0
_INSTALLED = False
_BASE_ROOM_WORKER = observer_resilience.room_worker


def _metrics(state: dict) -> dict:
    metrics = state.setdefault("metrics", {})
    for key in (
        "startup_export_attempts",
        "startup_export_successes",
        "startup_export_messages",
        "startup_export_failures",
    ):
        metrics.setdefault(key, 0)
    return metrics


async def _wait_or_stop(stop: asyncio.Event, delay: float) -> None:
    if delay <= 0:
        await asyncio.sleep(0)
        return
    try:
        await asyncio.wait_for(stop.wait(), timeout=delay)
    except TimeoutError:
        pass


async def startup_catchup(
    client,
    budget,
    state: dict,
    config: dict,
    room: str,
    own_did: str | None,
    mailbox: str | None,
    stop: asyncio.Event,
    writer=None,
) -> None:
    """Drain retained rows before the first live read for a persisted core cursor.

    The worker does not fall through to the live path until one export succeeds.
    On export failure the cursor is untouched and the guard retries with a bounded
    delay, respecting an explicit Retry-After value when present.
    """
    cursor = int(state.get("cursors", {}).get(room, 0) or 0)
    if room not in CORE_STARTUP_ROOMS or cursor <= 0:
        return

    metrics = _metrics(state)
    while not stop.is_set():
        metrics["startup_export_attempts"] += 1
        await budget.acquire()
        exported, retry, error = await observer_resilience.read_room_export(
            client, room
        )
        if error:
            metrics["startup_export_failures"] += 1
            changed = observer_resilience.set_error(
                state,
                room,
                f"startup_export_{error}",
                str(retry or ""),
            )
            if writer and changed:
                writer.mark_dirty()
            delay = (
                max(1.0, float(retry))
                if retry is not None
                else STARTUP_RETRY_SECONDS
            )
            await _wait_or_stop(stop, delay)
            continue

        metrics["startup_export_successes"] += 1
        changed, recovered = await observer_resilience._drain_export_snapshot(
            state,
            config,
            room,
            exported or [],
            own_did,
            mailbox,
        )
        metrics["startup_export_messages"] += recovered
        changed = observer_resilience.set_success(state, room) or changed
        if writer and (changed or recovered):
            writer.mark_dirty()
        return


async def room_worker(
    client,
    budget,
    state: dict,
    config: dict,
    room: str,
    own_did: str | None,
    mailbox: str | None,
    stop: asyncio.Event,
    writer=None,
) -> None:
    await startup_catchup(
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
    if stop.is_set():
        return
    await _BASE_ROOM_WORKER(
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
    """Install startup protection after the main resilience overlay."""
    global _INSTALLED
    if _INSTALLED:
        return
    observer.room_worker = room_worker
    _INSTALLED = True
