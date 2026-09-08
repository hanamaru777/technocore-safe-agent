"""Startup catch-up guard for the read-only Technocore Observer.

A Resident restart can leave an existing cursor behind a hot room. Before the
first post-restart live tail is allowed to run, protected core rooms must prove
that no unseen interval is being skipped.

Lobby keeps the conservative retained-ring export-first behavior. For the lower-
volume ``events`` core room, Production showed that a full retained export can be
pathologically slow even when the persisted cursor is already current. Events
therefore retries a bounded GET-only live probe from its persisted cursor first.
A successful contiguous/empty probe proves startup continuity. A transport error
stays fail-closed and retries the live probe; it does not immediately escalate to
the known-pathological full export. Only a successful probe that proves an actual
sequence hole falls back to retained export.

This module performs no Technocore writes, signing, command execution, URL
following, or secret access.
"""
from __future__ import annotations

import asyncio

from . import observer, observer_resilience

CORE_STARTUP_ROOMS = frozenset({"lobby", "events"})
EVENTS_LIVE_PROBE_ROOM = "events"
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
        "startup_live_probe_attempts",
        "startup_live_probe_successes",
        "startup_live_probe_messages",
        "startup_live_probe_fallbacks",
        "startup_live_probe_failures",
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


def _unseen_live_is_contiguous(live: list[dict], cursor: int) -> bool:
    unseen = [item["seq"] for item in live if item["seq"] > cursor]
    if not unseen:
        return True
    expected = cursor + 1
    for seq in unseen:
        if seq != expected:
            return False
        expected += 1
    return True


async def _try_events_live_probe(
    client,
    budget,
    state: dict,
    config: dict,
    room: str,
    own_did: str | None,
    mailbox: str | None,
    writer=None,
) -> tuple[str, float | None]:
    """Return ``success``, ``retry`` or ``export`` for one events startup probe."""
    if room != EVENTS_LIVE_PROBE_ROOM:
        return "export", None

    cursor = int(state.get("cursors", {}).get(room, 0) or 0)
    if cursor <= 0:
        return "success", None

    metrics = _metrics(state)
    metrics["startup_live_probe_attempts"] += 1
    await budget.acquire()
    payload, retry, error = await observer_resilience.read_room_live(
        client,
        room,
        cursor,
        0,
    )
    if error:
        metrics["startup_live_probe_failures"] += 1
        changed = observer_resilience.set_error(
            state,
            room,
            f"startup_live_probe_{error}",
            str(retry or ""),
        )
        if writer and changed:
            writer.mark_dirty()
        return "retry", retry

    live = observer_resilience._valid_messages(payload or {})
    if not _unseen_live_is_contiguous(live, cursor):
        metrics["startup_live_probe_fallbacks"] += 1
        first_unseen = next(
            (item["seq"] for item in live if item["seq"] > cursor),
            None,
        )
        changed = observer_resilience.set_error(
            state,
            room,
            "startup_live_probe_gap",
            f"cursor={cursor};first_unseen={first_unseen}",
        )
        if writer and changed:
            writer.mark_dirty()
        return "export", None

    changed, _drain = await observer_resilience.process_live_payload_with_recovery(
        client,
        budget,
        state,
        config,
        room,
        payload or {},
        own_did,
        mailbox,
        bootstrap=False,
    )
    changed = observer_resilience.set_success(state, room) or changed
    new_cursor = int(state.get("cursors", {}).get(room, cursor) or cursor)
    metrics["startup_live_probe_successes"] += 1
    metrics["startup_live_probe_messages"] += max(0, new_cursor - cursor)
    if writer:
        writer.mark_dirty()
    return "success", None


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
    """Prove continuity before the first normal live worker cycle.

    ``events`` retries zero-wait bounded live probes while transport itself is
    failing. A contiguous/empty unseen result is sufficient proof and avoids a
    full export. A successful probe that proves a real sequence hole falls back
    to the retained-export guard. Lobby remains export-first.

    The export guard does not fall through to the normal live path until one
    export succeeds. On export failure the cursor is untouched and the guard
    retries with a bounded delay, respecting an explicit Retry-After value when
    present.
    """
    cursor = int(state.get("cursors", {}).get(room, 0) or 0)
    if room not in CORE_STARTUP_ROOMS or cursor <= 0:
        return

    if room == EVENTS_LIVE_PROBE_ROOM:
        while not stop.is_set():
            outcome, retry = await _try_events_live_probe(
                client,
                budget,
                state,
                config,
                room,
                own_did,
                mailbox,
                writer,
            )
            if outcome == "success":
                return
            if outcome == "export":
                break
            delay = (
                max(1.0, float(retry))
                if retry is not None
                else STARTUP_RETRY_SECONDS
            )
            await _wait_or_stop(stop, delay)
        if stop.is_set():
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
