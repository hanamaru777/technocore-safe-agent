"""Startup catch-up guard for the read-only Technocore Observer.

A Resident restart can leave an existing cursor behind a hot room. Before the
first post-restart live tail is allowed to run, protected core rooms must prove
that no unseen interval is being skipped.

Lobby keeps the conservative retained-ring export-first behavior. For the lower-
volume ``events`` core room, Production showed two separate failure modes:

* a transient startup live-probe transport error must not immediately force the
  pathologically slow full retained export; retry the bounded live probe instead;
* when a successful live probe proves a real sequence hole, buffering the whole
  export before processing can time out repeatedly without making any progress.

Events therefore retries zero-wait GET-only live probes while transport is
uncertain. If a successful probe proves a real hole, startup consumes the official
snapshot-at-open JSONL export incrementally and drains contiguous rows in bounded
chunks as they arrive. The cursor advances only through rows actually received and
validated. A stream failure stays fail-closed and retries from the resulting cursor.

This module performs no Technocore writes, signing, command execution, URL
following, or secret access.
"""
from __future__ import annotations

import asyncio
import json
from urllib.parse import quote

from . import core, observer, observer_resilience

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
        "startup_stream_export_attempts",
        "startup_stream_export_successes",
        "startup_stream_export_messages",
        "startup_stream_export_failures",
        "startup_stream_export_bytes",
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


def _strict_export_item(raw: str) -> dict:
    try:
        item = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("invalid_export") from error
    if (
        not isinstance(item, dict)
        or not isinstance(item.get("seq"), int)
        or item["seq"] < 0
        or not isinstance(item.get("text"), str)
    ):
        raise RuntimeError("invalid_export")
    return item


async def _drain_stream_rows(
    state: dict,
    config: dict,
    room: str,
    rows: list[dict],
    own_did: str | None,
    mailbox: str | None,
    writer=None,
) -> int:
    """Drain one already-validated ordered stream chunk into the existing recovery path."""
    if not rows:
        return 0
    changed, recovered = await observer_resilience._drain_export_snapshot(
        state,
        config,
        room,
        rows,
        own_did,
        mailbox,
        gap_end=rows[-1]["seq"],
        event_message=rows[0],
    )
    if writer and (changed or recovered):
        writer.mark_dirty()
    return recovered


async def _stream_events_startup_export(
    client,
    budget,
    state: dict,
    config: dict,
    room: str,
    own_did: str | None,
    mailbox: str | None,
    writer=None,
) -> tuple[int, float | None, str | None]:
    """Incrementally consume one official retained-ring snapshot for ``events``.

    Technocore's export is a bounded snapshot-at-open forward JSONL stream. Unlike
    ``client.get()``, this path does not wait for the complete body before using a
    contiguous retained prefix. The existing inactivity/connect timeouts and export
    byte ceiling still bound a broken response. There is deliberately no separate
    all-body wall-clock deadline here: partial contiguous progress is itself safe,
    persisted state, while a stalled stream is still terminated by HTTPX inactivity.
    """
    if room != EVENTS_LIVE_PROBE_ROOM:
        return 0, None, "invalid_stream_room"

    metrics = _metrics(state)
    metrics["startup_stream_export_attempts"] += 1
    await budget.acquire()

    total_bytes = 0
    recovered_total = 0
    pending: list[dict] = []
    last_seq: int | None = None

    try:
        async with client.stream(
            "GET",
            f"{core.BASE_URL}/r/{quote(room, safe='')}/export",
            timeout=observer_resilience._http_timeout(
                observer_resilience.EXPORT_READ_TIMEOUT_SECONDS
            ),
        ) as response:
            if response.status_code == 429:
                metrics["startup_stream_export_failures"] += 1
                return 0, observer_resilience._retry_after(response), "rate_limited"
            response.raise_for_status()

            async for raw in response.aiter_lines():
                if not raw.strip():
                    continue
                total_bytes += len(raw.encode("utf-8")) + 1
                if total_bytes > observer_resilience.EXPORT_MAX_BYTES:
                    raise RuntimeError("export_too_large")

                item = _strict_export_item(raw)
                seq = item["seq"]
                if last_seq is not None and seq <= last_seq:
                    raise RuntimeError("invalid_export_order")
                last_seq = seq

                cursor = int(state.get("cursors", {}).get(room, 0) or 0)
                if seq <= cursor:
                    continue

                pending.append(item)
                if len(pending) >= observer_resilience.RECOVERY_CHUNK_MESSAGES:
                    recovered = await _drain_stream_rows(
                        state,
                        config,
                        room,
                        pending,
                        own_did,
                        mailbox,
                        writer,
                    )
                    recovered_total += recovered
                    pending = []

            if pending:
                recovered_total += await _drain_stream_rows(
                    state,
                    config,
                    room,
                    pending,
                    own_did,
                    mailbox,
                    writer,
                )

    except observer.httpx.HTTPError as error:
        metrics["startup_stream_export_failures"] += 1
        metrics["startup_stream_export_messages"] += recovered_total
        metrics["startup_stream_export_bytes"] += total_bytes
        return recovered_total, None, type(error).__name__
    except RuntimeError as error:
        metrics["startup_stream_export_failures"] += 1
        metrics["startup_stream_export_messages"] += recovered_total
        metrics["startup_stream_export_bytes"] += total_bytes
        return recovered_total, None, str(error)

    metrics["startup_stream_export_successes"] += 1
    metrics["startup_stream_export_messages"] += recovered_total
    metrics["startup_stream_export_bytes"] += total_bytes
    changed = observer_resilience.set_success(state, room)
    if writer and (changed or recovered_total):
        writer.mark_dirty()
    return recovered_total, None, None


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
    failing. A contiguous/empty unseen result is sufficient proof. A successful
    probe that proves a real sequence hole switches to incremental streaming of
    the official retained export until one complete snapshot succeeds. Lobby keeps
    the original full-export startup guard.
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

        while not stop.is_set():
            _recovered, retry, error = await _stream_events_startup_export(
                client,
                budget,
                state,
                config,
                room,
                own_did,
                mailbox,
                writer,
            )
            if not error:
                return
            changed = observer_resilience.set_error(
                state,
                room,
                f"startup_stream_export_{error}",
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
