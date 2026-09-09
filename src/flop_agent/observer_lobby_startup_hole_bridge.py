"""Bridge exact lobby startup holes with a bounded streaming server snapshot.

The standalone lobby capture can be far ahead of the Rich Observer while still
containing an isolated local hole.  In that case the existing startup chain drains
all exact local rows, then falls back to ``client.get(.../export)`` for the lobby.
Production showed that the full-body export can time out even though the event loop,
events worker, capture service, and core-gap counters remain healthy.

This final startup overlay keeps the local spool authoritative where exact rows
exist.  When capture has crossed the Rich cursor but the exact next local row is
missing, it streams the official GET-only lobby export only until continuity reaches
the next exact local row, then returns to SQLite recovery.  A successful snapshot
that proves rows absent still records them as genuinely unrecoverable; transport
errors never invent progress.

No Technocore write, signing, shell execution, URL following, or secret access is
introduced here.
"""
from __future__ import annotations

from urllib.parse import quote

from . import (
    core,
    observer,
    observer_core_local_continuity as local,
    observer_lobby_capture as capture,
    observer_lobby_spool_recovery as spool,
    observer_resilience as resilience,
    observer_startup_resilience as startup,
)

LOBBY_ROOM = "lobby"
BRIDGE_CHUNK_MESSAGES = spool.SPOOL_CHUNK_MESSAGES
_INSTALLED = False
_BASE_STARTUP_CATCHUP = None


def _metrics(state: dict) -> dict:
    metrics = state.setdefault("metrics", {})
    for key in (
        "lobby_startup_bridge_attempts",
        "lobby_startup_bridge_successes",
        "lobby_startup_bridge_messages",
        "lobby_startup_bridge_failures",
        "lobby_startup_bridge_bytes",
        "lobby_startup_bridge_unrecoverable_events",
        "lobby_startup_bridge_unrecoverable_messages",
    ):
        metrics.setdefault(key, 0)
    return metrics


def _local_next_present(state: dict) -> bool:
    cursor = int(state.get("cursors", {}).get(LOBBY_ROOM, 0) or 0)
    return bool(capture.read_range(cursor + 1, cursor + 1))


def _record_missing_before(
    state: dict,
    seq: int,
    event_message: dict,
    writer=None,
) -> int:
    cursor = int(state.get("cursors", {}).get(LOBBY_ROOM, 0) or 0)
    if seq <= cursor + 1:
        return 0
    start = cursor + 1
    end = seq - 1
    resilience._record_unrecoverable_gap(
        state,
        LOBBY_ROOM,
        event_message,
        start,
        end,
        "not_in_retained_export",
    )
    state.setdefault("cursors", {})[LOBBY_ROOM] = end
    count = end - start + 1
    metrics = _metrics(state)
    metrics["lobby_startup_bridge_unrecoverable_events"] += 1
    metrics["lobby_startup_bridge_unrecoverable_messages"] += count
    if writer:
        writer.mark_dirty()
    return count


async def _stream_until_local_resume(
    client,
    budget,
    state: dict,
    config: dict,
    own_did: str | None,
    mailbox: str | None,
    stop,
    writer=None,
) -> tuple[int, float | None, str | None, bool]:
    """Stream retained lobby rows until the exact local spool can resume.

    Returns ``(recovered, retry_after, error, local_resume)``.  ``error`` is only
    transport/format/snapshot-incompleteness; a snapshot-proven retained absence is
    accounted exactly and is not hidden as a transport failure.
    """
    metrics = _metrics(state)
    metrics["lobby_startup_bridge_attempts"] += 1
    await budget.acquire()

    recovered_total = 0
    total_bytes = 0
    pending: list[dict] = []
    last_seq: int | None = None

    async def drain_pending() -> None:
        nonlocal pending, recovered_total
        if not pending:
            return
        changed, recovered = await resilience._drain_export_snapshot(
            state,
            config,
            LOBBY_ROOM,
            pending,
            own_did,
            mailbox,
            gap_end=pending[-1]["seq"],
            event_message=pending[0],
        )
        recovered_total += recovered
        if writer and (changed or recovered):
            writer.mark_dirty()
        pending = []

    try:
        async with client.stream(
            "GET",
            f"{core.BASE_URL}/r/{quote(LOBBY_ROOM, safe='')}/export",
            timeout=resilience._http_timeout(resilience.EXPORT_READ_TIMEOUT_SECONDS),
        ) as response:
            if response.status_code == 429:
                metrics["lobby_startup_bridge_failures"] += 1
                return 0, resilience._retry_after(response), "rate_limited", False
            response.raise_for_status()

            async for raw in response.aiter_lines():
                if stop.is_set():
                    break
                if not raw.strip():
                    continue
                total_bytes += len(raw.encode("utf-8")) + 1
                if total_bytes > resilience.EXPORT_MAX_BYTES:
                    raise RuntimeError("export_too_large")

                item = startup._strict_export_item(raw)
                seq = int(item["seq"])
                if last_seq is not None and seq <= last_seq:
                    raise RuntimeError("invalid_export_order")
                last_seq = seq

                cursor = int(state.get("cursors", {}).get(LOBBY_ROOM, 0) or 0)
                if seq <= cursor:
                    continue

                expected = pending[-1]["seq"] + 1 if pending else cursor + 1

                # Do not consume a server row that is already available exactly in
                # SQLite. Commit the pending bridge prefix and hand control back to
                # the local spool instead.
                if capture.read_range(expected, expected):
                    await drain_pending()
                    metrics["lobby_startup_bridge_successes"] += 1
                    metrics["lobby_startup_bridge_messages"] += recovered_total
                    metrics["lobby_startup_bridge_bytes"] += total_bytes
                    return recovered_total, None, None, True

                if seq > expected:
                    await drain_pending()
                    cursor = int(state.get("cursors", {}).get(LOBBY_ROOM, 0) or 0)
                    if capture.read_range(cursor + 1, cursor + 1):
                        metrics["lobby_startup_bridge_successes"] += 1
                        metrics["lobby_startup_bridge_messages"] += recovered_total
                        metrics["lobby_startup_bridge_bytes"] += total_bytes
                        return recovered_total, None, None, True
                    if seq > cursor + 1:
                        _record_missing_before(state, seq, item, writer)
                        cursor = int(state.get("cursors", {}).get(LOBBY_ROOM, 0) or 0)
                        if capture.read_range(cursor + 1, cursor + 1):
                            metrics["lobby_startup_bridge_successes"] += 1
                            metrics["lobby_startup_bridge_messages"] += recovered_total
                            metrics["lobby_startup_bridge_bytes"] += total_bytes
                            return recovered_total, None, None, True
                    expected = cursor + 1

                if seq != expected:
                    raise RuntimeError("invalid_export_order")

                pending.append(item)
                if len(pending) >= BRIDGE_CHUNK_MESSAGES:
                    await drain_pending()
                    if _local_next_present(state):
                        metrics["lobby_startup_bridge_successes"] += 1
                        metrics["lobby_startup_bridge_messages"] += recovered_total
                        metrics["lobby_startup_bridge_bytes"] += total_bytes
                        return recovered_total, None, None, True

            await drain_pending()

    except observer.httpx.HTTPError as error:
        metrics["lobby_startup_bridge_failures"] += 1
        metrics["lobby_startup_bridge_messages"] += recovered_total
        metrics["lobby_startup_bridge_bytes"] += total_bytes
        return recovered_total, None, type(error).__name__, False
    except RuntimeError as error:
        metrics["lobby_startup_bridge_failures"] += 1
        metrics["lobby_startup_bridge_messages"] += recovered_total
        metrics["lobby_startup_bridge_bytes"] += total_bytes
        return recovered_total, None, str(error), False

    metrics["lobby_startup_bridge_messages"] += recovered_total
    metrics["lobby_startup_bridge_bytes"] += total_bytes
    if _local_next_present(state):
        metrics["lobby_startup_bridge_successes"] += 1
        return recovered_total, None, None, True

    # A snapshot can end while the independent capture has already moved farther
    # ahead. That is not proof of loss; retry a fresh snapshot from the persisted
    # exact cursor rather than falling into the old full-body export path.
    metrics["lobby_startup_bridge_failures"] += 1
    return recovered_total, None, "snapshot_ended_before_local_resume", False


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
    if _BASE_STARTUP_CATCHUP is None:  # pragma: no cover
        raise RuntimeError("lobby startup hole bridge is not installed")
    if room != LOBBY_ROOM or int(state.get("cursors", {}).get(room, 0) or 0) <= 0:
        return await _BASE_STARTUP_CATCHUP(
            client, budget, state, config, room, own_did, mailbox, stop, writer
        )

    while not stop.is_set():
        status = capture.status()
        if not local._capture_fresh(status, not_before=local._BOOT_AT):
            return await _BASE_STARTUP_CATCHUP(
                client, budget, state, config, room, own_did, mailbox, stop, writer
            )

        current = int(state.get("cursors", {}).get(room, 0) or 0)
        capture_cursor = int(status.get("capture_cursor", 0) or 0)
        if current >= capture_cursor:
            changed = resilience.set_success(state, room)
            if writer and changed:
                writer.mark_dirty()
            return

        start = current + 1
        end = capture.contiguous_end(start)
        if end >= start:
            changed, recovered = await spool._drain_complete_spool_range(
                state,
                config,
                start,
                end,
                own_did,
                mailbox,
            )
            if writer and changed:
                writer.mark_dirty()
            if recovered <= 0:
                return await _BASE_STARTUP_CATCHUP(
                    client, budget, state, config, room, own_did, mailbox, stop, writer
                )
            continue

        # Capture has crossed the Rich cursor but cannot provide its exact next row.
        # Bridge only that hole from a streaming official snapshot, then return to
        # local recovery as soon as the SQLite suffix becomes exact again.
        recovered, retry, error, local_resume = await _stream_until_local_resume(
            client,
            budget,
            state,
            config,
            own_did,
            mailbox,
            stop,
            writer,
        )
        if local_resume:
            continue
        if stop.is_set():
            return

        detail = str(retry or "")
        changed = resilience.set_error(
            state,
            room,
            f"startup_lobby_bridge_{error or 'retry'}",
            detail,
        )
        if writer and (changed or recovered):
            writer.mark_dirty()
        delay = max(1.0, float(retry)) if retry is not None else startup.STARTUP_RETRY_SECONDS
        await startup._wait_or_stop(stop, delay)


def install() -> None:
    """Install after the final core-local continuity overlay."""
    global _INSTALLED, _BASE_STARTUP_CATCHUP
    if _INSTALLED:
        return
    _BASE_STARTUP_CATCHUP = startup.startup_catchup
    startup.startup_catchup = startup_catchup
    _INSTALLED = True
