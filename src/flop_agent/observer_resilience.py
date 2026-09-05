"""Production-only resilience overlay for the read-only Technocore Observer.

The base Observer remains intentionally simple and heavily tested.  This module
adds two operational safeguards discovered in production:

* hot-room gap recovery from the official retained-ring export before a cursor
  is allowed to advance past unseen sequence numbers;
* optional-lane health isolation so the secondary ``tclk-offers`` watcher can
  fail visibly without turning the core Agent red.

This module is read-only with respect to Technocore.  It performs GETs only and
never signs, posts, follows URLs found in room text, executes commands, or reads
Signer secrets.
"""
from __future__ import annotations

import asyncio
from bisect import bisect_left
import json
from typing import Any
from urllib.parse import quote

from . import core, observer, tclk_watch

LIVE_SLICE_LIMIT = 200
EXPORT_MAX_BYTES = 12 * 1024 * 1024
RECOVERY_CHUNK_MESSAGES = 2000
OPTIONAL_ROOMS = frozenset({tclk_watch.OFFER_ROOM})

_BASE_DEFAULT_STATE = observer.default_state
_BASE_SET_ERROR = observer.set_error
_BASE_SET_SUCCESS = observer.set_success
_BASE_PROCESS_PAYLOAD = observer.process_payload
_INSTALLED = False


def _metrics(state: dict) -> dict:
    metrics = state.setdefault("metrics", {})
    for key in (
        "gap_recovery_attempts",
        "gap_recovery_batches",
        "gap_recovered_messages",
        "unrecoverable_gap_events",
        "unrecoverable_gap_messages",
        "unrecoverable_retained_ring_start_events",
        "unrecoverable_retained_ring_start_messages",
        "unrecoverable_not_in_retained_export_events",
        "unrecoverable_not_in_retained_export_messages",
    ):
        metrics.setdefault(key, 0)
    return metrics


def default_state() -> dict:
    state = _BASE_DEFAULT_STATE()
    _metrics(state)
    return state


def _recompute_core_health(state: dict) -> str:
    health = state.setdefault("health", {"current": "ok", "rooms": {}})
    rooms = health.setdefault("rooms", {})
    degraded = any(
        isinstance(value, dict)
        and value.get("status") == "error"
        and room not in OPTIONAL_ROOMS
        for room, value in rooms.items()
    )
    health["current"] = "degraded" if degraded else "ok"
    return health["current"]


def set_error(state: dict, room: str, kind: str, detail: str = "") -> bool:
    changed = _BASE_SET_ERROR(state, room, kind, detail)
    record = state.get("health", {}).get("rooms", {}).get(room)
    if room in OPTIONAL_ROOMS and isinstance(record, dict):
        record["optional"] = True
        record["impact"] = "secondary_lane_only"
    before = state.get("health", {}).get("current")
    after = _recompute_core_health(state)
    return changed or before != after


def set_success(state: dict, room: str) -> bool:
    changed = _BASE_SET_SUCCESS(state, room)
    before = state.get("health", {}).get("current")
    after = _recompute_core_health(state)
    return changed or before != after


def _response_text(response: Any) -> str:
    content = getattr(response, "content", None)
    if isinstance(content, (bytes, bytearray)):
        if len(content) > EXPORT_MAX_BYTES:
            raise RuntimeError("export_too_large")
        try:
            return bytes(content).decode("utf-8")
        except UnicodeDecodeError as error:
            raise RuntimeError("invalid_export") from error
    text = getattr(response, "text", None)
    if not isinstance(text, str):
        raise RuntimeError("invalid_export")
    if len(text.encode("utf-8")) > EXPORT_MAX_BYTES:
        raise RuntimeError("export_too_large")
    return text


def _retry_after(response: Any) -> float:
    headers = getattr(response, "headers", {}) or {}
    try:
        return max(0.0, float(headers.get("Retry-After", "1")))
    except (TypeError, ValueError):
        return 1.0


async def read_room_export(
    client,
    room: str,
) -> tuple[list[dict] | None, float | None, str | None]:
    """Read and strictly parse the official retained-ring NDJSON export."""
    try:
        response = await client.get(
            f"{core.BASE_URL}/r/{quote(room, safe='')}/export",
            timeout=20,
        )
        if response.status_code == 429:
            return None, _retry_after(response), "rate_limited"
        response.raise_for_status()
        body = _response_text(response)
        rows: dict[int, dict] = {}
        for raw in body.splitlines():
            if not raw.strip():
                continue
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
            rows[item["seq"]] = item
        return [rows[key] for key in sorted(rows)], None, None
    except observer.httpx.HTTPError as error:
        return None, None, type(error).__name__
    except RuntimeError as error:
        return None, None, str(error)


def _valid_messages(payload: dict | list) -> list[dict]:
    messages = payload.get("messages", payload if isinstance(payload, list) else [])
    if not isinstance(messages, list):
        return []
    return sorted(
        (
            item
            for item in messages
            if isinstance(item, dict) and isinstance(item.get("seq"), int)
        ),
        key=lambda item: item["seq"],
    )


def _record_recovered_batch(
    state: dict,
    room: str,
    message: dict,
    start: int,
    end: int,
) -> None:
    count = max(0, end - start + 1)
    if not count:
        return
    if observer.emit_event(
        state,
        "message_gap_recovered",
        room,
        message,
        extra={
            "recovered_from": start,
            "recovered_to": end,
            "recovered_count": count,
            "recovery": "retained_ring_export",
        },
    ):
        metrics = _metrics(state)
        metrics["gap_recovery_batches"] += 1
        metrics["gap_recovered_messages"] += count


def _record_unrecoverable_gap(
    state: dict,
    room: str,
    message: dict,
    start: int,
    end: int,
    reason: str,
) -> None:
    count = max(0, end - start + 1)
    if not count:
        return
    if observer.emit_event(
        state,
        "message_gap",
        room,
        message,
        extra={
            "missing_from": start,
            "missing_to": end,
            "estimated_missing": count,
            "recovery": "unrecoverable",
            "recovery_reason": reason,
        },
    ):
        metrics = _metrics(state)
        metrics["message_gaps"] = int(metrics.get("message_gaps", 0)) + 1
        metrics["estimated_missing_messages"] = int(
            metrics.get("estimated_missing_messages", 0)
        ) + count
        metrics["unrecoverable_gap_events"] += 1
        metrics["unrecoverable_gap_messages"] += count
        if reason in {"retained_ring_start", "not_in_retained_export"}:
            metrics[f"unrecoverable_{reason}_events"] += 1
            metrics[f"unrecoverable_{reason}_messages"] += count


def _contiguous_chunk(
    rows_by_seq: dict[int, dict],
    start: int,
    end: int,
) -> list[dict]:
    chunk: list[dict] = []
    expected = start
    while expected <= end and len(chunk) < RECOVERY_CHUNK_MESSAGES:
        item = rows_by_seq.get(expected)
        if item is None:
            break
        chunk.append(item)
        expected += 1
    return chunk


async def process_live_payload_with_recovery(
    client,
    budget,
    state: dict,
    config: dict,
    room: str,
    payload: dict | list,
    own_did: str | None,
    mailbox: str | None,
    *,
    bootstrap: bool,
) -> tuple[bool, bool]:
    """Process one live slice without advancing across a recoverable hole.

    One retained-ring export is a point-in-time recovery snapshot.  Drain every
    recoverable record from that same snapshot in bounded in-memory chunks before
    touching the newer live slice.  This avoids repeatedly spending shared read
    budget and re-fetching a moving/compacting ring for one logical gap.

    Returns ``(changed, drain_immediately)``.  A true drain hint skips the normal
    room sleep, but the shared ReadBudget still paces the next GET.
    """
    live = _valid_messages(payload)
    full_live_slice = len(live) >= LIVE_SLICE_LIMIT
    if bootstrap or not live:
        return (
            _BASE_PROCESS_PAYLOAD(
                state,
                config,
                room,
                payload,
                own_did,
                mailbox,
                bootstrap=bootstrap,
            ),
            full_live_slice,
        )

    since = int(state.get("cursors", {}).get(room, 0) or 0)
    first_live = live[0]["seq"]
    if first_live <= since + 1:
        return (
            _BASE_PROCESS_PAYLOAD(
                state,
                config,
                room,
                payload,
                own_did,
                mailbox,
                bootstrap=False,
            ),
            full_live_slice,
        )

    metrics = _metrics(state)
    metrics["gap_recovery_attempts"] += 1
    await budget.acquire()
    exported, retry, error = await read_room_export(client, room)
    if error:
        set_error(state, room, f"gap_recovery_{error}", str(retry or ""))
        return True, False

    exported = exported or []
    gap_end = first_live - 1
    changed = False
    cursor = since
    rows_by_seq = {
        item["seq"]: item
        for item in exported
        if cursor < item["seq"] <= gap_end
    }
    ordered_seqs = sorted(rows_by_seq)

    if ordered_seqs and ordered_seqs[0] > cursor + 1:
        unrecoverable_end = min(gap_end, ordered_seqs[0] - 1)
        _record_unrecoverable_gap(
            state,
            room,
            live[0],
            cursor + 1,
            unrecoverable_end,
            "retained_ring_start",
        )
        state.setdefault("cursors", {})[room] = unrecoverable_end
        cursor = unrecoverable_end
        changed = True

    while cursor < gap_end:
        expected = cursor + 1
        chunk = _contiguous_chunk(rows_by_seq, expected, gap_end)
        if chunk:
            start = chunk[0]["seq"]
            end = chunk[-1]["seq"]
            changed = (
                _BASE_PROCESS_PAYLOAD(
                    state,
                    config,
                    room,
                    {"messages": chunk},
                    own_did,
                    mailbox,
                    bootstrap=False,
                )
                or changed
            )
            _record_recovered_batch(state, room, chunk[0], start, end)
            changed = True
            cursor = int(state.get("cursors", {}).get(room, cursor) or cursor)
            if cursor < gap_end:
                # Bound CPU/event-loop occupancy without throwing away this
                # already-fetched recovery snapshot or consuming more network budget.
                await asyncio.sleep(0)
            continue

        # The retained snapshot has a hole at the next expected sequence.  Mark
        # only that absent interval unrecoverable, then continue draining any
        # later contiguous records still present in this same snapshot.
        index = bisect_left(ordered_seqs, expected)
        next_retained = (
            ordered_seqs[index]
            if index < len(ordered_seqs) and ordered_seqs[index] <= gap_end
            else None
        )
        unrecoverable_end = gap_end if next_retained is None else next_retained - 1
        _record_unrecoverable_gap(
            state,
            room,
            live[0],
            expected,
            unrecoverable_end,
            "not_in_retained_export",
        )
        state.setdefault("cursors", {})[room] = unrecoverable_end
        cursor = unrecoverable_end
        changed = True

    changed = (
        _BASE_PROCESS_PAYLOAD(
            state,
            config,
            room,
            payload,
            own_did,
            mailbox,
            bootstrap=False,
        )
        or changed
    )
    set_success(state, room)
    return changed, full_live_slice


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
    """Hot-room worker with bounded catch-up and no unpaced busy loop."""
    backoff = 0.0
    while not stop.is_set():
        await budget.acquire()
        payload, retry, error = await observer.read_room(
            client,
            room,
            state.get("cursors", {}).get(room, 0),
            config["long_poll_seconds"],
        )
        changed = False
        drain_immediately = False
        if error:
            changed = set_error(state, room, error, str(retry or ""))
            backoff = (
                retry
                if retry is not None
                else min(300.0, max(1.0, backoff * 2 or 1.0))
            )
        else:
            changed, drain_immediately = await process_live_payload_with_recovery(
                client,
                budget,
                state,
                config,
                room,
                payload or {},
                own_did,
                mailbox,
                bootstrap=room not in state.get("cursors", {}),
            )
            changed = set_success(state, room) or changed
            backoff = 0.0
        if writer and changed:
            writer.mark_dirty()
        delay = backoff or (0 if drain_immediately else observer.room_interval(config, room, mailbox))
        if delay <= 0:
            await asyncio.sleep(0)
            continue
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
        except TimeoutError:
            pass


def install() -> None:
    """Install the overlay into the base Observer module exactly once."""
    global _INSTALLED
    if _INSTALLED:
        return
    observer.default_state = default_state
    observer.set_error = set_error
    observer.set_success = set_success
    observer.room_worker = room_worker
    observer.read_room_export = read_room_export
    observer.process_live_payload_with_recovery = process_live_payload_with_recovery
    _INSTALLED = True
