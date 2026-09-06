"""Production-only resilience overlay for the read-only Technocore Observer.

The base Observer remains intentionally simple and heavily tested. This module
adds operational safeguards discovered in production:

* hot-room gap recovery from the official retained-ring export before a cursor
  is allowed to advance past unseen sequence numbers;
* optional-lane health isolation so the secondary ``tclk-offers`` watcher can
  fail visibly without turning the core Agent red;
* bounded hot-core polling/retry behavior so a transient connection stall does
  not leave ``lobby`` blind long enough to outrun the retained ring;
* an immediate retained-ring fallback when a core live read fails, so retained
  rows can be captured before the next successful live tail reveals a gap.

This module is read-only with respect to Technocore. It performs GETs only and
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
CORE_FALLBACK_ROOMS = frozenset({"lobby", "events"})
HOT_LOBBY_INTERVAL_SECONDS = 1
CORE_CONNECT_TIMEOUT_SECONDS = 3.0
LIVE_READ_TIMEOUT_SECONDS = 15.0
EXPORT_READ_TIMEOUT_SECONDS = 20.0
CORE_BACKOFF_MAX_SECONDS = 5.0
OPTIONAL_BACKOFF_MAX_SECONDS = 60.0
CORE_RECOVERY_RETRY_SECONDS = 1.0
OPTIONAL_RECOVERY_RETRY_SECONDS = 5.0

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
        "live_error_export_fallback_attempts",
        "live_error_export_fallback_successes",
        "live_error_export_fallback_messages",
        "live_error_export_fallback_failures",
        "unrecoverable_gap_events",
        "unrecoverable_gap_messages",
        "unrecoverable_core_gap_events",
        "unrecoverable_core_gap_messages",
        "unrecoverable_optional_gap_events",
        "unrecoverable_optional_gap_messages",
        "unrecoverable_retained_ring_start_events",
        "unrecoverable_retained_ring_start_messages",
        "unrecoverable_not_in_retained_export_events",
        "unrecoverable_not_in_retained_export_messages",
    ):
        metrics.setdefault(key, 0)
    state.setdefault("last_unrecoverable_gap", None)
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


def _http_timeout(read_seconds: float):
    return observer.httpx.Timeout(
        read_seconds,
        connect=CORE_CONNECT_TIMEOUT_SECONDS,
        pool=CORE_CONNECT_TIMEOUT_SECONDS,
    )


async def read_room_live(
    client,
    room: str,
    since: int,
    wait: int,
) -> tuple[dict | list | None, float | None, str | None]:
    """Read one live tail with a fail-fast connect and a long-poll-safe read timeout."""
    try:
        response = await client.get(
            f"{core.BASE_URL}/r/{quote(room, safe='')}",
            params={
                "format": "json",
                "since": since,
                "wait": min(max(wait, 0), 10),
                "limit": LIVE_SLICE_LIMIT,
            },
            timeout=_http_timeout(LIVE_READ_TIMEOUT_SECONDS),
        )
        if response.status_code == 429:
            return None, _retry_after(response), "rate_limited"
        response.raise_for_status()
        return response.json(), None, None
    except observer.httpx.HTTPError as error:
        return None, None, type(error).__name__


async def read_room_export(
    client,
    room: str,
) -> tuple[list[dict] | None, float | None, str | None]:
    """Read and strictly parse the official retained-ring NDJSON export."""
    try:
        response = await client.get(
            f"{core.BASE_URL}/r/{quote(room, safe='')}/export",
            timeout=_http_timeout(EXPORT_READ_TIMEOUT_SECONDS),
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
        lane = "optional" if room in OPTIONAL_ROOMS else "core"
        metrics[f"unrecoverable_{lane}_gap_events"] += 1
        metrics[f"unrecoverable_{lane}_gap_messages"] += count
        if reason in {"retained_ring_start", "not_in_retained_export"}:
            metrics[f"unrecoverable_{reason}_events"] += 1
            metrics[f"unrecoverable_{reason}_messages"] += count
        state["last_unrecoverable_gap"] = {
            "room": room,
            "lane": lane,
            "observed_at": observer.now(),
            "missing_from": start,
            "missing_to": end,
            "estimated_missing": count,
            "recovery_reason": reason,
        }


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


async def _drain_export_snapshot(
    state: dict,
    config: dict,
    room: str,
    exported: list[dict],
    own_did: str | None,
    mailbox: str | None,
    *,
    gap_end: int | None = None,
    event_message: dict | None = None,
) -> tuple[bool, int]:
    """Drain one retained-ring snapshot from the current cursor forward.

    With ``gap_end`` set, this preserves the existing successful-live gap recovery
    semantics. Without it, the newest sequence in the export becomes the bounded
    fallback endpoint, allowing a failed live read to capture retained rows now
    rather than waiting for the live endpoint to recover.
    """
    cursor = int(state.get("cursors", {}).get(room, 0) or 0)
    candidates = [
        item
        for item in exported
        if item["seq"] > cursor and (gap_end is None or item["seq"] <= gap_end)
    ]
    if gap_end is None:
        if not candidates:
            return False, 0
        gap_end = candidates[-1]["seq"]
        event_message = candidates[0]
    elif event_message is None:
        event_message = candidates[0] if candidates else {"seq": gap_end, "text": ""}

    rows_by_seq = {item["seq"]: item for item in candidates}
    ordered_seqs = sorted(rows_by_seq)
    changed = False
    recovered = 0

    if ordered_seqs and ordered_seqs[0] > cursor + 1:
        unrecoverable_end = min(gap_end, ordered_seqs[0] - 1)
        _record_unrecoverable_gap(
            state,
            room,
            event_message,
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
            recovered += max(0, end - start + 1)
            changed = True
            cursor = int(state.get("cursors", {}).get(room, cursor) or cursor)
            if cursor < gap_end:
                await asyncio.sleep(0)
            continue

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
            event_message,
            expected,
            unrecoverable_end,
            "not_in_retained_export",
        )
        state.setdefault("cursors", {})[room] = unrecoverable_end
        cursor = unrecoverable_end
        changed = True

    return changed, recovered


def _next_error_backoff(
    room: str,
    previous: float,
    retry: float | None,
    *,
    recovery: bool = False,
) -> float:
    if retry is not None:
        return max(1.0, float(retry))
    if recovery:
        return (
            OPTIONAL_RECOVERY_RETRY_SECONDS
            if room in OPTIONAL_ROOMS
            else CORE_RECOVERY_RETRY_SECONDS
        )
    cap = (
        OPTIONAL_BACKOFF_MAX_SECONDS
        if room in OPTIONAL_ROOMS
        else CORE_BACKOFF_MAX_SECONDS
    )
    return min(cap, max(1.0, previous * 2 or 1.0))


def _gap_recovery_failed(state: dict, room: str) -> bool:
    record = state.get("health", {}).get("rooms", {}).get(room, {})
    return (
        isinstance(record, dict)
        and record.get("status") == "error"
        and str(record.get("kind", "")).startswith("gap_recovery_")
    )


def _gap_retry_hint(state: dict, room: str) -> float | None:
    record = state.get("health", {}).get("rooms", {}).get(room, {})
    if not isinstance(record, dict) or record.get("kind") != "gap_recovery_rate_limited":
        return None
    try:
        return float(record.get("detail", ""))
    except (TypeError, ValueError):
        return None


def _effective_room_interval(config: dict, room: str, mailbox: str | None) -> float:
    interval = float(observer.room_interval(config, room, mailbox))
    if room == "lobby":
        return min(interval, float(HOT_LOBBY_INTERVAL_SECONDS))
    return interval


async def recover_after_live_error(
    client,
    budget,
    state: dict,
    config: dict,
    room: str,
    own_did: str | None,
    mailbox: str | None,
) -> tuple[bool, int, float | None, str | None]:
    """Try exactly one retained-ring snapshot after a non-429 core live failure."""
    metrics = _metrics(state)
    metrics["live_error_export_fallback_attempts"] += 1
    await budget.acquire()
    exported, retry, error = await read_room_export(client, room)
    if error:
        metrics["live_error_export_fallback_failures"] += 1
        return True, 0, retry, error

    metrics["live_error_export_fallback_successes"] += 1
    _, recovered = await _drain_export_snapshot(
        state,
        config,
        room,
        exported or [],
        own_did,
        mailbox,
    )
    metrics["live_error_export_fallback_messages"] += recovered
    return True, recovered, None, None


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

    One retained-ring export is a point-in-time recovery snapshot. Drain every
    recoverable record from that same snapshot in bounded in-memory chunks before
    touching the newer live slice. This avoids repeatedly spending shared read
    budget and re-fetching a moving/compacting ring for one logical gap.

    Returns ``(changed, drain_immediately)``. A true drain hint skips the normal
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

    changed, _ = await _drain_export_snapshot(
        state,
        config,
        room,
        exported or [],
        own_did,
        mailbox,
        gap_end=first_live - 1,
        event_message=live[0],
    )
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
    """Hot-room worker with bounded catch-up and bounded core retry delay."""
    backoff = 0.0
    while not stop.is_set():
        await budget.acquire()
        payload, retry, error = await read_room_live(
            client,
            room,
            state.get("cursors", {}).get(room, 0),
            config["long_poll_seconds"],
        )
        changed = False
        drain_immediately = False
        if error:
            changed = set_error(state, room, error, str(retry or ""))
            fallback_retry = None
            fallback_error = None
            if room in CORE_FALLBACK_ROOMS and error != "rate_limited":
                fallback_changed, _, fallback_retry, fallback_error = (
                    await recover_after_live_error(
                        client,
                        budget,
                        state,
                        config,
                        room,
                        own_did,
                        mailbox,
                    )
                )
                changed = fallback_changed or changed
            effective_retry = (
                fallback_retry
                if fallback_error == "rate_limited" and fallback_retry is not None
                else retry
            )
            backoff = _next_error_backoff(room, backoff, effective_retry)
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
            if _gap_recovery_failed(state, room):
                backoff = _next_error_backoff(
                    room,
                    backoff,
                    _gap_retry_hint(state, room),
                    recovery=True,
                )
            else:
                changed = set_success(state, room) or changed
                backoff = 0.0
        if writer and changed:
            writer.mark_dirty()
        delay = backoff or (
            0
            if drain_immediately
            else _effective_room_interval(config, room, mailbox)
        )
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
