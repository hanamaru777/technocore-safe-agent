"""Final core continuity guard for Issue #57.

Production proved two remaining read-side races after the lobby shock absorber and
incremental events recovery were already installed:

* a hot lobby gap could be classified unrecoverable merely because a fixed grace
  period expired while the independent SQLite capture process was still behind;
* an exact events startup gap whose endpoint had already fallen out of the official
  retained snapshot could be retried forever even though the only safe outcome was
  to account that exact interval once as genuinely unrecoverable and continue.

This overlay makes local capture state part of the lobby decision and gives exact
startup events gaps deterministic retained-snapshot semantics. It is GET/read-only
with respect to Technocore and never signs, posts, follows URLs, executes commands,
or accesses Signer secrets.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from urllib.parse import quote

from . import (
    core,
    observer,
    observer_events_targeted_recovery as targeted,
    observer_lobby_capture as capture,
    observer_lobby_spool_recovery as spool,
    observer_resilience as resilience,
    observer_startup_resilience as startup,
)

LOBBY_ROOM = "lobby"
EVENTS_ROOM = "events"
CAPTURE_FRESH_SECONDS = 3.0
STARTUP_CAPTURE_WAIT_SECONDS = 5.0
STARTUP_CAPTURE_POLL_SECONDS = 0.25
_BOOT_AT = datetime.now(UTC)

_INSTALLED = False
_BASE_STARTUP_CATCHUP = None
_BASE_PROCESS_LIVE = None
_BASE_RECOVER_AFTER_ERROR = None
_BASE_EVENTS_STARTUP_STREAM = None


def _metrics(state: dict) -> dict:
    metrics = state.setdefault("metrics", {})
    for key in (
        "lobby_capture_pending_cycles",
        "lobby_live_error_capture_pending_cycles",
        "lobby_startup_capture_checks",
        "lobby_startup_capture_waits",
        "lobby_startup_capture_shortcuts",
        "lobby_startup_capture_messages",
        "events_startup_snapshot_unrecoverable_events",
        "events_startup_snapshot_unrecoverable_messages",
    ):
        metrics.setdefault(key, 0)
    return metrics


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _capture_fresh(status: dict, *, not_before: datetime | None = None) -> bool:
    if status.get("last_error"):
        return False
    stamp = _parse_time(status.get("last_success_at"))
    if stamp is None:
        return False
    now = datetime.now(UTC)
    if not_before is not None and stamp < not_before:
        return False
    age = (now - stamp.astimezone(UTC)).total_seconds()
    return 0 <= age <= CAPTURE_FRESH_SECONDS


def _record_snapshot_unavailable(
    state: dict,
    target: int,
    event_message: dict | None = None,
) -> int:
    cursor = int(state.get("cursors", {}).get(EVENTS_ROOM, 0) or 0)
    if target <= cursor:
        return 0
    start = cursor + 1
    end = target
    resilience._record_unrecoverable_gap(
        state,
        EVENTS_ROOM,
        event_message or {"seq": target + 1, "text": ""},
        start,
        end,
        "not_in_retained_export",
    )
    state.setdefault("cursors", {})[EVENTS_ROOM] = end
    count = end - start + 1
    metrics = _metrics(state)
    metrics["events_startup_snapshot_unrecoverable_events"] += 1
    metrics["events_startup_snapshot_unrecoverable_messages"] += count
    return count


async def _exact_events_startup_stream(
    client,
    budget,
    state: dict,
    config: dict,
    own_did: str | None,
    mailbox: str | None,
    writer,
    target: int,
):
    """Consume only the proven events gap and account retained absence exactly."""
    metrics = startup._metrics(state)
    metrics["startup_stream_export_attempts"] += 1
    await budget.acquire()

    total_bytes = 0
    recovered_total = 0
    pending: list[dict] = []
    last_seq: int | None = None
    reached = False
    event_message: dict | None = None

    async def drain_pending() -> None:
        nonlocal pending, recovered_total
        if not pending:
            return
        recovered_total += await startup._drain_stream_rows(
            state,
            config,
            EVENTS_ROOM,
            pending,
            own_did,
            mailbox,
            writer,
        )
        pending = []

    try:
        async with client.stream(
            "GET",
            f"{core.BASE_URL}/r/{quote(EVENTS_ROOM, safe='')}/export",
            timeout=resilience._http_timeout(resilience.EXPORT_READ_TIMEOUT_SECONDS),
        ) as response:
            if response.status_code == 429:
                metrics["startup_stream_export_failures"] += 1
                return 0, resilience._retry_after(response), "rate_limited"
            response.raise_for_status()

            async for raw in response.aiter_lines():
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

                cursor = int(state.get("cursors", {}).get(EVENTS_ROOM, 0) or 0)
                if seq <= cursor:
                    continue
                event_message = item

                if seq > target:
                    break

                expected = pending[-1]["seq"] + 1 if pending else cursor + 1
                if seq > expected:
                    await drain_pending()
                    cursor = int(state.get("cursors", {}).get(EVENTS_ROOM, 0) or 0)
                    if cursor < seq - 1:
                        _record_snapshot_unavailable(state, min(seq - 1, target), item)
                    cursor = int(state.get("cursors", {}).get(EVENTS_ROOM, 0) or 0)
                    if seq <= cursor:
                        continue
                    expected = cursor + 1

                if seq != expected:
                    raise RuntimeError("invalid_export_order")

                pending.append(item)
                if len(pending) >= resilience.RECOVERY_CHUNK_MESSAGES:
                    await drain_pending()

                if seq == target:
                    reached = True
                    break

            await drain_pending()

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

    if not reached:
        _record_snapshot_unavailable(state, target, event_message)

    metrics["startup_stream_export_successes"] += 1
    metrics["startup_stream_export_messages"] += recovered_total
    metrics["startup_stream_export_bytes"] += total_bytes
    changed = resilience.set_success(state, EVENTS_ROOM)
    if writer and (changed or recovered_total):
        writer.mark_dirty()
    return recovered_total, None, None


async def stream_events_startup_export(
    client,
    budget,
    state: dict,
    config: dict,
    room: str,
    own_did: str | None,
    mailbox: str | None,
    writer=None,
):
    if _BASE_EVENTS_STARTUP_STREAM is None:  # pragma: no cover
        raise RuntimeError("core local continuity overlay is not installed")
    target = targeted._startup_gap_target(state, room)
    if room == EVENTS_ROOM and target is not None and hasattr(client, "stream"):
        return await _exact_events_startup_stream(
            client,
            budget,
            state,
            config,
            own_did,
            mailbox,
            writer,
            target,
        )
    return await _BASE_EVENTS_STARTUP_STREAM(
        client,
        budget,
        state,
        config,
        room,
        own_did,
        mailbox,
        writer,
    )


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
        raise RuntimeError("core local continuity overlay is not installed")
    if room != LOBBY_ROOM or int(state.get("cursors", {}).get(room, 0) or 0) <= 0:
        return await _BASE_STARTUP_CATCHUP(
            client, budget, state, config, room, own_did, mailbox, stop, writer
        )

    metrics = _metrics(state)
    metrics["lobby_startup_capture_checks"] += 1
    loop = asyncio.get_running_loop()
    deadline = loop.time() + STARTUP_CAPTURE_WAIT_SECONDS
    waited = False

    while not stop.is_set():
        status = capture.status()
        if _capture_fresh(status, not_before=_BOOT_AT):
            current = int(state.get("cursors", {}).get(room, 0) or 0)
            capture_cursor = int(status.get("capture_cursor", 0) or 0)

            if capture_cursor > current:
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
                    metrics["lobby_startup_capture_messages"] += recovered
                    if writer and changed:
                        writer.mark_dirty()
                    current = int(state.get("cursors", {}).get(room, current) or current)

            status = capture.status()
            capture_cursor = int(status.get("capture_cursor", 0) or 0)
            current = int(state.get("cursors", {}).get(room, 0) or 0)
            if _capture_fresh(status, not_before=_BOOT_AT) and current >= capture_cursor:
                changed = resilience.set_success(state, room)
                metrics["lobby_startup_capture_shortcuts"] += 1
                if writer and changed:
                    writer.mark_dirty()
                return

            # Capture has already crossed this cursor but cannot provide a
            # contiguous local prefix. That is a real local-hole/prune condition;
            # preserve the existing server fallback rather than trusting it.
            if capture_cursor > current:
                break

        if loop.time() >= deadline:
            break
        if not waited:
            metrics["lobby_startup_capture_waits"] += 1
            waited = True
        try:
            await asyncio.wait_for(stop.wait(), timeout=STARTUP_CAPTURE_POLL_SECONDS)
        except TimeoutError:
            pass

    return await _BASE_STARTUP_CATCHUP(
        client, budget, state, config, room, own_did, mailbox, stop, writer
    )


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
):
    if _BASE_PROCESS_LIVE is None:  # pragma: no cover
        raise RuntimeError("core local continuity overlay is not installed")

    if room == LOBBY_ROOM and not bootstrap:
        live = resilience._valid_messages(payload)
        if live:
            since = int(state.get("cursors", {}).get(room, 0) or 0)
            first_live = int(live[0]["seq"])
            gap_end = first_live - 1
            if gap_end > since:
                changed, _recovered, complete = await spool._recover_exact_spool_range_with_grace(
                    state,
                    config,
                    since + 1,
                    gap_end,
                    own_did,
                    mailbox,
                    event_message=live[0],
                )
                if complete:
                    base_changed, drain = await _BASE_PROCESS_LIVE(
                        client,
                        budget,
                        state,
                        config,
                        room,
                        payload,
                        own_did,
                        mailbox,
                        bootstrap=False,
                    )
                    return changed or base_changed, drain

                # A contiguous local suffix remains.  Yield this worker so the
                # events worker and StateWriter run; never delegate protected
                # local rows to server fallback or process newer live data early.
                current = int(state.get("cursors", {}).get(room, since) or since)
                if capture.contiguous_end(current + 1) >= current + 1:
                    return changed, False

                status = capture.status()
                capture_cursor = int(status.get("capture_cursor", 0) or 0)
                if _capture_fresh(status) and capture_cursor < gap_end:
                    detail = f"capture_cursor={capture_cursor};gap_end={gap_end}"
                    health_changed = resilience.set_error(
                        state,
                        room,
                        "gap_recovery_lobby_capture_pending",
                        detail,
                    )
                    _metrics(state)["lobby_capture_pending_cycles"] += 1
                    return changed or health_changed, False

    return await _BASE_PROCESS_LIVE(
        client,
        budget,
        state,
        config,
        room,
        payload,
        own_did,
        mailbox,
        bootstrap=bootstrap,
    )


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
        raise RuntimeError("core local continuity overlay is not installed")

    if room == LOBBY_ROOM:
        since = int(state.get("cursors", {}).get(room, 0) or 0)
        start = since + 1
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
            if recovered:
                resilience.set_success(state, room)
                return True, recovered, None, None

        status = capture.status()
        capture_cursor = int(status.get("capture_cursor", 0) or 0)
        if _capture_fresh(status) and capture_cursor <= since:
            _metrics(state)["lobby_live_error_capture_pending_cycles"] += 1
            return True, 0, None, "capture_pending"

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
    """Install after the existing startup/recovery/health overlays."""
    global _INSTALLED
    global _BASE_STARTUP_CATCHUP, _BASE_PROCESS_LIVE, _BASE_RECOVER_AFTER_ERROR
    global _BASE_EVENTS_STARTUP_STREAM
    if _INSTALLED:
        return

    _BASE_STARTUP_CATCHUP = startup.startup_catchup
    _BASE_PROCESS_LIVE = resilience.process_live_payload_with_recovery
    _BASE_RECOVER_AFTER_ERROR = resilience.recover_after_live_error
    _BASE_EVENTS_STARTUP_STREAM = startup._stream_events_startup_export

    startup.startup_catchup = startup_catchup
    startup._stream_events_startup_export = stream_events_startup_export
    resilience.process_live_payload_with_recovery = process_live_payload_with_recovery
    resilience.recover_after_live_error = recover_after_live_error
    _INSTALLED = True
