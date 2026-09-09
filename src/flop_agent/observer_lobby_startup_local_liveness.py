"""Keep lobby startup on bounded exact local chunks before any server fallback.

Production showed two separate startup hazards:

* exact persisted SQLite rows were skipped when capture freshness exceeded a strict
  steady-state threshold, causing a return to the old full-body lobby export;
* the standalone capture can itself enter a transient ReadTimeout while a large,
  exact local backlog is still available. Once that local backlog is exhausted,
  delegating to the old full-body export recreates the same startup stall.

This startup guard is therefore local-first and streaming-only for unresolved lobby
continuity:
- exact persisted rows are always authoritative, regardless of capture freshness;
- startup drains at most 100 exact local rows per slice and yields;
- if capture is fresh and the Rich cursor has caught up to it, startup may succeed;
- otherwise any unresolved next-row condition uses the existing bounded streaming
  bridge, even while capture is stale or reporting a transient read error;
- the legacy full-body lobby export is not used for a stale/missing local next row.

No Technocore write, signing, shell execution, URL following, or secret access is
introduced here.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from . import (
    observer_core_local_continuity as local,
    observer_lobby_capture as capture,
    observer_lobby_startup_hole_bridge as bridge,
    observer_resilience as resilience,
    observer_startup_resilience as startup,
)

LOBBY_ROOM = "lobby"
LOCAL_CHUNK_MESSAGES = 100
STARTUP_CAPTURE_FRESH_SECONDS = 60.0
_INSTALLED = False
_BASE_STARTUP_CATCHUP = None


def _metrics(state: dict) -> dict:
    metrics = state.setdefault("metrics", {})
    for key in (
        "lobby_startup_local_liveness_slices",
        "lobby_startup_local_liveness_messages",
        "lobby_startup_local_liveness_bridge_attempts",
        "lobby_startup_local_liveness_delegations",
        "lobby_startup_local_liveness_stale_bridge_attempts",
    ):
        metrics.setdefault(key, 0)
    return metrics


def _startup_capture_fresh(status: dict) -> bool:
    """Startup-only liveness proof; steady-state keeps its stricter 3s policy."""
    if status.get("last_error"):
        return False
    stamp = local._parse_time(status.get("last_success_at"))
    if stamp is None or stamp < local._BOOT_AT:
        return False
    age = (datetime.now(UTC) - stamp.astimezone(UTC)).total_seconds()
    return 0 <= age <= STARTUP_CAPTURE_FRESH_SECONDS


def _read_bounded_local_prefix(start: int, capture_cursor: int) -> list[dict]:
    """Return a contiguous local prefix with O(chunk) work and no suffix scan."""
    if capture_cursor < start:
        return []
    available = min(LOCAL_CHUNK_MESSAGES, capture_cursor - start + 1)
    sizes: list[int] = []
    for candidate in (available, 50, 25, 10, 5, 1):
        size = min(available, candidate)
        if size > 0 and size not in sizes:
            sizes.append(size)
    for size in sizes:
        rows = capture.read_range(start, start + size - 1)
        if rows:
            return rows
    return []


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
        raise RuntimeError("lobby startup local liveness guard is not installed")
    if room != LOBBY_ROOM or int(state.get("cursors", {}).get(room, 0) or 0) <= 0:
        return await _BASE_STARTUP_CATCHUP(
            client, budget, state, config, room, own_did, mailbox, stop, writer
        )

    metrics = _metrics(state)

    while not stop.is_set():
        current = int(state.get("cursors", {}).get(room, 0) or 0)
        start = current + 1
        status = capture.status()
        capture_cursor = int(status.get("capture_cursor", 0) or 0)

        # Persisted exact rows are safe evidence even when the capture's latest
        # successful network poll is old or its current transport is timing out.
        rows = _read_bounded_local_prefix(start, capture_cursor)
        if rows:
            changed, recovered = await resilience._drain_export_snapshot(
                state,
                config,
                room,
                rows,
                own_did,
                mailbox,
                gap_end=int(rows[-1]["seq"]),
                event_message=rows[0],
            )
            metrics["lobby_startup_local_liveness_slices"] += 1
            metrics["lobby_startup_local_liveness_messages"] += recovered
            if writer and (changed or recovered):
                writer.mark_dirty()
            if recovered <= 0:
                # This is an internal local-drain invariant failure, not a capture
                # freshness decision. Preserve the prior fail-closed chain here.
                metrics["lobby_startup_local_liveness_delegations"] += 1
                return await _BASE_STARTUP_CATCHUP(
                    client, budget, state, config, room, own_did, mailbox, stop, writer
                )
            await asyncio.sleep(0)
            continue

        current = int(state.get("cursors", {}).get(room, 0) or 0)
        capture_cursor = int(status.get("capture_cursor", 0) or 0)
        capture_fresh = _startup_capture_fresh(status)

        # A fresh capture at or behind the Rich cursor proves there is no persisted
        # unseen local interval. Normal live processing can safely take over.
        if capture_fresh and current >= capture_cursor:
            changed = resilience.set_success(state, room)
            if writer and changed:
                writer.mark_dirty()
            return

        # Any unresolved next-row condition is handled through the bounded official
        # streaming export. This includes a genuine local hole and a temporarily
        # stale/timed-out capture that has stopped advancing. Do not fall back to the
        # old full-body export merely because capture liveness is uncertain.
        metrics["lobby_startup_local_liveness_bridge_attempts"] += 1
        if not capture_fresh:
            metrics["lobby_startup_local_liveness_stale_bridge_attempts"] += 1
        recovered, retry, error, local_resume = await bridge._stream_until_local_resume(
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

        changed = resilience.set_error(
            state,
            room,
            f"startup_lobby_bridge_{error or 'retry'}",
            str(retry or ""),
        )
        if writer and (changed or recovered):
            writer.mark_dirty()
        delay = max(1.0, float(retry)) if retry is not None else startup.STARTUP_RETRY_SECONDS
        await startup._wait_or_stop(stop, delay)


def install() -> None:
    """Install after the existing lobby startup hole bridge."""
    global _INSTALLED, _BASE_STARTUP_CATCHUP
    if _INSTALLED:
        return
    _BASE_STARTUP_CATCHUP = startup.startup_catchup
    startup.startup_catchup = startup_catchup
    _INSTALLED = True
