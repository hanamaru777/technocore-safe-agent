"""Recover lobby holes from the local capture spool before server-ring fallback.

The public lobby can burst faster than the rich Observer can score messages. A
separate GET-only capture process stores recent rows locally. This overlay uses
that durable local evidence first when a successful live tail reveals a hole, or
when a live read fails but captured rows are already available.

Production showed one race after the shock absorber was introduced: the rich
Observer can discover a live-tail gap a fraction of a second before the independent
capture process has committed the same rows. The old overlay checked
``range_complete`` exactly once and immediately fell through to the moving server
retained ring. A range later proved fully present in SQLite could therefore already
have been counted unrecoverable by the main Observer.

For an exact live-tail gap we now drain any contiguous local prefix immediately and
allow a short bounded grace period for the capture process to finish the exact
interval before server-ring fallback. Partial local progress is retained even when
the grace expires, so the server fallback only has to cover the remaining suffix.

The existing retained-ring export path remains the fallback. No outbound behavior,
Signer transport, URL following, or Technocore write is introduced here.
"""
from __future__ import annotations

import asyncio

from . import observer_lobby_capture as capture
from . import observer_resilience as resilience

# Rich Observer processing can be CPU-heavy.  One recovery invocation must give
# the event loop back promptly so events reads and StateWriter can run.
SPOOL_CHUNK_MESSAGES = 100
# Capture runs at 250 reads/minute (~240 ms cadence). Five seconds gives the
# independent process multiple chances to finish a just-observed exact gap without
# turning the rich Observer into an unbounded waiter.
SPOOL_CATCHUP_WAIT_SECONDS = 5.0
SPOOL_CATCHUP_POLL_SECONDS = 0.25
_INSTALLED = False
_BASE_PROCESS_LIVE = resilience.process_live_payload_with_recovery
_BASE_RECOVER_AFTER_ERROR = resilience.recover_after_live_error


def _metrics(state: dict) -> dict:
    metrics = state.setdefault("metrics", {})
    for key in (
        "lobby_spool_recovery_events",
        "lobby_spool_recovered_messages",
        "lobby_spool_live_error_recoveries",
        "lobby_spool_partial_recovery_messages",
        "lobby_spool_catchup_waits",
        "lobby_spool_catchup_successes",
        "lobby_spool_catchup_timeouts",
    ):
        metrics.setdefault(key, 0)
    return metrics


async def _drain_spool_prefix(
    state: dict,
    config: dict,
    start: int,
    end: int,
    own_did: str | None,
    mailbox: str | None,
    *,
    event_message: dict | None = None,
) -> tuple[bool, int]:
    """Drain the currently contiguous local prefix of ``start..end``.

    This intentionally does not require the whole target interval to be committed
    before making progress. The main state cursor only advances through exact rows
    read back from SQLite and validated by the existing recovery path.
    """
    if end < start:
        return False, 0

    available_end = min(end, capture.contiguous_end(start))
    if available_end < start:
        return False, 0

    changed = False
    recovered = 0
    current = start
    # A single bounded slice is intentional.  The persisted cursor records exact
    # progress; the next room cycle resumes at ``cursor + 1``.
    while current <= available_end:
        chunk_end = min(available_end, current + SPOOL_CHUNK_MESSAGES - 1)
        rows = capture.read_range(current, chunk_end)
        if len(rows) != chunk_end - current + 1:
            # The spool is append-only except bounded pruning. If a concurrent prune
            # removes a range between the contiguous check and read, stop locally and
            # let the normal fallback decide the remaining suffix.
            return changed, recovered
        batch_changed, batch_recovered = await resilience._drain_export_snapshot(
            state,
            config,
            capture.ROOM,
            rows,
            own_did,
            mailbox,
            gap_end=chunk_end,
            event_message=event_message or rows[0],
        )
        changed = batch_changed or changed
        recovered += batch_recovered
        current = chunk_end + 1
        break

    return changed, recovered


def _record_local_recovery(state: dict, recovered: int, *, partial: bool) -> None:
    if recovered <= 0:
        return
    metrics = _metrics(state)
    metrics["lobby_spool_recovery_events"] += 1
    metrics["lobby_spool_recovered_messages"] += recovered
    if partial:
        metrics["lobby_spool_partial_recovery_messages"] += recovered


async def _drain_complete_spool_range(
    state: dict,
    config: dict,
    start: int,
    end: int,
    own_did: str | None,
    mailbox: str | None,
    *,
    event_message: dict | None = None,
) -> tuple[bool, int]:
    """Compatibility helper: recover only when the full local range is present."""
    if end < start or not capture.range_complete(start, end):
        return False, 0

    changed = False
    recovered = 0
    current = start
    # Startup owns catch-up before the live worker starts.  Preserve its original
    # complete-range contract while each inner slice remains bounded and gives the
    # loop a turn between slices.
    while current <= end:
        batch_changed, batch_recovered = await _drain_spool_prefix(
            state, config, current, end, own_did, mailbox, event_message=event_message
        )
        changed = changed or batch_changed
        recovered += batch_recovered
        current = int(state.get("cursors", {}).get(capture.ROOM, current - 1) or current - 1) + 1
        if batch_recovered == 0:
            return changed, recovered
        if current <= end:
            await asyncio.sleep(0)
    _record_local_recovery(state, recovered, partial=False)
    return True, recovered


async def _recover_exact_spool_range_with_grace(
    state: dict,
    config: dict,
    start: int,
    end: int,
    own_did: str | None,
    mailbox: str | None,
    *,
    event_message: dict | None = None,
) -> tuple[bool, int, bool]:
    """Recover an exact live-proven lobby gap, allowing capture to catch up.

    Returns ``(changed, recovered, complete)``. Any exact contiguous prefix already
    in SQLite is consumed immediately. If the suffix is not committed yet, wait for
    at most ``SPOOL_CATCHUP_WAIT_SECONDS`` while the independent capture process
    continues running. A timeout never skips data: the caller delegates the reduced
    remaining suffix to the existing server-ring fallback.
    """
    if end < start:
        return False, 0, True

    loop = asyncio.get_running_loop()
    deadline = loop.time() + SPOOL_CATCHUP_WAIT_SECONDS
    changed = False
    recovered_total = 0
    waited = False

    while True:
        current = int(state.get("cursors", {}).get(capture.ROOM, start - 1) or start - 1) + 1
        if current < start:
            current = start
        if current > end:
            if recovered_total:
                _record_local_recovery(state, recovered_total, partial=False)
                changed = True
            if waited:
                _metrics(state)["lobby_spool_catchup_successes"] += 1
            return changed, recovered_total, True

        batch_changed, batch_recovered = await _drain_spool_prefix(
            state,
            config,
            current,
            end,
            own_did,
            mailbox,
            event_message=event_message,
        )
        changed = batch_changed or changed
        recovered_total += batch_recovered

        # Do not loop through a large captured suffix in this event-loop turn.
        # Partial exact cursor progress is durable; callers must defer newer live
        # rows and server fallback while another local contiguous row remains.
        if batch_recovered:
            current = int(state.get("cursors", {}).get(capture.ROOM, current - 1) or current - 1) + 1
            if current <= end:
                _record_local_recovery(state, recovered_total, partial=True)
                return True, recovered_total, False

        current = int(state.get("cursors", {}).get(capture.ROOM, current - 1) or current - 1) + 1
        if current > end:
            if recovered_total:
                _record_local_recovery(state, recovered_total, partial=False)
                changed = True
            if waited:
                _metrics(state)["lobby_spool_catchup_successes"] += 1
            return changed, recovered_total, True

        remaining = deadline - loop.time()
        if remaining <= 0:
            metrics = _metrics(state)
            metrics["lobby_spool_catchup_timeouts"] += 1
            if recovered_total:
                _record_local_recovery(state, recovered_total, partial=True)
                changed = True
            return changed, recovered_total, False

        if not waited:
            _metrics(state)["lobby_spool_catchup_waits"] += 1
            waited = True
        await asyncio.sleep(min(SPOOL_CATCHUP_POLL_SECONDS, remaining))


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
    if room == capture.ROOM and not bootstrap:
        live = resilience._valid_messages(payload)
        if live:
            since = int(state.get("cursors", {}).get(room, 0) or 0)
            first_live = int(live[0]["seq"])
            if first_live > since + 1:
                changed, recovered, complete = await _recover_exact_spool_range_with_grace(
                    state,
                    config,
                    since + 1,
                    first_live - 1,
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
                # The local capture still has the exact next row.  Return to the
                # scheduler rather than letting server fallback or newer live data
                # overtake this protected suffix.
                current = int(state.get("cursors", {}).get(room, since) or since)
                if capture.contiguous_end(current + 1) >= current + 1:
                    return changed, False
                # Partial local progress is intentionally preserved in state. The
                # base recovery therefore sees a smaller suffix, never the original
                # full gap.

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
    if room == capture.ROOM:
        since = int(state.get("cursors", {}).get(room, 0) or 0)
        end = capture.contiguous_end(since + 1)
        if end >= since + 1:
            changed, recovered = await _drain_spool_prefix(
                state,
                config,
                since + 1,
                end,
                own_did,
                mailbox,
            )
            if recovered:
                _metrics(state)["lobby_spool_live_error_recoveries"] += 1
                return True, recovered, None, None

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
    """Install local-spool recovery into the proven resilience worker."""
    global _INSTALLED
    if _INSTALLED:
        return
    resilience.process_live_payload_with_recovery = process_live_payload_with_recovery
    resilience.recover_after_live_error = recover_after_live_error
    _INSTALLED = True
