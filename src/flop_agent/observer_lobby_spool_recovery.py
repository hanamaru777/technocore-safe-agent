"""Recover lobby holes from the local capture spool before server-ring fallback.

The public lobby can burst faster than the rich Observer can score messages. A
separate GET-only capture process stores recent rows locally. This overlay uses
that durable local evidence first when a successful live tail reveals a hole, or
when a live read fails but captured rows are already available.

The existing retained-ring export path remains the fallback. No outbound behavior,
Signer transport, URL following, or Technocore write is introduced here.
"""
from __future__ import annotations

import asyncio

from . import observer_lobby_capture as capture
from . import observer_resilience as resilience

SPOOL_CHUNK_MESSAGES = 2000
_INSTALLED = False
_BASE_PROCESS_LIVE = resilience.process_live_payload_with_recovery
_BASE_RECOVER_AFTER_ERROR = resilience.recover_after_live_error


def _metrics(state: dict) -> dict:
    metrics = state.setdefault("metrics", {})
    for key in (
        "lobby_spool_recovery_events",
        "lobby_spool_recovered_messages",
        "lobby_spool_live_error_recoveries",
    ):
        metrics.setdefault(key, 0)
    return metrics


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
    if end < start or not capture.range_complete(start, end):
        return False, 0

    changed = False
    recovered = 0
    current = start
    while current <= end:
        chunk_end = min(end, current + SPOOL_CHUNK_MESSAGES - 1)
        rows = capture.read_range(current, chunk_end)
        if len(rows) != chunk_end - current + 1:
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
        if current <= end:
            await asyncio.sleep(0)

    if recovered:
        metrics = _metrics(state)
        metrics["lobby_spool_recovery_events"] += 1
        metrics["lobby_spool_recovered_messages"] += recovered
        changed = True
    return changed, recovered


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
                changed, recovered = await _drain_complete_spool_range(
                    state,
                    config,
                    since + 1,
                    first_live - 1,
                    own_did,
                    mailbox,
                    event_message=live[0],
                )
                if recovered == first_live - since - 1:
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
            changed, recovered = await _drain_complete_spool_range(
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
