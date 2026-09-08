"""Use the proven incremental events export recovery during steady-state too.

PR #82 proved that persisted ``events`` startup can recover a real sequence hole
from the official snapshot-at-open export when the client consumes JSONL rows
incrementally instead of buffering the whole retained body first.  After startup,
the base resilience worker still had two old all-or-nothing export branches:

* a non-429 ``events`` live-read error fallback;
* a successful ``events`` live slice whose first unseen sequence proves a gap.

This overlay routes only those steady-state ``events`` branches through the same
GET-only incremental exporter. Lobby continues through the already-installed local
spool/server-ring stack.  Exact unrecoverable-gap accounting remains authoritative.

No Technocore write, signing, shell execution, URL following, secret access, or
tclk Phase 2 behavior is introduced here.
"""
from __future__ import annotations

from . import observer_resilience as resilience
from . import observer_startup_resilience as startup

EVENTS_ROOM = "events"
_INSTALLED = False
_BASE_PROCESS_LIVE = None
_BASE_RECOVER_AFTER_ERROR = None


def _metrics(state: dict) -> dict:
    metrics = state.setdefault("metrics", {})
    for key in (
        "events_steady_stream_attempts",
        "events_steady_stream_successes",
        "events_steady_stream_failures",
        "events_steady_stream_messages",
        "events_steady_stream_live_error_attempts",
        "events_steady_stream_gap_attempts",
    ):
        metrics.setdefault(key, 0)
    return metrics


async def _stream_once(
    client,
    budget,
    state: dict,
    config: dict,
    own_did: str | None,
    mailbox: str | None,
) -> tuple[int, float | None, str | None]:
    metrics = _metrics(state)
    metrics["events_steady_stream_attempts"] += 1
    recovered, retry, error = await startup._stream_events_startup_export(
        client,
        budget,
        state,
        config,
        EVENTS_ROOM,
        own_did,
        mailbox,
        None,
    )
    metrics["events_steady_stream_messages"] += recovered
    if error:
        metrics["events_steady_stream_failures"] += 1
    else:
        metrics["events_steady_stream_successes"] += 1
    return recovered, retry, error


async def recover_after_live_error(
    client,
    budget,
    state: dict,
    config: dict,
    room: str,
    own_did: str | None,
    mailbox: str | None,
):
    """Steady ``events`` live-error fallback without whole-body buffering."""
    if _BASE_RECOVER_AFTER_ERROR is None:  # pragma: no cover - install contract guard
        raise RuntimeError("events steady stream recovery overlay is not installed")

    if room != EVENTS_ROOM:
        return await _BASE_RECOVER_AFTER_ERROR(
            client,
            budget,
            state,
            config,
            room,
            own_did,
            mailbox,
        )

    metrics = resilience._metrics(state)
    metrics["live_error_export_fallback_attempts"] += 1
    _metrics(state)["events_steady_stream_live_error_attempts"] += 1

    recovered, retry, error = await _stream_once(
        client,
        budget,
        state,
        config,
        own_did,
        mailbox,
    )
    if error:
        metrics["live_error_export_fallback_failures"] += 1
        return True, recovered, retry, error

    metrics["live_error_export_fallback_successes"] += 1
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
):
    """Recover a steady ``events`` live-tail hole with the incremental exporter."""
    if _BASE_PROCESS_LIVE is None:  # pragma: no cover - install contract guard
        raise RuntimeError("events steady stream recovery overlay is not installed")

    if room != EVENTS_ROOM or bootstrap:
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

    live = resilience._valid_messages(payload)
    if not live:
        return await _BASE_PROCESS_LIVE(
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

    since = int(state.get("cursors", {}).get(room, 0) or 0)
    first_live = int(live[0]["seq"])
    gap_end = first_live - 1
    if first_live <= since + 1:
        return await _BASE_PROCESS_LIVE(
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

    resilience._metrics(state)["gap_recovery_attempts"] += 1
    _metrics(state)["events_steady_stream_gap_attempts"] += 1

    _recovered, retry, error = await _stream_once(
        client,
        budget,
        state,
        config,
        own_did,
        mailbox,
    )
    if error:
        resilience.set_error(
            state,
            room,
            f"gap_recovery_{error}",
            str(retry or ""),
        )
        return True, False

    # A clean snapshot EOF is authoritative. If the stream completed but still
    # could not reach the first live row, those remaining sequences are genuinely
    # absent from this retained snapshot; account them instead of falling back to
    # the old buffered exporter.
    cursor = int(state.get("cursors", {}).get(room, 0) or 0)
    if cursor < gap_end:
        resilience._record_unrecoverable_gap(
            state,
            room,
            live[0],
            cursor + 1,
            gap_end,
            "not_in_retained_export",
        )
        state.setdefault("cursors", {})[room] = gap_end

    # The installed base chain (lobby spool -> original resilience) now sees no
    # events gap and therefore processes the live payload without another export.
    return await _BASE_PROCESS_LIVE(
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


def install() -> None:
    """Install after lobby spool recovery and before stale-health recovery."""
    global _INSTALLED, _BASE_PROCESS_LIVE, _BASE_RECOVER_AFTER_ERROR
    if _INSTALLED:
        return
    _BASE_PROCESS_LIVE = resilience.process_live_payload_with_recovery
    _BASE_RECOVER_AFTER_ERROR = resilience.recover_after_live_error
    resilience.process_live_payload_with_recovery = process_live_payload_with_recovery
    resilience.recover_after_live_error = recover_after_live_error
    _INSTALLED = True
