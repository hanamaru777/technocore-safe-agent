"""Bound events export recovery to an already-proven sequence gap.

Production after PR #83 showed the startup live probe could prove a small exact
``events`` gap while the incremental export still remained busy for minutes because
it kept consuming the retained snapshot past the sequence range actually needed.

This overlay keeps the existing official GET-only streaming implementation but
truncates a snapshot exactly at the proven gap endpoint.  Startup derives that
endpoint from its own ``startup_live_probe_gap`` record.  Steady-state live-gap
recovery derives it directly from the first live sequence.  A steady live transport
error has no proven missing interval, so it now stays fail-closed and retries live
instead of immediately launching an untargeted full export.

No Technocore write, signing, shell execution, URL following, secret access, or
tclk Phase 2 behavior is introduced here.
"""
from __future__ import annotations

import re

from . import observer_events_stream_recovery as steady
from . import observer_resilience as resilience
from . import observer_startup_resilience as startup

EVENTS_ROOM = "events"
_TARGET_RE = re.compile(r"(?:^|;)first_unseen=(\d+)(?:;|$)")
_INSTALLED = False
_BASE_STARTUP_STREAM = None
_BASE_PROCESS_LIVE = None
_BASE_RECOVER_AFTER_ERROR = None


def _startup_gap_target(state: dict, room: str) -> int | None:
    if room != EVENTS_ROOM:
        return None
    record = state.get("health", {}).get("rooms", {}).get(room)
    if not isinstance(record, dict) or record.get("kind") != "startup_live_probe_gap":
        return None
    match = _TARGET_RE.search(str(record.get("detail", "")))
    if not match:
        return None
    first_unseen = int(match.group(1))
    cursor = int(state.get("cursors", {}).get(room, 0) or 0)
    target = first_unseen - 1
    return target if target > cursor else None


class _TargetResponse:
    def __init__(self, response, target: int):
        self._response = response
        self._target = target

    def __getattr__(self, name):
        return getattr(self._response, name)

    async def aiter_lines(self):
        reached = False
        async for raw in self._response.aiter_lines():
            if not raw.strip():
                yield raw
                continue
            item = startup._strict_export_item(raw)
            seq = int(item["seq"])
            if seq > self._target:
                raise RuntimeError("target_not_in_export")
            yield raw
            if seq == self._target:
                reached = True
                break
        if not reached:
            raise RuntimeError("target_not_in_export")


class _TargetContext:
    def __init__(self, context, target: int):
        self._context = context
        self._target = target

    async def __aenter__(self):
        response = await self._context.__aenter__()
        return _TargetResponse(response, self._target)

    async def __aexit__(self, exc_type, exc, tb):
        return await self._context.__aexit__(exc_type, exc, tb)


class _TargetClient:
    def __init__(self, client, target: int):
        self._client = client
        self._target = target

    def __getattr__(self, name):
        return getattr(self._client, name)

    def stream(self, method, url, **kwargs):
        return _TargetContext(self._client.stream(method, url, **kwargs), self._target)


async def stream_events_export_targeted(
    client,
    budget,
    state: dict,
    config: dict,
    room: str,
    own_did: str | None,
    mailbox: str | None,
    writer=None,
    *,
    stop_after_seq: int | None,
):
    if _BASE_STARTUP_STREAM is None:  # pragma: no cover - install contract guard
        raise RuntimeError("targeted events recovery overlay is not installed")
    if stop_after_seq is None or not hasattr(client, "stream"):
        return await _BASE_STARTUP_STREAM(
            client,
            budget,
            state,
            config,
            room,
            own_did,
            mailbox,
            writer,
        )
    cursor = int(state.get("cursors", {}).get(room, 0) or 0)
    if stop_after_seq <= cursor:
        return 0, None, None
    return await _BASE_STARTUP_STREAM(
        _TargetClient(client, stop_after_seq),
        budget,
        state,
        config,
        room,
        own_did,
        mailbox,
        writer,
    )


async def _startup_stream_wrapper(
    client,
    budget,
    state: dict,
    config: dict,
    room: str,
    own_did: str | None,
    mailbox: str | None,
    writer=None,
):
    return await stream_events_export_targeted(
        client,
        budget,
        state,
        config,
        room,
        own_did,
        mailbox,
        writer,
        stop_after_seq=_startup_gap_target(state, room),
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
    if _BASE_PROCESS_LIVE is None:  # pragma: no cover - install contract guard
        raise RuntimeError("targeted events recovery overlay is not installed")
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
    if gap_end <= since:
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
    metrics = steady._metrics(state)
    metrics["events_steady_stream_gap_attempts"] += 1
    metrics["events_steady_stream_attempts"] += 1

    recovered, retry, error = await stream_events_export_targeted(
        client,
        budget,
        state,
        config,
        room,
        own_did,
        mailbox,
        None,
        stop_after_seq=gap_end,
    )
    metrics["events_steady_stream_messages"] += recovered
    if error:
        metrics["events_steady_stream_failures"] += 1
        resilience.set_error(state, room, f"gap_recovery_{error}", str(retry or ""))
        return True, False
    metrics["events_steady_stream_successes"] += 1

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


async def recover_after_live_error(
    client,
    budget,
    state: dict,
    config: dict,
    room: str,
    own_did: str | None,
    mailbox: str | None,
):
    if _BASE_RECOVER_AFTER_ERROR is None:  # pragma: no cover - install contract guard
        raise RuntimeError("targeted events recovery overlay is not installed")
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

    metrics = steady._metrics(state)
    metrics["events_steady_stream_live_error_attempts"] += 1
    metrics["events_steady_live_error_retries"] = int(
        metrics.get("events_steady_live_error_retries", 0)
    ) + 1
    # No sequence gap has been proven yet. Keep the cursor fixed and let the base
    # worker retry the cheap live read after its normal core backoff. If that later
    # live slice proves a gap, process_live_payload_with_recovery() above performs
    # the exact targeted stream recovery.
    return True, 0, None, "retry_live"


def install() -> None:
    """Install after PR #83 steady streaming and before stale-health recovery."""
    global _INSTALLED, _BASE_STARTUP_STREAM, _BASE_PROCESS_LIVE, _BASE_RECOVER_AFTER_ERROR
    if _INSTALLED:
        return
    _BASE_STARTUP_STREAM = startup._stream_events_startup_export
    _BASE_PROCESS_LIVE = resilience.process_live_payload_with_recovery
    _BASE_RECOVER_AFTER_ERROR = resilience.recover_after_live_error
    startup._stream_events_startup_export = _startup_stream_wrapper
    resilience.process_live_payload_with_recovery = process_live_payload_with_recovery
    resilience.recover_after_live_error = recover_after_live_error
    _INSTALLED = True
