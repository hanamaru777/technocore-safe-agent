"""Retry transient /rooms backfill failures without leaving stale health for an hour.

The base Observer performs the public room-directory backfill immediately and then
sleeps for ``rooms_backfill_interval_seconds`` (normally one hour). That cadence is
correct after success, but a transient GET failure otherwise leaves the ``rooms``
health record degraded for the same full interval even after the endpoint recovers.

This overlay changes only the worker retry cadence. Successful backfills keep the
configured interval. Errors retry with bounded exponential backoff, while explicit
rate limits honor Retry-After. The underlying backfill implementation remains the
existing GET-only path and remains solely responsible for setting/clearing health.

No Technocore write, signing, secret access, cursor manipulation, historical gap
counter rewrite, or recovery command is introduced here.
"""
from __future__ import annotations

import asyncio

from . import observer

RETRY_MIN_SECONDS = 5.0
RETRY_MAX_SECONDS = 60.0
_INSTALLED = False


def _rooms_error(state: dict) -> dict | None:
    record = state.get("health", {}).get("rooms", {}).get("rooms")
    if not isinstance(record, dict) or record.get("status") != "error":
        return None
    return record


def _retry_after(record: dict) -> float | None:
    if record.get("kind") != "rate_limited":
        return None
    try:
        value = float(record.get("detail", ""))
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def next_delay(state: dict, config: dict, backoff: float) -> tuple[float, float]:
    """Return ``(sleep_seconds, next_backoff)`` for the room-directory worker."""
    record = _rooms_error(state)
    if record is None:
        return float(config["rooms_backfill_interval_seconds"]), 0.0

    retry_after = _retry_after(record)
    if retry_after is not None:
        delay = max(RETRY_MIN_SECONDS, retry_after)
        return delay, min(RETRY_MAX_SECONDS, delay)

    delay = min(
        RETRY_MAX_SECONDS,
        max(RETRY_MIN_SECONDS, backoff * 2.0 if backoff else RETRY_MIN_SECONDS),
    )
    return delay, delay


async def backfill_worker(
    client,
    budget,
    state: dict,
    config: dict,
    stop: asyncio.Event,
    writer=None,
) -> None:
    """Run the existing GET-only backfill with short bounded retries after errors."""
    backoff = 0.0
    while not stop.is_set():
        changed = await observer.backfill_into_state(client, budget, state, config)
        if writer and changed:
            writer.mark_dirty()

        delay, backoff = next_delay(state, config, backoff)
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
        except TimeoutError:
            pass


def install() -> None:
    """Replace only the room-directory worker before observe_forever creates it."""
    global _INSTALLED
    if _INSTALLED:
        return
    observer.backfill_worker = backfill_worker
    _INSTALLED = True
