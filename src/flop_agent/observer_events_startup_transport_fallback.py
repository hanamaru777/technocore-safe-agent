"""Bound repeated events startup probe transport failures.

The events startup guard first uses a zero-wait live GET because a successful
contiguous slice is the cheapest continuity proof.  Production later showed that
this probe itself can remain unavailable while the already-reviewed incremental
streaming export path is usable.  Retrying the same failed probe forever pins the
core room in startup and leaves Observer health degraded.

After two consecutive non-rate-limit probe transport failures, this overlay asks
the existing startup guard to use its incremental streaming export path.  A single
transient failure still retries the cheap live probe.  Rate-limit responses keep
their Retry-After behavior and never trigger an extra export request.

No Technocore write, signing, command execution, URL following, secret access, or
historical counter rewrite is introduced here.
"""
from __future__ import annotations

from . import observer_startup_resilience as startup

EVENTS_ROOM = "events"
MAX_CONSECUTIVE_TRANSPORT_FAILURES = 2
_INSTALLED = False
_BASE_TRY_LIVE_PROBE = None


def _metrics(state: dict) -> dict:
    metrics = state.setdefault("metrics", {})
    metrics.setdefault("events_startup_transport_streak", 0)
    metrics.setdefault("events_startup_transport_escalations", 0)
    return metrics


async def try_events_live_probe(
    client,
    budget,
    state: dict,
    config: dict,
    room: str,
    own_did: str | None,
    mailbox: str | None,
    writer=None,
):
    if _BASE_TRY_LIVE_PROBE is None:  # pragma: no cover - install contract guard
        raise RuntimeError("events startup transport fallback is not installed")

    outcome, retry = await _BASE_TRY_LIVE_PROBE(
        client,
        budget,
        state,
        config,
        room,
        own_did,
        mailbox,
        writer,
    )

    if room != EVENTS_ROOM:
        return outcome, retry

    metrics = _metrics(state)

    if outcome != "retry":
        metrics["events_startup_transport_streak"] = 0
        return outcome, retry

    # A Retry-After means the server explicitly asked us to slow down.  Do not
    # convert that into an extra export request.
    if retry is not None:
        metrics["events_startup_transport_streak"] = 0
        return outcome, retry

    streak = int(metrics.get("events_startup_transport_streak", 0) or 0) + 1
    metrics["events_startup_transport_streak"] = streak
    if streak < MAX_CONSECUTIVE_TRANSPORT_FAILURES:
        return outcome, retry

    metrics["events_startup_transport_streak"] = 0
    metrics["events_startup_transport_escalations"] += 1
    return "export", None


def install() -> None:
    """Patch only the events startup probe decision surface."""
    global _INSTALLED, _BASE_TRY_LIVE_PROBE
    if _INSTALLED:
        return
    _BASE_TRY_LIVE_PROBE = startup._try_events_live_probe
    startup._try_events_live_probe = try_events_live_probe
    _INSTALLED = True
