"""Bound repeated events startup transport failures without pinning export mode.

The events startup guard first uses a zero-wait live GET because a successful
contiguous slice is the cheapest continuity proof. Production later showed two
complementary transport failure modes:

* the live probe itself can remain unavailable while the already-reviewed
  incremental streaming export path is usable;
* after escalation, the export path can remain unavailable while the cheap live
  endpoint has recovered. Staying in export mode forever then pins startup even
  though current live continuity is provable.

After two consecutive non-rate-limit live-probe transport failures, this overlay
asks the existing startup guard to use its incremental streaming export path. If
that export then fails with a transient transport error, startup returns to one
bounded live probe. A successful contiguous/empty live proof clears startup. A
live probe that proves a real gap returns to the exact targeted export recovery
path. Rate limits and content/integrity errors remain in export mode and therefore
stay fail-closed.

No Technocore write, signing, command execution, URL following, secret access, or
historical counter rewrite is introduced here.
"""
from __future__ import annotations

from . import observer_resilience as resilience
from . import observer_startup_resilience as startup

EVENTS_ROOM = "events"
MAX_CONSECUTIVE_TRANSPORT_FAILURES = 2
TRANSIENT_EXPORT_ERRORS = frozenset(
    {
        "ConnectError",
        "ConnectTimeout",
        "PoolTimeout",
        "ReadError",
        "ReadTimeout",
        "RemoteProtocolError",
        "TotalTimeout",
    }
)
_INSTALLED = False
_BASE_TRY_LIVE_PROBE = None
_BASE_STARTUP_CATCHUP = None


def _metrics(state: dict) -> dict:
    metrics = state.setdefault("metrics", {})
    metrics.setdefault("events_startup_transport_streak", 0)
    metrics.setdefault("events_startup_transport_escalations", 0)
    metrics.setdefault("events_startup_export_reprobes", 0)
    metrics.setdefault("events_startup_export_reprobe_successes", 0)
    return metrics


def _is_transient_export_error(error: str | None) -> bool:
    return isinstance(error, str) and error in TRANSIENT_EXPORT_ERRORS


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

    # A Retry-After means the server explicitly asked us to slow down. Do not
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
    """Run events startup with reversible transport-only export escalation.

    The existing wrapped live/export helpers remain authoritative. In particular,
    later installed targeted/core-continuity overlays can still turn a proven gap
    into exact retained-range recovery. This wrapper changes only the control flow
    after a transport failure from an export attempt that has not succeeded.
    """
    if _BASE_STARTUP_CATCHUP is None:  # pragma: no cover - install contract guard
        raise RuntimeError("events startup transport fallback is not installed")

    cursor = int(state.get("cursors", {}).get(room, 0) or 0)
    if room != EVENTS_ROOM or cursor <= 0:
        return await _BASE_STARTUP_CATCHUP(
            client,
            budget,
            state,
            config,
            room,
            own_did,
            mailbox,
            stop,
            writer,
        )

    mode = "live"
    reprobe_pending = False

    while not stop.is_set():
        if mode == "live":
            outcome, retry = await startup._try_events_live_probe(
                client,
                budget,
                state,
                config,
                room,
                own_did,
                mailbox,
                writer,
            )
            if outcome == "success":
                if reprobe_pending:
                    _metrics(state)["events_startup_export_reprobe_successes"] += 1
                return
            if outcome == "export":
                mode = "export"
                reprobe_pending = False
                continue

            delay = (
                max(1.0, float(retry))
                if retry is not None
                else startup.STARTUP_RETRY_SECONDS
            )
            await startup._wait_or_stop(stop, delay)
            continue

        _recovered, retry, error = await startup._stream_events_startup_export(
            client,
            budget,
            state,
            config,
            room,
            own_did,
            mailbox,
            writer,
        )
        if not error:
            return

        changed = resilience.set_error(
            state,
            room,
            f"startup_stream_export_{error}",
            str(retry or ""),
        )
        if writer and changed:
            writer.mark_dirty()

        delay = (
            max(1.0, float(retry))
            if retry is not None
            else startup.STARTUP_RETRY_SECONDS
        )
        await startup._wait_or_stop(stop, delay)
        if stop.is_set():
            return

        # Only transport uncertainty can return to the cheap live proof. A
        # Retry-After or an integrity/content error remains in export mode.
        if retry is None and _is_transient_export_error(error):
            _metrics(state)["events_startup_export_reprobes"] += 1
            mode = "live"
            reprobe_pending = True
        else:
            mode = "export"
            reprobe_pending = False


def install() -> None:
    """Patch only the events startup transport decision/control surface."""
    global _INSTALLED, _BASE_TRY_LIVE_PROBE, _BASE_STARTUP_CATCHUP
    if _INSTALLED:
        return
    _BASE_TRY_LIVE_PROBE = startup._try_events_live_probe
    _BASE_STARTUP_CATCHUP = startup.startup_catchup
    startup._try_events_live_probe = try_events_live_probe
    startup.startup_catchup = startup_catchup
    _INSTALLED = True
