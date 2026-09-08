"""Clear only stale core gap-recovery health after a later successful live cycle.

The resilience worker records a failed retained-ring recovery as a room health
error such as ``gap_recovery_TotalTimeout``.  A later successful live GET with a
contiguous (or empty) payload does not itself replace that old record, so the
worker can mistake historical health for a failure from the current cycle and
keep the core Observer degraded indefinitely.

This overlay wraps only the successful-live processing function.  It snapshots
the room's pre-cycle gap-recovery error record, delegates to the already-installed
recovery stack, and clears the room only when that exact old error record is still
unchanged afterwards.  Any new recovery failure replaces the record and remains
visible/fail-closed.

No network request, Technocore write, signing, shell execution, URL following, or
secret access is added here.
"""
from __future__ import annotations

from . import observer_resilience as resilience

_INSTALLED = False
_BASE_PROCESS_LIVE = None


def _gap_error_fingerprint(state: dict, room: str):
    record = state.get("health", {}).get("rooms", {}).get(room)
    if not isinstance(record, dict):
        return None
    if record.get("status") != "error":
        return None
    kind = str(record.get("kind", ""))
    if not kind.startswith("gap_recovery_"):
        return None
    return (
        kind,
        record.get("at"),
        record.get("detail", ""),
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
    """Delegate one successful-live cycle and clear only an unchanged old error."""
    if _BASE_PROCESS_LIVE is None:  # pragma: no cover - install contract guard
        raise RuntimeError("observer health recovery overlay is not installed")

    before = _gap_error_fingerprint(state, room)
    changed, drain = await _BASE_PROCESS_LIVE(
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
    after = _gap_error_fingerprint(state, room)

    # If the exact same gap-recovery error survived a successful live cycle,
    # nothing in this cycle re-raised it.  Clear only that stale record.  A fresh
    # failure has a new timestamp/fingerprint and therefore remains degraded.
    if before is not None and after == before:
        changed = resilience.set_success(state, room) or changed

    return changed, drain


def install() -> None:
    """Install after all other live-payload recovery overlays exactly once."""
    global _INSTALLED, _BASE_PROCESS_LIVE
    if _INSTALLED:
        return
    _BASE_PROCESS_LIVE = resilience.process_live_payload_with_recovery
    resilience.process_live_payload_with_recovery = process_live_payload_with_recovery
    _INSTALLED = True
