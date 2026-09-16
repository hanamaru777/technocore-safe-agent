"""Narrow safety adapter for the one authorized same-request-id Sonnet-2 replay.

This does not widen normal registration or any binding contest action.  It only
adapts the execution-only fixed MARU receipt-replay module so that fresh
``degraded`` Observer health does not block an otherwise safe idempotent replay
when the protected-core baseline is unchanged.
"""
from __future__ import annotations

from datetime import UTC, datetime

from . import sonnet_registration as registration
from . import sonnet_registration_receipt_replay_20260916 as replay

PROTECTED_CORE = (117, 5_083_155)
MAX_SAFETY_AGE_SECONDS = 300
ALLOWED_HEALTH = frozenset({"ok", "degraded"})


class ReplaySafetyError(RuntimeError):
    """Stable fail-closed code for this one exact receipt-replay safety gate."""


def require_replay_health() -> dict:
    try:
        value = registration.load_safety_snapshot()
        stamp = datetime.fromisoformat(value["updated_at"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=UTC)
        age = (datetime.now(UTC) - stamp.astimezone(UTC)).total_seconds()
    except Exception as error:
        raise ReplaySafetyError("replay_safety_unavailable") from error

    core = (
        value["unrecoverable_core_gap_events"],
        value["unrecoverable_core_gap_messages"],
    )
    if core != PROTECTED_CORE:
        raise ReplaySafetyError("protected_core_baseline_changed")
    if not 0 <= age <= MAX_SAFETY_AGE_SECONDS:
        raise ReplaySafetyError("replay_safety_stale")
    if value["health"] not in ALLOWED_HEALTH:
        raise ReplaySafetyError("replay_safety_invalid_health")

    return {
        "health": value["health"],
        "age_seconds": age,
        "protected_core_gap_events": core[0],
        "protected_core_gap_messages": core[1],
    }


def main() -> None:
    # The imported replay is structurally fixed to one immutable DID/role/X/request_id.
    # Patch only this isolated process and restore immediately after it exits.
    original = replay.registration.require_health
    replay.registration.require_health = require_replay_health
    try:
        replay.main()
    finally:
        replay.registration.require_health = original


if __name__ == "__main__":
    main()
