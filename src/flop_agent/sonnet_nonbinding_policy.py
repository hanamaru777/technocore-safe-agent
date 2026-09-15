"""Risk-tiered safety gate for explicitly non-binding Sonnet-2 discovery actions.

Binding contest actions must continue to use ``sonnet_registration.require_health``.
This module exists only for schemas that are structurally incapable of roster
consent, accepted words, X publication, or final submission.
"""
from __future__ import annotations

from datetime import UTC, datetime

from . import sonnet_registration as registration

PROTECTED_CORE = (117, 5_083_155)
MAX_SAFETY_AGE_SECONDS = 900
ALLOWED_GLOBAL_HEALTH = frozenset({"ok", "degraded"})


class NonBindingPolicyError(RuntimeError):
    """Stable fail-closed code for a non-binding discovery safety gate."""


def require_nonbinding_safety() -> dict:
    """Allow low-risk discovery under degraded-but-fresh Observer state.

    A global ``degraded`` state can be caused by unrelated transport/backlog work.
    That must not block an explicitly non-binding discovery note/application when:
    the safety snapshot is fresh, the protected-core baseline has not increased,
    and the caller separately enforces signer identity + exactly-once semantics.
    """
    try:
        value = registration.load_safety_snapshot()
        stamp = datetime.fromisoformat(value["updated_at"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=UTC)
        age = (datetime.now(UTC) - stamp.astimezone(UTC)).total_seconds()
    except Exception as error:
        raise NonBindingPolicyError("nonbinding_safety_unavailable") from error

    core = (
        value["unrecoverable_core_gap_events"],
        value["unrecoverable_core_gap_messages"],
    )
    if core != PROTECTED_CORE:
        raise NonBindingPolicyError("protected_core_baseline_changed")
    if not 0 <= age <= MAX_SAFETY_AGE_SECONDS:
        raise NonBindingPolicyError("nonbinding_safety_stale")
    if value["health"] not in ALLOWED_GLOBAL_HEALTH:
        raise NonBindingPolicyError("nonbinding_safety_invalid_health")

    return {
        "health": value["health"],
        "age_seconds": age,
        "protected_core_gap_events": core[0],
        "protected_core_gap_messages": core[1],
    }


def require_binding_safety() -> None:
    """Explicit boundary: irreversible/binding Sonnet actions stay strict."""
    registration.require_health()
