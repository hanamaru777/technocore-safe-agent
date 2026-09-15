"""Fast-path launcher for the already-approved fixed Mitsuri non-binding contact.

Only this fixed non-binding application receives the risk-tier relaxation:
fresh Observer safety may be ``ok`` or ``degraded`` while the protected-core
baseline remains exact. The underlying lane still enforces fixed payload,
identity, registration-local-record, exactly-once state, receipt verification,
and terminal ambiguity handling.
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime

from flop_agent import sonnet_registration as registration

try:
    import sonnet_mitsuri_contact as lane
    import sonnet_mitsuri_contact_v2 as bootstrap
except ImportError:  # normal package/test import
    from flop_agent import sonnet_mitsuri_contact as lane
    from flop_agent import sonnet_mitsuri_contact_v2 as bootstrap

PROTECTED_CORE = (117, 5_083_155)
MAX_AGE_SECONDS = 300
ALLOWED_HEALTH = frozenset({"ok", "degraded"})


class FastContactError(RuntimeError):
    pass


def require_nonbinding_safety() -> dict:
    try:
        value = registration.load_safety_snapshot()
        stamp = datetime.fromisoformat(value["updated_at"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=UTC)
        age = (datetime.now(UTC) - stamp.astimezone(UTC)).total_seconds()
    except Exception as error:
        raise FastContactError("nonbinding_safety_unavailable") from error

    core = (
        value["unrecoverable_core_gap_events"],
        value["unrecoverable_core_gap_messages"],
    )
    if core != PROTECTED_CORE:
        raise FastContactError("protected_core_baseline_changed")
    if not 0 <= age <= MAX_AGE_SECONDS:
        raise FastContactError("nonbinding_safety_stale")
    if value["health"] not in ALLOWED_HEALTH:
        raise FastContactError("nonbinding_safety_invalid_health")
    return {"health": value["health"], "age_seconds": age, "core": core}


def run_once() -> dict:
    # Replace only the lane's global-health predicate. All other lane gates remain.
    lane.require_health = require_nonbinding_safety
    return bootstrap.run_once()


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("Mitsuri fast contact accepts no arguments")
    try:
        result = run_once()
    except Exception:
        print(json.dumps({"ok": False, "error": "fast_contact_failed_closed"}))
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
