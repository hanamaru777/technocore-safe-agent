"""Strict pre-contest wrapper over the legacy non-binding Challenge Runner.

The legacy planner remains backward compatible. Future campaign operations should
use this wrapper: missing/invalid/stale readiness evidence is NO-GO.
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime

from . import (
    airdrop_challenge,
    precontest_plumbing_apply,
    precontest_readiness,
)


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _no_go(challenge_id: str, current: datetime, blocker: str, warning: str) -> dict:
    return {
        "schema_version": precontest_readiness.SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "non_binding": True,
        "status": "NO_GO",
        "go": False,
        "evaluated_at": current.astimezone(UTC).isoformat(),
        "gates": {},
        "blockers": [blocker],
        "warning": warning,
    }


def _require_plumbing_receipt(readiness: dict) -> dict:
    """Missing machine receipt must never inherit a manually asserted plumbing PASS."""
    forced = dict(readiness)
    gates = dict(forced.get("gates") or {})
    gates["NO_LIVE_PLUMBING_GATE"] = False
    blockers = [str(item) for item in forced.get("blockers", [])]
    blockers.append("NO_LIVE_PLUMBING_GATE")
    forced["gates"] = gates
    forced["blockers"] = _dedupe(blockers)
    forced["status"] = "NO_GO"
    forced["go"] = False
    forced["warning"] = (
        "A fresh machine-generated Production plumbing receipt is mandatory; "
        "manual readiness booleans cannot satisfy NO_LIVE_PLUMBING_GATE."
    )
    return forced


def build_plan(challenge_id: str, *, now: datetime | None = None) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_now_timezone_required")

    legacy = airdrop_challenge.build_plan(challenge_id, now=current)
    plumbing_error: str | None = None
    plumbing_applied: dict | None = None
    try:
        plumbing_applied = precontest_plumbing_apply.apply_if_present(
            challenge_id,
            now=current,
        )
    except precontest_plumbing_apply.PlumbingApplyError as error:
        plumbing_error = str(error) or "precontest_plumbing_receipt_invalid"

    if plumbing_error is not None:
        readiness = _no_go(
            challenge_id,
            current,
            plumbing_error,
            "Invalid Production plumbing receipt fails closed and never authorizes a binding action.",
        )
    else:
        try:
            readiness = precontest_readiness.evaluate_saved(
                challenge_id,
                now=current,
                expected_deadline=legacy["deadline"],
            )
        except precontest_readiness.ReadinessError as error:
            readiness = _no_go(
                challenge_id,
                current,
                str(error),
                "Invalid readiness evidence fails closed and never authorizes a binding action.",
            )

    if readiness is None:
        readiness = _no_go(
            challenge_id,
            current,
            "PRECONTEST_READINESS_EVIDENCE_MISSING",
            "Readiness evidence is mandatory for the strict pre-contest planner.",
        )
    elif plumbing_error is None and plumbing_applied is None:
        readiness = _require_plumbing_receipt(readiness)

    result = dict(legacy)
    blockers = list(legacy.get("critical_path", []))
    if readiness["go"] is not True:
        blockers.append("precontest_readiness_no_go")
        blockers.extend(str(item) for item in readiness.get("blockers", []))
    result["precontest_readiness"] = readiness
    result["critical_path"] = _dedupe(blockers)
    result["estimated_remaining_steps"] = len(result["critical_path"])
    result["ready_for_execution_path"] = bool(
        legacy.get("ready_for_execution_path") is True
        and readiness["go"] is True
    )
    result["precontest_gate_enforced"] = True
    warnings = list(result.get("warnings", []))
    warnings.append(
        "Strict pre-contest GO is operational readiness only; binding authorization remains separate."
    )
    result["warnings"] = warnings
    return result


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"status": "blocked", "reason": "challenge_id_required"}))
        return 2
    try:
        output = build_plan(sys.argv[1])
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}))
        return 1
    print(json.dumps(output, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if output["ready_for_execution_path"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
