"""Strict pre-contest wrapper over the legacy non-binding Challenge Runner.

The legacy planner remains backward compatible. Future campaign operations should
use this wrapper: missing/invalid/stale readiness evidence is NO-GO. Explicitly
profiled runtimes additionally require a compatible runtime adapter,
machine-generated Production plumbing, and matching machine collector provenance.
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime

from . import (
    airdrop_challenge,
    precontest_machine_provenance,
    precontest_plumbing_apply,
    precontest_readiness,
    precontest_runtime_compatibility,
    precontest_runtime_profile,
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
        "A fresh machine-generated Production plumbing receipt is mandatory for "
        "profile-enabled challenges; manual readiness booleans cannot satisfy "
        "NO_LIVE_PLUMBING_GATE."
    )
    return forced


def _runtime_profile_status(challenge_id: str) -> tuple[bool, dict | None, str | None]:
    """Return (required, profile, error). Missing profile preserves legacy behavior."""
    try:
        profile = precontest_runtime_profile.load(challenge_id)
    except Exception:
        return True, None, "precontest_runtime_profile_invalid"
    if profile is None:
        return False, None, None
    return True, profile, None


def _runtime_compatibility_status(
    challenge_id: str,
    *,
    now: datetime,
) -> tuple[bool, str | None]:
    try:
        proof = precontest_runtime_compatibility.load_validated(challenge_id, now=now)
    except precontest_runtime_compatibility.RuntimeCompatibilityError as error:
        return False, str(error) or "precontest_runtime_adapter_compatibility_invalid"
    if proof is None:
        return False, "precontest_runtime_adapter_compatibility_missing"
    if proof.get("status") != "PASS":
        return False, "precontest_runtime_adapter_incompatible"
    return True, None


def _machine_provenance_status(
    challenge_id: str,
    readiness: dict,
    *,
    now: datetime,
) -> tuple[bool, str | None]:
    evidence_digest = readiness.get("evidence_sha256")
    if not isinstance(evidence_digest, str):
        return False, "precontest_machine_provenance_evidence_mismatch"
    try:
        precontest_machine_provenance.load_validated(
            challenge_id,
            readiness_evidence_sha256=evidence_digest,
            now=now,
            require_no_unsupported=readiness.get("go") is True,
        )
    except precontest_machine_provenance.MachineProvenanceError as error:
        return False, str(error) or "precontest_machine_provenance_invalid"
    return True, None


def build_plan(challenge_id: str, *, now: datetime | None = None) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_now_timezone_required")
    current = current.astimezone(UTC)

    legacy = airdrop_challenge.build_plan(challenge_id, now=current)
    profile_required, _profile, profile_error = _runtime_profile_status(challenge_id)

    compatibility_valid = not profile_required
    compatibility_error: str | None = None
    if profile_required and profile_error is None:
        compatibility_valid, compatibility_error = _runtime_compatibility_status(
            challenge_id,
            now=current,
        )

    plumbing_error: str | None = None
    plumbing_applied: dict | None = None
    if profile_required and profile_error is None and compatibility_valid:
        try:
            plumbing_applied = precontest_plumbing_apply.apply_if_present(
                challenge_id,
                now=current,
            )
        except precontest_plumbing_apply.PlumbingApplyError as error:
            plumbing_error = str(error) or "precontest_plumbing_receipt_invalid"

    if profile_error is not None:
        readiness = _no_go(
            challenge_id,
            current,
            profile_error,
            "Invalid runtime profile fails closed and never authorizes a binding action.",
        )
    elif compatibility_error is not None:
        readiness = _no_go(
            challenge_id,
            current,
            compatibility_error,
            "Missing or incompatible runtime adapter evidence fails closed before any execution-path readiness can pass.",
        )
    elif plumbing_error is not None:
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
    elif (
        profile_required
        and profile_error is None
        and compatibility_valid
        and plumbing_error is None
        and plumbing_applied is None
    ):
        readiness = _require_plumbing_receipt(readiness)

    provenance_valid = not profile_required
    provenance_error: str | None = None
    if profile_required:
        if profile_error is not None:
            provenance_error = profile_error
        elif not compatibility_valid:
            provenance_error = compatibility_error or "precontest_runtime_adapter_incompatible"
        elif readiness.get("evidence_sha256") is None:
            provenance_error = "precontest_machine_provenance_evidence_mismatch"
        else:
            provenance_valid, provenance_error = _machine_provenance_status(
                challenge_id,
                readiness,
                now=current,
            )

    result = dict(legacy)
    blockers = list(legacy.get("critical_path", []))
    if readiness["go"] is not True:
        blockers.append("precontest_readiness_no_go")
        blockers.extend(str(item) for item in readiness.get("blockers", []))
    if profile_required and not compatibility_valid:
        blockers.append("precontest_runtime_adapter_incompatible")
        if compatibility_error:
            blockers.append(compatibility_error)
    if profile_required and not provenance_valid:
        blockers.append("precontest_machine_provenance_invalid")
        if provenance_error:
            blockers.append(provenance_error)

    result["precontest_readiness"] = readiness
    result["machine_provenance_required"] = profile_required
    result["machine_provenance_valid"] = provenance_valid
    result["critical_path"] = _dedupe(blockers)
    result["estimated_remaining_steps"] = len(result["critical_path"])
    result["ready_for_execution_path"] = bool(
        legacy.get("ready_for_execution_path") is True
        and readiness["go"] is True
        and compatibility_valid
        and provenance_valid
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
