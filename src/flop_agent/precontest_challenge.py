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
    precontest_control_path_proof,
    precontest_readiness,
)


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _evaluate_readiness(
    challenge_id: str,
    *,
    now: datetime,
    expected_deadline: str,
) -> dict | None:
    evidence = precontest_readiness.load_evidence(challenge_id)
    if evidence is None:
        return None

    proof_path = precontest_control_path_proof.proof_path(challenge_id)
    if proof_path.exists():
        if proof_path.is_symlink() or not proof_path.is_file():
            raise precontest_readiness.ReadinessError("precontest_control_proof_invalid")
        try:
            raw = json.loads(proof_path.read_text("utf-8"))
            proof = precontest_control_path_proof.validate_proof(
                raw,
                challenge_id=challenge_id,
                now=now,
            )
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            precontest_control_path_proof.ControlPathProofError,
        ) as error:
            raise precontest_readiness.ReadinessError(
                "precontest_control_proof_invalid"
            ) from error

        unsigned = dict(evidence)
        unsigned.pop("evidence_sha256", None)
        unsigned["control_paths"] = precontest_control_path_proof.readiness_paths(proof)
        evidence = precontest_readiness.seal_evidence(unsigned)

    return precontest_readiness.evaluate(
        evidence,
        now=now,
        expected_deadline=expected_deadline,
    )


def build_plan(challenge_id: str, *, now: datetime | None = None) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_now_timezone_required")

    legacy = airdrop_challenge.build_plan(challenge_id, now=current)
    try:
        readiness = _evaluate_readiness(
            challenge_id,
            now=current,
            expected_deadline=legacy["deadline"],
        )
    except precontest_readiness.ReadinessError as error:
        readiness = {
            "schema_version": precontest_readiness.SCHEMA_VERSION,
            "challenge_id": challenge_id,
            "non_binding": True,
            "status": "NO_GO",
            "go": False,
            "evaluated_at": current.astimezone(UTC).isoformat(),
            "gates": {},
            "blockers": [str(error)],
            "warning": "Invalid readiness evidence fails closed and never authorizes a binding action.",
        }

    if readiness is None:
        readiness = {
            "schema_version": precontest_readiness.SCHEMA_VERSION,
            "challenge_id": challenge_id,
            "non_binding": True,
            "status": "NO_GO",
            "go": False,
            "evaluated_at": current.astimezone(UTC).isoformat(),
            "gates": {},
            "blockers": ["PRECONTEST_READINESS_EVIDENCE_MISSING"],
            "warning": "Readiness evidence is mandatory for the strict pre-contest planner.",
        }

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
