"""Machine-derived, non-binding pre-contest readiness evidence.

This collector intentionally proves only what runtime artifacts can prove. It
never signs, posts, starts services, changes signer/Vault state, or authorizes a
binding action. Unsupported gates remain false until dedicated machine proofs
exist.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import (
    airdrop_challenge,
    close1_account_reconciliation as account,
    close1_autonomous_rehearsal,
    precontest_active_learning_proof,
    precontest_deadline_proof,
    precontest_readiness,
    precontest_reconciliation_proof,
)

SCHEMA_VERSION = 1
MAX_SOURCE_BYTES = 256 * 1024
HEX64_RE = re.compile(r"[0-9a-f]{64}")


class MachineEvidenceError(RuntimeError):
    """Fail-closed machine evidence collection error."""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_value(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise MachineEvidenceError(f"precontest_machine_{label}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise MachineEvidenceError(f"precontest_machine_{label}_invalid") from error
    if parsed.tzinfo is None:
        raise MachineEvidenceError(f"precontest_machine_{label}_invalid")
    return parsed.astimezone(UTC)


def _read_json_file(path: Path, *, label: str) -> tuple[dict, str]:
    if path.is_symlink() or not path.is_file():
        raise MachineEvidenceError(f"precontest_machine_{label}_missing")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_SOURCE_BYTES:
        raise MachineEvidenceError(f"precontest_machine_{label}_size_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MachineEvidenceError(f"precontest_machine_{label}_invalid") from error
    if not isinstance(value, dict):
        raise MachineEvidenceError(f"precontest_machine_{label}_invalid")
    return value, _sha_bytes(raw)


def _fresh_rehearsal(*, now: datetime) -> dict:
    result, digest = _read_json_file(
        close1_autonomous_rehearsal.result_path(),
        label="rehearsal",
    )
    required = {
        "schema_version",
        "status",
        "non_binding",
        "trade_id",
        "stage_sha256",
        "capture_to_rehearsal_ms",
        "capture_to_stage_ms",
        "target_capture_to_executor_ms",
        "target_met",
        "fresh_policy",
        "signer_access",
        "approval_written",
        "post_attempted",
        "evaluated_at",
    }
    if set(result) != required:
        raise MachineEvidenceError("precontest_machine_rehearsal_schema_invalid")
    if result["schema_version"] != close1_autonomous_rehearsal.SCHEMA_VERSION:
        raise MachineEvidenceError("precontest_machine_rehearsal_schema_invalid")
    if result["status"] != "WOULD_EXECUTE" or result["non_binding"] is not True:
        raise MachineEvidenceError("precontest_machine_rehearsal_not_passed")
    if result["target_met"] is not True:
        raise MachineEvidenceError("precontest_machine_rehearsal_sla_failed")
    if result["signer_access"] is not False:
        raise MachineEvidenceError("precontest_machine_rehearsal_signer_access")
    if result["approval_written"] is not False or result["post_attempted"] is not False:
        raise MachineEvidenceError("precontest_machine_rehearsal_binding_side_effect")

    latency = result["capture_to_rehearsal_ms"]
    if type(latency) is not int or not 0 <= latency <= precontest_readiness.MAX_CAPTURE_TO_EXECUTOR_MS:
        raise MachineEvidenceError("precontest_machine_rehearsal_latency_invalid")
    if result["target_capture_to_executor_ms"] != precontest_readiness.MAX_CAPTURE_TO_EXECUTOR_MS:
        raise MachineEvidenceError("precontest_machine_rehearsal_target_invalid")
    if type(result["capture_to_stage_ms"]) is not int or result["capture_to_stage_ms"] < 0:
        raise MachineEvidenceError("precontest_machine_rehearsal_stage_latency_invalid")

    stage_digest = result["stage_sha256"]
    if not isinstance(stage_digest, str) or not HEX64_RE.fullmatch(stage_digest):
        raise MachineEvidenceError("precontest_machine_rehearsal_stage_digest_invalid")
    if not isinstance(result["trade_id"], str) or not result["trade_id"]:
        raise MachineEvidenceError("precontest_machine_rehearsal_trade_id_invalid")

    policy = result["fresh_policy"]
    if not isinstance(policy, dict):
        raise MachineEvidenceError("precontest_machine_rehearsal_policy_invalid")
    for key in ("offer_fresh", "price_fresh", "account_ready"):
        if policy.get(key) is not True:
            raise MachineEvidenceError(f"precontest_machine_rehearsal_{key}_failed")

    evaluated = _parse_time(result["evaluated_at"], label="rehearsal_time")
    age = now - evaluated
    if age > precontest_readiness.MAX_EVIDENCE_AGE or age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise MachineEvidenceError("precontest_machine_rehearsal_stale")

    return {
        "sha256": digest,
        "evaluated_at": evaluated.isoformat(),
        "capture_to_rehearsal_ms": latency,
        "capture_to_stage_ms": result["capture_to_stage_ms"],
        "trade_id": result["trade_id"],
        "stage_sha256": stage_digest,
    }


def _settled_ledger_proof() -> dict:
    path = account.state_path()
    raw_value, digest = _read_json_file(path, label="ledger")
    try:
        ledger = account._validate_ledger(raw_value, owner_did=account.OWNER_DID)
    except ValueError as error:
        raise MachineEvidenceError("precontest_machine_ledger_invalid") from error
    if ledger["status"] != "reconciled":
        raise MachineEvidenceError("precontest_machine_ledger_not_reconciled")
    if ledger["pending_trade_ids"] or ledger["pending_trades"]:
        raise MachineEvidenceError("precontest_machine_ledger_pending")
    settled = ledger["settled_trade_ids"]
    if not isinstance(settled, list) or not settled:
        raise MachineEvidenceError("precontest_machine_ledger_no_settled_proof")
    evidence = ledger["trade_evidence"]
    if not isinstance(evidence, dict) or any(trade_id not in evidence for trade_id in settled):
        raise MachineEvidenceError("precontest_machine_ledger_trade_evidence_missing")
    return {
        "sha256": digest,
        "as_of_sweep": ledger["as_of_sweep"],
        "settled_trade_ids": sorted(settled),
        "last_reconciled_at": ledger["last_reconciled_at"],
    }


def _deadline_proof(
    challenge_id: str,
    *,
    expected_deadline: str,
    now: datetime,
) -> dict | None:
    path = precontest_deadline_proof.proof_path(challenge_id)
    if not path.exists():
        return None
    value, file_digest = _read_json_file(path, label="deadline_proof")
    try:
        valid = precontest_deadline_proof.validate_proof(
            value,
            challenge_id=challenge_id,
            expected_deadline=expected_deadline,
            now=now,
        )
    except precontest_deadline_proof.DeadlineProofError as error:
        raise MachineEvidenceError("precontest_machine_deadline_proof_invalid") from error
    return {
        "sha256": file_digest,
        "proof_sha256": valid["proof_sha256"],
        "generated_at": valid["generated_at"],
        "campaign_deadline": valid["campaign_deadline"],
        "runtime_lock_at": valid["runtime_lock_at"],
        "runtime_deadline_guard": True,
        "post_deadline_fail_closed": True,
    }


def _active_learning_proof(challenge_id: str, *, now: datetime) -> dict | None:
    path = precontest_active_learning_proof.proof_path(challenge_id)
    if not path.exists():
        return None
    value, file_digest = _read_json_file(path, label="active_learning_proof")
    try:
        valid = precontest_active_learning_proof.validate_proof(
            value,
            challenge_id=challenge_id,
            now=now,
        )
    except precontest_active_learning_proof.ActiveLearningProofError as error:
        raise MachineEvidenceError("precontest_machine_active_learning_proof_invalid") from error
    return {
        "sha256": file_digest,
        "proof_sha256": valid["proof_sha256"],
        "generated_at": valid["generated_at"],
        "runtime": valid["runtime"],
        "policy": valid["policy"],
        "first_leg_policy_predefined": True,
        "first_leg_risk_bounded": True,
        "zero_trade_deadlock_prevented": True,
    }


def _reconciliation_proof(challenge_id: str, *, now: datetime) -> dict | None:
    path = precontest_reconciliation_proof.proof_path(challenge_id)
    if not path.exists():
        return None
    value, file_digest = _read_json_file(path, label="reconciliation_proof")
    try:
        valid = precontest_reconciliation_proof.validate_proof(
            value,
            challenge_id=challenge_id,
            now=now,
        )
    except precontest_reconciliation_proof.ReconciliationProofError as error:
        raise MachineEvidenceError("precontest_machine_reconciliation_proof_invalid") from error
    return {
        "sha256": file_digest,
        "proof_sha256": valid["proof_sha256"],
        "generated_at": valid["generated_at"],
        "cases": valid["reconciliation_cases_rehearsed"],
    }


def provenance_path(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "precontest-readiness-sources.json"


def _write_provenance(challenge_id: str, value: dict) -> dict:
    sealed = dict(value)
    sealed["provenance_sha256"] = _sha_value(sealed)
    precontest_readiness._atomic_write(provenance_path(challenge_id), sealed)
    return sealed


def collect(challenge_id: str, *, now: datetime | None = None) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_machine_now_timezone_required")
    current = current.astimezone(UTC)

    plan = airdrop_challenge.build_plan(challenge_id, now=current)
    if plan.get("challenge_id") not in {None, challenge_id}:
        raise MachineEvidenceError("precontest_machine_challenge_mismatch")
    deadline = plan.get("deadline")
    _parse_time(deadline, label="deadline")

    rehearsal = _fresh_rehearsal(now=current)
    settled = _settled_ledger_proof()
    deadline_proof = _deadline_proof(
        challenge_id,
        expected_deadline=deadline,
        now=current,
    )
    active_proof = _active_learning_proof(challenge_id, now=current)
    reconciliation_proof = _reconciliation_proof(challenge_id, now=current)
    deadline_proven = deadline_proof is not None
    active_proven = active_proof is not None
    reconciliation_cases = (
        reconciliation_proof["cases"] if reconciliation_proof is not None else ["settled"]
    )

    evidence = {
        "schema_version": precontest_readiness.SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "measured_at": rehearsal["evaluated_at"],
        "campaign_deadline": deadline,
        "capture_to_executor_ms": rehearsal["capture_to_rehearsal_ms"],
        "requires_chat_relay": True,
        "requires_user_terminal": True,
        "control_paths": [],
        "execution_modes_required": ["single", "batch"],
        "execution_modes_rehearsed": ["single"],
        "reconciliation_cases_rehearsed": reconciliation_cases,
        "runtime_deadline_guard": deadline_proven,
        "post_deadline_fail_closed": deadline_proven,
        "first_leg_policy_predefined": active_proven,
        "first_leg_risk_bounded": active_proven,
        "zero_trade_deadlock_prevented": active_proven,
        "execution_plumbing_complete": False,
        "production_rehearsal_passed": False,
        "live_plumbing_changes_required": True,
    }
    saved = precontest_readiness.save_evidence(challenge_id, evidence)

    sources = {
        "close1_autonomous_rehearsal": rehearsal,
        "close1_reconciled_ledger": settled,
    }
    if deadline_proof is not None:
        sources["deadline_fail_closed"] = deadline_proof
    if active_proof is not None:
        sources["active_learning"] = active_proof
    if reconciliation_proof is not None:
        sources["reconciliation_matrix"] = reconciliation_proof

    unsupported = [
        "HUMAN_INDEPENDENCE_GATE",
        "CONTROL_PATH_REDUNDANCY_GATE",
        "NO_LIVE_PLUMBING_GATE",
    ]
    if deadline_proof is None:
        unsupported.append("DEADLINE_GATE")
    if active_proof is None:
        unsupported.append("ACTIVE_LEARNING_GATE")
    if reconciliation_proof is None:
        unsupported.append("SETTLEMENT_RECONCILIATION_GATE")

    provenance = _write_provenance(
        challenge_id,
        {
            "schema_version": SCHEMA_VERSION,
            "challenge_id": challenge_id,
            "collected_at": current.isoformat(),
            "collector": "precontest_machine_evidence",
            "non_binding": True,
            "readiness_evidence_sha256": saved["evidence_sha256"],
            "sources": sources,
            "unsupported_gates_forced_no_go": unsupported,
        },
    )
    evaluation = precontest_readiness.evaluate(
        saved,
        now=current,
        expected_deadline=deadline,
    )
    if evaluation["go"] is True:
        raise MachineEvidenceError("precontest_machine_unexpected_go")
    return {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "non_binding": True,
        "status": "COLLECTED_NO_GO",
        "readiness": evaluation,
        "evidence_sha256": saved["evidence_sha256"],
        "provenance_sha256": provenance["provenance_sha256"],
        "provenance_path": str(provenance_path(challenge_id)),
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"status": "blocked", "reason": "challenge_id_required"}))
        return 2
    try:
        result = collect(sys.argv[1])
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
