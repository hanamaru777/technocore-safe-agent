"""Machine-generated, non-binding proof that a contest runtime fails closed at lock.

The proof dynamically calls the resident runtime at the exact lock and just after
lock while replacing candidate staging with a sentinel.  It also binds the
currently installed approved-trade source guard to the same runtime deadline.
It never signs, posts, writes approvals, starts services, or accesses Vault data.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import re
import sys
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import (
    airdrop_challenge,
    close1_approved_trade,
    close1_autonomous_resident,
    close1_autonomous_stage,
    close_call,
    precontest_readiness,
)

SCHEMA_VERSION = 1
HEX64_RE = re.compile(r"[0-9a-f]{64}")


class DeadlineProofError(RuntimeError):
    """Fail-closed local deadline proof error."""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _source_sha(function: object) -> str:
    source = textwrap.dedent(inspect.getsource(function))
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise DeadlineProofError(f"precontest_deadline_{label}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise DeadlineProofError(f"precontest_deadline_{label}_invalid") from error
    if parsed.tzinfo is None:
        raise DeadlineProofError(f"precontest_deadline_{label}_invalid")
    return parsed.astimezone(UTC)


def proof_path(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "precontest-deadline-proof.json"


def _resident_probe(when: datetime) -> dict:
    if when.tzinfo is None:
        raise DeadlineProofError("precontest_deadline_probe_time_invalid")
    stage_calls: list[str] = []
    status_writes: list[dict] = []
    original_stage = close1_autonomous_stage.run_once
    original_write = close1_autonomous_resident._write_status

    def forbidden_stage():
        stage_calls.append("called")
        raise DeadlineProofError("precontest_deadline_stage_called")

    try:
        close1_autonomous_stage.run_once = forbidden_stage
        close1_autonomous_resident._write_status = status_writes.append
        result = close1_autonomous_resident.run_cycle(now=when)
    finally:
        close1_autonomous_stage.run_once = original_stage
        close1_autonomous_resident._write_status = original_write

    if stage_calls:
        raise DeadlineProofError("precontest_deadline_stage_called")
    if result.get("status") != "LOCKED" or result.get("non_binding") is not True:
        raise DeadlineProofError("precontest_deadline_resident_not_locked")
    if len(status_writes) != 1 or status_writes[0] != result:
        raise DeadlineProofError("precontest_deadline_resident_result_invalid")
    return {
        "at": when.astimezone(UTC).isoformat(),
        "status": "LOCKED",
        "stage_invocations": 0,
    }


def _approved_trade_guard() -> dict:
    preflight = textwrap.dedent(inspect.getsource(close1_approved_trade._fresh_preflight))
    run_locked = textwrap.dedent(inspect.getsource(close1_approved_trade._run_locked))
    required_preflight = (
        "close_call.LOCK_SWEEP",
        'TradeError("contest_locked")',
    )
    if any(token not in preflight for token in required_preflight):
        raise DeadlineProofError("precontest_deadline_executor_guard_missing")
    positions = [
        run_locked.find("_fresh_preflight("),
        run_locked.find("_sign("),
        run_locked.find("core.httpx.post("),
    ]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise DeadlineProofError("precontest_deadline_executor_order_invalid")
    return {
        "guard_present": True,
        "preflight_before_sign": True,
        "preflight_before_post": True,
        "fresh_preflight_sha256": _source_sha(close1_approved_trade._fresh_preflight),
        "run_locked_sha256": _source_sha(close1_approved_trade._run_locked),
    }


def build_proof(challenge_id: str, *, now: datetime | None = None) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_deadline_now_timezone_required")
    current = current.astimezone(UTC)

    plan = airdrop_challenge.build_plan(challenge_id, now=current)
    if plan.get("challenge_id") not in {None, challenge_id}:
        raise DeadlineProofError("precontest_deadline_challenge_mismatch")
    campaign_deadline = _parse_time(plan.get("deadline"), label="campaign_deadline")
    runtime_lock = close_call.LOCK.astimezone(UTC)
    if campaign_deadline != runtime_lock:
        raise DeadlineProofError("precontest_deadline_runtime_deadline_mismatch")

    exact = _resident_probe(runtime_lock)
    after = _resident_probe(runtime_lock + timedelta(seconds=1))
    executor = _approved_trade_guard()
    value = {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "status": "PASS",
        "non_binding": True,
        "generated_at": current.isoformat(),
        "campaign_deadline": campaign_deadline.isoformat(),
        "runtime_lock_at": runtime_lock.isoformat(),
        "exact_lock": exact,
        "post_lock": after,
        "runtime_deadline_guard": True,
        "post_deadline_fail_closed": True,
        "resident_run_cycle_sha256": _source_sha(close1_autonomous_resident.run_cycle),
        "executor_guard": executor,
    }
    value["proof_sha256"] = _sha(value)
    return value


def validate_proof(
    value: object,
    *,
    challenge_id: str,
    expected_deadline: str,
    now: datetime,
) -> dict:
    if not isinstance(value, dict):
        raise DeadlineProofError("precontest_deadline_proof_invalid")
    required = {
        "schema_version", "challenge_id", "status", "non_binding", "generated_at",
        "campaign_deadline", "runtime_lock_at", "exact_lock", "post_lock",
        "runtime_deadline_guard", "post_deadline_fail_closed",
        "resident_run_cycle_sha256", "executor_guard", "proof_sha256",
    }
    if set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise DeadlineProofError("precontest_deadline_proof_schema_invalid")
    digest = value.get("proof_sha256")
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise DeadlineProofError("precontest_deadline_proof_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("proof_sha256")
    if _sha(unsigned) != digest:
        raise DeadlineProofError("precontest_deadline_proof_integrity_invalid")
    if value.get("challenge_id") != airdrop_challenge.validate_challenge_id(challenge_id):
        raise DeadlineProofError("precontest_deadline_challenge_mismatch")
    if value.get("status") != "PASS" or value.get("non_binding") is not True:
        raise DeadlineProofError("precontest_deadline_proof_not_passed")
    deadline = _parse_time(expected_deadline, label="expected_deadline")
    if _parse_time(value.get("campaign_deadline"), label="campaign_deadline") != deadline:
        raise DeadlineProofError("precontest_deadline_campaign_deadline_mismatch")
    if _parse_time(value.get("runtime_lock_at"), label="runtime_lock") != deadline:
        raise DeadlineProofError("precontest_deadline_runtime_deadline_mismatch")
    generated = _parse_time(value.get("generated_at"), label="generated_at")
    age = now.astimezone(UTC) - generated
    if age > precontest_readiness.MAX_EVIDENCE_AGE or age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise DeadlineProofError("precontest_deadline_proof_stale")
    for label in ("exact_lock", "post_lock"):
        row = value.get(label)
        if not isinstance(row, dict) or row.get("status") != "LOCKED" or row.get("stage_invocations") != 0:
            raise DeadlineProofError("precontest_deadline_resident_proof_invalid")
    if value.get("runtime_deadline_guard") is not True or value.get("post_deadline_fail_closed") is not True:
        raise DeadlineProofError("precontest_deadline_guard_false")
    if value.get("resident_run_cycle_sha256") != _source_sha(close1_autonomous_resident.run_cycle):
        raise DeadlineProofError("precontest_deadline_resident_source_changed")
    executor = value.get("executor_guard")
    if not isinstance(executor, dict) or executor.get("guard_present") is not True:
        raise DeadlineProofError("precontest_deadline_executor_guard_invalid")
    if executor.get("preflight_before_sign") is not True or executor.get("preflight_before_post") is not True:
        raise DeadlineProofError("precontest_deadline_executor_guard_invalid")
    if executor.get("fresh_preflight_sha256") != _source_sha(close1_approved_trade._fresh_preflight):
        raise DeadlineProofError("precontest_deadline_executor_source_changed")
    if executor.get("run_locked_sha256") != _source_sha(close1_approved_trade._run_locked):
        raise DeadlineProofError("precontest_deadline_executor_source_changed")
    return dict(value)


def save_proof(challenge_id: str, *, now: datetime | None = None) -> dict:
    value = build_proof(challenge_id, now=now)
    precontest_readiness._atomic_write(proof_path(challenge_id), value)
    return value


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"status": "blocked", "reason": "challenge_id_required"}))
        return 2
    try:
        result = save_proof(sys.argv[1])
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
