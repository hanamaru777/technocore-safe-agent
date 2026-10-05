"""Low-pressure, non-binding supervisor for registered challenge readiness.

The supervisor reads local challenge specs and the strict pre-contest planner,
then writes one durable summary. An explicitly configured local runtime profile
may refresh non-binding machine proofs before planning. It never signs, posts,
registers, claims, spends, starts services, or accesses signer/Vault material.
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import (
    airdrop_challenge,
    airdrop_ledger,
    observer,
    precontest_active_learning_proof,
    precontest_batch_rehearsal_proof,
    precontest_challenge,
    precontest_control_path_proof,
    precontest_deadline_proof,
    precontest_human_independence_proof,
    precontest_machine_evidence,
    precontest_reconciliation_proof,
    precontest_runtime_profile,
)

SCHEMA_VERSION = 1
ACTION_WINDOW = timedelta(hours=72)
MAX_SPEC_BYTES = 256 * 1024
CLOSE1_PROFILE = "close1_short_liquidity"


class SupervisorError(RuntimeError):
    """Local fail-closed supervisor error."""


def _now() -> datetime:
    return datetime.now(UTC)


def challenges_root() -> Path:
    return airdrop_ledger.ledger_dir() / "challenges"


def state_path() -> Path:
    return airdrop_ledger.ledger_dir() / "precontest-supervisor.json"


def _parse_time(value: object, *, required: bool) -> datetime | None:
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise SupervisorError("precontest_supervisor_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SupervisorError("precontest_supervisor_time_invalid") from error
    if parsed.tzinfo is None:
        raise SupervisorError("precontest_supervisor_time_invalid")
    return parsed.astimezone(UTC)


def _read_spec(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise SupervisorError("precontest_supervisor_spec_invalid")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_SPEC_BYTES:
        raise SupervisorError("precontest_supervisor_spec_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SupervisorError("precontest_supervisor_spec_invalid") from error
    try:
        return airdrop_challenge.validate_spec(value)
    except ValueError as error:
        raise SupervisorError("precontest_supervisor_spec_invalid") from error


def _phase(spec: dict, *, now: datetime) -> tuple[str, int | None, int]:
    deadline = _parse_time(spec["deadline"], required=True)
    assert deadline is not None
    opening = _parse_time(spec.get("opening"), required=False)
    if now >= deadline:
        return "CLOSED", None, 0
    seconds_to_deadline = max(0, int((deadline - now).total_seconds()))
    if opening is not None and now < opening:
        return "UPCOMING", max(0, int((opening - now).total_seconds())), seconds_to_deadline
    # No exact opening is treated conservatively as already open.
    return "OPEN", 0, seconds_to_deadline


def _refresh_safe_proofs(challenge_id: str, *, now: datetime) -> list[str]:
    """Refresh only explicitly opted-in, non-binding proof artifacts.

    A missing profile is a deliberate no-op. The single-mode rehearsal must be
    newer than the profile configuration before the aggregate collector may run,
    preventing reuse of an old rehearsal for a newly configured challenge.
    """
    try:
        profile = precontest_runtime_profile.load(challenge_id)
    except Exception:
        return ["precontest_auto_runtime_profile_invalid"]
    if profile is None:
        return []
    if profile.get("runtime_profile") != CLOSE1_PROFILE:
        return ["precontest_auto_runtime_profile_unsupported"]

    blockers: list[str] = []
    configured_at = _parse_time(profile.get("configured_at"), required=True)
    assert configured_at is not None
    rehearsal_fresh_for_profile = False
    try:
        rehearsal = precontest_machine_evidence._fresh_rehearsal(now=now)
        evaluated_at = _parse_time(rehearsal.get("evaluated_at"), required=True)
        assert evaluated_at is not None
        if evaluated_at < configured_at:
            blockers.append("precontest_auto_single_rehearsal_predates_profile")
        else:
            rehearsal_fresh_for_profile = True
    except Exception:
        blockers.append("precontest_auto_single_rehearsal_blocked")

    proof_builders = (
        ("deadline", precontest_deadline_proof.save_proof),
        ("active_learning", precontest_active_learning_proof.save_proof),
        ("reconciliation", precontest_reconciliation_proof.save_proof),
        ("batch", precontest_batch_rehearsal_proof.save_proof),
        ("control_path", precontest_control_path_proof.save_proof),
        ("human_independence", precontest_human_independence_proof.save_proof),
    )
    for label, builder in proof_builders:
        try:
            builder(challenge_id, now=now)
        except Exception:
            blockers.append(f"precontest_auto_{label}_proof_blocked")

    if rehearsal_fresh_for_profile:
        try:
            precontest_machine_evidence.collect(challenge_id, now=now)
        except Exception:
            blockers.append("precontest_auto_machine_evidence_blocked")

    # Stable order with no duplicate noise in Mission Control.
    return list(dict.fromkeys(blockers))


def _challenge_row(spec: dict, *, now: datetime) -> dict:
    challenge_id = spec["challenge_id"]
    phase, seconds_to_open, seconds_to_deadline = _phase(spec, now=now)
    if phase == "CLOSED":
        return {
            "challenge_id": challenge_id,
            "phase": phase,
            "status": "CLOSED",
            "ready": False,
            "seconds_to_open": None,
            "seconds_to_deadline": 0,
            "blockers": [],
        }

    refresh_blockers = _refresh_safe_proofs(challenge_id, now=now)
    try:
        plan = precontest_challenge.build_plan(challenge_id, now=now)
        ready = plan.get("ready_for_execution_path") is True and not refresh_blockers
        blockers = refresh_blockers + [str(item) for item in plan.get("critical_path", [])]
        blockers = list(dict.fromkeys(blockers))
        readiness = plan.get("precontest_readiness")
        readiness_status = readiness.get("status") if isinstance(readiness, dict) else None
    except Exception as error:
        ready = False
        blockers = refresh_blockers + [str(error) or "precontest_supervisor_plan_failed"]
        blockers = list(dict.fromkeys(blockers))
        readiness_status = "ERROR"

    if ready:
        status = "READY"
    elif phase == "OPEN":
        status = "BLOCKED_LIVE"
    elif seconds_to_open is not None and seconds_to_open <= int(ACTION_WINDOW.total_seconds()):
        status = "ACTION_REQUIRED"
    else:
        status = "PREP_REQUIRED"

    return {
        "challenge_id": challenge_id,
        "phase": phase,
        "status": status,
        "ready": ready,
        "seconds_to_open": seconds_to_open,
        "seconds_to_deadline": seconds_to_deadline,
        "readiness_status": readiness_status,
        "blockers": blockers,
    }


def _error_row(challenge_id: str, reason: str) -> dict:
    return {
        "challenge_id": challenge_id,
        "phase": "ERROR",
        "status": "ACTION_REQUIRED",
        "ready": False,
        "seconds_to_open": None,
        "seconds_to_deadline": None,
        "readiness_status": "ERROR",
        "blockers": [reason],
    }


def _overall(rows: list[dict]) -> str:
    priorities = {
        "BLOCKED_LIVE": 0,
        "ACTION_REQUIRED": 1,
        "PREP_REQUIRED": 2,
        "READY": 3,
        "CLOSED": 4,
    }
    active = [row["status"] for row in rows if row["status"] != "CLOSED"]
    if not active:
        return "IDLE"
    return min(active, key=lambda item: priorities.get(item, -1))


def build_status(*, now: datetime | None = None) -> dict:
    current = now or _now()
    if current.tzinfo is None:
        raise ValueError("precontest_supervisor_timezone_required")
    current = current.astimezone(UTC)
    root = challenges_root()
    rows: list[dict] = []
    if root.exists():
        if root.is_symlink() or not root.is_dir():
            raise SupervisorError("precontest_supervisor_root_invalid")
        for directory in sorted(root.iterdir(), key=lambda item: item.name):
            if directory.is_symlink() or not directory.is_dir():
                continue
            try:
                challenge_id = airdrop_challenge.validate_challenge_id(directory.name)
            except ValueError:
                continue
            spec_path = directory / "spec.json"
            if not spec_path.exists():
                continue
            try:
                spec = _read_spec(spec_path)
                if spec["challenge_id"] != challenge_id:
                    raise SupervisorError("precontest_supervisor_challenge_mismatch")
                rows.append(_challenge_row(spec, now=current))
            except Exception as error:
                reason = str(error)
                if not reason.startswith("precontest_"):
                    reason = "precontest_supervisor_spec_failed"
                rows.append(_error_row(challenge_id, reason))

    return {
        "schema_version": SCHEMA_VERSION,
        "non_binding": True,
        "status": _overall(rows),
        "evaluated_at": current.isoformat(),
        "action_window_seconds": int(ACTION_WINDOW.total_seconds()),
        "challenge_count": len(rows),
        "challenges": rows,
    }


def run_once(*, now: datetime | None = None) -> dict:
    result = build_status(now=now)
    observer.atomic_json_write(state_path(), result, compact=True, mode=0o660)
    return result


def main() -> int:
    if len(sys.argv) != 1:
        print(json.dumps({"status": "blocked", "reason": "arguments_forbidden"}))
        return 2
    try:
        result = run_once()
    except Exception as error:
        reason = str(error)
        if not reason.startswith("precontest_"):
            reason = "precontest_supervisor_failed"
        print(json.dumps({"status": "blocked", "reason": reason}, sort_keys=True))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
