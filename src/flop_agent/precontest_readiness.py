"""Non-binding pre-contest autonomous execution readiness gate.

This module records and evaluates rehearsal evidence only. It never signs, posts,
submits, spends, claims, starts services, or changes external state.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import airdrop_ledger

SCHEMA_VERSION = 1
MAX_CAPTURE_TO_EXECUTOR_MS = 5_000
MAX_EVIDENCE_AGE = timedelta(hours=24)
MAX_CLOCK_SKEW = timedelta(minutes=1)
CHALLENGE_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
PATH_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
REQUIRED_RECONCILIATION_CASES = {"settled", "void", "ambiguous", "redacted"}
ALLOWED_EXECUTION_MODES = {"single", "batch"}

FIELDS = {
    "schema_version",
    "challenge_id",
    "measured_at",
    "campaign_deadline",
    "capture_to_executor_ms",
    "requires_chat_relay",
    "requires_user_terminal",
    "control_paths",
    "execution_modes_required",
    "execution_modes_rehearsed",
    "reconciliation_cases_rehearsed",
    "runtime_deadline_guard",
    "post_deadline_fail_closed",
    "first_leg_policy_predefined",
    "first_leg_risk_bounded",
    "zero_trade_deadlock_prevented",
    "execution_plumbing_complete",
    "production_rehearsal_passed",
    "live_plumbing_changes_required",
    "evidence_sha256",
}


class ReadinessError(RuntimeError):
    """Fail-closed local readiness evidence error."""


def _root() -> Path:
    return airdrop_ledger.ledger_dir() / "challenges"


def _challenge_id(value: object) -> str:
    if not isinstance(value, str) or not CHALLENGE_ID_RE.fullmatch(value):
        raise ValueError("precontest_challenge_id_invalid")
    return value


def _path(challenge_id: str) -> Path:
    return _root() / _challenge_id(challenge_id) / "precontest-readiness.json"


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"precontest_{label}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"precontest_{label}_invalid") from error
    if parsed.tzinfo is None:
        raise ValueError(f"precontest_{label}_invalid")
    return parsed.astimezone(UTC)


def _timestamp(value: object, *, label: str) -> str:
    return _parse_time(value, label=label).isoformat()


def _boolean(value: object, *, label: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"precontest_{label}_invalid")
    return value


def _string_set(value: object, *, label: str, allowed: set[str] | None = None) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 16:
        raise ValueError(f"precontest_{label}_invalid")
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"precontest_{label}_invalid")
    if len(set(value)) != len(value):
        raise ValueError(f"precontest_{label}_duplicate")
    if allowed is not None and any(item not in allowed for item in value):
        raise ValueError(f"precontest_{label}_invalid")
    return sorted(value)


def _control_paths(value: object) -> list[dict]:
    if not isinstance(value, list) or len(value) > 8:
        raise ValueError("precontest_control_paths_invalid")
    cleaned: list[dict] = []
    seen: set[str] = set()
    for row in value:
        if not isinstance(row, dict) or set(row) != {
            "id", "authenticated", "ready", "quota_independent", "verified_at"
        }:
            raise ValueError("precontest_control_path_invalid")
        path_id = row.get("id")
        if not isinstance(path_id, str) or not PATH_ID_RE.fullmatch(path_id):
            raise ValueError("precontest_control_path_id_invalid")
        if path_id in seen:
            raise ValueError("precontest_control_path_duplicate")
        seen.add(path_id)
        cleaned.append({
            "id": path_id,
            "authenticated": _boolean(row.get("authenticated"), label="control_authenticated"),
            "ready": _boolean(row.get("ready"), label="control_ready"),
            "quota_independent": _boolean(row.get("quota_independent"), label="control_quota_independent"),
            "verified_at": _timestamp(row.get("verified_at"), label="control_verified_at"),
        })
    cleaned.sort(key=lambda row: row["id"])
    return cleaned


def normalize_evidence(value: object, *, include_digest: bool = False) -> dict:
    if not isinstance(value, dict):
        raise ValueError("precontest_evidence_invalid")
    expected = FIELDS if include_digest else FIELDS - {"evidence_sha256"}
    if set(value) != expected:
        raise ValueError("precontest_evidence_schema_invalid")
    if type(value.get("schema_version")) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise ValueError("precontest_schema_version_invalid")
    capture_ms = value.get("capture_to_executor_ms")
    if type(capture_ms) is not int or capture_ms < 0 or capture_ms > 3_600_000:
        raise ValueError("precontest_capture_to_executor_ms_invalid")

    required = _string_set(
        value.get("execution_modes_required"),
        label="execution_modes_required",
        allowed=ALLOWED_EXECUTION_MODES,
    )
    rehearsed = _string_set(
        value.get("execution_modes_rehearsed"),
        label="execution_modes_rehearsed",
        allowed=ALLOWED_EXECUTION_MODES,
    )
    reconciliation = _string_set(
        value.get("reconciliation_cases_rehearsed"),
        label="reconciliation_cases_rehearsed",
        allowed=REQUIRED_RECONCILIATION_CASES,
    )

    cleaned = {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": _challenge_id(value.get("challenge_id")),
        "measured_at": _timestamp(value.get("measured_at"), label="measured_at"),
        "campaign_deadline": _timestamp(value.get("campaign_deadline"), label="campaign_deadline"),
        "capture_to_executor_ms": capture_ms,
        "requires_chat_relay": _boolean(value.get("requires_chat_relay"), label="requires_chat_relay"),
        "requires_user_terminal": _boolean(value.get("requires_user_terminal"), label="requires_user_terminal"),
        "control_paths": _control_paths(value.get("control_paths")),
        "execution_modes_required": required,
        "execution_modes_rehearsed": rehearsed,
        "reconciliation_cases_rehearsed": reconciliation,
        "runtime_deadline_guard": _boolean(value.get("runtime_deadline_guard"), label="runtime_deadline_guard"),
        "post_deadline_fail_closed": _boolean(value.get("post_deadline_fail_closed"), label="post_deadline_fail_closed"),
        "first_leg_policy_predefined": _boolean(value.get("first_leg_policy_predefined"), label="first_leg_policy_predefined"),
        "first_leg_risk_bounded": _boolean(value.get("first_leg_risk_bounded"), label="first_leg_risk_bounded"),
        "zero_trade_deadlock_prevented": _boolean(value.get("zero_trade_deadlock_prevented"), label="zero_trade_deadlock_prevented"),
        "execution_plumbing_complete": _boolean(value.get("execution_plumbing_complete"), label="execution_plumbing_complete"),
        "production_rehearsal_passed": _boolean(value.get("production_rehearsal_passed"), label="production_rehearsal_passed"),
        "live_plumbing_changes_required": _boolean(value.get("live_plumbing_changes_required"), label="live_plumbing_changes_required"),
    }
    if include_digest:
        digest = value.get("evidence_sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("precontest_evidence_digest_invalid")
        cleaned["evidence_sha256"] = digest
    return cleaned


def seal_evidence(value: object) -> dict:
    cleaned = normalize_evidence(value)
    cleaned["evidence_sha256"] = _sha(cleaned)
    return cleaned


def _atomic_write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
        newline="\n",
    )
    try:
        with handle:
            json.dump(value, handle, sort_keys=True, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    finally:
        if os.path.exists(handle.name):
            os.unlink(handle.name)


def save_evidence(challenge_id: str, value: object) -> dict:
    challenge_id = _challenge_id(challenge_id)
    sealed = seal_evidence(value)
    if sealed["challenge_id"] != challenge_id:
        raise ValueError("precontest_challenge_id_mismatch")
    _atomic_write(_path(challenge_id), sealed)
    return sealed


def load_evidence(challenge_id: str) -> dict | None:
    path = _path(challenge_id)
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text("utf-8"))
        cleaned = normalize_evidence(raw, include_digest=True)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise ReadinessError("precontest_readiness_invalid") from error
    digest = cleaned.pop("evidence_sha256")
    if _sha(cleaned) != digest:
        raise ReadinessError("precontest_readiness_integrity_invalid")
    cleaned["evidence_sha256"] = digest
    if cleaned["challenge_id"] != _challenge_id(challenge_id):
        raise ReadinessError("precontest_readiness_challenge_mismatch")
    return cleaned


def evaluate(
    evidence: dict,
    *,
    now: datetime | None = None,
    expected_deadline: str | None = None,
) -> dict:
    cleaned = normalize_evidence(evidence, include_digest=True)
    digest = cleaned.pop("evidence_sha256")
    if _sha(cleaned) != digest:
        raise ReadinessError("precontest_readiness_integrity_invalid")
    cleaned["evidence_sha256"] = digest

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_now_timezone_required")
    current = current.astimezone(UTC)
    measured = _parse_time(cleaned["measured_at"], label="measured_at")
    deadline = _parse_time(cleaned["campaign_deadline"], label="campaign_deadline")

    stale = current - measured > MAX_EVIDENCE_AGE or measured - current > MAX_CLOCK_SKEW
    expected_match = True
    if expected_deadline is not None:
        expected_match = deadline == _parse_time(expected_deadline, label="expected_deadline")

    fresh_paths = [
        row for row in cleaned["control_paths"]
        if -MAX_CLOCK_SKEW <= current - _parse_time(row["verified_at"], label="control_verified_at") <= MAX_EVIDENCE_AGE
    ]
    ready_paths = [row for row in fresh_paths if row["authenticated"] and row["ready"]]

    required_modes = set(cleaned["execution_modes_required"])
    rehearsed_modes = set(cleaned["execution_modes_rehearsed"])
    reconciliation = set(cleaned["reconciliation_cases_rehearsed"])

    gates = {
        "EXECUTION_LATENCY_GATE": (
            not stale
            and cleaned["capture_to_executor_ms"] <= MAX_CAPTURE_TO_EXECUTOR_MS
            and required_modes.issubset(rehearsed_modes)
        ),
        "HUMAN_INDEPENDENCE_GATE": (
            cleaned["requires_chat_relay"] is False
            and cleaned["requires_user_terminal"] is False
        ),
        "CONTROL_PATH_REDUNDANCY_GATE": (
            len(ready_paths) >= 2
            and any(row["quota_independent"] for row in ready_paths)
        ),
        "SETTLEMENT_RECONCILIATION_GATE": REQUIRED_RECONCILIATION_CASES.issubset(reconciliation),
        "DEADLINE_GATE": (
            expected_match
            and current < deadline
            and cleaned["runtime_deadline_guard"] is True
            and cleaned["post_deadline_fail_closed"] is True
        ),
        "ACTIVE_LEARNING_GATE": (
            cleaned["first_leg_policy_predefined"] is True
            and cleaned["first_leg_risk_bounded"] is True
            and cleaned["zero_trade_deadlock_prevented"] is True
        ),
        "NO_LIVE_PLUMBING_GATE": (
            cleaned["execution_plumbing_complete"] is True
            and cleaned["production_rehearsal_passed"] is True
            and cleaned["live_plumbing_changes_required"] is False
        ),
    }
    blockers = [name for name, passed in gates.items() if not passed]
    if stale and "EVIDENCE_FRESHNESS" not in blockers:
        blockers.insert(0, "EVIDENCE_FRESHNESS")
    return {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": cleaned["challenge_id"],
        "non_binding": True,
        "status": "GO" if not blockers else "NO_GO",
        "go": not blockers,
        "evaluated_at": current.isoformat(),
        "evidence_sha256": digest,
        "capture_to_executor_ms": cleaned["capture_to_executor_ms"],
        "max_capture_to_executor_ms": MAX_CAPTURE_TO_EXECUTOR_MS,
        "control_paths_ready": len(ready_paths),
        "quota_independent_ready": any(row["quota_independent"] for row in ready_paths),
        "evidence_fresh": not stale,
        "deadline_matches_challenge": expected_match,
        "gates": gates,
        "blockers": blockers,
        "warning": "GO is operational readiness only; it never authorizes a binding action.",
    }


def evaluate_saved(
    challenge_id: str,
    *,
    now: datetime | None = None,
    expected_deadline: str | None = None,
) -> dict | None:
    evidence = load_evidence(challenge_id)
    if evidence is None:
        return None
    return evaluate(evidence, now=now, expected_deadline=expected_deadline)
