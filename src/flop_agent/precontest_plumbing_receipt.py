"""Machine-generated Production receipt for the NO_LIVE_PLUMBING readiness gate.

The receipt is read-only with respect to external systems: it inspects the local
Git checkout, systemd state, installed unit bytes, and the existing non-binding
rehearsal artifact.  It never starts/stops services, signs, writes approvals, or
posts externally.  Its only mutation is an atomic local receipt file.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import airdrop_challenge
from . import close1_autonomous_rehearsal as rehearsal
from . import precontest_readiness

SCHEMA_VERSION = 1
HEX40_RE = re.compile(r"[0-9a-f]{40}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
MAX_FILE_BYTES = 512 * 1024

AUTO_RESIDENT_SERVICE = "technocore-safe-agent-close1-auto-resident.service"
SUPERVISOR_SERVICE = "technocore-safe-agent-precontest-supervisor.service"
SUPERVISOR_TIMER = "technocore-safe-agent-precontest-supervisor.timer"

REQUIRED_REPO_FILES = (
    "packaging/oracle/technocore-safe-agent-close1-auto-resident.service",
    "packaging/oracle/technocore-safe-agent-precontest-supervisor.service",
    "packaging/oracle/technocore-safe-agent-precontest-supervisor.timer",
    "src/flop_agent/close1_autonomous_stage.py",
    "src/flop_agent/close1_autonomous_rehearsal.py",
    "src/flop_agent/close1_autonomous_resident.py",
    "src/flop_agent/precontest_machine_evidence.py",
    "src/flop_agent/precontest_supervisor.py",
)
INSTALLED_UNITS = {
    AUTO_RESIDENT_SERVICE: "packaging/oracle/technocore-safe-agent-close1-auto-resident.service",
    SUPERVISOR_SERVICE: "packaging/oracle/technocore-safe-agent-precontest-supervisor.service",
    SUPERVISOR_TIMER: "packaging/oracle/technocore-safe-agent-precontest-supervisor.timer",
}


class PlumbingReceiptError(RuntimeError):
    """Fail-closed Production plumbing receipt error."""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise PlumbingReceiptError(f"precontest_plumbing_{label}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PlumbingReceiptError(f"precontest_plumbing_{label}_invalid") from error
    if parsed.tzinfo is None:
        raise PlumbingReceiptError(f"precontest_plumbing_{label}_invalid")
    return parsed.astimezone(UTC)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def receipt_path(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "precontest-plumbing-receipt.json"


def _run(*args: str) -> str:
    result = subprocess.run(
        args,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def _current_commit(root: Path) -> str:
    value = _run("git", "-C", str(root), "rev-parse", "HEAD")
    if not HEX40_RE.fullmatch(value):
        raise PlumbingReceiptError("precontest_plumbing_commit_invalid")
    return value


def _worktree_clean(root: Path) -> bool:
    return _run("git", "-C", str(root), "status", "--porcelain") == ""


def _bounded_bytes(path: Path, *, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise PlumbingReceiptError(f"precontest_plumbing_{label}_missing")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_FILE_BYTES:
        raise PlumbingReceiptError(f"precontest_plumbing_{label}_size_invalid")
    return raw


def _repo_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in REQUIRED_REPO_FILES:
        hashes[relative] = _sha_bytes(_bounded_bytes(root / relative, label="repo_file"))
    return hashes


def _installed_unit_state(root: Path) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for unit, relative in INSTALLED_UNITS.items():
        fragment = _run("systemctl", "show", unit, "-p", "FragmentPath", "--value")
        if fragment != f"/etc/systemd/system/{unit}":
            raise PlumbingReceiptError("precontest_plumbing_unit_fragment_invalid")
        installed = Path(fragment)
        installed_hash = _sha_bytes(_bounded_bytes(installed, label="installed_unit"))
        repo_hash = _sha_bytes(_bounded_bytes(root / relative, label="repo_unit"))
        if installed_hash != repo_hash:
            raise PlumbingReceiptError("precontest_plumbing_unit_hash_mismatch")
        enabled = _run("systemctl", "is-enabled", unit)
        active = _run("systemctl", "is-active", unit)
        if enabled != "enabled" or active != "active":
            raise PlumbingReceiptError("precontest_plumbing_unit_not_ready")
        rows[unit] = {
            "fragment": fragment,
            "enabled": enabled,
            "active": active,
            "sha256": installed_hash,
        }
    return rows


def _rehearsal_proof(*, now: datetime) -> dict:
    path = rehearsal.result_path()
    raw = _bounded_bytes(path, label="rehearsal")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_invalid") from error
    required = {
        "schema_version", "status", "non_binding", "trade_id", "stage_sha256",
        "capture_to_rehearsal_ms", "capture_to_stage_ms",
        "target_capture_to_executor_ms", "target_met", "fresh_policy",
        "signer_access", "approval_written", "post_attempted", "evaluated_at",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_schema_invalid")
    if value["schema_version"] != rehearsal.SCHEMA_VERSION:
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_schema_invalid")
    if value["status"] != "WOULD_EXECUTE" or value["non_binding"] is not True:
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_not_passed")
    if value["target_met"] is not True:
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_sla_failed")
    if value["signer_access"] is not False:
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_signer_access")
    if value["approval_written"] is not False or value["post_attempted"] is not False:
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_binding_side_effect")
    latency = value["capture_to_rehearsal_ms"]
    if type(latency) is not int or not 0 <= latency <= precontest_readiness.MAX_CAPTURE_TO_EXECUTOR_MS:
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_latency_invalid")
    if value["target_capture_to_executor_ms"] != precontest_readiness.MAX_CAPTURE_TO_EXECUTOR_MS:
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_target_invalid")
    policy = value["fresh_policy"]
    if not isinstance(policy, dict) or any(policy.get(key) is not True for key in (
        "offer_fresh", "price_fresh", "account_ready"
    )):
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_policy_invalid")
    evaluated = _parse_time(value["evaluated_at"], label="rehearsal_time")
    age = now - evaluated
    if age > precontest_readiness.MAX_EVIDENCE_AGE or age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_stale")
    return {
        "sha256": _sha_bytes(raw),
        "evaluated_at": evaluated.isoformat(),
        "capture_to_rehearsal_ms": latency,
        "trade_id": value["trade_id"],
        "stage_sha256": value["stage_sha256"],
        "signer_access": False,
        "approval_written": False,
        "post_attempted": False,
    }


def build_receipt(
    challenge_id: str,
    *,
    now: datetime | None = None,
    repo_root: Path | None = None,
) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_plumbing_now_timezone_required")
    current = current.astimezone(UTC)
    root = (repo_root or _repo_root()).resolve()
    commit = _current_commit(root)
    if not _worktree_clean(root):
        raise PlumbingReceiptError("precontest_plumbing_worktree_dirty")
    repo_hashes = _repo_hashes(root)
    units = _installed_unit_state(root)
    rehearsal_proof = _rehearsal_proof(now=current)
    value = {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "status": "PASS",
        "non_binding": True,
        "generated_at": current.isoformat(),
        "deployed_commit": commit,
        "worktree_clean": True,
        "repo_file_sha256": repo_hashes,
        "installed_units": units,
        "rehearsal": rehearsal_proof,
        "execution_plumbing_complete": True,
        "production_rehearsal_passed": True,
        "live_plumbing_changes_required": False,
    }
    value["receipt_sha256"] = _sha(value)
    return value


def validate_receipt(
    value: object,
    *,
    challenge_id: str,
    now: datetime,
    repo_root: Path | None = None,
) -> dict:
    if not isinstance(value, dict):
        raise PlumbingReceiptError("precontest_plumbing_receipt_invalid")
    required = {
        "schema_version", "challenge_id", "status", "non_binding", "generated_at",
        "deployed_commit", "worktree_clean", "repo_file_sha256", "installed_units",
        "rehearsal", "execution_plumbing_complete", "production_rehearsal_passed",
        "live_plumbing_changes_required", "receipt_sha256",
    }
    if set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise PlumbingReceiptError("precontest_plumbing_receipt_schema_invalid")
    digest = value.get("receipt_sha256")
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise PlumbingReceiptError("precontest_plumbing_receipt_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("receipt_sha256")
    if _sha(unsigned) != digest:
        raise PlumbingReceiptError("precontest_plumbing_receipt_integrity_invalid")
    if value.get("challenge_id") != airdrop_challenge.validate_challenge_id(challenge_id):
        raise PlumbingReceiptError("precontest_plumbing_challenge_mismatch")
    if value.get("status") != "PASS" or value.get("non_binding") is not True:
        raise PlumbingReceiptError("precontest_plumbing_receipt_not_passed")
    generated = _parse_time(value.get("generated_at"), label="generated_at")
    age = now.astimezone(UTC) - generated
    if age > precontest_readiness.MAX_EVIDENCE_AGE or age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise PlumbingReceiptError("precontest_plumbing_receipt_stale")
    if value.get("worktree_clean") is not True:
        raise PlumbingReceiptError("precontest_plumbing_worktree_not_clean")
    if value.get("execution_plumbing_complete") is not True:
        raise PlumbingReceiptError("precontest_plumbing_execution_incomplete")
    if value.get("production_rehearsal_passed") is not True:
        raise PlumbingReceiptError("precontest_plumbing_production_rehearsal_missing")
    if value.get("live_plumbing_changes_required") is not False:
        raise PlumbingReceiptError("precontest_plumbing_live_changes_required")

    root = (repo_root or _repo_root()).resolve()
    current_commit = _current_commit(root)
    if value.get("deployed_commit") != current_commit:
        raise PlumbingReceiptError("precontest_plumbing_commit_mismatch")
    if value.get("repo_file_sha256") != _repo_hashes(root):
        raise PlumbingReceiptError("precontest_plumbing_source_changed")

    units = value.get("installed_units")
    if not isinstance(units, dict) or set(units) != set(INSTALLED_UNITS):
        raise PlumbingReceiptError("precontest_plumbing_units_invalid")
    for unit, relative in INSTALLED_UNITS.items():
        row = units[unit]
        if not isinstance(row, dict) or set(row) != {"fragment", "enabled", "active", "sha256"}:
            raise PlumbingReceiptError("precontest_plumbing_unit_invalid")
        if row["fragment"] != f"/etc/systemd/system/{unit}":
            raise PlumbingReceiptError("precontest_plumbing_unit_fragment_invalid")
        if row["enabled"] != "enabled" or row["active"] != "active":
            raise PlumbingReceiptError("precontest_plumbing_unit_not_ready")
        expected_hash = _sha_bytes(_bounded_bytes(root / relative, label="repo_unit"))
        if row["sha256"] != expected_hash:
            raise PlumbingReceiptError("precontest_plumbing_unit_hash_mismatch")

    rehearse = value.get("rehearsal")
    if not isinstance(rehearse, dict) or set(rehearse) != {
        "sha256", "evaluated_at", "capture_to_rehearsal_ms", "trade_id",
        "stage_sha256", "signer_access", "approval_written", "post_attempted",
    }:
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_receipt_invalid")
    if rehearse["signer_access"] is not False or rehearse["approval_written"] is not False or rehearse["post_attempted"] is not False:
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_binding_side_effect")
    evaluated = _parse_time(rehearse["evaluated_at"], label="rehearsal_time")
    rehearsal_age = now.astimezone(UTC) - evaluated
    if rehearsal_age > precontest_readiness.MAX_EVIDENCE_AGE or rehearsal_age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_stale")
    latency = rehearse["capture_to_rehearsal_ms"]
    if type(latency) is not int or not 0 <= latency <= precontest_readiness.MAX_CAPTURE_TO_EXECUTOR_MS:
        raise PlumbingReceiptError("precontest_plumbing_rehearsal_latency_invalid")
    return dict(value)


def save_receipt(challenge_id: str, *, now: datetime | None = None) -> dict:
    value = build_receipt(challenge_id, now=now)
    precontest_readiness._atomic_write(receipt_path(challenge_id), value)
    return value


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"status": "blocked", "reason": "challenge_id_required"}))
        return 2
    try:
        result = save_receipt(sys.argv[1])
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
