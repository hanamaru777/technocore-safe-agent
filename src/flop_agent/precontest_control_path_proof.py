"""Machine evidence for pre-contest Production control-path redundancy.

This module is deliberately non-binding.  It records/validates narrow path
probe artifacts and evaluates whether at least two fresh authenticated ready
Production control paths exist, with at least one path independent of connector
quota.  It never opens a shell, signs, posts, starts services, or accesses
signer/Vault material.
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
from . import precontest_readiness

SCHEMA_VERSION = 1
PROBE_SCHEMA_VERSION = 1
HEX64_RE = re.compile(r"[0-9a-f]{64}")
PATH_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
ALLOWED_PATHS = {"ssh-operator", "remote-desktop", "resident-autonomous"}


class ControlPathProofError(RuntimeError):
    """Fail-closed control-path proof error."""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise ControlPathProofError(f"precontest_control_{label}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ControlPathProofError(f"precontest_control_{label}_invalid") from error
    if parsed.tzinfo is None:
        raise ControlPathProofError(f"precontest_control_{label}_invalid")
    return parsed.astimezone(UTC)


def _fresh(timestamp: str, *, now: datetime) -> bool:
    verified = _parse_time(timestamp, label="verified_at")
    age = now.astimezone(UTC) - verified
    return -precontest_readiness.MAX_CLOCK_SKEW <= age <= precontest_readiness.MAX_EVIDENCE_AGE


def proof_path(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "precontest-control-path-proof.json"


def probe_dir(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "control-path-probes"


def probe_path(challenge_id: str, path_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    if not isinstance(path_id, str) or not PATH_ID_RE.fullmatch(path_id):
        raise ControlPathProofError("precontest_control_path_id_invalid")
    if path_id not in ALLOWED_PATHS:
        raise ControlPathProofError("precontest_control_path_unsupported")
    return probe_dir(challenge_id) / f"{path_id}.json"


def seal_probe(value: object) -> dict:
    if not isinstance(value, dict):
        raise ControlPathProofError("precontest_control_probe_invalid")
    required = {
        "schema_version",
        "challenge_id",
        "path_id",
        "authenticated",
        "ready",
        "quota_independent",
        "verified_at",
        "evidence_kind",
        "evidence_ref",
    }
    if set(value) != required or value.get("schema_version") != PROBE_SCHEMA_VERSION:
        raise ControlPathProofError("precontest_control_probe_schema_invalid")
    challenge_id = airdrop_challenge.validate_challenge_id(value.get("challenge_id"))
    path_id = value.get("path_id")
    if not isinstance(path_id, str) or path_id not in ALLOWED_PATHS:
        raise ControlPathProofError("precontest_control_path_unsupported")
    for key in ("authenticated", "ready", "quota_independent"):
        if type(value.get(key)) is not bool:
            raise ControlPathProofError(f"precontest_control_{key}_invalid")
    verified_at = _parse_time(value.get("verified_at"), label="verified_at").isoformat()
    evidence_kind = value.get("evidence_kind")
    evidence_ref = value.get("evidence_ref")
    if not isinstance(evidence_kind, str) or not evidence_kind or len(evidence_kind) > 64:
        raise ControlPathProofError("precontest_control_evidence_kind_invalid")
    if not isinstance(evidence_ref, str) or not evidence_ref or len(evidence_ref) > 256:
        raise ControlPathProofError("precontest_control_evidence_ref_invalid")

    # Permanent policy: Remote Desktop is useful but connector/quota dependent.
    if path_id == "remote-desktop" and value["quota_independent"] is not False:
        raise ControlPathProofError("precontest_control_remote_desktop_quota_invalid")
    # The repository CI runner is explicitly not a Production control path.
    if evidence_kind in {"github-actions", "github-ci", "security-gate"}:
        raise ControlPathProofError("precontest_control_ci_not_production_path")
    # Do not count an autonomous resident before HUMAN_INDEPENDENCE is machine-proven.
    if path_id == "resident-autonomous":
        raise ControlPathProofError("precontest_control_resident_not_yet_eligible")

    cleaned = {
        "schema_version": PROBE_SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "path_id": path_id,
        "authenticated": value["authenticated"],
        "ready": value["ready"],
        "quota_independent": value["quota_independent"],
        "verified_at": verified_at,
        "evidence_kind": evidence_kind,
        "evidence_ref": evidence_ref,
    }
    cleaned["probe_sha256"] = _sha(cleaned)
    return cleaned


def validate_probe(value: object, *, challenge_id: str, now: datetime) -> dict:
    if not isinstance(value, dict):
        raise ControlPathProofError("precontest_control_probe_invalid")
    required = {
        "schema_version", "challenge_id", "path_id", "authenticated", "ready",
        "quota_independent", "verified_at", "evidence_kind", "evidence_ref", "probe_sha256",
    }
    if set(value) != required:
        raise ControlPathProofError("precontest_control_probe_schema_invalid")
    digest = value.get("probe_sha256")
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise ControlPathProofError("precontest_control_probe_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("probe_sha256")
    sealed = seal_probe(unsigned)
    if sealed["probe_sha256"] != digest:
        raise ControlPathProofError("precontest_control_probe_integrity_invalid")
    if sealed["challenge_id"] != airdrop_challenge.validate_challenge_id(challenge_id):
        raise ControlPathProofError("precontest_control_probe_challenge_mismatch")
    if not _fresh(sealed["verified_at"], now=now):
        raise ControlPathProofError("precontest_control_probe_stale")
    sealed["probe_sha256"] = digest
    return sealed


def save_probe(challenge_id: str, value: object) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    sealed = seal_probe(value)
    if sealed["challenge_id"] != challenge_id:
        raise ControlPathProofError("precontest_control_probe_challenge_mismatch")
    precontest_readiness._atomic_write(probe_path(challenge_id, sealed["path_id"]), sealed)
    return sealed


def capture_ssh_probe(challenge_id: str, *, now: datetime | None = None) -> dict:
    """Capture a narrow proof only when invoked inside a real SSH session.

    The proof stores no source/destination IPs or key material.  It records the
    current repository HEAD as a non-secret evidence reference.
    """
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_control_now_timezone_required")
    if not os.environ.get("SSH_CONNECTION") or not os.environ.get("SSH_CLIENT"):
        raise ControlPathProofError("precontest_control_ssh_session_missing")
    try:
        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parents[2],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise ControlPathProofError("precontest_control_repo_head_unavailable") from error
    if not HEX64_RE.fullmatch(head):
        raise ControlPathProofError("precontest_control_repo_head_invalid")
    return save_probe(
        challenge_id,
        {
            "schema_version": PROBE_SCHEMA_VERSION,
            "challenge_id": challenge_id,
            "path_id": "ssh-operator",
            "authenticated": True,
            "ready": True,
            "quota_independent": True,
            "verified_at": current.astimezone(UTC).isoformat(),
            "evidence_kind": "ssh-session",
            "evidence_ref": f"repo-head:{head}",
        },
    )


def _load_probes(challenge_id: str, *, now: datetime) -> list[dict]:
    directory = probe_dir(challenge_id)
    if not directory.exists():
        return []
    if directory.is_symlink() or not directory.is_dir():
        raise ControlPathProofError("precontest_control_probe_dir_invalid")
    rows: list[dict] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.json")):
        if path.is_symlink() or not path.is_file():
            raise ControlPathProofError("precontest_control_probe_file_invalid")
        try:
            raw = json.loads(path.read_text("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ControlPathProofError("precontest_control_probe_file_invalid") from error
        valid = validate_probe(raw, challenge_id=challenge_id, now=now)
        if valid["path_id"] in seen:
            raise ControlPathProofError("precontest_control_probe_duplicate")
        seen.add(valid["path_id"])
        rows.append(valid)
    return rows


def build_proof(challenge_id: str, *, now: datetime | None = None) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_control_now_timezone_required")
    current = current.astimezone(UTC)
    probes = _load_probes(challenge_id, now=current)
    ready = [row for row in probes if row["authenticated"] and row["ready"]]
    quota_independent = any(row["quota_independent"] for row in ready)
    passed = len(ready) >= 2 and quota_independent
    value = {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "status": "PASS" if passed else "NO_GO",
        "non_binding": True,
        "generated_at": current.isoformat(),
        "paths": probes,
        "ready_path_count": len(ready),
        "quota_independent_ready": quota_independent,
        "minimum_ready_paths": 2,
    }
    value["proof_sha256"] = _sha(value)
    return value


def validate_proof(value: object, *, challenge_id: str, now: datetime) -> dict:
    if not isinstance(value, dict):
        raise ControlPathProofError("precontest_control_proof_invalid")
    required = {
        "schema_version", "challenge_id", "status", "non_binding", "generated_at", "paths",
        "ready_path_count", "quota_independent_ready", "minimum_ready_paths", "proof_sha256",
    }
    if set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise ControlPathProofError("precontest_control_proof_schema_invalid")
    digest = value.get("proof_sha256")
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise ControlPathProofError("precontest_control_proof_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("proof_sha256")
    if _sha(unsigned) != digest:
        raise ControlPathProofError("precontest_control_proof_integrity_invalid")
    if value.get("challenge_id") != airdrop_challenge.validate_challenge_id(challenge_id):
        raise ControlPathProofError("precontest_control_proof_challenge_mismatch")
    generated = _parse_time(value.get("generated_at"), label="generated_at")
    age = now.astimezone(UTC) - generated
    if age > precontest_readiness.MAX_EVIDENCE_AGE or age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise ControlPathProofError("precontest_control_proof_stale")
    paths = value.get("paths")
    if not isinstance(paths, list) or len(paths) > 8:
        raise ControlPathProofError("precontest_control_paths_invalid")
    valid_paths = [validate_probe(row, challenge_id=challenge_id, now=now) for row in paths]
    if len({row["path_id"] for row in valid_paths}) != len(valid_paths):
        raise ControlPathProofError("precontest_control_probe_duplicate")
    ready = [row for row in valid_paths if row["authenticated"] and row["ready"]]
    independent = any(row["quota_independent"] for row in ready)
    expected_pass = len(ready) >= 2 and independent
    if value.get("ready_path_count") != len(ready):
        raise ControlPathProofError("precontest_control_ready_count_invalid")
    if value.get("quota_independent_ready") is not independent:
        raise ControlPathProofError("precontest_control_independent_invalid")
    if value.get("minimum_ready_paths") != 2:
        raise ControlPathProofError("precontest_control_minimum_invalid")
    if value.get("status") != ("PASS" if expected_pass else "NO_GO"):
        raise ControlPathProofError("precontest_control_status_invalid")
    if value.get("non_binding") is not True:
        raise ControlPathProofError("precontest_control_binding_invalid")
    return dict(value)


def save_proof(challenge_id: str, *, now: datetime | None = None) -> dict:
    value = build_proof(challenge_id, now=now)
    precontest_readiness._atomic_write(proof_path(challenge_id), value)
    return value


def readiness_paths(value: dict) -> list[dict]:
    return [
        {
            "id": row["path_id"],
            "authenticated": row["authenticated"],
            "ready": row["ready"],
            "quota_independent": row["quota_independent"],
            "verified_at": row["verified_at"],
        }
        for row in value["paths"]
    ]


def main() -> int:
    if len(sys.argv) not in {2, 3}:
        print(json.dumps({"status": "blocked", "reason": "challenge_id_required"}))
        return 2
    try:
        if len(sys.argv) == 3 and sys.argv[2] == "capture-ssh":
            result = capture_ssh_probe(sys.argv[1])
        elif len(sys.argv) == 2:
            result = save_proof(sys.argv[1])
        else:
            raise ControlPathProofError("precontest_control_command_invalid")
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
