"""Fail-closed, non-binding evidence for Production control-path redundancy.

This module validates machine probe receipts produced by distinct control paths.
It does not create credentials, open SSH sessions, start services, sign, post, or
mutate Production. A path counts only when its receipt proves a fresh,
authenticated, ready binding-capable control path. Aliases sharing one failure
domain are never double-counted.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from . import airdrop_challenge, precontest_readiness

SCHEMA_VERSION = 1
MAX_RECEIPT_BYTES = 64 * 1024
HEX64_RE = re.compile(r"[0-9a-f]{64}")
ALLOWED_PATH_TYPES = {"direct_ssh", "connector", "ci_deploy", "fixed_rpc"}
NON_BINDING_TYPES = {"discord", "watcher", "read_only_rpc"}
EMPTY_RECEIPTS_SHA256 = hashlib.sha256(b"[]").hexdigest()


class ControlPathProofError(RuntimeError):
    """Fail-closed control-path evidence error."""


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


def receipts_path(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "precontest-control-path-receipts.json"


def proof_path(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "precontest-control-path-proof.json"


def _receipt_digest(row: dict) -> str:
    unsigned = dict(row)
    unsigned.pop("receipt_sha256", None)
    return _sha(unsigned)


def validate_receipt(row: object, *, now: datetime) -> dict:
    if not isinstance(row, dict):
        raise ControlPathProofError("precontest_control_receipt_invalid")
    required = {
        "schema_version", "path_id", "path_type", "endpoint_fingerprint",
        "failure_domain", "authenticated", "ready", "binding_capable",
        "quota_independent", "verified_at", "probe_method", "receipt_sha256",
    }
    if set(row) != required or row.get("schema_version") != SCHEMA_VERSION:
        raise ControlPathProofError("precontest_control_receipt_schema_invalid")
    for key in ("path_id", "endpoint_fingerprint", "failure_domain", "probe_method"):
        value = row.get(key)
        if not isinstance(value, str) or not value or len(value) > 200:
            raise ControlPathProofError("precontest_control_receipt_field_invalid")
    path_type = row.get("path_type")
    if path_type in NON_BINDING_TYPES:
        raise ControlPathProofError("precontest_control_non_binding_path_forbidden")
    if path_type not in ALLOWED_PATH_TYPES:
        raise ControlPathProofError("precontest_control_path_type_invalid")
    for key in ("authenticated", "ready", "binding_capable", "quota_independent"):
        if type(row.get(key)) is not bool:
            raise ControlPathProofError("precontest_control_receipt_boolean_invalid")
    digest = row.get("receipt_sha256")
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise ControlPathProofError("precontest_control_receipt_digest_invalid")
    if _receipt_digest(row) != digest:
        raise ControlPathProofError("precontest_control_receipt_integrity_invalid")
    verified = _parse_time(row.get("verified_at"), label="verified_at")
    age = now.astimezone(UTC) - verified
    if age > precontest_readiness.MAX_EVIDENCE_AGE or age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise ControlPathProofError("precontest_control_receipt_stale")
    return dict(row)


def _read_receipt_source(challenge_id: str) -> tuple[list[object], str]:
    path = receipts_path(challenge_id)
    if not path.exists():
        return [], EMPTY_RECEIPTS_SHA256
    if path.is_symlink() or not path.is_file():
        raise ControlPathProofError("precontest_control_receipts_invalid")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_RECEIPT_BYTES:
        raise ControlPathProofError("precontest_control_receipts_size_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlPathProofError("precontest_control_receipts_invalid") from error
    if not isinstance(value, list):
        raise ControlPathProofError("precontest_control_receipts_invalid")
    return value, hashlib.sha256(raw).hexdigest()


def _load_receipts(challenge_id: str, *, now: datetime) -> tuple[list[dict], str]:
    raw_rows, source_digest = _read_receipt_source(challenge_id)
    rows = [validate_receipt(row, now=now) for row in raw_rows]
    ids = [row["path_id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ControlPathProofError("precontest_control_duplicate_path_id")
    return rows, source_digest


def _independent_ready_paths(rows: list[dict]) -> list[dict]:
    eligible = [
        row for row in rows
        if row["authenticated"] and row["ready"] and row["binding_capable"]
    ]
    seen_domains: set[tuple[str, str]] = set()
    independent: list[dict] = []
    for row in sorted(eligible, key=lambda item: item["path_id"]):
        domain = (row["endpoint_fingerprint"], row["failure_domain"])
        if domain in seen_domains:
            continue
        seen_domains.add(domain)
        independent.append(row)
    return independent


def _project_path(row: dict) -> dict:
    # Preserve the existing readiness evidence schema. Endpoint/failure-domain
    # details are used above to establish independence but are not promoted.
    return {
        "id": row["path_id"],
        "authenticated": row["authenticated"],
        "ready": row["ready"],
        "quota_independent": row["quota_independent"],
        "verified_at": row["verified_at"],
    }


def build_proof(challenge_id: str, *, now: datetime | None = None) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_control_now_timezone_required")
    current = current.astimezone(UTC)
    receipts, receipts_digest = _load_receipts(challenge_id, now=current)
    ready = _independent_ready_paths(receipts)
    projected = [_project_path(row) for row in ready]
    gate_pass = len(projected) >= 2 and any(row["quota_independent"] for row in projected)
    value = {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "status": "PASS" if gate_pass else "NO_GO",
        "non_binding": True,
        "generated_at": current.isoformat(),
        "receipts_sha256": receipts_digest,
        "receipt_count": len(receipts),
        "ready_independent_count": len(projected),
        "quota_independent_ready": any(row["quota_independent"] for row in projected),
        "control_paths": projected,
    }
    value["proof_sha256"] = _sha(value)
    return value


def validate_proof(value: object, *, challenge_id: str, now: datetime) -> dict:
    if not isinstance(value, dict):
        raise ControlPathProofError("precontest_control_proof_invalid")
    required = {
        "schema_version", "challenge_id", "status", "non_binding", "generated_at",
        "receipts_sha256", "receipt_count", "ready_independent_count",
        "quota_independent_ready", "control_paths", "proof_sha256",
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
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    if value.get("challenge_id") != challenge_id:
        raise ControlPathProofError("precontest_control_challenge_mismatch")
    generated = _parse_time(value.get("generated_at"), label="generated_at")
    age = now.astimezone(UTC) - generated
    if age > precontest_readiness.MAX_EVIDENCE_AGE or age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise ControlPathProofError("precontest_control_proof_stale")

    receipts, receipts_digest = _load_receipts(challenge_id, now=now)
    ready = [_project_path(row) for row in _independent_ready_paths(receipts)]
    if value.get("receipts_sha256") != receipts_digest:
        raise ControlPathProofError("precontest_control_receipt_source_changed")
    if value.get("receipt_count") != len(receipts):
        raise ControlPathProofError("precontest_control_receipt_count_invalid")
    if value.get("control_paths") != ready:
        raise ControlPathProofError("precontest_control_paths_source_mismatch")
    if value.get("ready_independent_count") != len(ready):
        raise ControlPathProofError("precontest_control_count_invalid")
    quota_independent = any(row["quota_independent"] for row in ready)
    if value.get("quota_independent_ready") is not quota_independent:
        raise ControlPathProofError("precontest_control_quota_flag_invalid")
    should_pass = len(ready) >= 2 and quota_independent
    if value.get("status") != ("PASS" if should_pass else "NO_GO"):
        raise ControlPathProofError("precontest_control_status_invalid")
    if value.get("non_binding") is not True:
        raise ControlPathProofError("precontest_control_binding_proof_invalid")
    return dict(value)


def save_proof(challenge_id: str, *, now: datetime | None = None) -> dict:
    value = build_proof(challenge_id, now=now)
    precontest_readiness._atomic_write(proof_path(challenge_id), value)
    return value
