"""Fail-closed, non-binding evidence for HUMAN_INDEPENDENCE_GATE.

A PASS is intentionally impossible until the reviewed fixed-function dispatcher
and its systemd unit exist and a fresh Production pre-sign rehearsal receipt is
present.  This module never signs, writes approvals, posts, starts services, or
accesses signer/Vault material.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from . import airdrop_challenge, precontest_readiness

SCHEMA_VERSION = 1
MAX_BYTES = 128 * 1024
HEX64_RE = re.compile(r"[0-9a-f]{64}")
PROBE_METHOD = "fixed_handler_pre_sign_rehearsal"

DISPATCHER_FILE = "src/flop_agent/close1_autonomous_dispatcher.py"
DISPATCHER_SERVICE = "packaging/oracle/technocore-safe-agent-close1-autonomous-dispatcher.service"
EXECUTOR_FILE = "src/flop_agent/close1_approved_trade.py"


class HumanIndependenceProofError(RuntimeError):
    """Fail-closed human-independence proof error."""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise HumanIndependenceProofError(f"precontest_human_{label}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise HumanIndependenceProofError(f"precontest_human_{label}_invalid") from error
    if parsed.tzinfo is None:
        raise HumanIndependenceProofError(f"precontest_human_{label}_invalid")
    return parsed.astimezone(UTC)


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def receipt_path(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "precontest-human-independence-receipt.json"


def proof_path(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "precontest-human-independence-proof.json"


def _bounded_file(path: Path, *, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise HumanIndependenceProofError(f"precontest_human_{label}_missing")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_BYTES:
        raise HumanIndependenceProofError(f"precontest_human_{label}_invalid")
    return raw


def _required_source_hashes(root: Path | None = None) -> dict[str, str] | None:
    base = (root or _root()).resolve()
    paths = [DISPATCHER_FILE, DISPATCHER_SERVICE, EXECUTOR_FILE]
    if any(not (base / relative).is_file() for relative in paths):
        return None
    return {
        relative: _sha_bytes(_bounded_file(base / relative, label="source"))
        for relative in paths
    }


def _receipt_digest(value: dict) -> str:
    unsigned = dict(value)
    unsigned.pop("receipt_sha256", None)
    return _sha(unsigned)


def validate_receipt(
    value: object,
    *,
    challenge_id: str,
    now: datetime,
    repo_root: Path | None = None,
) -> dict:
    if not isinstance(value, dict):
        raise HumanIndependenceProofError("precontest_human_receipt_invalid")
    required = {
        "schema_version", "challenge_id", "status", "non_binding", "generated_at",
        "path_id", "probe_method", "binding_capable", "automatic_handoff",
        "requires_chat_relay", "requires_user_terminal", "policy_preconfigured",
        "signer_boundary_preserved", "fixed_function_only",
        "generic_privileged_rpc_exposed", "source_sha256", "receipt_sha256",
    }
    if set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise HumanIndependenceProofError("precontest_human_receipt_schema_invalid")
    digest = value.get("receipt_sha256")
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise HumanIndependenceProofError("precontest_human_receipt_digest_invalid")
    if _receipt_digest(value) != digest:
        raise HumanIndependenceProofError("precontest_human_receipt_integrity_invalid")
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    if value.get("challenge_id") != challenge_id:
        raise HumanIndependenceProofError("precontest_human_challenge_mismatch")
    if value.get("status") != "PASS" or value.get("non_binding") is not True:
        raise HumanIndependenceProofError("precontest_human_receipt_not_passed")
    if value.get("probe_method") != PROBE_METHOD:
        raise HumanIndependenceProofError("precontest_human_probe_method_invalid")
    path_id = value.get("path_id")
    if not isinstance(path_id, str) or not path_id or len(path_id) > 128:
        raise HumanIndependenceProofError("precontest_human_path_id_invalid")
    generated = _parse_time(value.get("generated_at"), label="generated_at")
    current = now.astimezone(UTC)
    age = current - generated
    if age > precontest_readiness.MAX_EVIDENCE_AGE or age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise HumanIndependenceProofError("precontest_human_receipt_stale")

    required_flags = {
        "binding_capable": True,
        "automatic_handoff": True,
        "requires_chat_relay": False,
        "requires_user_terminal": False,
        "policy_preconfigured": True,
        "signer_boundary_preserved": True,
        "fixed_function_only": True,
        "generic_privileged_rpc_exposed": False,
    }
    if any(value.get(key) is not expected for key, expected in required_flags.items()):
        raise HumanIndependenceProofError("precontest_human_receipt_claim_invalid")

    expected_hashes = _required_source_hashes(repo_root)
    if expected_hashes is None:
        raise HumanIndependenceProofError("precontest_human_dispatcher_not_implemented")
    if value.get("source_sha256") != expected_hashes:
        raise HumanIndependenceProofError("precontest_human_source_changed")
    return dict(value)


def _read_receipt(challenge_id: str) -> tuple[dict | None, str | None]:
    path = receipt_path(challenge_id)
    if not path.exists():
        return None, None
    raw = _bounded_file(path, label="receipt")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HumanIndependenceProofError("precontest_human_receipt_invalid") from error
    if not isinstance(value, dict):
        raise HumanIndependenceProofError("precontest_human_receipt_invalid")
    return value, _sha_bytes(raw)


def build_proof(
    challenge_id: str,
    *,
    now: datetime | None = None,
    repo_root: Path | None = None,
) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_human_now_timezone_required")
    current = current.astimezone(UTC)

    receipt, file_digest = _read_receipt(challenge_id)
    status = "NO_GO"
    reason = "precontest_human_receipt_missing"
    path_id = None
    if receipt is not None:
        try:
            valid = validate_receipt(
                receipt,
                challenge_id=challenge_id,
                now=current,
                repo_root=repo_root,
            )
        except HumanIndependenceProofError as error:
            reason = str(error)
        else:
            status = "PASS"
            reason = None
            path_id = valid["path_id"]

    value = {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "status": status,
        "non_binding": True,
        "generated_at": current.isoformat(),
        "receipt_present": receipt is not None,
        "receipt_file_sha256": file_digest,
        "path_id": path_id,
        "requires_chat_relay": status != "PASS",
        "requires_user_terminal": status != "PASS",
        "reason": reason,
    }
    value["proof_sha256"] = _sha(value)
    return value


def validate_proof(
    value: object,
    *,
    challenge_id: str,
    now: datetime,
    repo_root: Path | None = None,
) -> dict:
    if not isinstance(value, dict):
        raise HumanIndependenceProofError("precontest_human_proof_invalid")
    required = {
        "schema_version", "challenge_id", "status", "non_binding", "generated_at",
        "receipt_present", "receipt_file_sha256", "path_id", "requires_chat_relay",
        "requires_user_terminal", "reason", "proof_sha256",
    }
    if set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise HumanIndependenceProofError("precontest_human_proof_schema_invalid")
    digest = value.get("proof_sha256")
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise HumanIndependenceProofError("precontest_human_proof_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("proof_sha256")
    if _sha(unsigned) != digest:
        raise HumanIndependenceProofError("precontest_human_proof_integrity_invalid")
    if value.get("challenge_id") != airdrop_challenge.validate_challenge_id(challenge_id):
        raise HumanIndependenceProofError("precontest_human_challenge_mismatch")
    generated = _parse_time(value.get("generated_at"), label="proof_time")
    current = now.astimezone(UTC)
    age = current - generated
    if age > precontest_readiness.MAX_EVIDENCE_AGE or age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise HumanIndependenceProofError("precontest_human_proof_stale")

    current_receipt, current_digest = _read_receipt(challenge_id)
    if value.get("receipt_present") is not (current_receipt is not None):
        raise HumanIndependenceProofError("precontest_human_receipt_source_changed")
    if value.get("receipt_file_sha256") != current_digest:
        raise HumanIndependenceProofError("precontest_human_receipt_source_changed")

    if value.get("status") == "PASS":
        if current_receipt is None:
            raise HumanIndependenceProofError("precontest_human_receipt_missing")
        valid = validate_receipt(
            current_receipt,
            challenge_id=challenge_id,
            now=current,
            repo_root=repo_root,
        )
        if value.get("path_id") != valid["path_id"]:
            raise HumanIndependenceProofError("precontest_human_path_id_mismatch")
        if value.get("requires_chat_relay") is not False or value.get("requires_user_terminal") is not False:
            raise HumanIndependenceProofError("precontest_human_proof_claim_invalid")
        if value.get("reason") is not None:
            raise HumanIndependenceProofError("precontest_human_proof_claim_invalid")
    elif value.get("status") == "NO_GO":
        if value.get("requires_chat_relay") is not True or value.get("requires_user_terminal") is not True:
            raise HumanIndependenceProofError("precontest_human_no_go_claim_invalid")
        if not isinstance(value.get("reason"), str) or not value["reason"]:
            raise HumanIndependenceProofError("precontest_human_no_go_reason_missing")
    else:
        raise HumanIndependenceProofError("precontest_human_proof_status_invalid")
    if value.get("non_binding") is not True:
        raise HumanIndependenceProofError("precontest_human_proof_binding_invalid")
    return dict(value)


def save_proof(challenge_id: str, *, now: datetime | None = None) -> dict:
    value = build_proof(challenge_id, now=now)
    precontest_readiness._atomic_write(proof_path(challenge_id), value)
    return value
