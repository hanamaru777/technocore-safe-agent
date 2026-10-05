"""Validate machine collector provenance for profile-enabled pre-contest GO.

The provenance is local, non-binding evidence. Validation never signs, posts,
starts services, or changes external state.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from . import airdrop_challenge, precontest_readiness

SCHEMA_VERSION = 1
MAX_BYTES = 512 * 1024
HEX64_RE = re.compile(r"[0-9a-f]{64}")


class MachineProvenanceError(RuntimeError):
    """Fail-closed machine provenance error."""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise MachineProvenanceError("precontest_machine_provenance_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise MachineProvenanceError("precontest_machine_provenance_time_invalid") from error
    if parsed.tzinfo is None:
        raise MachineProvenanceError("precontest_machine_provenance_time_invalid")
    return parsed.astimezone(UTC)


def provenance_path(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "precontest-readiness-sources.json"


def validate(
    value: object,
    *,
    challenge_id: str,
    readiness_evidence_sha256: str,
    now: datetime,
    require_no_unsupported: bool,
) -> dict:
    if not isinstance(value, dict):
        raise MachineProvenanceError("precontest_machine_provenance_invalid")
    required = {
        "schema_version",
        "challenge_id",
        "collected_at",
        "collector",
        "non_binding",
        "readiness_evidence_sha256",
        "sources",
        "unsupported_gates_forced_no_go",
        "provenance_sha256",
    }
    if set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise MachineProvenanceError("precontest_machine_provenance_schema_invalid")
    digest = value.get("provenance_sha256")
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise MachineProvenanceError("precontest_machine_provenance_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("provenance_sha256")
    if _sha(unsigned) != digest:
        raise MachineProvenanceError("precontest_machine_provenance_integrity_invalid")

    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    if value.get("challenge_id") != challenge_id:
        raise MachineProvenanceError("precontest_machine_provenance_challenge_mismatch")
    if value.get("collector") != "precontest_machine_evidence" or value.get("non_binding") is not True:
        raise MachineProvenanceError("precontest_machine_provenance_collector_invalid")

    evidence_digest = value.get("readiness_evidence_sha256")
    if (
        not isinstance(evidence_digest, str)
        or not HEX64_RE.fullmatch(evidence_digest)
        or evidence_digest != readiness_evidence_sha256
    ):
        raise MachineProvenanceError("precontest_machine_provenance_evidence_mismatch")

    if now.tzinfo is None:
        raise ValueError("precontest_machine_provenance_now_timezone_required")
    collected = _parse_time(value.get("collected_at"))
    current = now.astimezone(UTC)
    age = current - collected
    if age > precontest_readiness.MAX_EVIDENCE_AGE or age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise MachineProvenanceError("precontest_machine_provenance_stale")

    sources = value.get("sources")
    if not isinstance(sources, dict) or len(sources) > 32:
        raise MachineProvenanceError("precontest_machine_provenance_sources_invalid")
    if any(not isinstance(key, str) or not key or len(key) > 128 for key in sources):
        raise MachineProvenanceError("precontest_machine_provenance_sources_invalid")

    unsupported = value.get("unsupported_gates_forced_no_go")
    if (
        not isinstance(unsupported, list)
        or len(unsupported) > 32
        or not all(isinstance(item, str) and 0 < len(item) <= 128 for item in unsupported)
        or len(set(unsupported)) != len(unsupported)
    ):
        raise MachineProvenanceError("precontest_machine_provenance_unsupported_invalid")
    if require_no_unsupported and unsupported:
        raise MachineProvenanceError("precontest_machine_provenance_unsupported_gates")
    return dict(value)


def load_validated(
    challenge_id: str,
    *,
    readiness_evidence_sha256: str,
    now: datetime,
    require_no_unsupported: bool,
) -> dict:
    path = provenance_path(challenge_id)
    if not path.exists() or path.is_symlink() or not path.is_file():
        raise MachineProvenanceError("precontest_machine_provenance_missing")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_BYTES:
        raise MachineProvenanceError("precontest_machine_provenance_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MachineProvenanceError("precontest_machine_provenance_invalid") from error
    return validate(
        value,
        challenge_id=challenge_id,
        readiness_evidence_sha256=readiness_evidence_sha256,
        now=now,
        require_no_unsupported=require_no_unsupported,
    )
