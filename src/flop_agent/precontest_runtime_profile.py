"""Explicit local runtime profile for safe pre-contest proof automation.

The profile is separate from the immutable official challenge spec. Missing
profile means no challenge-specific proof automation. This module never signs,
posts, starts services, or changes external state.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import airdrop_challenge, precontest_readiness

SCHEMA_VERSION = 1
ALLOWED_PROFILES = {"close1_short_liquidity"}
HEX64_RE = re.compile(r"[0-9a-f]{64}")


class RuntimeProfileError(RuntimeError):
    """Fail-closed runtime-profile error."""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise RuntimeProfileError("precontest_runtime_profile_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeProfileError("precontest_runtime_profile_time_invalid") from error
    if parsed.tzinfo is None:
        raise RuntimeProfileError("precontest_runtime_profile_time_invalid")
    return parsed.astimezone(UTC)


def profile_path(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "precontest-runtime-profile.json"


def seal(challenge_id: str, runtime_profile: str, *, now: datetime | None = None) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    if runtime_profile not in ALLOWED_PROFILES:
        raise ValueError("precontest_runtime_profile_invalid")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_runtime_profile_timezone_required")
    value = {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "runtime_profile": runtime_profile,
        "configured_at": current.astimezone(UTC).isoformat(),
    }
    value["profile_sha256"] = _sha(value)
    return value


def validate(value: object, *, challenge_id: str) -> dict:
    if not isinstance(value, dict):
        raise RuntimeProfileError("precontest_runtime_profile_invalid")
    required = {
        "schema_version", "challenge_id", "runtime_profile", "configured_at",
        "profile_sha256",
    }
    if set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeProfileError("precontest_runtime_profile_schema_invalid")
    digest = value.get("profile_sha256")
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise RuntimeProfileError("precontest_runtime_profile_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("profile_sha256")
    if _sha(unsigned) != digest:
        raise RuntimeProfileError("precontest_runtime_profile_integrity_invalid")
    if value.get("challenge_id") != airdrop_challenge.validate_challenge_id(challenge_id):
        raise RuntimeProfileError("precontest_runtime_profile_challenge_mismatch")
    if value.get("runtime_profile") not in ALLOWED_PROFILES:
        raise RuntimeProfileError("precontest_runtime_profile_invalid")
    _parse_time(value.get("configured_at"))
    return dict(value)


def save(challenge_id: str, runtime_profile: str, *, now: datetime | None = None) -> dict:
    value = seal(challenge_id, runtime_profile, now=now)
    precontest_readiness._atomic_write(profile_path(challenge_id), value)
    return value


def load(challenge_id: str) -> dict | None:
    path = profile_path(challenge_id)
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise RuntimeProfileError("precontest_runtime_profile_invalid")
    try:
        raw = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeProfileError("precontest_runtime_profile_invalid") from error
    return validate(raw, challenge_id=challenge_id)


def main() -> int:
    if len(sys.argv) != 3:
        print(json.dumps({"status": "blocked", "reason": "challenge_id_and_profile_required"}))
        return 2
    try:
        result = save(sys.argv[1], sys.argv[2])
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
