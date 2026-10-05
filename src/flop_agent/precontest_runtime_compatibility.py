"""Fail-closed compatibility proof for a challenge-specific runtime adapter.

A configured runtime profile is not reusable merely because its name matches.
This module binds the profile to the immutable official challenge authority,
deadline, protocol constants and current adapter/executor source. It is local
and non-binding: no service mutation, signing, approval write, POST or Vault
access is possible here.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import re
import textwrap
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from . import airdrop_challenge
from . import close1_approved_trade as executor
from . import close1_autonomous_rehearsal as rehearsal
from . import close1_autonomous_resident as resident
from . import close1_autonomous_stage as stage
from . import close_call
from . import precontest_readiness
from . import precontest_runtime_profile

SCHEMA_VERSION = 1
PROFILE = "close1_short_liquidity"
FROZEN_REFEREE_COMMIT = "0ae6b063107b77e3a6cb794186fdd341a947e5e1"
RULES_OWNER = "flop-labs"
RULES_REPO = "technocore-close-call-challenge"
HEX64_RE = re.compile(r"[0-9a-f]{64}")


class RuntimeCompatibilityError(RuntimeError):
    """Fail-closed runtime-adapter compatibility error."""


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _source_sha(function: object) -> str:
    source = textwrap.dedent(inspect.getsource(function))
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise RuntimeCompatibilityError(f"precontest_runtime_compat_{label}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeCompatibilityError(f"precontest_runtime_compat_{label}_invalid") from error
    if parsed.tzinfo is None:
        raise RuntimeCompatibilityError(f"precontest_runtime_compat_{label}_invalid")
    return parsed.astimezone(UTC)


def proof_path(challenge_id: str) -> Path:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return precontest_readiness._root() / challenge_id / "precontest-runtime-compatibility.json"


def _spec(challenge_id: str) -> dict:
    path = airdrop_challenge._spec_path(challenge_id)
    if path.is_symlink() or not path.is_file():
        raise RuntimeCompatibilityError("precontest_runtime_compat_spec_missing")
    try:
        raw = json.loads(path.read_text("utf-8"))
        return airdrop_challenge.validate_spec(raw)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeCompatibilityError("precontest_runtime_compat_spec_invalid") from error


def _rules_url_commit(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "raw.githubusercontent.com":
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 4 or parts[0] != RULES_OWNER or parts[1] != RULES_REPO:
        return None
    commit = parts[2]
    return commit if re.fullmatch(r"[0-9a-f]{40}", commit) else None


def _bindings() -> dict:
    return {
        "runtime_profile": PROFILE,
        "contest_id": close_call.CONTEST_ID,
        "runtime_lock": close_call.LOCK.isoformat(),
        "lock_sweep": close_call.LOCK_SWEEP,
        "launch_repo_commit": close_call.OFFICIAL_REPO_COMMIT,
        "frozen_rules_repo": f"{RULES_OWNER}/{RULES_REPO}",
        "frozen_rules_commit": FROZEN_REFEREE_COMMIT,
        "stage_build_sha256": _source_sha(stage.build_stage),
        "rehearsal_run_sha256": _source_sha(rehearsal.run_once),
        "resident_cycle_sha256": _source_sha(resident.run_cycle),
        "executor_preflight_sha256": _source_sha(executor._fresh_preflight),
        "executor_run_locked_sha256": _source_sha(executor._run_locked),
    }


def _evaluate_current(challenge_id: str) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    profile = precontest_runtime_profile.load(challenge_id)
    if profile is None:
        raise RuntimeCompatibilityError("precontest_runtime_compat_profile_missing")
    if profile.get("runtime_profile") != PROFILE:
        raise RuntimeCompatibilityError("precontest_runtime_compat_profile_unsupported")

    spec = _spec(challenge_id)
    source = spec["source"]
    pinned = source.get("pinned_commit")
    rules_url_commit = _rules_url_commit(source.get("rules_url", ""))
    deadline = _parse_time(spec.get("deadline"), label="deadline")

    reason = "compatible"
    if source.get("authority_type") != "flop_labs_github":
        reason = "authority_type_mismatch"
    elif pinned != FROZEN_REFEREE_COMMIT:
        reason = "pinned_commit_mismatch"
    elif rules_url_commit != FROZEN_REFEREE_COMMIT:
        reason = "rules_repo_or_commit_mismatch"
    elif deadline != close_call.LOCK:
        reason = "deadline_mismatch"

    return {
        "status": "PASS" if reason == "compatible" else "NO_GO",
        "reason": reason,
        "runtime_profile": PROFILE,
        "profile_sha256": profile["profile_sha256"],
        "spec_pinned_commit": pinned,
        "rules_url_commit": rules_url_commit,
        "campaign_deadline": deadline.isoformat(),
        "adapter_bindings": _bindings(),
    }


def build_proof(challenge_id: str, *, now: datetime | None = None) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_runtime_compat_now_timezone_required")
    current = current.astimezone(UTC)
    current_state = _evaluate_current(challenge_id)
    value = {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "non_binding": True,
        "generated_at": current.isoformat(),
        **current_state,
    }
    value["proof_sha256"] = _sha(value)
    return value


def validate_proof(value: object, *, challenge_id: str, now: datetime) -> dict:
    if not isinstance(value, dict):
        raise RuntimeCompatibilityError("precontest_runtime_compat_proof_invalid")
    required = {
        "schema_version", "challenge_id", "non_binding", "generated_at", "status", "reason",
        "runtime_profile", "profile_sha256", "spec_pinned_commit", "rules_url_commit",
        "campaign_deadline", "adapter_bindings", "proof_sha256",
    }
    if set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeCompatibilityError("precontest_runtime_compat_proof_schema_invalid")
    digest = value.get("proof_sha256")
    if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
        raise RuntimeCompatibilityError("precontest_runtime_compat_proof_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("proof_sha256")
    if _sha(unsigned) != digest:
        raise RuntimeCompatibilityError("precontest_runtime_compat_proof_integrity_invalid")
    if value.get("challenge_id") != airdrop_challenge.validate_challenge_id(challenge_id):
        raise RuntimeCompatibilityError("precontest_runtime_compat_challenge_mismatch")
    if value.get("non_binding") is not True:
        raise RuntimeCompatibilityError("precontest_runtime_compat_binding_invalid")

    generated = _parse_time(value.get("generated_at"), label="generated_at")
    age = now.astimezone(UTC) - generated
    if age > precontest_readiness.MAX_EVIDENCE_AGE or age < -precontest_readiness.MAX_CLOCK_SKEW:
        raise RuntimeCompatibilityError("precontest_runtime_compat_proof_stale")

    current = _evaluate_current(challenge_id)
    for key in (
        "status", "reason", "runtime_profile", "profile_sha256", "spec_pinned_commit",
        "rules_url_commit", "campaign_deadline", "adapter_bindings",
    ):
        if value.get(key) != current[key]:
            raise RuntimeCompatibilityError("precontest_runtime_compat_source_changed")
    return dict(value)


def save_proof(challenge_id: str, *, now: datetime | None = None) -> dict:
    value = build_proof(challenge_id, now=now)
    precontest_readiness._atomic_write(proof_path(challenge_id), value)
    return value


def load_validated(challenge_id: str, *, now: datetime) -> dict | None:
    path = proof_path(challenge_id)
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise RuntimeCompatibilityError("precontest_runtime_compat_proof_invalid")
    try:
        raw = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeCompatibilityError("precontest_runtime_compat_proof_invalid") from error
    return validate_proof(raw, challenge_id=challenge_id, now=now)
