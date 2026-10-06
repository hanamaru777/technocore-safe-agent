"""Generate local non-binding review packets for unregistered challenge candidates.

Packets make the first review step explicit without fabricating rules.  They are
built only from candidate evidence already derived from the tamper-evident Radar
ledger.  Unknown campaign rules remain UNKNOWN until a validated challenge spec
is created from authoritative sources.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from . import airdrop_ledger, observer, precontest_candidate_discovery as discovery

SCHEMA_VERSION = 1
PACKET_DIR = "challenge-candidate-reviews"
REQUIRED_UNKNOWN_FIELDS = (
    "authoritative_rules_commit",
    "authoritative_rules_file",
    "opening",
    "deadline",
    "prize",
    "eligibility",
    "submission_path",
    "collaboration_required",
    "registration_required",
    "runtime_profile",
)


class CandidateReviewError(RuntimeError):
    """Fail-closed pre-spec review packet error."""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: dict) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _parse_time(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise CandidateReviewError(f"precontest_review_{label}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CandidateReviewError(f"precontest_review_{label}_invalid") from error
    if parsed.tzinfo is None:
        raise CandidateReviewError(f"precontest_review_{label}_invalid")
    return parsed.astimezone(UTC).isoformat()


def packet_path(repo_name: str) -> Path:
    repo = discovery._repo_name(repo_name)
    return airdrop_ledger.ledger_dir() / PACKET_DIR / f"{repo}.json"


def _unknowns() -> dict:
    return {name: {"status": "UNKNOWN", "value": None} for name in REQUIRED_UNKNOWN_FIELDS}


def build_packet(candidate: dict, *, now: datetime | None = None) -> dict:
    repo = discovery._repo_name(candidate.get("repo_name"))
    first_seen = _parse_time(candidate.get("first_seen_at"), label="first_seen")
    last_seen = _parse_time(candidate.get("last_seen_at"), label="last_seen")
    if datetime.fromisoformat(last_seen) < datetime.fromisoformat(first_seen):
        raise CandidateReviewError("precontest_review_time_order_invalid")
    if candidate.get("listed_now") is not True:
        raise CandidateReviewError("precontest_review_candidate_not_current")
    branch = candidate.get("default_branch")
    if branch is not None and (not isinstance(branch, str) or not branch or len(branch) > 200):
        raise CandidateReviewError("precontest_review_branch_invalid")
    pushed = candidate.get("pushed_at")
    if pushed is not None:
        pushed = _parse_time(pushed, label="pushed_at")
    event_ids = candidate.get("event_ids")
    if (
        not isinstance(event_ids, list)
        or not event_ids
        or len(set(event_ids)) != len(event_ids)
        or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{24}", item) for item in event_ids)
    ):
        raise CandidateReviewError("precontest_review_event_ids_invalid")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_review_now_timezone_required")
    value = {
        "schema_version": SCHEMA_VERSION,
        "non_binding": True,
        "status": "RULES_REVIEW_REQUIRED",
        "repo_name": repo,
        "official_repo_url": f"https://github.com/flop-labs/{repo}",
        "official_api_url": f"https://api.github.com/repos/flop-labs/{repo}",
        "default_branch": branch,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "pushed_at": pushed,
        "event_ids": list(event_ids),
        "generated_at": current.astimezone(UTC).isoformat(),
        "unknown_rules": _unknowns(),
        "warning": "Repository discovery is review evidence only; campaign rules must be pinned from authoritative content before creating a challenge spec.",
    }
    value["packet_sha256"] = _digest(value)
    return value


def validate_packet(value: object, *, expected_repo: str | None = None) -> dict:
    if not isinstance(value, dict):
        raise CandidateReviewError("precontest_review_packet_invalid")
    expected_keys = {
        "schema_version",
        "non_binding",
        "status",
        "repo_name",
        "official_repo_url",
        "official_api_url",
        "default_branch",
        "first_seen_at",
        "last_seen_at",
        "pushed_at",
        "event_ids",
        "generated_at",
        "unknown_rules",
        "warning",
        "packet_sha256",
    }
    if set(value) != expected_keys or value.get("schema_version") != SCHEMA_VERSION:
        raise CandidateReviewError("precontest_review_schema_invalid")
    digest = value.get("packet_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise CandidateReviewError("precontest_review_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("packet_sha256")
    if _digest(unsigned) != digest:
        raise CandidateReviewError("precontest_review_integrity_invalid")
    if value.get("non_binding") is not True or value.get("status") != "RULES_REVIEW_REQUIRED":
        raise CandidateReviewError("precontest_review_status_invalid")
    repo = discovery._repo_name(value.get("repo_name"))
    if expected_repo is not None and repo != discovery._repo_name(expected_repo):
        raise CandidateReviewError("precontest_review_repo_mismatch")
    if value.get("official_repo_url") != f"https://github.com/flop-labs/{repo}":
        raise CandidateReviewError("precontest_review_repo_url_invalid")
    if value.get("official_api_url") != f"https://api.github.com/repos/flop-labs/{repo}":
        raise CandidateReviewError("precontest_review_api_url_invalid")
    _parse_time(value.get("first_seen_at"), label="first_seen")
    _parse_time(value.get("last_seen_at"), label="last_seen")
    _parse_time(value.get("generated_at"), label="generated_at")
    if value.get("pushed_at") is not None:
        _parse_time(value.get("pushed_at"), label="pushed_at")
    unknowns = value.get("unknown_rules")
    if not isinstance(unknowns, dict) or set(unknowns) != set(REQUIRED_UNKNOWN_FIELDS):
        raise CandidateReviewError("precontest_review_unknown_rules_invalid")
    for field in REQUIRED_UNKNOWN_FIELDS:
        row = unknowns.get(field)
        if row != {"status": "UNKNOWN", "value": None}:
            raise CandidateReviewError("precontest_review_rule_fabricated")
    event_ids = value.get("event_ids")
    if (
        not isinstance(event_ids, list)
        or not event_ids
        or len(set(event_ids)) != len(event_ids)
        or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{24}", item) for item in event_ids)
    ):
        raise CandidateReviewError("precontest_review_event_ids_invalid")
    return dict(value)


def _load_existing(repo_name: str) -> dict | None:
    path = packet_path(repo_name)
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise CandidateReviewError("precontest_review_packet_path_invalid")
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidateReviewError("precontest_review_packet_invalid") from error
    return validate_packet(value, expected_repo=repo_name)


def save_packet(candidate: dict, *, now: datetime | None = None) -> dict:
    repo = discovery._repo_name(candidate.get("repo_name"))
    # Existing packet integrity is checked before refresh. Corruption is never
    # silently repaired because that would hide readiness evidence tampering.
    _load_existing(repo)
    packet = build_packet(candidate, now=now)
    observer.atomic_json_write(packet_path(repo), packet, compact=True, mode=0o660)
    return packet


def ensure_for_unregistered(
    candidate_state: dict,
    *,
    now: datetime | None = None,
) -> list[dict]:
    current = discovery.validate_state(candidate_state)
    rows = discovery.unregistered_candidates(current)
    packets: list[dict] = []
    for row in rows:
        packet = save_packet(row, now=now)
        packets.append(
            {
                "repo_name": packet["repo_name"],
                "status": packet["status"],
                "packet_sha256": packet["packet_sha256"],
                "packet_path": str(packet_path(packet["repo_name"])),
            }
        )
    return packets
