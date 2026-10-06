"""Detect new official challenge repositories before a full challenge spec exists.

Candidates are derived only from the tamper-evident Radar Evidence Ledger's
before->after material events.  The initial Radar baseline is never treated as a
new campaign.  This module writes local readiness metadata only; it never
registers, signs, posts, claims, spends, submits, or mutates protocol state.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from . import airdrop_challenge, airdrop_ledger, observer

SCHEMA_VERSION = 1
STATE_NAME = "precontest-candidates.json"
OFFICIAL_GITHUB_ORG_URL = "https://api.github.com/orgs/flop-labs/repos"
REPO_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}")
CHALLENGE_RE = re.compile(r"challenge", re.IGNORECASE)
ALLOWED_EVENT_TYPES = {
    "NEW",
    "CHANGED",
    "REMOVED",
    "RECOVERED_SOURCE_FACT_NEW",
    "RECOVERED_SOURCE_FACT_CHANGED",
    "RECOVERED_SOURCE_FACT_REMOVED",
}


class CandidateDiscoveryError(RuntimeError):
    """Fail-closed challenge candidate state/evidence error."""


def state_path() -> Path:
    return airdrop_ledger.ledger_dir() / STATE_NAME


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: dict) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _parse_time(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise CandidateDiscoveryError(f"precontest_candidate_{label}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CandidateDiscoveryError(f"precontest_candidate_{label}_invalid") from error
    if parsed.tzinfo is None:
        raise CandidateDiscoveryError(f"precontest_candidate_{label}_invalid")
    return parsed.astimezone(UTC).isoformat()


def _repo_name(value: object) -> str:
    if not isinstance(value, str) or not REPO_RE.fullmatch(value):
        raise CandidateDiscoveryError("precontest_candidate_repo_invalid")
    return value


def _empty() -> dict:
    value = {
        "schema_version": SCHEMA_VERSION,
        "non_binding": True,
        "updated_at": None,
        "ledger_count": 0,
        "ledger_tip_hash": "",
        "candidates": {},
    }
    value["state_sha256"] = _digest(value)
    return value


def _validate_candidate(repo: str, row: object) -> dict:
    if not isinstance(row, dict):
        raise CandidateDiscoveryError("precontest_candidate_row_invalid")
    expected = {
        "repo_name",
        "first_seen_at",
        "last_seen_at",
        "listed_now",
        "default_branch",
        "pushed_at",
        "event_ids",
    }
    if set(row) != expected or row.get("repo_name") != repo:
        raise CandidateDiscoveryError("precontest_candidate_row_invalid")
    _repo_name(repo)
    first = _parse_time(row.get("first_seen_at"), label="first_seen")
    last = _parse_time(row.get("last_seen_at"), label="last_seen")
    if datetime.fromisoformat(last) < datetime.fromisoformat(first):
        raise CandidateDiscoveryError("precontest_candidate_time_order_invalid")
    if type(row.get("listed_now")) is not bool:
        raise CandidateDiscoveryError("precontest_candidate_listed_invalid")
    branch = row.get("default_branch")
    if branch is not None and (not isinstance(branch, str) or not branch or len(branch) > 200):
        raise CandidateDiscoveryError("precontest_candidate_branch_invalid")
    pushed = row.get("pushed_at")
    if pushed is not None:
        pushed = _parse_time(pushed, label="pushed_at")
    event_ids = row.get("event_ids")
    if (
        not isinstance(event_ids, list)
        or not event_ids
        or len(event_ids) > 256
        or len(set(event_ids)) != len(event_ids)
        or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{24}", item) for item in event_ids)
    ):
        raise CandidateDiscoveryError("precontest_candidate_event_ids_invalid")
    return {
        "repo_name": repo,
        "first_seen_at": first,
        "last_seen_at": last,
        "listed_now": row["listed_now"],
        "default_branch": branch,
        "pushed_at": pushed,
        "event_ids": list(event_ids),
    }


def validate_state(value: object) -> dict:
    if not isinstance(value, dict):
        raise CandidateDiscoveryError("precontest_candidate_state_invalid")
    expected = {
        "schema_version",
        "non_binding",
        "updated_at",
        "ledger_count",
        "ledger_tip_hash",
        "candidates",
        "state_sha256",
    }
    if set(value) != expected or value.get("schema_version") != SCHEMA_VERSION:
        raise CandidateDiscoveryError("precontest_candidate_state_schema_invalid")
    if value.get("non_binding") is not True:
        raise CandidateDiscoveryError("precontest_candidate_state_binding_invalid")
    digest = value.get("state_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise CandidateDiscoveryError("precontest_candidate_state_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("state_sha256")
    if _digest(unsigned) != digest:
        raise CandidateDiscoveryError("precontest_candidate_state_integrity_invalid")
    updated = value.get("updated_at")
    if updated is not None:
        updated = _parse_time(updated, label="updated_at")
    count = value.get("ledger_count")
    tip = value.get("ledger_tip_hash")
    if type(count) is not int or count < 0:
        raise CandidateDiscoveryError("precontest_candidate_ledger_count_invalid")
    if not isinstance(tip, str) or (tip and not re.fullmatch(r"[0-9a-f]{64}", tip)):
        raise CandidateDiscoveryError("precontest_candidate_ledger_tip_invalid")
    candidates = value.get("candidates")
    if not isinstance(candidates, dict) or len(candidates) > 256:
        raise CandidateDiscoveryError("precontest_candidate_rows_invalid")
    cleaned = {
        repo: _validate_candidate(_repo_name(repo), row)
        for repo, row in candidates.items()
    }
    result = {
        "schema_version": SCHEMA_VERSION,
        "non_binding": True,
        "updated_at": updated,
        "ledger_count": count,
        "ledger_tip_hash": tip,
        "candidates": dict(sorted(cleaned.items())),
        "state_sha256": digest,
    }
    return result


def load_state() -> dict:
    path = state_path()
    if not path.exists():
        return _empty()
    if path.is_symlink() or not path.is_file():
        raise CandidateDiscoveryError("precontest_candidate_state_path_invalid")
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidateDiscoveryError("precontest_candidate_state_invalid") from error
    return validate_state(value)


def _activity_rows(value: object) -> dict[str, dict]:
    if isinstance(value, dict) and "value" in value:
        value = value.get("value")
    if not isinstance(value, list):
        return {}
    result: dict[str, dict] = {}
    for item in value:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not REPO_RE.fullmatch(name) or not CHALLENGE_RE.search(name):
            continue
        result[name] = {
            "name": name,
            "archived": bool(item.get("archived")),
            "default_branch": item.get("default_branch") if isinstance(item.get("default_branch"), str) else None,
            "pushed_at": item.get("pushed_at") if isinstance(item.get("pushed_at"), str) else None,
        }
    return result


def _official_github_evidence(record: dict) -> bool:
    rows = record.get("source_evidence")
    if not isinstance(rows, list):
        return False
    for row in rows:
        if not isinstance(row, dict) or row.get("name") != "github_org":
            continue
        url = row.get("url") or row.get("final_url")
        if isinstance(url, str) and url.startswith(OFFICIAL_GITHUB_ORG_URL):
            return True
    return False


def _candidate_event(record: dict) -> tuple[dict[str, dict], dict[str, dict]] | None:
    event = record.get("event")
    if not isinstance(event, dict):
        return None
    if event.get("key") != "github_critical_repo_activity":
        return None
    if event.get("type") not in ALLOWED_EVENT_TYPES or not _official_github_evidence(record):
        return None
    return _activity_rows(event.get("before")), _activity_rows(event.get("after"))


def _event_time(record: dict) -> str:
    return _parse_time(record.get("observed_at") or record.get("first_seen"), label="event_time")


def _repo_from_rules_url(url: object) -> str | None:
    if not isinstance(url, str):
        return None
    parsed = urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.hostname == "raw.githubusercontent.com":
        if len(parts) >= 3 and parts[0] == "flop-labs" and REPO_RE.fullmatch(parts[1]):
            return parts[1]
    if parsed.hostname == "api.github.com":
        if len(parts) >= 3 and parts[0] == "repos" and parts[1] == "flop-labs" and REPO_RE.fullmatch(parts[2]):
            return parts[2]
    return None


def registered_repo_names() -> set[str]:
    root = airdrop_ledger.ledger_dir() / "challenges"
    if not root.exists():
        return set()
    if root.is_symlink() or not root.is_dir():
        raise CandidateDiscoveryError("precontest_candidate_challenge_root_invalid")
    registered: set[str] = set()
    for directory in sorted(root.iterdir(), key=lambda item: item.name):
        if directory.is_symlink() or not directory.is_dir():
            continue
        spec_path = directory / "spec.json"
        if not spec_path.exists():
            continue
        if spec_path.is_symlink() or not spec_path.is_file():
            raise CandidateDiscoveryError("precontest_candidate_spec_path_invalid")
        try:
            raw = json.loads(spec_path.read_text("utf-8"))
            spec = airdrop_challenge.validate_spec(raw)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise CandidateDiscoveryError("precontest_candidate_spec_invalid") from error
        source = spec.get("source", {})
        repo = _repo_from_rules_url(source.get("rules_url"))
        if repo:
            registered.add(repo)
            continue
        if source.get("authority_type") == "flop_labs_github":
            authority_id = source.get("authority_id")
            if isinstance(authority_id, str) and authority_id.startswith("flop-labs/"):
                candidate = authority_id.split("/", 1)[1]
                if REPO_RE.fullmatch(candidate):
                    registered.add(candidate)
    return registered


def refresh_from_ledger(*, now: datetime | None = None) -> dict:
    # Validate any prior state before replacing it. Corruption is a readiness
    # blocker, never silently healed over.
    load_state()
    try:
        verified = airdrop_ledger.verify_ledger()
    except airdrop_ledger.LedgerIntegrityError as error:
        raise CandidateDiscoveryError("precontest_candidate_ledger_invalid") from error

    candidates: dict[str, dict] = {}
    for record in verified.get("records", []):
        if not isinstance(record, dict):
            raise CandidateDiscoveryError("precontest_candidate_ledger_record_invalid")
        parsed = _candidate_event(record)
        if parsed is None:
            continue
        before, after = parsed
        event_id = record.get("event_id")
        if not isinstance(event_id, str) or not re.fullmatch(r"[0-9a-f]{24}", event_id):
            raise CandidateDiscoveryError("precontest_candidate_event_id_invalid")
        observed = _event_time(record)

        # Existing tracked candidates follow the current official list.
        for repo, row in list(candidates.items()):
            if repo in before and repo not in after:
                row["listed_now"] = False
                row["last_seen_at"] = observed
                if event_id not in row["event_ids"]:
                    row["event_ids"].append(event_id)

        for repo, meta in after.items():
            if meta["archived"]:
                if repo in candidates:
                    candidates[repo]["listed_now"] = False
                    candidates[repo]["last_seen_at"] = observed
                continue

            existed_before = repo in before
            row = candidates.get(repo)
            # Crucial baseline guard: an already-present repository does not
            # become a candidate merely because another field changed.
            if row is None and existed_before:
                continue
            if row is None:
                row = {
                    "repo_name": repo,
                    "first_seen_at": observed,
                    "last_seen_at": observed,
                    "listed_now": True,
                    "default_branch": meta["default_branch"],
                    "pushed_at": meta["pushed_at"],
                    "event_ids": [event_id],
                }
                candidates[repo] = row
            else:
                row["last_seen_at"] = observed
                row["listed_now"] = True
                row["default_branch"] = meta["default_branch"]
                row["pushed_at"] = meta["pushed_at"]
                if event_id not in row["event_ids"]:
                    row["event_ids"].append(event_id)

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_candidate_now_timezone_required")
    value = {
        "schema_version": SCHEMA_VERSION,
        "non_binding": True,
        "updated_at": current.astimezone(UTC).isoformat(),
        "ledger_count": int(verified.get("count", 0)),
        "ledger_tip_hash": str(verified.get("tip_hash") or ""),
        "candidates": dict(sorted(candidates.items())),
    }
    value["state_sha256"] = _digest(value)
    cleaned = validate_state(value)
    observer.atomic_json_write(state_path(), cleaned, compact=True, mode=0o660)
    return cleaned


def unregistered_candidates(state: dict | None = None) -> list[dict]:
    current = validate_state(state) if state is not None else load_state()
    registered = registered_repo_names()
    return [
        {**row, "registered": False}
        for repo, row in sorted(current["candidates"].items())
        if row["listed_now"] and repo not in registered
    ]
