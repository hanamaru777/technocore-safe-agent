"""Deadline-safe, non-binding FLOP challenge planner.

This module prepares and audits challenge execution plans. It can perform bounded
read-only GETs to pin official public artifacts, but it never signs, posts,
registers, joins, submits, spends, claims, or changes Production state.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx

from . import airdrop_ledger

SCHEMA_VERSION = 1
MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
CHALLENGE_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
REQUEST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
SAFE_ARTIFACT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
ALLOWED_HOSTS = {
    "flop.finance",
    "www.flop.finance",
    "raw.githubusercontent.com",
    "api.github.com",
}
REQUEST_STATES = {
    "planned",
    "sent",
    "accepted",
    "rejected",
    "ambiguous",
    "reconciled_accepted",
    "reconciled_not_found",
}
AMBIGUOUS_BLOCKING = {"ambiguous"}


def _root() -> Path:
    return airdrop_ledger.ledger_dir() / "challenges"


def _challenge_dir(challenge_id: str) -> Path:
    return _root() / validate_challenge_id(challenge_id)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _utc(value: datetime | None = None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("challenge_timestamp_timezone_required")
    return current.astimezone(UTC).isoformat()


def _parse_time(value: object, *, required: bool = True) -> datetime | None:
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise ValueError("challenge_exact_timestamp_required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("challenge_exact_timestamp_required") from error
    if parsed.tzinfo is None:
        raise ValueError("challenge_exact_timestamp_required")
    return parsed.astimezone(UTC)


def _atomic_json_write(path: Path, value: dict) -> None:
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
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    finally:
        if os.path.exists(handle.name):
            os.unlink(handle.name)


def _atomic_bytes_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "wb",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    try:
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    finally:
        if os.path.exists(handle.name):
            os.unlink(handle.name)


def _read_json(path: Path, *, default: dict | None = None) -> dict:
    if not path.exists():
        if default is None:
            raise RuntimeError(f"challenge_state_missing:{path.name}")
        return default
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"challenge_state_corrupt:{path.name}") from error
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError(f"challenge_schema_mismatch:{path.name}")
    return value


def validate_challenge_id(value: str) -> str:
    if not isinstance(value, str) or not CHALLENGE_ID_RE.fullmatch(value):
        raise ValueError("challenge_id_invalid")
    return value


def _validate_public_url(url: str) -> str:
    if not isinstance(url, str):
        raise ValueError("challenge_official_url_invalid")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("challenge_official_url_invalid")
    if parsed.hostname == "raw.githubusercontent.com":
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) < 4 or parts[0] != "flop-labs":
            raise ValueError("challenge_untrusted_github_owner")
    if parsed.hostname == "api.github.com":
        if not parsed.path.startswith("/repos/flop-labs/"):
            raise ValueError("challenge_untrusted_github_owner")
    return url


def _immutable_official_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.hostname != "raw.githubusercontent.com":
        return False
    parts = [part for part in parsed.path.split("/") if part]
    return (
        len(parts) >= 4
        and parts[0] == "flop-labs"
        and bool(re.fullmatch(r"[0-9a-f]{40}", parts[2]))
    )


def _bounded_json_object(value: object, *, label: str, limit: int = 20_000) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"challenge_{label}_invalid")
    try:
        encoded = _canonical(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"challenge_{label}_invalid") from error
    if len(encoded.encode("utf-8")) > limit:
        raise ValueError(f"challenge_{label}_too_large")
    return value


def _validate_artifact_name(name: str) -> str:
    if (
        not isinstance(name, str)
        or not SAFE_ARTIFACT_RE.fullmatch(name)
        or name.startswith("/")
        or ".." in Path(name).parts
    ):
        raise ValueError("challenge_artifact_name_invalid")
    return name


def _spec_path(challenge_id: str) -> Path:
    return _challenge_dir(challenge_id) / "spec.json"


def _progress_path(challenge_id: str) -> Path:
    return _challenge_dir(challenge_id) / "progress.json"


def _request_path(challenge_id: str) -> Path:
    return _challenge_dir(challenge_id) / "requests.json"


def _artifact_index_path(challenge_id: str) -> Path:
    return _challenge_dir(challenge_id) / "artifacts.json"


def _default_progress() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "updated_at": None,
        "rules_authority_pinned": False,
        "identity_proven": False,
        "registration_proven": False,
        "submission_path_proven": False,
        "rehearsal_passed": False,
        "execution_path_audited": False,
        "primary_route": None,
        "alternate_routes": [],
        "collaborators": {},
    }


def _default_requests() -> dict:
    return {"schema_version": SCHEMA_VERSION, "requests": {}}


def _default_artifacts() -> dict:
    return {"schema_version": SCHEMA_VERSION, "artifacts": {}}


def validate_spec(spec: dict) -> dict:
    if not isinstance(spec, dict):
        raise ValueError("challenge_spec_invalid")
    challenge_id = validate_challenge_id(str(spec.get("challenge_id", "")))
    deadline = _parse_time(spec.get("deadline"), required=True)
    opening = _parse_time(spec.get("opening"), required=False)
    if opening and deadline <= opening:
        raise ValueError("challenge_deadline_not_after_opening")

    source = spec.get("source")
    if not isinstance(source, dict):
        raise ValueError("challenge_source_missing")
    rules_url = _validate_public_url(str(source.get("rules_url", "")))
    authority_type = source.get("authority_type")
    if authority_type not in {"flop_site", "flop_labs_github", "signed_launch"}:
        raise ValueError("challenge_authority_type_invalid")

    pinned_commit = source.get("pinned_commit")
    if pinned_commit is not None and (
        not isinstance(pinned_commit, str)
        or not re.fullmatch(r"[0-9a-f]{40}", pinned_commit)
    ):
        raise ValueError("challenge_pinned_commit_invalid")

    authority_id = source.get("authority_id")
    if authority_id is not None and (
        not isinstance(authority_id, str) or len(authority_id) > 300
    ):
        raise ValueError("challenge_authority_id_invalid")
    source_sha256 = source.get("source_sha256")
    if source_sha256 is not None and (
        not isinstance(source_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", source_sha256)
    ):
        raise ValueError("challenge_source_sha_invalid")

    submission = _bounded_json_object(
        spec.get("submission"),
        label="submission",
    )
    submission_path = submission.get("path")
    if submission_path is not None and (
        not isinstance(submission_path, str) or len(submission_path) > 1000
    ):
        raise ValueError("challenge_submission_path_invalid")

    eligibility = _bounded_json_object(
        spec.get("eligibility"),
        label="eligibility",
    )

    artifacts = spec.get("required_artifacts", [])
    if not isinstance(artifacts, list):
        raise ValueError("challenge_artifacts_invalid")
    cleaned_artifacts: list[dict] = []
    for row in artifacts:
        if not isinstance(row, dict):
            raise ValueError("challenge_artifact_invalid")
        name = _validate_artifact_name(str(row.get("name", "")))
        url = _validate_public_url(str(row.get("url", "")))
        expected = row.get("sha256")
        if expected is not None and (
            not isinstance(expected, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected)
        ):
            raise ValueError("challenge_artifact_sha_invalid")
        cleaned_artifacts.append(
            {
                "name": name,
                "url": url,
                "sha256": expected,
                "required": bool(row.get("required", True)),
                "kind": str(row.get("kind", "artifact"))[:80],
            }
        )

    prize = spec.get("prize")
    if prize is not None:
        if not isinstance(prize, dict):
            raise ValueError("challenge_prize_invalid")
        amount = prize.get("amount")
        unit = prize.get("unit")
        if amount is not None and (
            not isinstance(amount, (int, float)) or amount < 0
        ):
            raise ValueError("challenge_prize_invalid")
        if unit is not None and (not isinstance(unit, str) or len(unit) > 40):
            raise ValueError("challenge_prize_invalid")

    cleaned = {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "opening": opening.isoformat() if opening else None,
        "deadline": deadline.isoformat(),
        "prize": prize,
        "eligibility": eligibility,
        "submission": submission,
        "collaboration_required": bool(spec.get("collaboration_required", False)),
        "registration_required": bool(spec.get("registration_required", False)),
        "source": {
            "rules_url": rules_url,
            "authority_type": authority_type,
            "authority_id": authority_id,
            "pinned_commit": pinned_commit,
            "source_sha256": source_sha256,
        },
        "required_artifacts": cleaned_artifacts,
        "notes": [
            str(item)[:500]
            for item in spec.get("notes", [])
            if isinstance(item, str)
        ][:50],
    }
    return cleaned


def create_challenge(spec: dict, *, now: datetime | None = None) -> dict:
    cleaned = validate_spec(spec)
    challenge_id = cleaned["challenge_id"]
    directory = _challenge_dir(challenge_id)
    directory.mkdir(parents=True, exist_ok=True)
    if _spec_path(challenge_id).exists():
        existing = _read_json(_spec_path(challenge_id))
        if _canonical(existing) != _canonical(cleaned):
            raise RuntimeError("challenge_spec_already_exists_with_different_content")
        return existing
    _atomic_json_write(_spec_path(challenge_id), cleaned)
    progress = _default_progress()
    progress["updated_at"] = _utc(now)
    _atomic_json_write(_progress_path(challenge_id), progress)
    _atomic_json_write(_request_path(challenge_id), _default_requests())
    _atomic_json_write(_artifact_index_path(challenge_id), _default_artifacts())
    return cleaned


def load_spec(challenge_id: str) -> dict:
    return _read_json(_spec_path(validate_challenge_id(challenge_id)))


def load_progress(challenge_id: str) -> dict:
    return _read_json(
        _progress_path(validate_challenge_id(challenge_id)),
        default=_default_progress(),
    )


def update_progress(
    challenge_id: str,
    patch: dict,
    *,
    now: datetime | None = None,
) -> dict:
    challenge_id = validate_challenge_id(challenge_id)
    allowed = {
        "rules_authority_pinned",
        "identity_proven",
        "registration_proven",
        "submission_path_proven",
        "rehearsal_passed",
        "execution_path_audited",
        "primary_route",
        "alternate_routes",
        "collaborators",
    }
    if not isinstance(patch, dict) or any(key not in allowed for key in patch):
        raise ValueError("challenge_progress_patch_invalid")
    progress = load_progress(challenge_id)
    for key, value in patch.items():
        if key in {
            "rules_authority_pinned",
            "identity_proven",
            "registration_proven",
            "submission_path_proven",
            "rehearsal_passed",
            "execution_path_audited",
        } and not isinstance(value, bool):
            raise ValueError("challenge_progress_boolean_invalid")
        if key == "primary_route" and value is not None and not isinstance(value, str):
            raise ValueError("challenge_primary_route_invalid")
        if key == "alternate_routes" and (
            not isinstance(value, list)
            or not all(isinstance(item, str) for item in value)
        ):
            raise ValueError("challenge_alternate_routes_invalid")
        if key == "collaborators" and not isinstance(value, dict):
            raise ValueError("challenge_collaborators_invalid")
        progress[key] = value
    progress["updated_at"] = _utc(now)
    _atomic_json_write(_progress_path(challenge_id), progress)
    return progress


def _artifact_index(challenge_id: str) -> dict:
    value = _read_json(
        _artifact_index_path(validate_challenge_id(challenge_id)),
        default=_default_artifacts(),
    )
    if not isinstance(value.get("artifacts"), dict):
        raise RuntimeError("challenge_artifact_index_invalid")
    return value


def pin_artifact_bytes(
    challenge_id: str,
    *,
    name: str,
    source_url: str,
    data: bytes,
    expected_sha256: str | None = None,
    now: datetime | None = None,
) -> dict:
    challenge_id = validate_challenge_id(challenge_id)
    name = _validate_artifact_name(name)
    source_url = _validate_public_url(source_url)
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("challenge_artifact_bytes_invalid")
    data = bytes(data)
    if len(data) > MAX_ARTIFACT_BYTES:
        raise RuntimeError("challenge_artifact_too_large")
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ValueError("challenge_artifact_sha_invalid")
        if digest != expected_sha256:
            raise RuntimeError("challenge_artifact_hash_mismatch")

    target = _challenge_dir(challenge_id) / "artifacts" / name
    _atomic_bytes_write(target, data)
    index = _artifact_index(challenge_id)
    index["artifacts"][name] = {
        "name": name,
        "source_url": source_url,
        "sha256": digest,
        "bytes": len(data),
        "pinned_at": _utc(now),
        "relative_path": str(Path("artifacts") / name).replace("\\", "/"),
    }
    _atomic_json_write(_artifact_index_path(challenge_id), index)
    return index["artifacts"][name]


def _read_official_bytes(url: str) -> bytes:
    _validate_public_url(url)
    with httpx.stream(
        "GET",
        url,
        follow_redirects=True,
        timeout=20,
        headers={"User-Agent": "technocore-safe-agent-challenge-runner/1"},
    ) as response:
        response.raise_for_status()
        _validate_public_url(str(response.url))
        length = response.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_ARTIFACT_BYTES:
            raise RuntimeError("challenge_artifact_too_large")
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > MAX_ARTIFACT_BYTES:
                raise RuntimeError("challenge_artifact_too_large")
            chunks.append(chunk)
        return b"".join(chunks)


def fetch_and_pin_artifact(
    challenge_id: str,
    *,
    name: str,
    source_url: str,
    expected_sha256: str | None = None,
    now: datetime | None = None,
) -> dict:
    data = _read_official_bytes(source_url)
    return pin_artifact_bytes(
        challenge_id,
        name=name,
        source_url=source_url,
        data=data,
        expected_sha256=expected_sha256,
        now=now,
    )


def verify_artifacts(challenge_id: str) -> dict:
    challenge_id = validate_challenge_id(challenge_id)
    spec = load_spec(challenge_id)
    index = _artifact_index(challenge_id)
    rows: list[dict] = []
    all_required_ok = True
    for required in spec.get("required_artifacts", []):
        name = required["name"]
        pinned = index["artifacts"].get(name)
        ok = False
        reason = "missing"
        if isinstance(pinned, dict):
            path = _challenge_dir(challenge_id) / pinned["relative_path"]
            if path.is_file():
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
                declared = required.get("sha256")
                anchored = bool(declared) or _immutable_official_url(
                    str(required.get("url", ""))
                )
                ok = (
                    anchored
                    and actual == pinned.get("sha256")
                    and (declared is None or actual == declared)
                )
                if not anchored:
                    reason = "unanchored_expected_hash_missing"
                else:
                    reason = "ok" if ok else "hash_mismatch"
        if required.get("required", True) and not ok:
            all_required_ok = False
        rows.append(
            {
                "name": name,
                "required": required.get("required", True),
                "ok": ok,
                "reason": reason,
            }
        )
    return {
        "challenge_id": challenge_id,
        "all_required_ok": all_required_ok,
        "artifacts": rows,
    }


def _seconds_remaining(spec: dict, now: datetime) -> int:
    deadline = _parse_time(spec["deadline"])
    assert deadline is not None
    return int((deadline - now.astimezone(UTC)).total_seconds())


def deadline_gate(spec: dict, *, now: datetime | None = None) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("challenge_timestamp_timezone_required")
    seconds = _seconds_remaining(spec, current)
    if seconds < 0:
        gate = "EXPIRED"
    elif seconds <= 600:
        gate = "T-10m"
    elif seconds <= 1800:
        gate = "T-30m"
    elif seconds <= 7200:
        gate = "T-2h"
    elif seconds <= 21600:
        gate = "T-6h"
    elif seconds <= 43200:
        gate = "T-12h"
    elif seconds <= 86400:
        gate = "T-24h"
    else:
        gate = "EARLY"
    return {"gate": gate, "seconds_remaining": seconds}


def _collaborator(progress: dict, route: str | None) -> dict | None:
    if not route:
        return None
    row = progress.get("collaborators", {}).get(route)
    return row if isinstance(row, dict) else None


def _binding_ready(row: dict | None) -> bool:
    return bool(
        row
        and row.get("target_authored_binding") is True
        and row.get("current_conflict") is not True
    )


def _responsive_ready(row: dict | None) -> bool:
    return bool(_binding_ready(row) and row.get("responsive_proof") is True)


def _collaboration_status(spec: dict, progress: dict, gate: str) -> dict:
    if not spec.get("collaboration_required"):
        return {
            "required": False,
            "primary_ready": True,
            "alternates_ready": 0,
            "route_failures": [],
        }
    primary = progress.get("primary_route")
    alternates = [
        item for item in progress.get("alternate_routes", []) if isinstance(item, str)
    ]
    primary_row = _collaborator(progress, primary)
    alternate_rows = [_collaborator(progress, item) for item in alternates]

    binding_required = gate in {"T-12h", "T-6h", "T-2h", "T-30m", "T-10m"}
    responsive_required = gate in {"T-2h", "T-30m", "T-10m"}
    if responsive_required:
        primary_ready = _responsive_ready(primary_row)
        alternates_ready = sum(_responsive_ready(row) for row in alternate_rows)
    elif binding_required:
        primary_ready = _binding_ready(primary_row)
        alternates_ready = sum(_binding_ready(row) for row in alternate_rows)
    else:
        primary_ready = primary is not None
        alternates_ready = len([row for row in alternate_rows if row])

    failures: list[str] = []
    routes_enforced = gate in {"T-12h", "T-6h", "T-2h", "T-30m", "T-10m"}
    if routes_enforced:
        if not primary:
            failures.append("primary_route_missing")
        elif binding_required and not _binding_ready(primary_row):
            failures.append("primary_not_binding_ready")
        elif responsive_required and not _responsive_ready(primary_row):
            failures.append("primary_not_proven_responsive")

        if alternates_ready < 2:
            failures.append("fewer_than_two_ready_alternates")

    return {
        "required": True,
        "primary_route": primary,
        "primary_ready": primary_ready,
        "alternates": alternates,
        "alternates_ready": alternates_ready,
        "route_failures": failures,
    }


def _mandatory_steps(spec: dict, progress: dict, gate: str, artifacts: dict) -> list[dict]:
    steps = [
        {
            "id": "rules_authority_pinned",
            "required": True,
            "complete": progress.get("rules_authority_pinned") is True,
        },
        {
            "id": "required_artifacts_verified",
            "required": bool(spec.get("required_artifacts")),
            "complete": artifacts["all_required_ok"],
        },
        {
            "id": "submission_path_proven",
            "required": gate != "EARLY",
            "complete": progress.get("submission_path_proven") is True,
        },
        {
            "id": "identity_proven",
            "required": gate in {
                "T-24h",
                "T-12h",
                "T-6h",
                "T-2h",
                "T-30m",
                "T-10m",
            },
            "complete": progress.get("identity_proven") is True,
        },
        {
            "id": "registration_proven",
            "required": bool(spec.get("registration_required"))
            and gate
            in {"T-24h", "T-12h", "T-6h", "T-2h", "T-30m", "T-10m"},
            "complete": progress.get("registration_proven") is True,
        },
        {
            "id": "rehearsal_passed",
            "required": gate in {"T-2h", "T-30m", "T-10m"},
            "complete": progress.get("rehearsal_passed") is True,
        },
        {
            "id": "execution_path_audited",
            "required": gate in {"T-30m", "T-10m"},
            "complete": progress.get("execution_path_audited") is True,
        },
    ]
    return steps


def _work_policy(gate: str) -> dict:
    if gate == "EXPIRED":
        return {
            "new_code": False,
            "ci_wait": False,
            "nonbinding_coordination": False,
            "execution_only": False,
            "participant_actions_open": False,
        }
    if gate == "T-10m":
        return {
            "new_code": False,
            "ci_wait": False,
            "nonbinding_coordination": False,
            "execution_only": True,
            "participant_actions_open": True,
        }
    if gate == "T-30m":
        return {
            "new_code": False,
            "ci_wait": False,
            "nonbinding_coordination": "only_if_directly_unblocks_binding",
            "execution_only": True,
            "participant_actions_open": True,
        }
    if gate == "T-2h":
        return {
            "new_code": False,
            "ci_wait": False,
            "nonbinding_coordination": False,
            "execution_only": True,
            "participant_actions_open": True,
        }
    if gate == "T-6h":
        return {
            "new_code": "targeted_only",
            "ci_wait": "targeted_only",
            "nonbinding_coordination": "replace_unbound_primary",
            "execution_only": False,
            "participant_actions_open": True,
        }
    return {
        "new_code": True,
        "ci_wait": True,
        "nonbinding_coordination": True,
        "execution_only": False,
        "participant_actions_open": True,
    }


def build_plan(challenge_id: str, *, now: datetime | None = None) -> dict:
    challenge_id = validate_challenge_id(challenge_id)
    spec = load_spec(challenge_id)
    progress = load_progress(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("challenge_timestamp_timezone_required")
    gate = deadline_gate(spec, now=current)
    artifacts = verify_artifacts(challenge_id)
    collaboration = _collaboration_status(spec, progress, gate["gate"])
    steps = _mandatory_steps(spec, progress, gate["gate"], artifacts)
    blockers = [
        row["id"]
        for row in steps
        if row["required"] and not row["complete"]
    ]
    blockers.extend(collaboration["route_failures"])
    if gate["gate"] == "EXPIRED":
        blockers.append("deadline_expired")

    requests = _read_json(
        _request_path(challenge_id),
        default=_default_requests(),
    )
    ambiguous = [
        request_id
        for request_id, row in requests.get("requests", {}).items()
        if isinstance(row, dict) and row.get("status") in AMBIGUOUS_BLOCKING
    ]
    if ambiguous:
        blockers.append("ambiguous_request_reconcile_required")

    policy = _work_policy(gate["gate"])
    critical_path = []
    for blocker in blockers:
        if blocker not in critical_path:
            critical_path.append(blocker)

    return {
        "schema_version": SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "non_binding": True,
        "generated_at": _utc(current),
        "opening": spec.get("opening"),
        "deadline": spec["deadline"],
        "deadline_gate": gate,
        "prize": spec.get("prize"),
        "eligibility": spec.get("eligibility"),
        "submission": spec.get("submission"),
        "authority": spec.get("source"),
        "artifact_status": artifacts,
        "collaboration": collaboration,
        "mandatory_steps": steps,
        "ambiguous_request_ids": ambiguous,
        "critical_path": critical_path,
        "estimated_remaining_steps": len(critical_path),
        "work_policy": policy,
        "ready_for_execution_path": (
            not critical_path
            and gate["gate"] != "EXPIRED"
        ),
        "authorization_required_for": [
            "registration",
            "joining_or_roster_consent",
            "signed_protocol_write",
            "X_post",
            "submission",
            "claim",
            "value_transfer",
        ],
        "warnings": [
            "This planner never grants authorization for a binding action.",
            "Generic availability or recruitment text is not binding proof.",
            "An ambiguous write must be reconciled before any replacement request.",
        ],
    }


def plan_request(
    challenge_id: str,
    *,
    action: str,
    request_id: str,
    payload: dict,
    now: datetime | None = None,
) -> dict:
    challenge_id = validate_challenge_id(challenge_id)
    if not isinstance(action, str) or not action or len(action) > 100:
        raise ValueError("challenge_request_action_invalid")
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise ValueError("challenge_request_id_invalid")
    if not isinstance(payload, dict):
        raise ValueError("challenge_request_payload_invalid")

    state = _read_json(
        _request_path(challenge_id),
        default=_default_requests(),
    )
    requests = state.setdefault("requests", {})
    if not isinstance(requests, dict):
        raise RuntimeError("challenge_request_state_invalid")

    payload_sha = _sha(payload)
    existing = requests.get(request_id)
    if isinstance(existing, dict):
        if (
            existing.get("action") == action
            and existing.get("payload_sha256") == payload_sha
        ):
            return existing
        raise RuntimeError("challenge_request_id_reuse_with_different_payload")

    if any(
        isinstance(row, dict) and row.get("status") in AMBIGUOUS_BLOCKING
        for row in requests.values()
    ):
        raise RuntimeError("challenge_ambiguous_request_reconcile_first")

    row = {
        "request_id": request_id,
        "action": action,
        "payload_sha256": payload_sha,
        "status": "planned",
        "planned_at": _utc(now),
        "updated_at": _utc(now),
        "receipt_hash": None,
    }
    requests[request_id] = row
    _atomic_json_write(_request_path(challenge_id), state)
    return row


def mark_request(
    challenge_id: str,
    *,
    request_id: str,
    status: str,
    receipt_hash: str | None = None,
    now: datetime | None = None,
) -> dict:
    challenge_id = validate_challenge_id(challenge_id)
    if status not in REQUEST_STATES - {"planned"}:
        raise ValueError("challenge_request_status_invalid")
    state = _read_json(
        _request_path(challenge_id),
        default=_default_requests(),
    )
    row = state.get("requests", {}).get(request_id)
    if not isinstance(row, dict):
        raise RuntimeError("challenge_request_not_found")
    current = row.get("status")
    allowed = {
        "planned": {"sent", "accepted", "rejected", "ambiguous"},
        "sent": {"accepted", "rejected", "ambiguous"},
        "ambiguous": {"reconciled_accepted", "reconciled_not_found"},
        "reconciled_not_found": set(),
        "accepted": set(),
        "rejected": set(),
        "reconciled_accepted": set(),
    }
    if status not in allowed.get(str(current), set()):
        raise RuntimeError("challenge_request_transition_invalid")
    if receipt_hash is not None and not re.fullmatch(r"[0-9a-f]{64}", receipt_hash):
        raise ValueError("challenge_receipt_hash_invalid")
    row["status"] = status
    row["updated_at"] = _utc(now)
    if receipt_hash is not None:
        row["receipt_hash"] = receipt_hash
    _atomic_json_write(_request_path(challenge_id), state)
    return row


def request_status(challenge_id: str) -> dict:
    challenge_id = validate_challenge_id(challenge_id)
    state = _read_json(
        _request_path(challenge_id),
        default=_default_requests(),
    )
    requests = state.get("requests", {})
    ambiguous = [
        request_id
        for request_id, row in requests.items()
        if isinstance(row, dict) and row.get("status") == "ambiguous"
    ]
    return {
        "challenge_id": challenge_id,
        "requests": requests,
        "ambiguous_request_ids": ambiguous,
        "blind_retry_allowed": False if ambiguous else None,
    }
