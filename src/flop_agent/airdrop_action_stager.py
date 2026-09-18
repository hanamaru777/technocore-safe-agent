"""Fail-closed bridge from trusted Radar evidence to exact Action Inbox requests.

This module does not execute any external action. It persists an exact, secret-free
candidate payload and asks airdrop_approval to create a local approval request whose
payload digest matches that candidate. Future executors must re-verify both stores.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from . import airdrop_approval, airdrop_ledger, core

SCHEMA_VERSION = 1
STORE_NAME = "action-candidates.json"
LOCK_NAME = "action-candidates.lock"
MAX_CANDIDATES = 256
MAX_PAYLOAD_BYTES = 16_384
MAX_EXPIRY = timedelta(days=7)
AUTO_STAGE_KEYS = {
    "faucet": "faucet_status",
    "registration": "registration_status",
    "claim": "claim_status",
}
OPEN_VALUES = frozenset({"open", "live", "enabled"})
TRUSTED_AUTHORITIES = frozenset({"normative", "official"})
FORBIDDEN_KEY_RE = re.compile(
    r"(?:secret|private[_-]?key|seed|mnemonic|password|authorization|cookie|"
    r"signing[_-]?key|bearer|signature|signed[_-]?tx|raw[_-]?transaction)",
    re.IGNORECASE,
)
HEX24 = re.compile(r"^[0-9a-f]{24}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class StagingBridgeError(RuntimeError):
    """Stable fail-closed Staging Bridge error."""


def bridge_dir() -> Path:
    return core.STATE / "airdrop-radar"


def store_path() -> Path:
    return bridge_dir() / STORE_NAME


@contextmanager
def _store_lock():
    directory = bridge_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / LOCK_NAME
        with path.open("a+", encoding="utf-8") as handle:
            os.chmod(path, 0o640)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError as error:
        raise StagingBridgeError("airdrop_stager_lock_failed") from error


def _canonical(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise StagingBridgeError("airdrop_stager_payload_not_canonical_json") from error


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise StagingBridgeError("airdrop_stager_timestamp_invalid") from error
    if parsed.tzinfo is None:
        raise StagingBridgeError("airdrop_stager_timestamp_timezone_required")
    return parsed.astimezone(UTC)


def _validate_payload_node(value: object, *, depth: int = 0) -> None:
    if depth > 8:
        raise StagingBridgeError("airdrop_stager_payload_too_deep")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        raise StagingBridgeError("airdrop_stager_payload_float_forbidden")
    if isinstance(value, str):
        if len(value) > 4_000:
            raise StagingBridgeError("airdrop_stager_payload_string_too_long")
        return
    if isinstance(value, list):
        if len(value) > 128:
            raise StagingBridgeError("airdrop_stager_payload_list_too_large")
        for item in value:
            _validate_payload_node(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 128:
            raise StagingBridgeError("airdrop_stager_payload_object_too_large")
        for key, item in value.items():
            if not isinstance(key, str) or not 1 <= len(key) <= 120:
                raise StagingBridgeError("airdrop_stager_payload_key_invalid")
            if FORBIDDEN_KEY_RE.search(key):
                raise StagingBridgeError("airdrop_stager_payload_secret_like_key")
            if key.lower() in {"url", "endpoint", "action_url"} and isinstance(item, str):
                parsed = urlparse(item)
                host = (parsed.hostname or "").lower()
                if parsed.scheme != "https" or not (
                    host == "flop.finance" or host.endswith(".flop.finance")
                ):
                    raise StagingBridgeError("airdrop_stager_payload_url_not_allowlisted")
            _validate_payload_node(item, depth=depth + 1)
        return
    raise StagingBridgeError("airdrop_stager_payload_type_invalid")


def _payload_digest(payload: dict) -> str:
    if not isinstance(payload, dict) or not payload:
        raise StagingBridgeError("airdrop_stager_payload_invalid")
    _validate_payload_node(payload)
    rendered = _canonical(payload).encode("utf-8")
    if len(rendered) > MAX_PAYLOAD_BYTES:
        raise StagingBridgeError("airdrop_stager_payload_too_large")
    return hashlib.sha256(rendered).hexdigest()


def _default_store() -> dict:
    return {"schema_version": SCHEMA_VERSION, "candidates": {}}


def _atomic_write(value: dict) -> None:
    path = store_path()
    handle = None
    try:
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
        with handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(handle.name, 0o640)
        os.replace(handle.name, path)
    except OSError as error:
        raise StagingBridgeError("airdrop_stager_store_write_failed") from error
    finally:
        if handle is not None and os.path.exists(handle.name):
            try:
                os.unlink(handle.name)
            except OSError:
                pass


def _candidate_id(
    source_event_id: str,
    action_class: str,
    payload_sha256: str,
    expires_at: str,
) -> str:
    return hashlib.sha256(
        _canonical(
            {
                "source_event_id": source_event_id,
                "action_class": action_class,
                "payload_sha256": payload_sha256,
                "expires_at": expires_at,
            }
        ).encode("utf-8")
    ).hexdigest()[:32]


def _validate_stored(candidate_id: str, row: object) -> dict:
    required = {
        "candidate_id",
        "source_event_id",
        "source_ledger_hash",
        "action_class",
        "payload",
        "payload_sha256",
        "summary",
        "cost_note",
        "reversible",
        "expires_at",
        "created_at",
        "request_id",
        "approval_digest",
    }
    if not isinstance(row, dict) or set(row) != required:
        raise StagingBridgeError("airdrop_stager_stored_candidate_invalid")
    if row.get("candidate_id") != candidate_id or not HEX32.fullmatch(candidate_id):
        raise StagingBridgeError("airdrop_stager_stored_candidate_invalid")
    if not isinstance(row.get("source_event_id"), str) or not HEX24.fullmatch(row["source_event_id"]):
        raise StagingBridgeError("airdrop_stager_stored_candidate_invalid")
    if not isinstance(row.get("source_ledger_hash"), str) or not HEX64.fullmatch(row["source_ledger_hash"]):
        raise StagingBridgeError("airdrop_stager_stored_candidate_invalid")
    if row.get("action_class") not in AUTO_STAGE_KEYS:
        raise StagingBridgeError("airdrop_stager_stored_candidate_invalid")
    payload_sha = _payload_digest(row.get("payload"))
    if payload_sha != row.get("payload_sha256"):
        raise StagingBridgeError("airdrop_stager_payload_digest_mismatch")
    if not isinstance(row.get("summary"), str) or not 1 <= len(row["summary"]) <= 500:
        raise StagingBridgeError("airdrop_stager_stored_candidate_invalid")
    if not isinstance(row.get("cost_note"), str) or not 1 <= len(row["cost_note"]) <= 240:
        raise StagingBridgeError("airdrop_stager_stored_candidate_invalid")
    if not isinstance(row.get("reversible"), bool):
        raise StagingBridgeError("airdrop_stager_stored_candidate_invalid")
    created = _parse_utc(row["created_at"])
    expires = _parse_utc(row["expires_at"])
    if created >= expires or expires - created > MAX_EXPIRY:
        raise StagingBridgeError("airdrop_stager_stored_candidate_invalid")
    request_id = row.get("request_id")
    approval_digest = row.get("approval_digest")
    if (request_id is None) != (approval_digest is None):
        raise StagingBridgeError("airdrop_stager_stored_candidate_invalid")
    if request_id is not None and (
        not isinstance(request_id, str)
        or not HEX32.fullmatch(request_id)
        or not isinstance(approval_digest, str)
        or not HEX64.fullmatch(approval_digest)
    ):
        raise StagingBridgeError("airdrop_stager_stored_candidate_invalid")
    expected = _candidate_id(
        row["source_event_id"],
        row["action_class"],
        row["payload_sha256"],
        row["expires_at"],
    )
    if expected != candidate_id:
        raise StagingBridgeError("airdrop_stager_candidate_id_mismatch")
    return row


def _load_store() -> dict:
    path = store_path()
    if not path.exists():
        return _default_store()
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise StagingBridgeError("airdrop_stager_store_unreadable") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "candidates"}
        or value.get("schema_version") != SCHEMA_VERSION
        or not isinstance(value.get("candidates"), dict)
        or len(value["candidates"]) > MAX_CANDIDATES
    ):
        raise StagingBridgeError("airdrop_stager_store_invalid")
    for candidate_id, row in value["candidates"].items():
        _validate_stored(candidate_id, row)
    return value


def _after_is_open(event: dict) -> bool:
    after = event.get("after")
    value = after.get("value") if isinstance(after, dict) else after
    return str(value).lower() in OPEN_VALUES


def _trusted_evidence(rows: object) -> bool:
    if not isinstance(rows, list):
        return False
    for row in rows:
        if not isinstance(row, dict):
            continue
        tier = row.get("tier")
        if (
            row.get("observation") in {"current", "last_success"}
            and row.get("status") == "ok"
            and isinstance(tier, int)
            and tier <= 2
            and row.get("authority") in TRUSTED_AUTHORITIES
        ):
            return True
    return False


def _validate_candidate(durable: dict, raw: object, current: datetime) -> dict:
    if not isinstance(raw, dict):
        raise StagingBridgeError("airdrop_stager_candidate_invalid")
    allowed = {
        "schema_version",
        "action_class",
        "payload",
        "summary",
        "cost_note",
        "reversible",
        "expires_at",
    }
    if set(raw) != allowed or raw.get("schema_version") != SCHEMA_VERSION:
        raise StagingBridgeError("airdrop_stager_candidate_schema_invalid")

    event = durable.get("event")
    if not isinstance(event, dict):
        raise StagingBridgeError("airdrop_stager_event_missing")
    source_event_id = event.get("event_id")
    if not isinstance(source_event_id, str) or not HEX24.fullmatch(source_event_id):
        raise StagingBridgeError("airdrop_stager_event_id_invalid")
    if durable.get("event_id") != source_event_id:
        raise StagingBridgeError("airdrop_stager_event_id_mismatch")
    ledger_hash = durable.get("hash")
    if not isinstance(ledger_hash, str) or not HEX64.fullmatch(ledger_hash):
        raise StagingBridgeError("airdrop_stager_ledger_hash_invalid")

    action_class = raw.get("action_class")
    if action_class not in AUTO_STAGE_KEYS:
        raise StagingBridgeError("airdrop_stager_action_class_not_auto_stageable")
    if event.get("key") != AUTO_STAGE_KEYS[action_class]:
        raise StagingBridgeError("airdrop_stager_action_key_mismatch")
    if event.get("severity") not in {"ACTION_NOW", "HIGH"}:
        raise StagingBridgeError("airdrop_stager_event_severity_not_actionable")
    if not _after_is_open(event):
        raise StagingBridgeError("airdrop_stager_action_not_open")
    if not _trusted_evidence(durable.get("source_evidence")):
        raise StagingBridgeError("airdrop_stager_trusted_evidence_missing")

    payload = raw.get("payload")
    payload_sha = _payload_digest(payload)
    summary = raw.get("summary")
    cost_note = raw.get("cost_note")
    reversible = raw.get("reversible")
    if not isinstance(summary, str) or not 1 <= len(summary) <= 500:
        raise StagingBridgeError("airdrop_stager_summary_invalid")
    if not isinstance(cost_note, str) or not 1 <= len(cost_note) <= 240:
        raise StagingBridgeError("airdrop_stager_cost_note_invalid")
    if not isinstance(reversible, bool):
        raise StagingBridgeError("airdrop_stager_reversible_invalid")
    expires = _parse_utc(raw.get("expires_at"))
    if expires <= current or expires - current > MAX_EXPIRY:
        raise StagingBridgeError("airdrop_stager_expiry_invalid")

    return {
        "source_event_id": source_event_id,
        "source_ledger_hash": ledger_hash,
        "action_class": action_class,
        "payload": payload,
        "payload_sha256": payload_sha,
        "summary": summary,
        "cost_note": cost_note,
        "reversible": reversible,
        "expires_at": expires.isoformat(),
    }


def _persist_candidate(candidate: dict, current: datetime) -> dict:
    candidate_id = _candidate_id(
        candidate["source_event_id"],
        candidate["action_class"],
        candidate["payload_sha256"],
        candidate["expires_at"],
    )
    row = {
        "candidate_id": candidate_id,
        **candidate,
        "created_at": current.isoformat(),
        "request_id": None,
        "approval_digest": None,
    }
    _validate_stored(candidate_id, row)
    with _store_lock():
        store = _load_store()
        known = store["candidates"].get(candidate_id)
        if known is not None:
            if _canonical({k: v for k, v in known.items() if k not in {"request_id", "approval_digest"}}) != _canonical(
                {k: v for k, v in row.items() if k not in {"request_id", "approval_digest"}}
            ):
                raise StagingBridgeError("airdrop_stager_existing_candidate_mismatch")
            return json.loads(json.dumps(known))
        if len(store["candidates"]) >= MAX_CANDIDATES:
            raise StagingBridgeError("airdrop_stager_capacity_exceeded")
        store["candidates"][candidate_id] = row
        _atomic_write(store)
    return json.loads(json.dumps(row))


def _bind_approval(candidate_id: str, current: datetime) -> dict:
    with _store_lock():
        store = _load_store()
        row = store["candidates"].get(candidate_id)
        if not isinstance(row, dict):
            raise StagingBridgeError("airdrop_stager_candidate_not_found")
        row = json.loads(json.dumps(row))
    if row.get("request_id") is not None:
        return row

    approval = airdrop_approval.stage_request(
        action_class=row["action_class"],
        payload_sha256=row["payload_sha256"],
        source_event_id=row["source_event_id"],
        summary=row["summary"],
        cost_note=row["cost_note"],
        reversible=row["reversible"],
        expires_at=_parse_utc(row["expires_at"]),
        now=current,
    )

    with _store_lock():
        store = _load_store()
        latest = store["candidates"].get(candidate_id)
        if not isinstance(latest, dict):
            raise StagingBridgeError("airdrop_stager_candidate_not_found")
        if latest.get("request_id") not in {None, approval["request_id"]}:
            raise StagingBridgeError("airdrop_stager_request_binding_conflict")
        latest["request_id"] = approval["request_id"]
        latest["approval_digest"] = approval["approval_digest"]
        _validate_stored(candidate_id, latest)
        _atomic_write(store)
        return json.loads(json.dumps(latest))


def _ledger_records_by_id() -> dict[str, dict]:
    verified = airdrop_ledger.verify_ledger()
    return {
        str(row["event_id"]): row
        for row in verified.get("records", [])
        if isinstance(row, dict) and isinstance(row.get("event_id"), str)
    }


def reconcile_incomplete(*, now: datetime | None = None) -> list[dict]:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    records = _ledger_records_by_id()
    with _store_lock():
        store = _load_store()
        pending = [
            json.loads(json.dumps(row))
            for row in store["candidates"].values()
            if isinstance(row, dict)
            and row.get("request_id") is None
            and _parse_utc(row["expires_at"]) > current
        ]
    repaired: list[dict] = []
    for row in pending:
        durable = records.get(row["source_event_id"])
        if not isinstance(durable, dict) or durable.get("hash") != row["source_ledger_hash"]:
            raise StagingBridgeError("airdrop_stager_source_ledger_record_missing")
        repaired.append(_bind_approval(row["candidate_id"], current))
    return repaired


def stage_durable_event(durable: dict, *, now: datetime | None = None) -> dict | None:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    event = durable.get("event")
    if not isinstance(event, dict):
        raise StagingBridgeError("airdrop_stager_event_missing")
    raw = event.get("action_candidate")
    if raw is None:
        return None
    candidate = _validate_candidate(durable, raw, current)
    stored = _persist_candidate(candidate, current)
    return _bind_approval(stored["candidate_id"], current)


def stage_new_events(
    event_ids: list[str],
    records_by_id: dict[str, dict],
    *,
    now: datetime | None = None,
) -> dict:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    repaired = reconcile_incomplete(now=current)
    staged: list[dict] = []
    skipped = 0
    for event_id in event_ids:
        durable = records_by_id.get(event_id)
        if not isinstance(durable, dict):
            raise StagingBridgeError("airdrop_stager_new_event_missing_from_ledger")
        row = stage_durable_event(durable, now=current)
        if row is None:
            skipped += 1
            continue
        staged.append(row)
    return {
        "outcome": "ok",
        "staged": staged,
        "repaired": repaired,
        "skipped_without_candidate": skipped,
    }


def get_candidate_for_request(request_id: str) -> dict:
    if not isinstance(request_id, str) or not HEX32.fullmatch(request_id):
        raise StagingBridgeError("airdrop_stager_request_id_invalid")
    with _store_lock():
        store = _load_store()
        matches = [
            row
            for row in store["candidates"].values()
            if isinstance(row, dict) and row.get("request_id") == request_id
        ]
    if len(matches) != 1:
        raise StagingBridgeError("airdrop_stager_request_candidate_not_unique")
    return json.loads(json.dumps(matches[0]))
