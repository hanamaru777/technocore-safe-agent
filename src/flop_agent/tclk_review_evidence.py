"""Bounded durable public evidence for automatically reviewed tclk candidates.

Only already-retained, review-worthy offers may enter this store. Resolution reuses the
fixed-origin Note resolver and therefore performs at most two bounded same-origin reads.
The store contains public/untrusted task evidence and hashes only: never signing keys,
preimages, payment material, private config, or protocol write state.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Callable

from . import core, observer, tclk_note_review, tclk_triage

SCHEMA_VERSION = 1
EVIDENCE_NAME = "tclk-review-evidence.json"
MAX_RECORDS = 100
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OFFER_ID = re.compile(r"^0x[0-9a-f]{64}$")
_LOCK = Lock()


class EvidenceError(RuntimeError):
    """Fail-closed local evidence error with a public-safe reason."""


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def evidence_path() -> Path:
    return core.STATE / "resident" / EVIDENCE_NAME


def _default_store() -> dict:
    return {"schema_version": SCHEMA_VERSION, "records": []}


def _validate_note(note: object, *, material: bool) -> dict | None:
    if note is None and material:
        return None
    if not isinstance(note, dict) or set(note) != {"namespace", "key", "value", "sha256", "bytes"}:
        raise EvidenceError("evidence_note_invalid")
    expected_ns = tclk_note_review.MATERIAL_NAMESPACE if material else tclk_note_review.FULL_SPEC_NAMESPACE
    if note.get("namespace") != expected_ns or not isinstance(note.get("key"), str):
        raise EvidenceError("evidence_note_invalid")
    value = note.get("value")
    digest = note.get("sha256")
    size = note.get("bytes")
    if not isinstance(value, str) or not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise EvidenceError("evidence_note_invalid")
    encoded = value.encode("utf-8")
    if not isinstance(size, int) or size != len(encoded) or not 0 < size <= tclk_note_review.MAX_NOTE_BYTES:
        raise EvidenceError("evidence_note_invalid")
    if hashlib.sha256(encoded).hexdigest() != digest:
        raise EvidenceError("evidence_hash_mismatch")
    return note


def _validate_record(record: object) -> dict:
    required = {
        "offer_id", "job_id", "frame_sha256", "expires_ms", "resolved_at",
        "triage_reason", "full_spec", "material", "external_url_present",
        "read_count", "accepted",
    }
    if not isinstance(record, dict) or set(record) != required:
        raise EvidenceError("evidence_record_invalid")
    if not isinstance(record.get("offer_id"), str) or not _OFFER_ID.fullmatch(record["offer_id"]):
        raise EvidenceError("evidence_record_invalid")
    if not isinstance(record.get("job_id"), str) or not record["job_id"]:
        raise EvidenceError("evidence_record_invalid")
    if not isinstance(record.get("frame_sha256"), str) or not _HEX64.fullmatch(record["frame_sha256"]):
        raise EvidenceError("evidence_record_invalid")
    if not isinstance(record.get("expires_ms"), int) or not isinstance(record.get("resolved_at"), str):
        raise EvidenceError("evidence_record_invalid")
    if record.get("triage_reason") != "human_review_required":
        raise EvidenceError("evidence_record_invalid")
    if not isinstance(record.get("external_url_present"), bool) or record.get("accepted") is not False:
        raise EvidenceError("evidence_record_invalid")
    _validate_note(record.get("full_spec"), material=False)
    material = _validate_note(record.get("material"), material=True)
    expected_reads = 1 + (1 if material is not None else 0)
    if record.get("read_count") != expected_reads:
        raise EvidenceError("evidence_record_invalid")
    return record


def load_store() -> dict:
    path = evidence_path()
    if not path.exists():
        return _default_store()
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("evidence_store_unreadable") from error
    if not isinstance(value, dict) or set(value) != {"schema_version", "records"} or value.get("schema_version") != SCHEMA_VERSION or not isinstance(value.get("records"), list):
        raise EvidenceError("evidence_store_invalid")
    if len(value["records"]) > MAX_RECORDS:
        raise EvidenceError("evidence_store_unbounded")
    for record in value["records"]:
        _validate_record(record)
    return value


def _save_store(store: dict) -> None:
    observer.atomic_json_write(evidence_path(), store, compact=True, mode=0o640)


def get(offer_id: str) -> dict | None:
    if not isinstance(offer_id, str) or not _OFFER_ID.fullmatch(offer_id):
        return None
    store = load_store()
    for record in reversed(store["records"]):
        if record["offer_id"] == offer_id:
            return record
    return None


def capture(
    item: dict,
    *,
    reader: Callable[[str, str], str] = core.read_note,
    now_ms: int | None = None,
) -> dict:
    """Resolve and persist one review-worthy offer exactly once by offer/frame identity."""
    current = _now_ms() if now_ms is None else now_ms
    if not isinstance(item, dict):
        raise EvidenceError("offer_not_reviewable")
    offer_id = item.get("id")
    frame_hash = item.get("frame_sha256")
    if not isinstance(offer_id, str) or not _OFFER_ID.fullmatch(offer_id) or not isinstance(frame_hash, str) or not _HEX64.fullmatch(frame_hash):
        raise EvidenceError("offer_not_reviewable")

    with _LOCK:
        store = load_store()
        for existing in reversed(store["records"]):
            if existing["offer_id"] != offer_id:
                continue
            if existing["frame_sha256"] != frame_hash:
                raise EvidenceError("evidence_offer_collision")
            return existing

        verdict = tclk_triage.classify(item, now_ms=current)
        if verdict.get("reviewable") is not True or verdict.get("reason") != "human_review_required":
            raise EvidenceError("offer_not_reviewable")
        try:
            resolved = tclk_note_review.resolve_offer(item, reader=reader, now_ms=current)
        except tclk_note_review.ResolutionError as error:
            raise EvidenceError(str(error)) from error

        record = {
            "offer_id": resolved["offer_id"],
            "job_id": resolved["job_id"],
            "frame_sha256": resolved["frame_sha256"],
            "expires_ms": resolved["expires_ms"],
            "resolved_at": datetime.fromtimestamp(current / 1000, UTC).isoformat(),
            "triage_reason": verdict["reason"],
            "full_spec": resolved["full_spec"],
            "material": resolved["material"],
            "external_url_present": resolved["external_url_present"],
            "read_count": resolved["read_count"],
            "accepted": False,
        }
        _validate_record(record)
        store["records"].append(record)
        store["records"] = store["records"][-MAX_RECORDS:]
        _save_store(store)
        return record
