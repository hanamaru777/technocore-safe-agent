"""Typed public staging for the first genuine tclk/1 PaperRail pilot.

This module performs local state writes only. It consumes already-retained, already-resolved
public review evidence and emits an immutable hash-bound stage file for the isolated
PREPARE-only signer helper. It never signs, posts, mints a protocol secret, follows URLs,
or executes task text.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from . import core, observer, tclk_review_evidence, tclk_triage, tclk_watch

SCHEMA_VERSION = 1
MAX_STAGES = 32
MIN_STAGE_SECONDS = 300

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OFFER_ID = re.compile(r"^0x[0-9a-f]{64}$")
_DID = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}$")
_KEY = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")


class PilotError(RuntimeError):
    """Stable fail-closed stage error; messages contain no untrusted task text."""


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def _canonical(value: dict) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _sha(value: dict) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def pilot_root() -> Path:
    return core.STATE / "autopilot" / "tclk-pilot"


def stage_dir() -> Path:
    return pilot_root() / "stages"


def preview_dir() -> Path:
    return pilot_root() / "previews"


def stage_path(stage_id: str) -> Path:
    if not isinstance(stage_id, str) or not _HEX32.fullmatch(stage_id):
        raise PilotError("invalid_stage_id")
    return stage_dir() / f"{stage_id}.json"


def preview_path(stage_id: str) -> Path:
    if not isinstance(stage_id, str) or not _HEX32.fullmatch(stage_id):
        raise PilotError("invalid_stage_id")
    return preview_dir() / f"{stage_id}.json"


def secret_path(stage_id: str) -> Path:
    if not isinstance(stage_id, str) or not _HEX32.fullmatch(stage_id):
        raise PilotError("invalid_stage_id")
    return core.STATE / "signer" / "tclk-pilot-secrets" / f"{stage_id}.json"


def _verified_did() -> str:
    path = core.verified_did_path()
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PilotError("verified_did_unavailable") from error
    did = value.get("did") if isinstance(value, dict) else None
    if not isinstance(did, str) or not _DID.fullmatch(did):
        raise PilotError("verified_did_unavailable")
    return did


def _evidence_hashes(evidence: dict) -> tuple[str, str | None]:
    if not isinstance(evidence, dict):
        raise PilotError("evidence_invalid")
    full = evidence.get("full_spec")
    material = evidence.get("material")
    full_hash = full.get("sha256") if isinstance(full, dict) else None
    material_hash = material.get("sha256") if isinstance(material, dict) else None
    if not isinstance(full_hash, str) or not _HEX64.fullmatch(full_hash):
        raise PilotError("evidence_invalid")
    if material_hash is not None and (not isinstance(material_hash, str) or not _HEX64.fullmatch(material_hash)):
        raise PilotError("evidence_invalid")
    return full_hash, material_hash


def _bindings(
    *,
    our_did: str,
    counterpart_did: str,
    offer_id: str,
    offer_line: str,
    frame_sha256: str,
    job_id: str,
    expires_ms: int,
    full_spec_sha256: str,
    material_sha256: str | None,
    evidence_digest: str,
) -> dict:
    return {
        "our_did": our_did,
        "counterpart_did": counterpart_did,
        "room": tclk_watch.OFFER_ROOM,
        "offer_id": offer_id,
        "offer_line": offer_line,
        "frame_sha256": frame_sha256,
        "job_proto": "a2a",
        "job_id": job_id,
        "rail": "paper",
        "lock": "hash",
        "expires_ms": expires_ms,
        "full_spec_sha256": full_spec_sha256,
        "material_sha256": material_sha256,
        "evidence_digest": evidence_digest,
    }


def _validate_stage(record: object, *, now_ms: int | None = None, require_live: bool = False) -> dict:
    required = {
        "schema_version", "stage_id", "stage_digest", "status", "created_at",
        "our_did", "counterpart_did", "room", "offer_id", "offer_line",
        "frame_sha256", "job_proto", "job_id", "rail", "lock", "expires_ms",
        "full_spec_sha256", "material_sha256", "evidence_digest",
    }
    if not isinstance(record, dict) or set(record) != required:
        raise PilotError("stage_schema_invalid")
    if record.get("schema_version") != SCHEMA_VERSION or record.get("status") != "staged":
        raise PilotError("stage_schema_invalid")
    if not isinstance(record.get("stage_id"), str) or not _HEX32.fullmatch(record["stage_id"]):
        raise PilotError("stage_schema_invalid")
    if not isinstance(record.get("stage_digest"), str) or not _HEX64.fullmatch(record["stage_digest"]):
        raise PilotError("stage_schema_invalid")
    if not isinstance(record.get("created_at"), str):
        raise PilotError("stage_schema_invalid")
    for field in ("our_did", "counterpart_did"):
        if not isinstance(record.get(field), str) or not _DID.fullmatch(record[field]):
            raise PilotError("stage_schema_invalid")
    if hmac.compare_digest(record["our_did"], record["counterpart_did"]):
        raise PilotError("self_offer")
    if record.get("room") != tclk_watch.OFFER_ROOM:
        raise PilotError("stage_schema_invalid")
    if not isinstance(record.get("offer_id"), str) or not _OFFER_ID.fullmatch(record["offer_id"]):
        raise PilotError("stage_schema_invalid")
    if not isinstance(record.get("offer_line"), str) or not record["offer_line"].startswith(tclk_watch.TCLK_PREFIX) or len(record["offer_line"]) > tclk_watch.MAX_FRAME_CHARS:
        raise PilotError("stage_schema_invalid")
    if not isinstance(record.get("frame_sha256"), str) or not _HEX64.fullmatch(record["frame_sha256"]):
        raise PilotError("stage_schema_invalid")
    if hashlib.sha256(record["offer_line"].encode("utf-8")).hexdigest() != record["frame_sha256"]:
        raise PilotError("stage_frame_hash_mismatch")
    if record.get("job_proto") != "a2a" or not isinstance(record.get("job_id"), str) or not _KEY.fullmatch(record["job_id"]):
        raise PilotError("stage_schema_invalid")
    if record.get("rail") != "paper" or record.get("lock") != "hash":
        raise PilotError("stage_schema_invalid")
    if not isinstance(record.get("expires_ms"), int):
        raise PilotError("stage_schema_invalid")
    if not isinstance(record.get("full_spec_sha256"), str) or not _HEX64.fullmatch(record["full_spec_sha256"]):
        raise PilotError("stage_schema_invalid")
    material_hash = record.get("material_sha256")
    if material_hash is not None and (not isinstance(material_hash, str) or not _HEX64.fullmatch(material_hash)):
        raise PilotError("stage_schema_invalid")
    if not isinstance(record.get("evidence_digest"), str) or not _HEX64.fullmatch(record["evidence_digest"]):
        raise PilotError("stage_schema_invalid")

    bindings = _bindings(
        our_did=record["our_did"],
        counterpart_did=record["counterpart_did"],
        offer_id=record["offer_id"],
        offer_line=record["offer_line"],
        frame_sha256=record["frame_sha256"],
        job_id=record["job_id"],
        expires_ms=record["expires_ms"],
        full_spec_sha256=record["full_spec_sha256"],
        material_sha256=record["material_sha256"],
        evidence_digest=record["evidence_digest"],
    )
    digest = _sha(bindings)
    if not hmac.compare_digest(digest, record["stage_digest"]) or record["stage_id"] != digest[:32]:
        raise PilotError("stage_digest_mismatch")
    if require_live:
        current = _now_ms() if now_ms is None else now_ms
        if record["expires_ms"] - current < MIN_STAGE_SECONDS * 1000:
            raise PilotError("stage_review_window_elapsed")
    return record


def load_stage(stage_id: str, *, now_ms: int | None = None, require_live: bool = False) -> dict:
    path = stage_path(stage_id)
    try:
        value = json.loads(path.read_text("utf-8"))
    except FileNotFoundError as error:
        raise PilotError("stage_not_found") from error
    except (OSError, json.JSONDecodeError) as error:
        raise PilotError("stage_store_unavailable") from error
    return _validate_stage(value, now_ms=now_ms, require_live=require_live)


def _prune_stages() -> None:
    try:
        files = sorted(stage_dir().glob("*.json"), key=lambda path: path.stat().st_mtime)
        for path in files[:-MAX_STAGES]:
            path.unlink()
    except OSError as error:
        raise PilotError("stage_store_unavailable") from error


def stage_from_evidence(item: dict, evidence: dict, *, now_ms: int | None = None) -> dict:
    current = _now_ms() if now_ms is None else now_ms
    verdict = tclk_triage.classify(item, now_ms=current)
    if verdict.get("reviewable") is not True or verdict.get("reason") != "human_review_required":
        raise PilotError("offer_not_reviewable")
    if verdict.get("seconds_left", 0) < MIN_STAGE_SECONDS:
        raise PilotError("stage_review_window_elapsed")

    our_did = _verified_did()
    counterpart = item.get("from")
    if not isinstance(counterpart, str) or not _DID.fullmatch(counterpart):
        raise PilotError("counterpart_invalid")
    if hmac.compare_digest(our_did, counterpart):
        raise PilotError("self_offer")

    offer_id = item.get("id")
    frame_hash = item.get("frame_sha256")
    offer_line = item.get("frame_text")
    job_id = item.get("job_id")
    expires_ms = item.get("expires_ms")
    if not isinstance(offer_id, str) or not _OFFER_ID.fullmatch(offer_id):
        raise PilotError("offer_invalid")
    if not isinstance(frame_hash, str) or not _HEX64.fullmatch(frame_hash):
        raise PilotError("offer_invalid")
    if not isinstance(offer_line, str) or hashlib.sha256(offer_line.encode("utf-8")).hexdigest() != frame_hash:
        raise PilotError("offer_frame_hash_mismatch")
    # Defense in depth: do not trust the retained convenience role alone. Re-decode the
    # exact hash-bound raw offer with the pinned parser and require a payer-origin offer,
    # so our accepting identity is the payee that correctly mints the hash preimage.
    decoded = tclk_watch.official_offer(offer_line)
    if decoded is None or decoded.get("id") != offer_id or decoded.get("from") != counterpart:
        raise PilotError("offer_revalidation_failed")
    if decoded.get("role") != "payer" or item.get("role") != "payer":
        raise PilotError("first_pilot_role_not_payer")
    if not isinstance(job_id, str) or not _KEY.fullmatch(job_id) or not isinstance(expires_ms, int):
        raise PilotError("offer_invalid")
    if item.get("rail") != "paper" or item.get("job_proto") != "a2a" or item.get("read_only") is not True or item.get("accepted") is not False:
        raise PilotError("offer_invalid")

    full_hash, material_hash = _evidence_hashes(evidence)
    if evidence.get("offer_id") != offer_id or evidence.get("frame_sha256") != frame_hash or evidence.get("job_id") != job_id or evidence.get("expires_ms") != expires_ms or evidence.get("accepted") is not False:
        raise PilotError("evidence_binding_mismatch")
    evidence_digest = _sha({
        "offer_id": offer_id,
        "frame_sha256": frame_hash,
        "job_id": job_id,
        "expires_ms": expires_ms,
        "full_spec_sha256": full_hash,
        "material_sha256": material_hash,
    })
    bindings = _bindings(
        our_did=our_did,
        counterpart_did=counterpart,
        offer_id=offer_id,
        offer_line=offer_line,
        frame_sha256=frame_hash,
        job_id=job_id,
        expires_ms=expires_ms,
        full_spec_sha256=full_hash,
        material_sha256=material_hash,
        evidence_digest=evidence_digest,
    )
    digest = _sha(bindings)
    record = {
        "schema_version": SCHEMA_VERSION,
        "stage_id": digest[:32],
        "stage_digest": digest,
        "status": "staged",
        "created_at": datetime.fromtimestamp(current / 1000, UTC).isoformat(),
        **bindings,
    }
    _validate_stage(record, now_ms=current, require_live=True)
    path = stage_path(record["stage_id"])
    if path.exists():
        existing = load_stage(record["stage_id"], now_ms=current, require_live=True)
        if existing["stage_digest"] != record["stage_digest"]:
            raise PilotError("stage_collision")
        return existing
    try:
        stage_dir().mkdir(parents=True, exist_ok=True, mode=0o770)
        observer.atomic_json_write(path, record, compact=True, mode=0o640)
        _prune_stages()
    except PilotError:
        raise
    except OSError as error:
        raise PilotError("stage_store_unavailable") from error
    return record


def stage_pending(*, now_ms: int | None = None, max_count: int = 4) -> dict:
    """Stage recent auto-resolved evidence without any protocol/network write."""
    current = _now_ms() if now_ms is None else now_ms
    if not isinstance(max_count, int) or not 1 <= max_count <= 8:
        raise PilotError("invalid_stage_batch")
    try:
        evidence_records = list(tclk_review_evidence.load_store()["records"])
        state = observer.load_state()
    except (RuntimeError, tclk_review_evidence.EvidenceError) as error:
        raise PilotError("stage_source_unavailable") from error

    staged: list[str] = []
    skipped = 0
    for evidence in reversed(evidence_records):
        if len(staged) >= max_count:
            break
        offer_id = evidence.get("offer_id") if isinstance(evidence, dict) else None
        if not isinstance(offer_id, str):
            skipped += 1
            continue
        item = tclk_watch.offer(state, offer_id)
        if item is None:
            skipped += 1
            continue
        try:
            record = stage_from_evidence(item, evidence, now_ms=current)
        except PilotError:
            skipped += 1
            continue
        staged.append(record["stage_id"])
    return {"staged": staged, "count": len(staged), "skipped": skipped}
