"""Deterministic local work evidence for the first genuine tclk/1 PaperRail pilot.

This slice runs only after authenticated PaperRail lock evidence exists. It never signs,
posts, follows URLs, executes commands, reads signer-private protocol material, or performs
arbitrary network I/O. The only supported first-pilot work is a narrow verification of the
already-resolved fixed-origin public material Note: SHA-256 matching and/or JSON validity.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import observer, tclk_pilot, tclk_pilot_lock, tclk_pilot_signer, tclk_review_evidence

SCHEMA_VERSION = 1
MAX_SCAN = 4
MAX_RESULT_FIELDS = 16

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_URL = re.compile(r"https?://", re.I)
_SHA_DIRECTIVE = re.compile(r"\bsha-?256\s*[:=]\s*([0-9a-f]{64})\b", re.I)
_JSON_TASK = re.compile(
    r"(?:\b(?:verify|check|validate|audit)\b.{0,80}\bjson\b|\bjson\b.{0,80}\b(?:verify|check|validate|audit)\b)",
    re.I | re.S,
)
_UNSUPPORTED_VERB = re.compile(r"\b(?:review|inspect|analy[sz]e|extract|summari[sz]e|compare)\b", re.I)
_FORBIDDEN = re.compile(
    r"\b(?:private\s+key|seed\s+phrase|signing\s+key|credential|password|nonce\s+replay|"
    r"prediction\s+market|flopmarket|bet|buy|swap|powershell|cmd\.exe|shell(?:\s+command)?|"
    r"run\s+command|execute\s+command|curl|wget|x402|ptlc|adaptor|payment|transfer\s+funds|"
    r"send\s+funds|wallet|sign\s+this|sign\s+message|signed\s+replay|same\s+signed)\b",
    re.I,
)


class WorkError(RuntimeError):
    """Stable public-safe failure from the local deterministic work slice."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def evidence_dir() -> Path:
    return tclk_pilot.pilot_root() / "work"


def evidence_path(stage_id: str) -> Path:
    if not isinstance(stage_id, str) or not _HEX32.fullmatch(stage_id):
        raise WorkError("invalid_stage_id")
    return evidence_dir() / f"{stage_id}.json"


def _note_hash(note: object, *, required: bool) -> str | None:
    if note is None and not required:
        return None
    if not isinstance(note, dict):
        raise WorkError("review_evidence_invalid")
    digest = note.get("sha256")
    value = note.get("value")
    size = note.get("bytes")
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest) or not isinstance(value, str):
        raise WorkError("review_evidence_invalid")
    encoded = value.encode("utf-8")
    if not isinstance(size, int) or size != len(encoded) or hashlib.sha256(encoded).hexdigest() != digest:
        raise WorkError("review_evidence_invalid")
    return digest


def _require_bindings(stage: dict, preview: dict, review: dict, lock: dict) -> tuple[str, str, str]:
    full_hash = _note_hash(review.get("full_spec"), required=True)
    material_hash = _note_hash(review.get("material"), required=False)
    if material_hash is None:
        raise WorkError("work_material_required")
    if review.get("external_url_present") is True:
        raise WorkError("work_policy_unsupported")
    if (
        review.get("offer_id") != stage["offer_id"]
        or review.get("job_id") != stage["job_id"]
        or review.get("frame_sha256") != stage["frame_sha256"]
        or not hmac.compare_digest(full_hash or "", stage["full_spec_sha256"])
        or stage.get("material_sha256") is None
        or not hmac.compare_digest(material_hash, stage["material_sha256"])
    ):
        raise WorkError("review_binding_changed")
    if (
        lock.get("status") != "lock_verified"
        or lock.get("stage_id") != stage["stage_id"]
        or lock.get("stage_digest") != stage["stage_digest"]
        or lock.get("offer_id") != stage["offer_id"]
        or lock.get("counterpart_did") != stage["counterpart_did"]
        or lock.get("our_did") != stage["our_did"]
        or lock.get("job_id") != stage["job_id"]
        or lock.get("contract_id") != preview.get("contract_id")
        or lock.get("deal_room") != preview.get("deal_room")
        or lock.get("lock_from") != stage["counterpart_did"]
        or lock.get("lock_ref") != preview.get("contract_id")
    ):
        raise WorkError("lock_binding_changed")
    contract_id = preview.get("contract_id")
    deal_room = preview.get("deal_room")
    if not isinstance(contract_id, str) or not isinstance(deal_room, str):
        raise WorkError("public_accept_binding_invalid")
    expected_ns, expected_key = tclk_pilot_lock._paper_note_location(contract_id)
    if lock.get("paper_note_namespace") != expected_ns or lock.get("paper_note_key") != expected_key:
        raise WorkError("lock_binding_changed")
    return full_hash or "", material_hash, contract_id


def _task_result(review: dict) -> tuple[str, dict, bool]:
    full = review["full_spec"]["value"]
    material = review["material"]["value"]
    if _URL.search(full) or _URL.search(material) or _FORBIDDEN.search(full) or _FORBIDDEN.search(material):
        raise WorkError("work_policy_unsupported")
    if _UNSUPPORTED_VERB.search(full):
        raise WorkError("work_policy_unsupported")

    directives = {value.lower() for value in _SHA_DIRECTIVE.findall(full)}
    wants_json = bool(_JSON_TASK.search(full))
    if len(directives) > 1:
        raise WorkError("work_policy_ambiguous")
    if not directives and not wants_json:
        raise WorkError("work_policy_unsupported")

    result: dict[str, object] = {
        "material_sha256": hashlib.sha256(material.encode("utf-8")).hexdigest(),
        "material_bytes": len(material.encode("utf-8")),
    }
    ok = True
    family_parts = []
    if directives:
        expected = next(iter(directives))
        matched = hmac.compare_digest(expected, result["material_sha256"])
        result["expected_sha256"] = expected
        result["sha256_match"] = matched
        ok = ok and matched
        family_parts.append("sha256")
    if wants_json:
        try:
            parsed = json.loads(material)
        except json.JSONDecodeError:
            result["json_valid"] = False
            ok = False
        else:
            result["json_valid"] = True
            result["json_top_level"] = (
                "object" if isinstance(parsed, dict)
                else "array" if isinstance(parsed, list)
                else "string" if isinstance(parsed, str)
                else "boolean" if isinstance(parsed, bool)
                else "null" if parsed is None
                else "number"
            )
            if isinstance(parsed, (dict, list)):
                result["json_items"] = len(parsed)
            result["json_canonical_sha256"] = hashlib.sha256(_canonical(parsed)).hexdigest()
        family_parts.append("json")
    if len(result) > MAX_RESULT_FIELDS:
        raise WorkError("work_result_unbounded")
    return f"public_material_{'_'.join(family_parts)}_v1", result, ok


def _validate_evidence(value: object) -> dict:
    required = {
        "schema_version", "status", "created_at", "stage_id", "stage_digest", "offer_id",
        "counterpart_did", "job_id", "contract_id", "deal_room", "lock_line_sha256",
        "lock_ref", "lock_seq", "lock_timestamp_ms", "paper_note_sha256",
        "full_spec_sha256", "material_sha256", "work_family", "result", "work_evidence_sha256",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise WorkError("work_evidence_invalid")
    if value.get("status") not in {"work_ready", "work_failed"} or not isinstance(value.get("created_at"), str):
        raise WorkError("work_evidence_invalid")
    if not isinstance(value.get("stage_id"), str) or not _HEX32.fullmatch(value["stage_id"]):
        raise WorkError("work_evidence_invalid")
    for field in (
        "stage_digest", "lock_line_sha256", "paper_note_sha256", "full_spec_sha256",
        "material_sha256", "work_evidence_sha256",
    ):
        if not isinstance(value.get(field), str) or not _HEX64.fullmatch(value[field]):
            raise WorkError("work_evidence_invalid")
    if not isinstance(value.get("lock_seq"), int) or value["lock_seq"] < 0 or not isinstance(value.get("lock_timestamp_ms"), int) or value["lock_timestamp_ms"] < 0:
        raise WorkError("work_evidence_invalid")
    if not isinstance(value.get("work_family"), str) or not isinstance(value.get("result"), dict) or len(value["result"]) > MAX_RESULT_FIELDS:
        raise WorkError("work_evidence_invalid")
    payload = {key: item for key, item in value.items() if key not in {"created_at", "work_evidence_sha256"}}
    if not hmac.compare_digest(_sha(payload), value["work_evidence_sha256"]):
        raise WorkError("work_evidence_hash_mismatch")
    return value


def load_evidence(stage_id: str) -> dict | None:
    path = evidence_path(stage_id)
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise WorkError("work_evidence_invalid") from error
    return _validate_evidence(value)


def run_stage(stage_id: str) -> dict:
    try:
        stage = tclk_pilot.load_stage(stage_id, require_live=False)
        preview = tclk_pilot_signer._load_preview(stage_id)
        if preview is None:
            raise WorkError("public_accept_binding_invalid")
        tclk_pilot_signer._require_preview_binding(preview, stage)
        review = tclk_review_evidence.get(stage["offer_id"])
        lock = tclk_pilot_lock.load_evidence(stage_id)
    except (tclk_pilot.PilotError, tclk_pilot_signer.PrepareError, tclk_review_evidence.EvidenceError, tclk_pilot_lock.LockError) as error:
        raise WorkError("work_source_invalid") from error
    if review is None or lock is None:
        raise WorkError("work_source_missing")

    full_hash, material_hash, contract_id = _require_bindings(stage, preview, review, lock)
    family, result, ok = _task_result(review)
    status = "work_ready" if ok else "work_failed"
    payload = {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "stage_id": stage["stage_id"],
        "stage_digest": stage["stage_digest"],
        "offer_id": stage["offer_id"],
        "counterpart_did": stage["counterpart_did"],
        "job_id": stage["job_id"],
        "contract_id": contract_id,
        "deal_room": preview["deal_room"],
        "lock_line_sha256": lock["lock_line_sha256"],
        "lock_ref": lock["lock_ref"],
        "lock_seq": lock["lock_seq"],
        "lock_timestamp_ms": lock["lock_timestamp_ms"],
        "paper_note_sha256": lock["paper_note_sha256"],
        "full_spec_sha256": full_hash,
        "material_sha256": material_hash,
        "work_family": family,
        "result": result,
    }
    record = {
        **payload,
        "created_at": _now(),
        "work_evidence_sha256": _sha(payload),
    }
    _validate_evidence(record)

    existing = load_evidence(stage_id)
    if existing is not None:
        if existing["work_evidence_sha256"] != record["work_evidence_sha256"]:
            raise WorkError("work_evidence_conflict")
        return {"action": "already_recorded", "evidence": existing}
    try:
        evidence_dir().mkdir(parents=True, exist_ok=True, mode=0o770)
        observer.atomic_json_write(evidence_path(stage_id), record, compact=True, mode=0o640)
    except OSError as error:
        raise WorkError("work_evidence_persistence_failed") from error
    return {"action": status, "evidence": record}


def scan_pending(*, max_count: int = MAX_SCAN) -> dict:
    if not isinstance(max_count, int) or not 1 <= max_count <= 8:
        raise WorkError("invalid_scan_batch")
    try:
        paths = sorted(tclk_pilot_lock.evidence_dir().glob("*.json"), key=lambda path: path.stat().st_mtime)
    except OSError as error:
        raise WorkError("lock_store_unavailable") from error
    results = []
    for path in paths:
        if len(results) >= max_count:
            break
        stage_id = path.stem
        try:
            if load_evidence(stage_id) is not None:
                continue
            results.append(run_stage(stage_id))
        except WorkError as error:
            results.append({"action": "error", "stage_id": stage_id, "error": str(error)})
    return {"count": len(results), "results": results}


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("tclk pilot work watcher accepts no arguments")
    try:
        result = scan_pending()
    except WorkError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        raise SystemExit(1)
    print(json.dumps({"ok": True, **result}, sort_keys=True))


if __name__ == "__main__":
    main()
