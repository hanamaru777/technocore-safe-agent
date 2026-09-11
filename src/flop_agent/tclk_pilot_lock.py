"""Read-only post-accept verifier for the first genuine tclk/1 PaperRail pilot.

Only public stage/PREPARE state plus the hash-chained successful accept activity is used to
select a contract. The module re-reads the exact Technocore offer/deal transcripts and the
fixed-origin PaperRail Note, then delegates protocol verification to the pinned local tclk
runtime. It never reads signer-private preimages, signs, posts, writes a Note, or follows a URL.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

import httpx

from . import core, observer, tclk_pilot, tclk_pilot_signer, tclk_watch

SCHEMA_VERSION = 1
MAX_SCAN = 4
BRIDGE = Path(__file__).resolve().parents[2] / "tools" / "tclk_verify_lock.mjs"

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CONTRACT = re.compile(r"^0x[0-9a-f]{64}$")
_DEAL_ROOM = re.compile(r"^mb-p-tclk-[0-9a-f]{16}$")
_DID = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}$")


class LockError(RuntimeError):
    """Stable public-safe failure for read-only first-pilot lock verification."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def evidence_dir() -> Path:
    return tclk_pilot.pilot_root() / "locks"


def evidence_path(stage_id: str) -> Path:
    if not isinstance(stage_id, str) or not _HEX32.fullmatch(stage_id):
        raise LockError("invalid_stage_id")
    return evidence_dir() / f"{stage_id}.json"


def _paper_note_location(contract_id: str) -> tuple[str, str]:
    if not isinstance(contract_id, str) or not _CONTRACT.fullmatch(contract_id):
        raise LockError("contract_invalid")
    return f"tclk-paper-{contract_id[2:4]}", contract_id[4:18]


def _timestamp_ms(value: str) -> int:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise LockError("accept_activity_invalid") from error
    if parsed.tzinfo is None:
        raise LockError("accept_activity_invalid")
    return int(parsed.timestamp() * 1000)


def _load_activities() -> list[dict]:
    try:
        ok, _ = core.verify_activity_log()
    except Exception as error:
        raise LockError("activity_log_unavailable") from error
    if not ok:
        raise LockError("activity_log_invalid")
    path = core.STATE / "activities.jsonl"
    if not path.exists():
        return []
    try:
        rows = [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError) as error:
        raise LockError("activity_log_invalid") from error
    if not all(isinstance(row, dict) for row in rows):
        raise LockError("activity_log_invalid")
    return rows


def _matching_accept_activity(stage: dict, preview: dict, activities: list[dict]) -> dict | None:
    matches = []
    for row in activities:
        if (
            row.get("action") == "tclk_first_pilot_accept"
            and row.get("room") == tclk_watch.OFFER_ROOM
            and row.get("did") == stage["our_did"]
            and row.get("text") == preview["accept_line"]
            and isinstance(row.get("seq"), int)
            and isinstance(row.get("ts"), str)
            and isinstance(row.get("nonce"), str)
            and row["nonce"].isdigit()
            and isinstance(row.get("hash"), str)
            and _HEX64.fullmatch(row["hash"])
        ):
            matches.append(row)
    if len(matches) > 1:
        raise LockError("accept_activity_ambiguous")
    return matches[0] if matches else None


def _messages(payload: object) -> list[dict]:
    if isinstance(payload, dict):
        rows = payload.get("messages", [])
    elif isinstance(payload, list):
        rows = payload
    else:
        raise LockError("room_read_invalid")
    if not isinstance(rows, list) or len(rows) > 200 or not all(isinstance(row, dict) for row in rows):
        raise LockError("room_read_invalid")
    return rows


def _read_note_optional(namespace: str, key: str) -> str | None:
    try:
        return core.read_note(namespace, key)
    except httpx.HTTPStatusError as error:
        if error.response.status_code == 404:
            return None
        raise


def _bridge_environment() -> dict[str, str]:
    return tclk_watch._node_environment()


def _run_bridge(request: dict) -> dict:
    env = _bridge_environment()
    if not shutil.which("node", path=env.get("PATH")):
        raise LockError("node_unavailable")
    if not BRIDGE.is_file():
        raise LockError("lock_bridge_unavailable")
    package = BRIDGE.parent.parent / "node_modules" / "@flop-labs" / "tclk" / "package.json"
    if not package.is_file():
        raise LockError("pinned_runtime_unavailable")
    try:
        result = subprocess.run(
            ["node", str(BRIDGE)],
            input=json.dumps(request, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise LockError("lock_bridge_failed") from error
    if result.returncode != 0:
        cause = RuntimeError((result.stderr or "bridge returned nonzero")[:200])
        raise LockError("lock_bridge_failed") from cause
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LockError("lock_bridge_failed") from error
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise LockError("lock_bridge_output_invalid")
    if any(key in value for key in ("secret", "preimage", "seed", "private_key")):
        raise LockError("lock_bridge_output_invalid")
    return value


def _validate_evidence(value: object) -> dict:
    required = {
        "schema_version", "status", "observed_at", "stage_id", "stage_digest", "offer_id",
        "counterpart_did", "our_did", "job_id", "contract_id", "deal_room",
        "accept_activity_hash", "accept_line_sha256", "accept_seq", "accept_ts",
        "lock_from", "lock_ref", "lock_seq", "lock_timestamp_ms", "lock_line_sha256",
        "paper_note_namespace", "paper_note_key", "paper_note_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise LockError("lock_evidence_invalid")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("status") != "lock_verified":
        raise LockError("lock_evidence_invalid")
    if not isinstance(value.get("observed_at"), str):
        raise LockError("lock_evidence_invalid")
    if not isinstance(value.get("stage_id"), str) or not _HEX32.fullmatch(value["stage_id"]):
        raise LockError("lock_evidence_invalid")
    for field in ("stage_digest", "accept_activity_hash", "accept_line_sha256", "lock_line_sha256", "paper_note_sha256"):
        if not isinstance(value.get(field), str) or not _HEX64.fullmatch(value[field]):
            raise LockError("lock_evidence_invalid")
    if not isinstance(value.get("offer_id"), str) or not _CONTRACT.fullmatch(value["offer_id"]):
        raise LockError("lock_evidence_invalid")
    if not isinstance(value.get("contract_id"), str) or not _CONTRACT.fullmatch(value["contract_id"]):
        raise LockError("lock_evidence_invalid")
    if not isinstance(value.get("deal_room"), str) or not _DEAL_ROOM.fullmatch(value["deal_room"]):
        raise LockError("lock_evidence_invalid")
    for field in ("counterpart_did", "our_did", "lock_from"):
        if not isinstance(value.get(field), str) or not _DID.fullmatch(value[field]):
            raise LockError("lock_evidence_invalid")
    if value["lock_from"] != value["counterpart_did"] or value.get("lock_ref") != value["contract_id"]:
        raise LockError("lock_evidence_invalid")
    if not isinstance(value.get("job_id"), str) or not value["job_id"]:
        raise LockError("lock_evidence_invalid")
    if not isinstance(value.get("accept_seq"), int) or value["accept_seq"] < 0 or not isinstance(value.get("lock_seq"), int) or value["lock_seq"] < 0:
        raise LockError("lock_evidence_invalid")
    if not isinstance(value.get("accept_ts"), str) or not isinstance(value.get("lock_timestamp_ms"), int) or value["lock_timestamp_ms"] < 0:
        raise LockError("lock_evidence_invalid")
    if not isinstance(value.get("paper_note_namespace"), str) or not isinstance(value.get("paper_note_key"), str):
        raise LockError("lock_evidence_invalid")
    return value


def load_evidence(stage_id: str) -> dict | None:
    path = evidence_path(stage_id)
    if not path.exists():
        return None
    try:
        return _validate_evidence(json.loads(path.read_text("utf-8")))
    except (OSError, json.JSONDecodeError) as error:
        raise LockError("lock_evidence_invalid") from error


def inspect_stage(
    stage_id: str,
    *,
    room_reader: Callable[..., object] = core.read_room,
    note_reader: Callable[[str, str], str | None] = _read_note_optional,
    activities: list[dict] | None = None,
) -> dict:
    try:
        stage = tclk_pilot.load_stage(stage_id, require_live=False)
        preview = tclk_pilot_signer._load_preview(stage_id)
        if preview is None:
            return {"action": "waiting_prepare", "stage_id": stage_id}
        tclk_pilot_signer._require_preview_binding(preview, stage)
    except (tclk_pilot.PilotError, tclk_pilot_signer.PrepareError) as error:
        raise LockError("public_accept_binding_invalid") from error

    if stage.get("rail") != "paper" or stage.get("lock") != "hash":
        raise LockError("first_pilot_terms_invalid")
    if not _DID.fullmatch(stage.get("counterpart_did", "")) or not _DID.fullmatch(stage.get("our_did", "")):
        raise LockError("first_pilot_terms_invalid")
    if hmac.compare_digest(stage["counterpart_did"], stage["our_did"]):
        raise LockError("first_pilot_terms_invalid")

    activity_rows = _load_activities() if activities is None else activities
    activity = _matching_accept_activity(stage, preview, activity_rows)
    if activity is None:
        return {"action": "waiting_accept", "stage_id": stage_id}

    contract_id = preview.get("contract_id")
    deal_room = preview.get("deal_room")
    if not isinstance(contract_id, str) or not _CONTRACT.fullmatch(contract_id) or not isinstance(deal_room, str) or not _DEAL_ROOM.fullmatch(deal_room):
        raise LockError("public_accept_binding_invalid")
    namespace, key = _paper_note_location(contract_id)

    try:
        offer_payload = room_reader(tclk_watch.OFFER_ROOM, limit=200, cache_buster=secrets.token_hex(16))
        deal_payload = room_reader(deal_room, limit=200, cache_buster=secrets.token_hex(16))
        paper_value = note_reader(namespace, key)
    except Exception as error:
        raise LockError("lock_source_unavailable") from error
    if paper_value is not None and not isinstance(paper_value, str):
        raise LockError("paper_note_invalid")

    request = {
        "contract_id": contract_id,
        "deal_room": deal_room,
        "offer_records": _messages(offer_payload),
        "deal_records": _messages(deal_payload),
        "paper_note_value": paper_value,
    }
    result = _run_bridge(request)
    if result.get("contract_id") != contract_id or result.get("deal_room") != deal_room:
        raise LockError("transcript_binding_mismatch")
    if result.get("status") == "accept_not_found":
        raise LockError("posted_accept_not_observed")

    expected_namespace, expected_key = _paper_note_location(contract_id)
    checks = (
        result.get("offer_id") == stage["offer_id"],
        result.get("offer_from") == stage["counterpart_did"],
        result.get("offer_role") == "payer",
        result.get("accept_from") == stage["our_did"],
        result.get("accept_nonce") == activity["nonce"],
        result.get("accept_seq") == activity["seq"],
        result.get("accept_timestamp_ms") == _timestamp_ms(activity["ts"]),
        result.get("accept_line_sha256") == preview["accept_sha256"],
        result.get("paper_note_namespace") == expected_namespace,
        result.get("paper_note_key") == expected_key,
    )
    if not all(checks):
        raise LockError("transcript_binding_mismatch")

    if result.get("lock_present") is not True:
        return {"action": "waiting_lock", "stage_id": stage_id, "contract_id": contract_id}
    if (
        result.get("lock_verified") is not True
        or result.get("status") != "locked"
        or result.get("lock_from") != stage["counterpart_did"]
        or result.get("lock_rail") != "paper"
        or result.get("lock_ref") != contract_id
        or not isinstance(result.get("lock_seq"), int)
        or not isinstance(result.get("lock_timestamp_ms"), int)
        or not isinstance(result.get("lock_line_sha256"), str)
        or not _HEX64.fullmatch(result["lock_line_sha256"])
        or not isinstance(result.get("paper_note_sha256"), str)
        or not _HEX64.fullmatch(result["paper_note_sha256"])
    ):
        return {"action": "waiting_verified_paper_lock", "stage_id": stage_id, "contract_id": contract_id}

    evidence = {
        "schema_version": SCHEMA_VERSION,
        "status": "lock_verified",
        "observed_at": _now(),
        "stage_id": stage["stage_id"],
        "stage_digest": stage["stage_digest"],
        "offer_id": stage["offer_id"],
        "counterpart_did": stage["counterpart_did"],
        "our_did": stage["our_did"],
        "job_id": stage["job_id"],
        "contract_id": contract_id,
        "deal_room": deal_room,
        "accept_activity_hash": activity["hash"],
        "accept_line_sha256": preview["accept_sha256"],
        "accept_seq": activity["seq"],
        "accept_ts": activity["ts"],
        "lock_from": result["lock_from"],
        "lock_ref": result["lock_ref"],
        "lock_seq": result["lock_seq"],
        "lock_timestamp_ms": result["lock_timestamp_ms"],
        "lock_line_sha256": result["lock_line_sha256"],
        "paper_note_namespace": expected_namespace,
        "paper_note_key": expected_key,
        "paper_note_sha256": result["paper_note_sha256"],
    }
    _validate_evidence(evidence)

    existing = load_evidence(stage_id)
    if existing is not None:
        comparable = dict(existing)
        comparable["observed_at"] = evidence["observed_at"]
        if comparable != evidence:
            raise LockError("lock_evidence_conflict")
        return {"action": "already_verified", "evidence": existing}

    try:
        evidence_dir().mkdir(parents=True, exist_ok=True, mode=0o770)
        observer.atomic_json_write(evidence_path(stage_id), evidence, compact=True, mode=0o640)
    except OSError as error:
        raise LockError("lock_evidence_persistence_failed") from error
    return {"action": "lock_verified", "evidence": evidence}


def scan_pending(*, max_count: int = MAX_SCAN) -> dict:
    if not isinstance(max_count, int) or not 1 <= max_count <= 8:
        raise LockError("invalid_scan_batch")
    activities = _load_activities()
    try:
        preview_paths = sorted(tclk_pilot.preview_dir().glob("*.json"), key=lambda path: path.stat().st_mtime)
    except OSError as error:
        raise LockError("preview_store_unavailable") from error
    results = []
    for path in preview_paths:
        if len(results) >= max_count:
            break
        stage_id = path.stem
        try:
            if load_evidence(stage_id) is not None:
                continue
            stage = tclk_pilot.load_stage(stage_id, require_live=False)
            preview = tclk_pilot_signer._load_preview(stage_id)
            if preview is None or _matching_accept_activity(stage, preview, activities) is None:
                continue
            results.append(inspect_stage(stage_id, activities=activities))
        except LockError as error:
            results.append({"action": "error", "stage_id": stage_id, "error": str(error)})
    return {"count": len(results), "results": results}


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("tclk pilot lock watcher accepts no arguments")
    try:
        result = scan_pending()
    except LockError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        raise SystemExit(1)
    print(json.dumps({"ok": True, **result}, sort_keys=True))


if __name__ == "__main__":
    main()
