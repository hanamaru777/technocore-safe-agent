"""Signer-isolated PREPARE-only reveal path for the first genuine tclk/1 PaperRail pilot.

A reveal publishes the hash-lock preimage, so the exact reveal line is never exposed through
this module's public state or stdout. The signer-private Node bridge alone reads the existing
accept preimage and persists the exact reveal line under 0600. Shared state receives only a
hash-bound preview after the authenticated lock and deterministic work evidence are revalidated.
No transport signature, POST, Note write, receipt, payment, or arbitrary task execution occurs.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import core, observer, tclk_pilot, tclk_pilot_lock, tclk_pilot_signer, tclk_pilot_work

SCHEMA_VERSION = 1
MIN_REVEAL_PREPARE_MS = 120_000
BRIDGE = Path(__file__).resolve().parents[2] / "tools" / "tclk_prepare_reveal.mjs"

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CONTRACT = re.compile(r"^0x[0-9a-f]{64}$")
_DEAL_ROOM = re.compile(r"^mb-p-tclk-[0-9a-f]{16}$")
_DID = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}$")
_KEY = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")


class RevealPrepareError(RuntimeError):
    """Stable public-safe failure from the reveal PREPARE boundary."""


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def preview_dir() -> Path:
    return tclk_pilot.pilot_root() / "reveal-previews"


def preview_path(stage_id: str) -> Path:
    if not isinstance(stage_id, str) or not _HEX32.fullmatch(stage_id):
        raise RevealPrepareError("invalid_stage_id")
    return preview_dir() / f"{stage_id}.json"


def private_reveal_dir() -> Path:
    return core.STATE / "signer" / "tclk-pilot-reveals"


def private_reveal_path(stage_id: str) -> Path:
    if not isinstance(stage_id, str) or not _HEX32.fullmatch(stage_id):
        raise RevealPrepareError("invalid_stage_id")
    return private_reveal_dir() / f"{stage_id}.json"


def _require_private_reveal(stage_id: str) -> Path:
    path = private_reveal_path(stage_id)
    if not path.is_file():
        raise RevealPrepareError("private_reveal_missing")
    try:
        if (path.stat().st_mode & 0o777) != 0o600:
            raise RevealPrepareError("private_reveal_permissions_invalid")
    except OSError as error:
        raise RevealPrepareError("private_reveal_missing") from error
    return path


def _validate_public_preview(value: object) -> dict:
    required = {
        "schema_version", "status", "prepared_at", "stage_id", "stage_digest", "offer_id",
        "counterpart_did", "our_did", "job_id", "contract_id", "deal_room", "accept_sha256",
        "lock_line_sha256", "lock_ref", "paper_note_sha256", "work_evidence_sha256",
        "expires_ms", "claim_by_ms", "refund_after_ms", "reveal_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise RevealPrepareError("reveal_preview_invalid")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("status") != "prepared":
        raise RevealPrepareError("reveal_preview_invalid")
    if not isinstance(value.get("prepared_at"), str):
        raise RevealPrepareError("reveal_preview_invalid")
    if not isinstance(value.get("stage_id"), str) or not _HEX32.fullmatch(value["stage_id"]):
        raise RevealPrepareError("reveal_preview_invalid")
    for field in (
        "stage_digest", "accept_sha256", "lock_line_sha256", "paper_note_sha256",
        "work_evidence_sha256", "reveal_sha256",
    ):
        if not isinstance(value.get(field), str) or not _HEX64.fullmatch(value[field]):
            raise RevealPrepareError("reveal_preview_invalid")
    for field in ("offer_id", "contract_id", "lock_ref"):
        if not isinstance(value.get(field), str) or not _CONTRACT.fullmatch(value[field]):
            raise RevealPrepareError("reveal_preview_invalid")
    for field in ("counterpart_did", "our_did"):
        if not isinstance(value.get(field), str) or not _DID.fullmatch(value[field]):
            raise RevealPrepareError("reveal_preview_invalid")
    if hmac.compare_digest(value["counterpart_did"], value["our_did"]):
        raise RevealPrepareError("reveal_preview_invalid")
    if not isinstance(value.get("job_id"), str) or not _KEY.fullmatch(value["job_id"]):
        raise RevealPrepareError("reveal_preview_invalid")
    if value["lock_ref"] != value["contract_id"]:
        raise RevealPrepareError("reveal_preview_invalid")
    if not isinstance(value.get("deal_room"), str) or not _DEAL_ROOM.fullmatch(value["deal_room"]):
        raise RevealPrepareError("reveal_preview_invalid")
    if value["deal_room"] != f"mb-p-tclk-{value['contract_id'][2:18]}":
        raise RevealPrepareError("reveal_preview_invalid")
    for field in ("expires_ms", "claim_by_ms", "refund_after_ms"):
        if not isinstance(value.get(field), int) or value[field] <= 0:
            raise RevealPrepareError("reveal_preview_invalid")
    if value["claim_by_ms"] >= value["refund_after_ms"]:
        raise RevealPrepareError("reveal_preview_invalid")
    return value


def load_preview(stage_id: str) -> dict | None:
    path = preview_path(stage_id)
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RevealPrepareError("reveal_preview_invalid") from error
    return _validate_public_preview(value)


def _require_bindings(stage: dict, accept: dict, lock: dict, work: dict) -> dict:
    try:
        tclk_pilot_signer._require_preview_binding(accept, stage)
    except tclk_pilot_signer.PrepareError as error:
        raise RevealPrepareError("accept_binding_invalid") from error
    contract_id = accept.get("contract_id")
    deal_room = accept.get("deal_room")
    accept_hash = accept.get("accept_sha256")
    counterpart = stage.get("counterpart_did")
    our_did = stage.get("our_did")
    job_id = stage.get("job_id")
    if (
        not isinstance(contract_id, str)
        or not _CONTRACT.fullmatch(contract_id)
        or not isinstance(deal_room, str)
        or not _DEAL_ROOM.fullmatch(deal_room)
        or deal_room != f"mb-p-tclk-{contract_id[2:18]}"
        or not isinstance(accept_hash, str)
        or not _HEX64.fullmatch(accept_hash)
        or not isinstance(counterpart, str)
        or not _DID.fullmatch(counterpart)
        or not isinstance(our_did, str)
        or not _DID.fullmatch(our_did)
        or hmac.compare_digest(counterpart, our_did)
        or not isinstance(job_id, str)
        or not _KEY.fullmatch(job_id)
    ):
        raise RevealPrepareError("accept_binding_invalid")
    if (
        lock.get("status") != "lock_verified"
        or lock.get("stage_id") != stage["stage_id"]
        or lock.get("stage_digest") != stage["stage_digest"]
        or lock.get("offer_id") != stage["offer_id"]
        or lock.get("counterpart_did") != counterpart
        or lock.get("our_did") != our_did
        or lock.get("job_id") != job_id
        or lock.get("contract_id") != contract_id
        or lock.get("deal_room") != deal_room
        or lock.get("accept_line_sha256") != accept_hash
        or lock.get("lock_from") != counterpart
        or lock.get("lock_ref") != contract_id
    ):
        raise RevealPrepareError("lock_binding_invalid")
    if (
        work.get("status") != "work_ready"
        or work.get("stage_id") != stage["stage_id"]
        or work.get("stage_digest") != stage["stage_digest"]
        or work.get("offer_id") != stage["offer_id"]
        or work.get("counterpart_did") != counterpart
        or work.get("our_did") != our_did
        or work.get("job_id") != job_id
        or work.get("contract_id") != contract_id
        or work.get("deal_room") != deal_room
        or work.get("accept_sha256") != accept_hash
        or work.get("lock_line_sha256") != lock.get("lock_line_sha256")
        or work.get("lock_ref") != contract_id
        or work.get("paper_note_sha256") != lock.get("paper_note_sha256")
        or work.get("full_spec_sha256") != stage["full_spec_sha256"]
        or work.get("material_sha256") != stage["material_sha256"]
    ):
        raise RevealPrepareError("work_binding_invalid")
    work_hash = work.get("work_evidence_sha256")
    if not isinstance(work_hash, str) or not _HEX64.fullmatch(work_hash):
        raise RevealPrepareError("work_binding_invalid")
    return {
        "stage_id": stage["stage_id"],
        "stage_digest": stage["stage_digest"],
        "offer_id": stage["offer_id"],
        "offer_line": stage["offer_line"],
        "counterpart_did": counterpart,
        "our_did": our_did,
        "job_id": job_id,
        "accept_line": accept["accept_line"],
        "accept_sha256": accept_hash,
        "contract_id": contract_id,
        "deal_room": deal_room,
        "lock_line_sha256": lock["lock_line_sha256"],
        "lock_ref": lock["lock_ref"],
        "paper_note_sha256": lock["paper_note_sha256"],
        "work_evidence_sha256": work_hash,
        "expires_ms": stage["expires_ms"],
    }


def _live_reverify_lock(stage_id: str, expected: dict) -> None:
    try:
        result = tclk_pilot_lock.inspect_stage(stage_id)
    except tclk_pilot_lock.LockError as error:
        raise RevealPrepareError("live_lock_revalidation_failed") from error
    if result.get("action") != "already_verified" or not isinstance(result.get("evidence"), dict):
        raise RevealPrepareError("live_lock_revalidation_failed")
    actual = result["evidence"]
    for field in (
        "stage_id", "stage_digest", "offer_id", "counterpart_did", "our_did", "job_id",
        "contract_id", "deal_room", "accept_line_sha256", "lock_line_sha256", "lock_ref",
        "paper_note_sha256",
    ):
        source = expected["accept_sha256"] if field == "accept_line_sha256" else expected.get(field)
        if actual.get(field) != source:
            raise RevealPrepareError("live_lock_binding_changed")


def _bridge_environment() -> dict[str, str]:
    allowed = {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP"}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    env["FLOP_STATE_DIR"] = str(core.STATE)
    return env


def _run_bridge(request: dict) -> dict:
    env = _bridge_environment()
    if not shutil.which("node", path=env.get("PATH")):
        raise RevealPrepareError("node_unavailable")
    if not BRIDGE.is_file():
        raise RevealPrepareError("reveal_bridge_unavailable")
    package = BRIDGE.parent.parent / "node_modules" / "@flop-labs" / "tclk" / "package.json"
    if not package.is_file():
        raise RevealPrepareError("pinned_runtime_unavailable")
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
        raise RevealPrepareError("reveal_bridge_failed") from error
    if result.returncode != 0:
        raise RevealPrepareError("reveal_bridge_failed")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RevealPrepareError("reveal_bridge_failed") from error
    required = {
        "stage_id", "stage_digest", "offer_id", "counterpart_did", "our_did", "job_id",
        "contract_id", "deal_room", "accept_sha256", "lock_line_sha256", "lock_ref",
        "paper_note_sha256", "work_evidence_sha256", "expires_ms", "claim_by_ms",
        "refund_after_ms", "reveal_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise RevealPrepareError("reveal_bridge_output_invalid")
    if any(key in value for key in ("secret", "preimage", "reveal_line", "seed", "private_key")):
        raise RevealPrepareError("reveal_bridge_output_invalid")
    for field in (
        "stage_id", "stage_digest", "offer_id", "counterpart_did", "our_did", "job_id",
        "contract_id", "deal_room", "accept_sha256", "lock_line_sha256", "lock_ref",
        "paper_note_sha256", "work_evidence_sha256", "expires_ms",
    ):
        if value.get(field) != request.get(field):
            raise RevealPrepareError("reveal_bridge_binding_mismatch")
    if not isinstance(value.get("reveal_sha256"), str) or not _HEX64.fullmatch(value["reveal_sha256"]):
        raise RevealPrepareError("reveal_bridge_output_invalid")
    if not isinstance(value.get("claim_by_ms"), int) or not isinstance(value.get("refund_after_ms"), int):
        raise RevealPrepareError("reveal_bridge_output_invalid")
    if value["claim_by_ms"] >= value["refund_after_ms"]:
        raise RevealPrepareError("reveal_bridge_output_invalid")
    return value


def _require_preview_binding(preview: dict, request: dict) -> None:
    for field in (
        "stage_id", "stage_digest", "offer_id", "counterpart_did", "our_did", "job_id",
        "contract_id", "deal_room", "accept_sha256", "lock_line_sha256", "lock_ref",
        "paper_note_sha256", "work_evidence_sha256", "expires_ms",
    ):
        if preview.get(field) != request.get(field):
            raise RevealPrepareError("reveal_preview_binding_mismatch")


def prepare_stage(stage_id: str, *, now_ms: int | None = None) -> dict:
    current = _now_ms() if now_ms is None else now_ms
    try:
        stage = tclk_pilot.load_stage(stage_id, require_live=False)
        accept = tclk_pilot_signer._load_preview(stage_id)
        lock = tclk_pilot_lock.load_evidence(stage_id)
        work = tclk_pilot_work.load_evidence(stage_id)
    except (tclk_pilot.PilotError, tclk_pilot_signer.PrepareError, tclk_pilot_lock.LockError, tclk_pilot_work.WorkError) as error:
        raise RevealPrepareError("reveal_source_invalid") from error
    if accept is None or lock is None or work is None:
        raise RevealPrepareError("reveal_source_missing")
    try:
        expected_did = tclk_pilot_signer._expected_did()
    except tclk_pilot_signer.PrepareError as error:
        raise RevealPrepareError("expected_did_unavailable") from error
    if not hmac.compare_digest(expected_did, stage.get("our_did", "")):
        raise RevealPrepareError("stage_did_mismatch")
    request = _require_bindings(stage, accept, lock, work)

    existing = load_preview(stage_id)
    if existing is not None:
        _require_preview_binding(existing, request)
        _require_private_reveal(stage_id)
        return {"action": "already_prepared", "preview": existing}

    recovering = private_reveal_path(stage_id).exists()
    if recovering:
        _require_private_reveal(stage_id)

    _live_reverify_lock(stage_id, request)
    prepared = _run_bridge(request)
    if prepared["claim_by_ms"] - current < MIN_REVEAL_PREPARE_MS:
        raise RevealPrepareError("reveal_prepare_window_elapsed")
    _require_private_reveal(stage_id)

    preview = {
        "schema_version": SCHEMA_VERSION,
        "status": "prepared",
        "prepared_at": datetime.fromtimestamp(current / 1000, UTC).isoformat(),
        **prepared,
    }
    _validate_public_preview(preview)
    _require_preview_binding(preview, request)
    try:
        preview_dir().mkdir(parents=True, exist_ok=True, mode=0o770)
        observer.atomic_json_write(preview_path(stage_id), preview, compact=True, mode=0o640)
    except OSError as error:
        raise RevealPrepareError("reveal_preview_persistence_failed") from error
    return {"action": "recovered" if recovering else "prepared", "preview": preview}


def prepare_next() -> dict:
    try:
        paths = sorted(tclk_pilot_work.evidence_dir().glob("*.json"), key=lambda path: path.stat().st_mtime)
    except OSError as error:
        raise RevealPrepareError("work_store_unavailable") from error
    for path in paths:
        stage_id = path.stem
        try:
            work = tclk_pilot_work.load_evidence(stage_id)
        except tclk_pilot_work.WorkError as error:
            raise RevealPrepareError("work_source_invalid") from error
        if work is None or work.get("status") != "work_ready":
            continue
        existing = load_preview(stage_id)
        if existing is not None:
            _require_private_reveal(stage_id)
            continue
        return prepare_stage(stage_id)
    return {"action": "idle", "preview": None}


def public_result(result: dict) -> dict:
    preview = result.get("preview")
    if not isinstance(preview, dict):
        return {"ok": True, "action": result.get("action")}
    return {
        "ok": True,
        "action": result.get("action"),
        "stage_id": preview["stage_id"],
        "stage_digest": preview["stage_digest"],
        "offer_id": preview["offer_id"],
        "counterpart_did": preview["counterpart_did"],
        "our_did": preview["our_did"],
        "job_id": preview["job_id"],
        "contract_id": preview["contract_id"],
        "deal_room": preview["deal_room"],
        "work_evidence_sha256": preview["work_evidence_sha256"],
        "reveal_sha256": preview["reveal_sha256"],
        "claim_by_ms": preview["claim_by_ms"],
        "refund_after_ms": preview["refund_after_ms"],
    }


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("tclk reveal preparer accepts no arguments")
    try:
        result = prepare_next()
    except RevealPrepareError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        raise SystemExit(1)
    print(json.dumps(public_result(result), sort_keys=True))


if __name__ == "__main__":
    main()
