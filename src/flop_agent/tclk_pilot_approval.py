"""Exact root-operator approval record for the first genuine tclk/1 pilot.

This module never signs or posts.  It accepts only a stage id, the full approval
digest shown by the prepared preview, and the literal ``APPROVE``.  The caller
(root-owned wrapper in production) is responsible for persisting the returned
record as a root-owned file readable by the isolated signer.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import core, tclk_pilot, tclk_pilot_signer

SCHEMA_VERSION = 1
MIN_APPROVAL_SECONDS = 90

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OFFER_ID = re.compile(r"^0x[0-9a-f]{64}$")
_DEAL_ROOM = re.compile(r"^mb-p-tclk-[0-9a-f]{16}$")


class ApprovalError(RuntimeError):
    """Stable fail-closed error for the exact human approval boundary."""


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def approval_dir() -> Path:
    return core.STATE / "signer" / "tclk-pilot-approvals"


def approval_path(stage_id: str) -> Path:
    if not isinstance(stage_id, str) or not _HEX32.fullmatch(stage_id):
        raise ApprovalError("invalid_stage_id")
    return approval_dir() / f"{stage_id}.json"


def _canonical(value: dict) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _bindings(stage: dict, preview: dict) -> dict:
    required_stage = {
        "stage_id", "stage_digest", "offer_id", "frame_sha256", "full_spec_sha256",
        "material_sha256", "expires_ms",
    }
    required_preview = {
        "stage_id", "stage_digest", "offer_id", "frame_sha256", "full_spec_sha256",
        "material_sha256", "expires_ms", "accept_sha256", "contract_id", "deal_room",
    }
    if not required_stage <= set(stage) or not required_preview <= set(preview):
        raise ApprovalError("approval_binding_missing")
    if any(stage[field] != preview[field] for field in required_stage):
        raise ApprovalError("approval_binding_mismatch")
    if not _HEX32.fullmatch(str(stage["stage_id"])) or not _HEX64.fullmatch(str(stage["stage_digest"])):
        raise ApprovalError("approval_binding_invalid")
    if not _OFFER_ID.fullmatch(str(stage["offer_id"])):
        raise ApprovalError("approval_binding_invalid")
    for field in ("frame_sha256", "full_spec_sha256", "accept_sha256"):
        value = preview[field]
        if not isinstance(value, str) or not _HEX64.fullmatch(value):
            raise ApprovalError("approval_binding_invalid")
    material = preview["material_sha256"]
    if material is not None and (not isinstance(material, str) or not _HEX64.fullmatch(material)):
        raise ApprovalError("approval_binding_invalid")
    if not isinstance(preview["contract_id"], str) or not _OFFER_ID.fullmatch(preview["contract_id"]):
        raise ApprovalError("approval_binding_invalid")
    if not isinstance(preview["deal_room"], str) or not _DEAL_ROOM.fullmatch(preview["deal_room"]):
        raise ApprovalError("approval_binding_invalid")
    if not isinstance(preview["expires_ms"], int) or preview["expires_ms"] <= 0:
        raise ApprovalError("approval_binding_invalid")
    return {
        "stage_id": preview["stage_id"],
        "stage_digest": preview["stage_digest"],
        "offer_id": preview["offer_id"],
        "frame_sha256": preview["frame_sha256"],
        "full_spec_sha256": preview["full_spec_sha256"],
        "material_sha256": preview["material_sha256"],
        "accept_sha256": preview["accept_sha256"],
        "contract_id": preview["contract_id"],
        "deal_room": preview["deal_room"],
        "expires_ms": preview["expires_ms"],
    }


def approval_digest(stage: dict, preview: dict) -> str:
    return hashlib.sha256(("technocore-safe-agent|tclk-first-pilot-approval|" + _canonical(_bindings(stage, preview))).encode("ascii")).hexdigest()


def prepared_approval(stage_id: str, *, now_ms: int | None = None) -> dict:
    current = _now_ms() if now_ms is None else now_ms
    try:
        stage = tclk_pilot.load_stage(stage_id, now_ms=current, require_live=False)
    except tclk_pilot.PilotError as error:
        raise ApprovalError(str(error)) from error
    if stage["expires_ms"] - current < MIN_APPROVAL_SECONDS * 1000:
        raise ApprovalError("approval_window_elapsed")
    preview = tclk_pilot_signer._load_preview(stage_id)
    if preview is None:
        raise ApprovalError("preview_missing")
    tclk_pilot_signer._require_preview_binding(preview, stage)
    tclk_pilot_signer._require_protocol_file(stage_id)
    bindings = _bindings(stage, preview)
    return {"stage": stage, "preview": preview, "bindings": bindings, "approval_digest": approval_digest(stage, preview)}


def build_approval(stage_id: str, supplied_digest: str, *, now_ms: int | None = None) -> dict:
    if not isinstance(supplied_digest, str) or not _HEX64.fullmatch(supplied_digest):
        raise ApprovalError("approval_digest_invalid")
    current = _now_ms() if now_ms is None else now_ms
    prepared = prepared_approval(stage_id, now_ms=current)
    expected = prepared["approval_digest"]
    if not hmac.compare_digest(expected, supplied_digest):
        raise ApprovalError("approval_digest_mismatch")
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "approved",
        "approved_at": datetime.fromtimestamp(current / 1000, UTC).isoformat(),
        "approval_digest": expected,
        **prepared["bindings"],
    }


def validate_approval(record: object, stage: dict, preview: dict, *, now_ms: int | None = None) -> dict:
    required = {
        "schema_version", "status", "approved_at", "approval_digest", "stage_id", "stage_digest",
        "offer_id", "frame_sha256", "full_spec_sha256", "material_sha256", "accept_sha256",
        "contract_id", "deal_room", "expires_ms",
    }
    if not isinstance(record, dict) or set(record) != required:
        raise ApprovalError("approval_schema_invalid")
    if record.get("schema_version") != SCHEMA_VERSION or record.get("status") != "approved":
        raise ApprovalError("approval_schema_invalid")
    if not isinstance(record.get("approved_at"), str):
        raise ApprovalError("approval_schema_invalid")
    digest = record.get("approval_digest")
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise ApprovalError("approval_schema_invalid")
    bindings = _bindings(stage, preview)
    if any(record.get(field) != value for field, value in bindings.items()):
        raise ApprovalError("approval_binding_mismatch")
    expected = approval_digest(stage, preview)
    if not hmac.compare_digest(digest, expected):
        raise ApprovalError("approval_digest_mismatch")
    current = _now_ms() if now_ms is None else now_ms
    if record["expires_ms"] - current < MIN_APPROVAL_SECONDS * 1000:
        raise ApprovalError("approval_window_elapsed")
    return record


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[3] != "APPROVE":
        raise SystemExit("usage: tclk_pilot_approval <stage-id> <approval-digest> APPROVE")
    try:
        record = build_approval(sys.argv[1], sys.argv[2])
    except ApprovalError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        raise SystemExit(1)
    print(_canonical(record))


if __name__ == "__main__":
    main()
