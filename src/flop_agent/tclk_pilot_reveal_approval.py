"""Separate exact human approval for publishing a prepared tclk PaperRail reveal.

Accept approval never authorizes reveal.  This module is public-state-only until the
strong root path additionally proves the signer-private reveal file exists with mode
0600.  It never signs, posts, claims a Note, or exposes the reveal line/preimage.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
from datetime import UTC, datetime

from . import tclk_pilot_reveal

SCHEMA_VERSION = 1
MIN_REVEAL_APPROVAL_MS = 90_000

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CONTRACT = re.compile(r"^0x[0-9a-f]{64}$")


class RevealApprovalError(RuntimeError):
    """Stable fail-closed error for the reveal approval boundary."""


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def approval_dir():
    from . import core
    return core.STATE / "signer" / "tclk-pilot-reveal-approvals"


def approval_path(stage_id: str):
    if not isinstance(stage_id, str) or not _HEX32.fullmatch(stage_id):
        raise RevealApprovalError("invalid_stage_id")
    return approval_dir() / f"{stage_id}.json"


def _canonical(value: dict) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _bindings(preview: dict) -> dict:
    try:
        value = tclk_pilot_reveal._validate_public_preview(dict(preview))
    except tclk_pilot_reveal.RevealPrepareError as error:
        raise RevealApprovalError("reveal_binding_invalid") from error
    return {
        "stage_id": value["stage_id"],
        "stage_digest": value["stage_digest"],
        "offer_id": value["offer_id"],
        "counterpart_did": value["counterpart_did"],
        "our_did": value["our_did"],
        "job_id": value["job_id"],
        "contract_id": value["contract_id"],
        "deal_room": value["deal_room"],
        "accept_sha256": value["accept_sha256"],
        "lock_line_sha256": value["lock_line_sha256"],
        "lock_ref": value["lock_ref"],
        "paper_note_sha256": value["paper_note_sha256"],
        "work_evidence_sha256": value["work_evidence_sha256"],
        "expires_ms": value["expires_ms"],
        "claim_by_ms": value["claim_by_ms"],
        "refund_after_ms": value["refund_after_ms"],
        "reveal_sha256": value["reveal_sha256"],
    }


def approval_digest(preview: dict) -> str:
    payload = "technocore-safe-agent|tclk-first-pilot-reveal-approval|" + _canonical(_bindings(preview))
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def public_prepared_approval(stage_id: str, *, now_ms: int | None = None) -> dict:
    current = _now_ms() if now_ms is None else now_ms
    try:
        preview = tclk_pilot_reveal.load_preview(stage_id)
    except tclk_pilot_reveal.RevealPrepareError as error:
        raise RevealApprovalError(str(error)) from error
    if preview is None:
        raise RevealApprovalError("reveal_preview_missing")
    bindings = _bindings(preview)
    if bindings["claim_by_ms"] - current < MIN_REVEAL_APPROVAL_MS:
        raise RevealApprovalError("reveal_approval_window_elapsed")
    return {
        "preview": preview,
        "bindings": bindings,
        "approval_digest": approval_digest(preview),
    }


def prepared_approval(stage_id: str, *, now_ms: int | None = None) -> dict:
    prepared = public_prepared_approval(stage_id, now_ms=now_ms)
    try:
        tclk_pilot_reveal._require_private_reveal(stage_id)
    except tclk_pilot_reveal.RevealPrepareError as error:
        raise RevealApprovalError(str(error)) from error
    return prepared


def build_approval(stage_id: str, supplied_digest: str, *, now_ms: int | None = None) -> dict:
    if not isinstance(supplied_digest, str) or not _HEX64.fullmatch(supplied_digest):
        raise RevealApprovalError("reveal_approval_digest_invalid")
    current = _now_ms() if now_ms is None else now_ms
    prepared = prepared_approval(stage_id, now_ms=current)
    expected = prepared["approval_digest"]
    if not hmac.compare_digest(expected, supplied_digest):
        raise RevealApprovalError("reveal_approval_digest_mismatch")
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "approved",
        "approved_at": datetime.fromtimestamp(current / 1000, UTC).isoformat(),
        "approval_digest": expected,
        **prepared["bindings"],
    }


def validate_approval(record: object, preview: dict, *, now_ms: int | None = None) -> dict:
    bindings = _bindings(preview)
    required = {"schema_version", "status", "approved_at", "approval_digest", *bindings.keys()}
    if not isinstance(record, dict) or set(record) != required:
        raise RevealApprovalError("reveal_approval_schema_invalid")
    if record.get("schema_version") != SCHEMA_VERSION or record.get("status") != "approved":
        raise RevealApprovalError("reveal_approval_schema_invalid")
    if not isinstance(record.get("approved_at"), str):
        raise RevealApprovalError("reveal_approval_schema_invalid")
    digest = record.get("approval_digest")
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise RevealApprovalError("reveal_approval_schema_invalid")
    if any(record.get(field) != value for field, value in bindings.items()):
        raise RevealApprovalError("reveal_approval_binding_mismatch")
    expected = approval_digest(preview)
    if not hmac.compare_digest(digest, expected):
        raise RevealApprovalError("reveal_approval_digest_mismatch")
    current = _now_ms() if now_ms is None else now_ms
    if record["claim_by_ms"] - current < MIN_REVEAL_APPROVAL_MS:
        raise RevealApprovalError("reveal_approval_window_elapsed")
    return record


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[3] != "APPROVE_REVEAL":
        raise SystemExit("usage: tclk_pilot_reveal_approval <stage-id> <approval-digest> APPROVE_REVEAL")
    try:
        record = build_approval(sys.argv[1], sys.argv[2])
    except RevealApprovalError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        raise SystemExit(1)
    print(_canonical(record))


if __name__ == "__main__":
    main()
