"""Read-only terminal claimed evidence for the first genuine tclk/1 PaperRail pilot.

The collector starts only from exact durable first-pilot state, re-reads the derived deal
room and the fixed PaperRail Note, verifies transport signatures locally, and delegates
protocol folding to the pinned published tclk runtime. It never signs, posts, writes a
Note, opens Vault material, follows task URLs, or executes task content.
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

from . import (
    core,
    observer,
    tclk_pilot,
    tclk_pilot_lock,
    tclk_pilot_reveal,
    tclk_pilot_reveal_approval,
    tclk_pilot_reveal_publish,
    tclk_pilot_signer,
    tclk_pilot_work,
    tclk_watch,
)
from .public_record import verify_signed_record

SCHEMA_VERSION = 1
MAX_SCAN = 200
BRIDGE = Path(__file__).resolve().parents[2] / "tools" / "tclk_verify_terminal.mjs"

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_CONTRACT = re.compile(r"^0x[0-9a-f]{64}$")
_DID = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}$")
_DEAL_ROOM = re.compile(r"^mb-p-tclk-[0-9a-f]{16}$")
_KEY = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")


class TerminalError(RuntimeError):
    """Stable public-safe terminal collector failure."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _timestamp_ms(value: str) -> int:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise TerminalError("timestamp_invalid") from error
    if parsed.tzinfo is None:
        raise TerminalError("timestamp_invalid")
    result = int(parsed.timestamp() * 1000)
    if result < 0:
        raise TerminalError("timestamp_invalid")
    return result


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as error:
        raise TerminalError("terminal_value_not_canonical") from error


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def evidence_dir() -> Path:
    return tclk_pilot.pilot_root() / "terminal"


def evidence_path(stage_id: str) -> Path:
    if not isinstance(stage_id, str) or not _HEX32.fullmatch(stage_id):
        raise TerminalError("invalid_stage_id")
    return evidence_dir() / f"{stage_id}.json"


def _validate_receipt_fields(value: dict) -> None:
    fields = ("receipt_sha256", "receipt_seq", "receipt_ts", "receipt_from")
    present = [value.get(field) is not None for field in fields]
    if any(present) and not all(present):
        raise TerminalError("terminal_evidence_invalid")
    if not any(present):
        return
    if not isinstance(value["receipt_sha256"], str) or not _HEX64.fullmatch(value["receipt_sha256"]):
        raise TerminalError("terminal_evidence_invalid")
    if not isinstance(value["receipt_seq"], int) or value["receipt_seq"] < 0:
        raise TerminalError("terminal_evidence_invalid")
    if not isinstance(value["receipt_ts"], str):
        raise TerminalError("terminal_evidence_invalid")
    _timestamp_ms(value["receipt_ts"])
    if not isinstance(value["receipt_from"], str) or not _DID.fullmatch(value["receipt_from"]):
        raise TerminalError("terminal_evidence_invalid")
    if value["receipt_from"] not in {value["counterpart_did"], value["our_did"]}:
        raise TerminalError("terminal_evidence_invalid")


def _validate_evidence(value: object) -> dict:
    required = {
        "schema_version", "status", "created_at", "stage_id", "stage_digest", "offer_id",
        "offer_sha256", "offer_seq", "offer_ts", "counterpart_did", "our_did", "job_id",
        "contract_id", "deal_room", "accept_sha256", "accept_seq", "accept_ts",
        "lock_sha256", "lock_seq", "lock_ts", "work_status", "work_evidence_sha256",
        "reveal_sha256", "reveal_seq", "reveal_ts", "paper_note_sha256", "witness_sha256",
        "outcome", "receipt_sha256", "receipt_seq", "receipt_ts", "receipt_from",
        "reveal_publish_git_commit_sha", "git_commit_sha", "terminal_evidence_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise TerminalError("terminal_evidence_invalid")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("status") != "terminal_claimed" or value.get("outcome") != "claimed":
        raise TerminalError("terminal_evidence_invalid")
    if not isinstance(value.get("created_at"), str):
        raise TerminalError("terminal_evidence_invalid")
    _timestamp_ms(value["created_at"])
    if not isinstance(value.get("stage_id"), str) or not _HEX32.fullmatch(value["stage_id"]):
        raise TerminalError("terminal_evidence_invalid")
    for field in (
        "stage_digest", "offer_sha256", "accept_sha256", "lock_sha256", "work_evidence_sha256",
        "reveal_sha256", "paper_note_sha256", "witness_sha256", "terminal_evidence_sha256",
    ):
        if not isinstance(value.get(field), str) or not _HEX64.fullmatch(value[field]):
            raise TerminalError("terminal_evidence_invalid")
    for field in ("reveal_publish_git_commit_sha", "git_commit_sha"):
        if not isinstance(value.get(field), str) or not _GIT_SHA.fullmatch(value[field]):
            raise TerminalError("terminal_evidence_invalid")
    if not isinstance(value.get("offer_id"), str) or not _CONTRACT.fullmatch(value["offer_id"]):
        raise TerminalError("terminal_evidence_invalid")
    if not isinstance(value.get("contract_id"), str) or not _CONTRACT.fullmatch(value["contract_id"]):
        raise TerminalError("terminal_evidence_invalid")
    for field in ("counterpart_did", "our_did"):
        if not isinstance(value.get(field), str) or not _DID.fullmatch(value[field]):
            raise TerminalError("terminal_evidence_invalid")
    if hmac.compare_digest(value["counterpart_did"], value["our_did"]):
        raise TerminalError("terminal_evidence_invalid")
    if not isinstance(value.get("job_id"), str) or not _KEY.fullmatch(value["job_id"]):
        raise TerminalError("terminal_evidence_invalid")
    if not isinstance(value.get("deal_room"), str) or not _DEAL_ROOM.fullmatch(value["deal_room"]):
        raise TerminalError("terminal_evidence_invalid")
    if value["deal_room"] != f"mb-p-tclk-{value['contract_id'][2:18]}":
        raise TerminalError("terminal_evidence_invalid")
    for field in ("offer_seq", "accept_seq", "lock_seq", "reveal_seq"):
        if not isinstance(value.get(field), int) or value[field] < 0:
            raise TerminalError("terminal_evidence_invalid")
    for field in ("offer_ts", "accept_ts", "lock_ts", "reveal_ts"):
        if not isinstance(value.get(field), str):
            raise TerminalError("terminal_evidence_invalid")
        _timestamp_ms(value[field])
    if value.get("work_status") != "work_ready":
        raise TerminalError("terminal_evidence_invalid")
    _validate_receipt_fields(value)
    digest_source = {key: item for key, item in value.items() if key != "terminal_evidence_sha256"}
    if not hmac.compare_digest(_sha(digest_source), value["terminal_evidence_sha256"]):
        raise TerminalError("terminal_evidence_digest_mismatch")
    return value


def load_evidence(stage_id: str) -> dict | None:
    path = evidence_path(stage_id)
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TerminalError("terminal_evidence_invalid") from error
    value = _validate_evidence(value)
    if value["stage_id"] != stage_id:
        raise TerminalError("terminal_evidence_invalid")
    return value


def _retained_offer(stage: dict) -> dict:
    try:
        state = observer.load_state()
    except RuntimeError as error:
        raise TerminalError("observer_state_unavailable") from error
    data = state.get("tclk") if isinstance(state, dict) else None
    offers = data.get("offers") if isinstance(data, dict) else None
    item = offers.get(stage["offer_id"]) if isinstance(offers, dict) else None
    if not isinstance(item, dict):
        raise TerminalError("offer_transport_evidence_missing")
    if (
        item.get("id") != stage["offer_id"]
        or item.get("from") != stage["counterpart_did"]
        or item.get("frame_text") != stage["offer_line"]
        or item.get("frame_sha256") != stage["frame_sha256"]
        or item.get("role") != "payer"
        or item.get("room") != tclk_watch.OFFER_ROOM
        or not isinstance(item.get("seq"), int)
        or item["seq"] < 0
        or not isinstance(item.get("ts"), str)
    ):
        raise TerminalError("offer_transport_binding_invalid")
    _timestamp_ms(item["ts"])
    return item


def _load_reveal_approval(stage_id: str, reveal: dict) -> dict:
    path = tclk_pilot_reveal_approval.approval_path(stage_id)
    if not tclk_pilot_reveal_publish._approval_secure(path):
        raise TerminalError("reveal_approval_file_unsafe")
    try:
        record = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TerminalError("reveal_approval_invalid") from error
    approved_at = record.get("approved_at") if isinstance(record, dict) else None
    if not isinstance(approved_at, str):
        raise TerminalError("reveal_approval_invalid")
    try:
        return tclk_pilot_reveal_approval.validate_approval(record, reveal, now_ms=_timestamp_ms(approved_at))
    except tclk_pilot_reveal_approval.RevealApprovalError as error:
        raise TerminalError("reveal_approval_invalid") from error


def _sources(stage_id: str) -> dict:
    try:
        stage = tclk_pilot.load_stage(stage_id, require_live=False)
        accept = tclk_pilot_signer._load_preview(stage_id)
        lock = tclk_pilot_lock.load_evidence(stage_id)
        work = tclk_pilot_work.load_evidence(stage_id)
        reveal = tclk_pilot_reveal.load_preview(stage_id)
        published = tclk_pilot_reveal_publish._load_state(stage_id)
    except Exception as error:
        raise TerminalError("terminal_source_invalid") from error
    if accept is None or lock is None or work is None or reveal is None or published is None:
        raise TerminalError("terminal_source_missing")
    try:
        tclk_pilot_signer._require_preview_binding(accept, stage)
        request = tclk_pilot_reveal._require_bindings(stage, accept, lock, work)
        tclk_pilot_reveal._require_preview_binding(reveal, request)
    except (tclk_pilot_signer.PrepareError, tclk_pilot_reveal.RevealPrepareError) as error:
        raise TerminalError("terminal_source_binding_invalid") from error
    if work.get("status") != "work_ready":
        raise TerminalError("work_not_ready")
    _load_reveal_approval(stage_id, reveal)
    if (
        published.get("state") != "claimed"
        or published.get("stage_id") != stage_id
        or published.get("offer_id") != stage["offer_id"]
        or published.get("contract_id") != reveal["contract_id"]
        or published.get("deal_room") != reveal["deal_room"]
        or published.get("did") != stage["our_did"]
        or published.get("reveal_sha256") != reveal["reveal_sha256"]
        or not isinstance(published.get("reveal_seq"), int)
        or published["reveal_seq"] < 0
        or not isinstance(published.get("reveal_ts"), str)
        or not isinstance(published.get("claimed_note_sha256"), str)
        or not _HEX64.fullmatch(published["claimed_note_sha256"])
        or not isinstance(published.get("git_commit_sha"), str)
        or not _GIT_SHA.fullmatch(published["git_commit_sha"])
    ):
        raise TerminalError("reveal_publish_binding_invalid")
    _timestamp_ms(published["reveal_ts"])
    offer = _retained_offer(stage)
    return {"stage": stage, "accept": accept, "lock": lock, "work": work, "reveal": reveal, "published": published, "offer": offer}


def _verified_deal_records(room: str, payload: object) -> list[dict]:
    rows = payload.get("messages", []) if isinstance(payload, dict) else payload if isinstance(payload, list) else None
    if not isinstance(rows, list) or len(rows) > MAX_SCAN:
        raise TerminalError("deal_room_read_invalid")
    verified: list[dict] = []
    previous = -1
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            verify_signed_record(room, row)
        except ValueError:
            continue
        seq = row.get("seq")
        ts = row.get("ts")
        sender = row.get("from")
        text = row.get("text")
        if not isinstance(seq, int) or seq < 0 or not isinstance(ts, str) or not isinstance(sender, str) or not isinstance(text, str):
            continue
        _timestamp_ms(ts)
        if seq <= previous:
            raise TerminalError("deal_record_order_invalid")
        previous = seq
        verified.append({"seq": seq, "ts": ts, "from": sender, "text": text})
    return verified


def _run_bridge(request: dict) -> dict:
    env = tclk_watch._node_environment()
    if not shutil.which("node", path=env.get("PATH")):
        raise TerminalError("node_unavailable")
    if not BRIDGE.is_file():
        raise TerminalError("terminal_bridge_unavailable")
    package = BRIDGE.parent.parent / "node_modules" / "@flop-labs" / "tclk" / "package.json"
    if not package.is_file():
        raise TerminalError("pinned_runtime_unavailable")
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
        raise TerminalError("terminal_bridge_failed") from error
    if result.returncode != 0:
        raise TerminalError("terminal_bridge_failed")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise TerminalError("terminal_bridge_failed") from error
    required = {
        "ok", "status", "offer_id", "payer_did", "payee_did", "job_id", "contract_id",
        "deal_room", "accept_line_sha256", "lock_from", "lock_ref", "lock_line_sha256",
        "lock_seq", "lock_ts", "reveal_from", "reveal_line_sha256", "reveal_seq", "reveal_ts",
        "witness_sha256", "paper_note_namespace", "paper_note_key", "paper_note_sha256", "receipt",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("ok") is not True or value.get("status") != "claimed":
        raise TerminalError("terminal_bridge_output_invalid")
    for field in ("accept_line_sha256", "lock_line_sha256", "reveal_line_sha256", "witness_sha256", "paper_note_sha256"):
        if not isinstance(value.get(field), str) or not _HEX64.fullmatch(value[field]):
            raise TerminalError("terminal_bridge_output_invalid")
    receipt = value.get("receipt")
    if receipt is not None:
        if not isinstance(receipt, dict) or set(receipt) != {"from", "line_sha256", "seq", "ts"}:
            raise TerminalError("terminal_bridge_output_invalid")
        if not isinstance(receipt.get("line_sha256"), str) or not _HEX64.fullmatch(receipt["line_sha256"]):
            raise TerminalError("terminal_bridge_output_invalid")
    return value


def _current_terminal(sources: dict) -> dict:
    stage, accept, lock, work, reveal, published, offer = (sources[key] for key in ("stage", "accept", "lock", "work", "reveal", "published", "offer"))
    room = reveal["deal_room"]
    try:
        payload = core.read_room(room, limit=MAX_SCAN, cache_buster=secrets.token_hex(16))
        paper_value = core.read_note(lock["paper_note_namespace"], lock["paper_note_key"])
    except Exception as error:
        raise TerminalError("terminal_public_source_unavailable") from error
    paper_hash = hashlib.sha256(paper_value.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(paper_hash, published["claimed_note_sha256"]):
        raise TerminalError("paper_claim_binding_changed")
    request = {
        "offer_line": stage["offer_line"],
        "accept_line": accept["accept_line"],
        "accept_timestamp_ms": _timestamp_ms(lock["accept_ts"]),
        "contract_id": reveal["contract_id"],
        "deal_room": room,
        "deal_records": _verified_deal_records(room, payload),
        "paper_note_value": paper_value,
    }
    result = _run_bridge(request)
    checks = (
        result.get("offer_id") == stage["offer_id"],
        result.get("payer_did") == stage["counterpart_did"],
        result.get("payee_did") == stage["our_did"],
        result.get("job_id") == stage["job_id"],
        result.get("contract_id") == reveal["contract_id"],
        result.get("deal_room") == room,
        result.get("accept_line_sha256") == accept["accept_sha256"],
        result.get("lock_from") == stage["counterpart_did"],
        result.get("lock_ref") == reveal["contract_id"],
        result.get("lock_line_sha256") == lock["lock_line_sha256"],
        result.get("lock_seq") == lock["lock_seq"],
        _timestamp_ms(result.get("lock_ts")) == lock["lock_timestamp_ms"],
        result.get("reveal_from") == stage["our_did"],
        result.get("reveal_line_sha256") == reveal["reveal_sha256"] == published["reveal_sha256"],
        result.get("reveal_seq") == published["reveal_seq"],
        _timestamp_ms(result.get("reveal_ts")) == _timestamp_ms(published["reveal_ts"]),
        result.get("paper_note_namespace") == lock["paper_note_namespace"],
        result.get("paper_note_key") == lock["paper_note_key"],
        result.get("paper_note_sha256") == published["claimed_note_sha256"],
    )
    if not all(checks):
        raise TerminalError("terminal_binding_mismatch")
    receipt = result.get("receipt")
    if receipt is not None and receipt.get("from") not in {stage["counterpart_did"], stage["our_did"]}:
        raise TerminalError("receipt_party_invalid")
    return {"result": result, "offer": offer, "work": work, "published": published, "stage": stage, "lock": lock, "reveal": reveal}


def _static_from_current(current: dict) -> dict:
    result, offer, work, published, stage, lock, reveal = (current[key] for key in ("result", "offer", "work", "published", "stage", "lock", "reveal"))
    receipt = result["receipt"]
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "terminal_claimed",
        "stage_id": stage["stage_id"],
        "stage_digest": stage["stage_digest"],
        "offer_id": stage["offer_id"],
        "offer_sha256": stage["frame_sha256"],
        "offer_seq": offer["seq"],
        "offer_ts": offer["ts"],
        "counterpart_did": stage["counterpart_did"],
        "our_did": stage["our_did"],
        "job_id": stage["job_id"],
        "contract_id": reveal["contract_id"],
        "deal_room": reveal["deal_room"],
        "accept_sha256": result["accept_line_sha256"],
        "accept_seq": lock["accept_seq"],
        "accept_ts": lock["accept_ts"],
        "lock_sha256": result["lock_line_sha256"],
        "lock_seq": result["lock_seq"],
        "lock_ts": result["lock_ts"],
        "work_status": work["status"],
        "work_evidence_sha256": work["work_evidence_sha256"],
        "reveal_sha256": result["reveal_line_sha256"],
        "reveal_seq": result["reveal_seq"],
        "reveal_ts": result["reveal_ts"],
        "paper_note_sha256": result["paper_note_sha256"],
        "witness_sha256": result["witness_sha256"],
        "outcome": "claimed",
        "receipt_sha256": None if receipt is None else receipt["line_sha256"],
        "receipt_seq": None if receipt is None else receipt["seq"],
        "receipt_ts": None if receipt is None else receipt["ts"],
        "receipt_from": None if receipt is None else receipt["from"],
        "reveal_publish_git_commit_sha": published["git_commit_sha"],
    }


def _matches_existing(existing: dict, static: dict) -> bool:
    ignored = {"created_at", "git_commit_sha", "terminal_evidence_sha256"}
    for key, value in static.items():
        if key in ignored:
            continue
        old = existing.get(key)
        # A receipt that appeared after an already-valid claimed proof is additive public
        # evidence, not a mutation of the claimed contract. Preserve the immutable first proof.
        if key.startswith("receipt_") and old is None:
            continue
        if old != value:
            return False
    return True


def collect_stage(stage_id: str) -> dict:
    existing = load_evidence(stage_id)
    current = _current_terminal(_sources(stage_id))
    static = _static_from_current(current)
    if existing is not None:
        if not _matches_existing(existing, static):
            raise TerminalError("terminal_binding_changed")
        return {"action": "already_complete", "evidence": existing}

    record = {
        **static,
        "created_at": _now(),
        "git_commit_sha": core.git_commit_sha(),
    }
    record["terminal_evidence_sha256"] = _sha(record)
    _validate_evidence(record)
    try:
        evidence_dir().mkdir(parents=True, exist_ok=True, mode=0o770)
        observer.atomic_json_write(evidence_path(stage_id), record, compact=True, mode=0o640)
    except OSError as error:
        raise TerminalError("terminal_evidence_write_failed") from error
    return {"action": "collected", "evidence": record}


def public_result(result: dict) -> dict:
    evidence = result.get("evidence")
    if not isinstance(evidence, dict):
        return {"ok": True, "action": result.get("action")}
    return {
        "ok": True,
        "action": result.get("action"),
        "stage_id": evidence["stage_id"],
        "contract_id": evidence["contract_id"],
        "outcome": evidence["outcome"],
        "terminal_evidence_sha256": evidence["terminal_evidence_sha256"],
        "receipt_present": evidence["receipt_sha256"] is not None,
    }


def main() -> None:
    if len(sys.argv) != 2 or not _HEX32.fullmatch(sys.argv[1]):
        raise SystemExit("usage: tclk_pilot_terminal <stage-id>")
    try:
        result = collect_stage(sys.argv[1])
    except TerminalError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        raise SystemExit(1)
    print(json.dumps(public_result(result), sort_keys=True))


if __name__ == "__main__":
    main()
