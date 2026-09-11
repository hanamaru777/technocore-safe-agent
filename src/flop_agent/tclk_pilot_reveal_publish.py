"""Human-gated one-shot reveal publisher for the first genuine PaperRail pilot.

The reveal transcript is primary.  The exact signer-private reveal is signed and posted
once to the derived deal room only after a distinct root approval.  Only after that exact
signed reveal is confirmed does the publisher attempt one conditional PaperRail
locked->claimed Note transition.  Ambiguous writes are never retried; later invocations
reconcile read-only.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from . import (
    core,
    observer,
    oracle_signer,
    tclk_pilot,
    tclk_pilot_accept,
    tclk_pilot_lock,
    tclk_pilot_reveal,
    tclk_pilot_reveal_approval,
    tclk_pilot_signer,
    tclk_pilot_work,
)
from .public_record import verify_signed_record

SCHEMA_VERSION = 1
MIN_REVEAL_POST_MS = 60_000
BRIDGE = Path(__file__).resolve().parents[2] / "tools" / "tclk_prepare_paper_claim.mjs"

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CONTRACT = re.compile(r"^0x[0-9a-f]{64}$")
_SIG = re.compile(r"^[A-Za-z0-9_-]{85}[AQgw]$")


class RevealPublishError(RuntimeError):
    """Stable public-safe error for the irreversible reveal/claim boundary."""


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def state_dir() -> Path:
    return core.STATE / "signer" / "tclk-pilot-reveal-publishes"


def state_path(stage_id: str) -> Path:
    if not isinstance(stage_id, str) or not _HEX32.fullmatch(stage_id):
        raise RevealPublishError("invalid_stage_id")
    return state_dir() / f"{stage_id}.json"


def _required_state() -> set[str]:
    return {
        "schema_version", "state", "stage_id", "approval_digest", "offer_id", "contract_id",
        "deal_room", "did", "reveal_sha256", "nonce", "sig", "prepared_at",
        "reveal_attempted_at", "reveal_posted_at", "reveal_seq", "reveal_ts",
        "claim_attempted_at", "claimed_at", "locked_note_sha256", "claimed_note_sha256",
        "last_error", "git_commit_sha", "executed_at",
    }


def _validate_state(value: object) -> dict:
    states = {"prepared", "reveal_attempting", "reveal_ambiguous", "reveal_posted", "claim_attempting", "claim_ambiguous", "claimed"}
    if not isinstance(value, dict) or set(value) != _required_state() or value.get("schema_version") != SCHEMA_VERSION:
        raise RevealPublishError("reveal_publish_state_invalid")
    if value.get("state") not in states or not _HEX32.fullmatch(str(value.get("stage_id", ""))):
        raise RevealPublishError("reveal_publish_state_invalid")
    for field in ("approval_digest", "reveal_sha256", "git_commit_sha"):
        if not _HEX64.fullmatch(str(value.get(field, ""))):
            raise RevealPublishError("reveal_publish_state_invalid")
    if not _CONTRACT.fullmatch(str(value.get("offer_id", ""))) or not _CONTRACT.fullmatch(str(value.get("contract_id", ""))):
        raise RevealPublishError("reveal_publish_state_invalid")
    if not isinstance(value.get("deal_room"), str) or not isinstance(value.get("did"), str):
        raise RevealPublishError("reveal_publish_state_invalid")
    if not isinstance(value.get("nonce"), str) or not value["nonce"].isdigit() or not _SIG.fullmatch(str(value.get("sig", ""))):
        raise RevealPublishError("reveal_publish_state_invalid")
    for field in ("prepared_at", "executed_at"):
        if not isinstance(value.get(field), str):
            raise RevealPublishError("reveal_publish_state_invalid")
    for field in ("reveal_attempted_at", "reveal_posted_at", "reveal_ts", "claim_attempted_at", "claimed_at", "last_error"):
        if value.get(field) is not None and not isinstance(value[field], str):
            raise RevealPublishError("reveal_publish_state_invalid")
    if value.get("reveal_seq") is not None and (not isinstance(value["reveal_seq"], int) or value["reveal_seq"] < 0):
        raise RevealPublishError("reveal_publish_state_invalid")
    for field in ("locked_note_sha256", "claimed_note_sha256"):
        if value.get(field) is not None and not _HEX64.fullmatch(str(value[field])):
            raise RevealPublishError("reveal_publish_state_invalid")
    return value


def _load_state(stage_id: str) -> dict | None:
    path = state_path(stage_id)
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RevealPublishError("reveal_publish_state_invalid") from error
    value = _validate_state(value)
    if value["stage_id"] != stage_id:
        raise RevealPublishError("reveal_publish_state_invalid")
    return value


def _save_state(value: dict) -> None:
    _validate_state(value)
    try:
        state_dir().mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            os.chmod(state_dir(), 0o700)
        observer.atomic_json_write(state_path(value["stage_id"]), value, compact=True, mode=0o600)
    except OSError as error:
        raise RevealPublishError("reveal_publish_state_persistence_failed") from error


def _approval_secure(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode):
        return False
    if os.name != "posix":
        return True
    return info.st_uid == 0 and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == 0o640


def _load_root_approval(stage_id: str, preview: dict, *, now_ms: int) -> dict:
    path = tclk_pilot_reveal_approval.approval_path(stage_id)
    if not _approval_secure(path):
        raise RevealPublishError("reveal_approval_file_unsafe")
    try:
        record = json.loads(path.read_text("utf-8"))
        return tclk_pilot_reveal_approval.validate_approval(record, preview, now_ms=now_ms)
    except (OSError, json.JSONDecodeError, tclk_pilot_reveal_approval.RevealApprovalError) as error:
        raise RevealPublishError("reveal_approval_invalid") from error


def _load_private_reveal(stage_id: str, preview: dict) -> dict:
    try:
        path = tclk_pilot_reveal._require_private_reveal(stage_id)
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError, tclk_pilot_reveal.RevealPrepareError) as error:
        raise RevealPublishError("private_reveal_invalid") from error
    required = {
        "schema_version", "stage_id", "stage_digest", "offer_id", "counterpart_did", "our_did", "job_id",
        "contract_id", "accept_sha256", "lock_line_sha256", "work_evidence_sha256",
        "claim_by_ms", "refund_after_ms", "reveal_line", "reveal_sha256",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != 1:
        raise RevealPublishError("private_reveal_invalid")
    for field in (
        "stage_id", "stage_digest", "offer_id", "counterpart_did", "our_did", "job_id", "contract_id",
        "accept_sha256", "lock_line_sha256", "work_evidence_sha256", "claim_by_ms", "refund_after_ms", "reveal_sha256",
    ):
        if value.get(field) != preview.get(field):
            raise RevealPublishError("private_reveal_binding_mismatch")
    line = value.get("reveal_line")
    if not isinstance(line, str) or not line.startswith("tclk1 ") or core.clean_text(line) != line:
        raise RevealPublishError("private_reveal_invalid")
    if hashlib.sha256(line.encode("utf-8")).hexdigest() != preview["reveal_sha256"]:
        raise RevealPublishError("private_reveal_hash_mismatch")
    return value


def _exact_sources(stage_id: str, *, now_ms: int) -> tuple[dict, dict, dict, dict, dict, dict, dict]:
    try:
        stage = tclk_pilot.load_stage(stage_id, require_live=False)
        accept = tclk_pilot_signer._load_preview(stage_id)
        lock = tclk_pilot_lock.load_evidence(stage_id)
        work = tclk_pilot_work.load_evidence(stage_id)
        reveal = tclk_pilot_reveal.load_preview(stage_id)
    except Exception as error:
        raise RevealPublishError("reveal_source_invalid") from error
    if accept is None or lock is None or work is None or reveal is None:
        raise RevealPublishError("reveal_source_missing")
    try:
        request = tclk_pilot_reveal._require_bindings(stage, accept, lock, work)
        tclk_pilot_reveal._require_preview_binding(reveal, request)
        tclk_pilot_reveal._live_reverify_lock(stage_id, request)
    except tclk_pilot_reveal.RevealPrepareError as error:
        raise RevealPublishError(str(error)) from error
    if reveal["claim_by_ms"] - now_ms < MIN_REVEAL_POST_MS:
        raise RevealPublishError("reveal_window_elapsed")
    accept_state = tclk_pilot_accept._load_state(stage_id)
    if accept_state is None or accept_state.get("state") != "posted":
        raise RevealPublishError("accept_not_confirmed")
    if (
        accept_state.get("contract_id") != reveal["contract_id"]
        or accept_state.get("deal_room") != reveal["deal_room"]
        or accept_state.get("accept_sha256") != reveal["accept_sha256"]
        or accept_state.get("did") != reveal["our_did"]
    ):
        raise RevealPublishError("accept_state_binding_mismatch")
    approval = _load_root_approval(stage_id, reveal, now_ms=now_ms)
    private = _load_private_reveal(stage_id, reveal)
    return stage, accept, lock, work, reveal, approval, private


def _sign_exact(room: str, did: str, nonce: str, line: str) -> str:
    if core.clean_text(line) != line:
        raise RevealPublishError("reveal_line_not_canonical_transport_text")
    try:
        expected = oracle_signer.expected_did()
        if not hmac.compare_digest(expected, did):
            raise RevealPublishError("reveal_did_mismatch")
        core.require_verified_did(did)
        if not core.signer_matches_pinned():
            raise RevealPublishError("signer_not_pinned")
        def operation() -> str:
            lines = core.invoke_signer("say", room, nonce, line)
            if len(lines) != 2 or not hmac.compare_digest(lines[0], did) or not _SIG.fullmatch(lines[1]):
                raise RevealPublishError("signature_invalid")
            return lines[1]
        return oracle_signer.with_vault_seed(operation)
    except RevealPublishError:
        raise
    except RuntimeError as error:
        raise RevealPublishError("signing_failed") from error


def _new_state(reveal: dict, approval: dict, private: dict, *, now_ms: int) -> dict:
    did = reveal["our_did"]
    room = reveal["deal_room"]
    nonce = core.make_nonce(room, did)
    sig = _sign_exact(room, did, nonce, private["reveal_line"])
    stamp = datetime.fromtimestamp(now_ms / 1000, UTC).isoformat()
    value = {
        "schema_version": SCHEMA_VERSION,
        "state": "prepared",
        "stage_id": reveal["stage_id"],
        "approval_digest": approval["approval_digest"],
        "offer_id": reveal["offer_id"],
        "contract_id": reveal["contract_id"],
        "deal_room": room,
        "did": did,
        "reveal_sha256": reveal["reveal_sha256"],
        "nonce": nonce,
        "sig": sig,
        "prepared_at": stamp,
        "reveal_attempted_at": None,
        "reveal_posted_at": None,
        "reveal_seq": None,
        "reveal_ts": None,
        "claim_attempted_at": None,
        "claimed_at": None,
        "locked_note_sha256": None,
        "claimed_note_sha256": None,
        "last_error": None,
        "git_commit_sha": core.git_commit_sha(),
        "executed_at": stamp,
    }
    _save_state(value)
    return value


def _verified_room_rows(room: str) -> list[dict]:
    try:
        payload = core.read_room(room, limit=200, cache_buster=secrets.token_hex(16))
        rows = payload.get("messages", payload if isinstance(payload, list) else [])
    except Exception as error:
        raise RevealPublishError("reveal_reconcile_read_failed") from error
    if not isinstance(rows, list):
        raise RevealPublishError("reveal_reconcile_read_failed")
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            verify_signed_record(room, row)
        except ValueError:
            continue
        out.append(row)
    return out


def _find_reveal(value: dict, line: str) -> dict | None:
    matches = [
        row for row in _verified_room_rows(value["deal_room"])
        if row.get("from") == value["did"]
        and str(row.get("nonce")) == value["nonce"]
        and row.get("sig") == value["sig"]
        and row.get("text") == line
        and isinstance(row.get("seq"), int)
        and isinstance(row.get("ts"), str)
    ]
    if len(matches) > 1:
        raise RevealPublishError("reveal_transport_ambiguous")
    return matches[0] if matches else None


def _mark_reveal_posted(value: dict, matched: dict) -> None:
    value["state"] = "reveal_posted"
    value["reveal_posted_at"] = datetime.now(UTC).isoformat()
    value["reveal_seq"] = matched["seq"]
    value["reveal_ts"] = matched["ts"]
    value["last_error"] = None
    _save_state(value)


def _reconcile_reveal(value: dict, line: str) -> bool:
    matched = _find_reveal(value, line)
    if matched is None:
        if value["state"] == "reveal_attempting":
            value["state"] = "reveal_ambiguous"
            value["last_error"] = "reveal_submission_unknown"
            _save_state(value)
        return False
    _mark_reveal_posted(value, matched)
    return True


def _post_reveal_once(value: dict, line: str):
    body = {"did": value["did"], "sig": value["sig"], "nonce": value["nonce"], "text": line}
    return core.httpx.post(f"{core.BASE_URL}/r/{quote(value['deal_room'], safe='')}?format=json", json=body, timeout=20)


def _validate_reveal_receipt(value: dict, line: str, response) -> dict:
    response.raise_for_status()
    try:
        payload = response.json()
    except Exception as error:
        raise core.SubmissionAmbiguityError("reveal POST receipt invalid") from error
    row = payload.get("posted") if isinstance(payload, dict) else None
    if not isinstance(row, dict) or not isinstance(row.get("seq"), int) or not isinstance(row.get("ts"), str):
        raise core.SubmissionAmbiguityError("reveal POST receipt invalid")
    if row.get("from") != value["did"] or str(row.get("nonce")) != value["nonce"] or row.get("sig") != value["sig"] or row.get("text") != line:
        raise core.SubmissionAmbiguityError("reveal POST receipt mismatch")
    return row


def _run_claim_bridge(reveal: dict, private: dict, current_note: str, *, now_ms: int) -> dict:
    env = tclk_pilot_reveal._bridge_environment()
    request = {
        "contract_id": reveal["contract_id"],
        "our_did": reveal["our_did"],
        "accept_line": tclk_pilot_signer._load_preview(reveal["stage_id"])["accept_line"],
        "reveal_line": private["reveal_line"],
        "current_note": current_note,
        "refund_after_ms": reveal["refund_after_ms"],
        "now_ms": now_ms,
    }
    try:
        result = subprocess.run(["node", str(BRIDGE)], input=json.dumps(request, sort_keys=True, separators=(",", ":")), text=True, capture_output=True, timeout=5, check=False, env=env)
    except (OSError, subprocess.SubprocessError) as error:
        raise RevealPublishError("paper_claim_bridge_failed") from error
    if result.returncode != 0:
        raise RevealPublishError("paper_claim_bridge_failed")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RevealPublishError("paper_claim_bridge_failed") from error
    required = {"status", "namespace", "key", "current_sha256", "claimed_line", "claimed_sha256", "secret_sha256"}
    if not isinstance(value, dict) or set(value) != required or value.get("status") not in {"ready", "already_claimed"}:
        raise RevealPublishError("paper_claim_bridge_output_invalid")
    for field in ("current_sha256", "claimed_sha256", "secret_sha256"):
        if not _HEX64.fullmatch(str(value.get(field, ""))):
            raise RevealPublishError("paper_claim_bridge_output_invalid")
    if hashlib.sha256(current_note.encode("utf-8")).hexdigest() != value["current_sha256"]:
        raise RevealPublishError("paper_claim_bridge_output_invalid")
    if hashlib.sha256(value["claimed_line"].encode("utf-8")).hexdigest() != value["claimed_sha256"]:
        raise RevealPublishError("paper_claim_bridge_output_invalid")
    return value


def _read_paper(reveal: dict) -> str:
    lock = tclk_pilot_lock.load_evidence(reveal["stage_id"])
    if lock is None:
        raise RevealPublishError("lock_evidence_missing")
    if lock.get("paper_note_namespace") is None or lock.get("paper_note_key") is None:
        raise RevealPublishError("paper_note_location_invalid")
    try:
        return core.read_note(lock["paper_note_namespace"], lock["paper_note_key"])
    except Exception as error:
        raise RevealPublishError("paper_note_read_failed") from error


def _reconcile_claim(value: dict, reveal: dict, private: dict, *, now_ms: int) -> bool:
    current = _read_paper(reveal)
    plan = _run_claim_bridge(reveal, private, current, now_ms=now_ms)
    if plan["status"] == "already_claimed" and (value["claimed_note_sha256"] is None or hmac.compare_digest(plan["claimed_sha256"], value["claimed_note_sha256"])):
        value["state"] = "claimed"
        value["claimed_at"] = datetime.now(UTC).isoformat()
        value["claimed_note_sha256"] = plan["claimed_sha256"]
        value["last_error"] = None
        _save_state(value)
        return True
    if value["state"] == "claim_attempting":
        value["state"] = "claim_ambiguous"
        value["last_error"] = "paper_claim_unknown"
        _save_state(value)
    return False


def _claim_once(value: dict, reveal: dict, private: dict, *, now_ms: int) -> bool:
    tclk_pilot_accept._require_write_interlock()
    current = _read_paper(reveal)
    plan = _run_claim_bridge(reveal, private, current, now_ms=now_ms)
    if plan["status"] == "already_claimed":
        value["claimed_note_sha256"] = plan["claimed_sha256"]
        value["state"] = "claimed"
        value["claimed_at"] = datetime.now(UTC).isoformat()
        value["last_error"] = None
        _save_state(value)
        return True
    value["state"] = "claim_attempting"
    value["claim_attempted_at"] = datetime.now(UTC).isoformat()
    value["locked_note_sha256"] = plan["current_sha256"]
    value["claimed_note_sha256"] = plan["claimed_sha256"]
    value["last_error"] = None
    _save_state(value)
    tclk_pilot_accept._require_write_interlock()
    try:
        response = core.httpx.post(
            f"{core.BASE_URL}/kv/{quote(plan['namespace'], safe='')}/{quote(plan['key'], safe='')}?format=json",
            json={"value": plan["claimed_line"], "if": current},
            timeout=20,
        )
        if response.status_code not in {200, 409}:
            response.raise_for_status()
    except Exception:
        pass
    return _reconcile_claim(value, reveal, private, now_ms=now_ms)


def publish_stage(stage_id: str, *, now_ms: int | None = None) -> dict:
    current = _now_ms() if now_ms is None else now_ms
    value = _load_state(stage_id)
    if value is not None and value["state"] == "claimed":
        return {"action": "already_claimed", "state": value}

    # Ambiguous phases are read-only forever: no second POST/CAS.
    if value is not None and value["state"] in {"reveal_attempting", "reveal_ambiguous"}:
        reveal = tclk_pilot_reveal.load_preview(stage_id)
        if reveal is None:
            raise RevealPublishError("reveal_preview_missing")
        private = _load_private_reveal(stage_id, reveal)
        if _reconcile_reveal(value, private["reveal_line"]):
            return {"action": "reveal_reconciled", "state": value}
        return {"action": "reveal_ambiguous", "state": value}
    if value is not None and value["state"] in {"claim_attempting", "claim_ambiguous"}:
        reveal = tclk_pilot_reveal.load_preview(stage_id)
        if reveal is None:
            raise RevealPublishError("reveal_preview_missing")
        private = _load_private_reveal(stage_id, reveal)
        if _reconcile_claim(value, reveal, private, now_ms=current):
            return {"action": "claim_reconciled", "state": value}
        return {"action": "claim_ambiguous", "state": value}

    tclk_pilot_accept._require_write_interlock()
    _, _, _, _, reveal, approval, private = _exact_sources(stage_id, now_ms=current)
    if value is None:
        value = _new_state(reveal, approval, private, now_ms=current)
    else:
        if value["approval_digest"] != approval["approval_digest"] or value["reveal_sha256"] != reveal["reveal_sha256"]:
            raise RevealPublishError("reveal_publish_state_binding_mismatch")

    if value["state"] == "prepared":
        tclk_pilot_accept._require_write_interlock()
        value["state"] = "reveal_attempting"
        value["reveal_attempted_at"] = datetime.now(UTC).isoformat()
        value["last_error"] = None
        _save_state(value)
        try:
            response = _post_reveal_once(value, private["reveal_line"])
            row = _validate_reveal_receipt(value, private["reveal_line"], response)
            _mark_reveal_posted(value, row)
        except Exception as error:
            try:
                if not _reconcile_reveal(value, private["reveal_line"]):
                    raise RevealPublishError("reveal_submission_unknown") from error
            except RevealPublishError:
                raise
    if value["state"] == "reveal_posted":
        if _claim_once(value, reveal, private, now_ms=current):
            return {"action": "claimed", "state": value}
        return {"action": "claim_ambiguous", "state": value}
    return {"action": value["state"], "state": value}


def public_result(result: dict) -> dict:
    value = result.get("state")
    if not isinstance(value, dict):
        return {"ok": True, "action": result.get("action")}
    return {
        "ok": True,
        "action": result.get("action"),
        "stage_id": value["stage_id"],
        "contract_id": value["contract_id"],
        "deal_room": value["deal_room"],
        "reveal_sha256": value["reveal_sha256"],
        "state": value["state"],
        "claimed_note_sha256": value["claimed_note_sha256"],
    }


def main() -> None:
    if len(sys.argv) != 2 or not _HEX32.fullmatch(sys.argv[1]):
        raise SystemExit("usage: tclk_pilot_reveal_publish <stage-id>")
    try:
        result = publish_stage(sys.argv[1])
    except (RevealPublishError, tclk_pilot_accept.AcceptError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        raise SystemExit(1)
    print(json.dumps(public_result(result), sort_keys=True))


if __name__ == "__main__":
    main()
