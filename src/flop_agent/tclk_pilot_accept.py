"""Typed one-shot publisher for the first genuine tclk/1 PaperRail accept.

The only CLI input is a 32-hex stage id. Human approval is loaded from a
root-owned exact-binding record; the accept line itself is reconstructed from the
already-PREPAREd signer material and pinned tclk runtime. No arbitrary text,
room, URL or task command can enter the signing path.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from . import core, observer, oracle_signer, tclk_pilot, tclk_pilot_approval, tclk_pilot_signer, tclk_watch

SCHEMA_VERSION = 1
MIN_POST_SECONDS = 60
PROTECTED_CORE_GAP_EVENTS = 117
PROTECTED_CORE_GAP_MESSAGES = 5_083_155

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DID = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}$")
_SIG = re.compile(r"^[A-Za-z0-9_-]{85}[AQgw]$")


class AcceptError(RuntimeError):
    """Stable public-safe error for the typed first-pilot accept path."""


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def state_dir() -> Path:
    return core.STATE / "signer" / "tclk-pilot-accepts"


def state_path(stage_id: str) -> Path:
    if not isinstance(stage_id, str) or not _HEX32.fullmatch(stage_id):
        raise AcceptError("invalid_stage_id")
    return state_dir() / f"{stage_id}.json"


def _approval_file_secure(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode):
        return False
    if os.name != "posix":
        return True
    return info.st_uid == 0 and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == 0o640


def _load_approval(stage_id: str, stage: dict, preview: dict, *, now_ms: int) -> dict:
    path = tclk_pilot_approval.approval_path(stage_id)
    if not _approval_file_secure(path):
        raise AcceptError("approval_file_unsafe")
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AcceptError("approval_file_invalid") from error
    try:
        return tclk_pilot_approval.validate_approval(value, stage, preview, now_ms=now_ms)
    except tclk_pilot_approval.ApprovalError as error:
        raise AcceptError(str(error)) from error


def _state_required() -> set[str]:
    return {
        "schema_version", "state", "stage_id", "approval_digest", "offer_id", "accept_line",
        "accept_sha256", "contract_id", "deal_room", "did", "nonce", "sig", "prepared_at",
        "attempted_at", "posted_at", "seq", "ts", "last_error", "git_commit_sha", "executed_at",
    }


def _validate_state(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != _state_required() or value.get("schema_version") != SCHEMA_VERSION:
        raise AcceptError("accept_state_invalid")
    if value.get("state") not in {"prepared", "attempting", "ambiguous", "posted"}:
        raise AcceptError("accept_state_invalid")
    if not isinstance(value.get("stage_id"), str) or not _HEX32.fullmatch(value["stage_id"]):
        raise AcceptError("accept_state_invalid")
    for field in ("approval_digest", "accept_sha256", "git_commit_sha"):
        if not isinstance(value.get(field), str) or not _HEX64.fullmatch(value[field]):
            raise AcceptError("accept_state_invalid")
    if not isinstance(value.get("accept_line"), str) or not value["accept_line"].startswith("tclk1 "):
        raise AcceptError("accept_state_invalid")
    if hashlib.sha256(value["accept_line"].encode("utf-8")).hexdigest() != value["accept_sha256"]:
        raise AcceptError("accept_state_invalid")
    if not isinstance(value.get("offer_id"), str) or not re.fullmatch(r"0x[0-9a-f]{64}", value["offer_id"]):
        raise AcceptError("accept_state_invalid")
    if not isinstance(value.get("contract_id"), str) or not re.fullmatch(r"0x[0-9a-f]{64}", value["contract_id"]):
        raise AcceptError("accept_state_invalid")
    if not isinstance(value.get("deal_room"), str) or not re.fullmatch(r"mb-p-tclk-[0-9a-f]{16}", value["deal_room"]):
        raise AcceptError("accept_state_invalid")
    if not isinstance(value.get("did"), str) or not _DID.fullmatch(value["did"]):
        raise AcceptError("accept_state_invalid")
    if not isinstance(value.get("nonce"), str) or not value["nonce"].isdigit():
        raise AcceptError("accept_state_invalid")
    if not isinstance(value.get("sig"), str) or not _SIG.fullmatch(value["sig"]):
        raise AcceptError("accept_state_invalid")
    if not isinstance(value.get("prepared_at"), str) or not isinstance(value.get("executed_at"), str):
        raise AcceptError("accept_state_invalid")
    if value["attempted_at"] is not None and not isinstance(value["attempted_at"], str):
        raise AcceptError("accept_state_invalid")
    if value["posted_at"] is not None and not isinstance(value["posted_at"], str):
        raise AcceptError("accept_state_invalid")
    if value["seq"] is not None and (not isinstance(value["seq"], int) or value["seq"] < 0):
        raise AcceptError("accept_state_invalid")
    if value["ts"] is not None and not isinstance(value["ts"], str):
        raise AcceptError("accept_state_invalid")
    if value["last_error"] is not None and not isinstance(value["last_error"], str):
        raise AcceptError("accept_state_invalid")
    return value


def _load_state(stage_id: str) -> dict | None:
    path = state_path(stage_id)
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AcceptError("accept_state_invalid") from error
    value = _validate_state(value)
    if value["stage_id"] != stage_id:
        raise AcceptError("accept_state_invalid")
    return value


def _save_state(value: dict) -> None:
    _validate_state(value)
    try:
        state_dir().mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            os.chmod(state_dir(), 0o700)
        observer.atomic_json_write(state_path(value["stage_id"]), value, compact=True, mode=0o600)
    except OSError as error:
        raise AcceptError("accept_state_persistence_failed") from error


def _require_write_interlock() -> None:
    """Fail closed unless current Observer state is safe for a new irreversible write."""
    try:
        state = observer.load_state()
    except Exception as error:
        raise AcceptError("observer_state_unavailable") from error
    health = state.get("health", {})
    metrics = state.get("metrics", {})
    if not isinstance(health, dict) or health.get("current") != "ok":
        raise AcceptError("observer_health_not_ok")
    if (
        metrics.get("unrecoverable_core_gap_events") != PROTECTED_CORE_GAP_EVENTS
        or metrics.get("unrecoverable_core_gap_messages") != PROTECTED_CORE_GAP_MESSAGES
    ):
        raise AcceptError("protected_core_baseline_changed")


def _exact_prepared(stage_id: str, *, now_ms: int) -> tuple[dict, dict, dict, dict]:
    try:
        stage = tclk_pilot.load_stage(stage_id, now_ms=now_ms, require_live=False)
    except tclk_pilot.PilotError as error:
        raise AcceptError(str(error)) from error
    if stage["expires_ms"] - now_ms < MIN_POST_SECONDS * 1000:
        raise AcceptError("accept_window_elapsed")
    preview = tclk_pilot_signer._load_preview(stage_id)
    if preview is None:
        raise AcceptError("preview_missing")
    try:
        tclk_pilot_signer._require_preview_binding(preview, stage)
        tclk_pilot_signer._require_protocol_file(stage_id)
    except tclk_pilot_signer.PrepareError as error:
        raise AcceptError(str(error)) from error
    approval = _load_approval(stage_id, stage, preview, now_ms=now_ms)
    try:
        tclk_pilot_signer._resolve_and_bind(stage, reader=core.read_note, now_ms=now_ms)
        reconstructed = tclk_pilot_signer._run_bridge(stage)
    except tclk_pilot_signer.PrepareError as error:
        raise AcceptError(str(error)) from error
    for field in (
        "stage_id", "stage_digest", "offer_id", "frame_sha256", "full_spec_sha256",
        "material_sha256", "expires_ms", "accept_line", "accept_sha256", "contract_id", "deal_room",
    ):
        if reconstructed.get(field) != preview.get(field):
            raise AcceptError("prepared_accept_binding_mismatch")
    if preview.get("accepted") is not False:
        raise AcceptError("preview_not_unaccepted")
    return stage, preview, approval, reconstructed


def _messages(room: str) -> list[dict]:
    try:
        payload = core.read_room(room, limit=200, cache_buster=secrets.token_hex(16))
    except Exception as error:
        raise AcceptError("reconcile_read_failed") from error
    rows = payload.get("messages", payload if isinstance(payload, list) else [])
    if not isinstance(rows, list):
        raise AcceptError("reconcile_read_failed")
    return [item for item in rows if isinstance(item, dict)]


def _find_exact_message(value: dict, accept_line: str) -> dict | None:
    for item in _messages(tclk_watch.OFFER_ROOM):
        if (
            item.get("from") == value["did"]
            and str(item.get("nonce")) == value["nonce"]
            and item.get("sig") == value["sig"]
            and item.get("text") == accept_line
            and isinstance(item.get("seq"), int)
            and isinstance(item.get("ts"), str)
        ):
            return item
    return None


def _activity_exists(value: dict, accept_line: str) -> bool:
    path = core.STATE / "activities.jsonl"
    if not path.exists():
        return False
    try:
        lines = path.read_text("utf-8").splitlines()
    except OSError:
        return False
    for line in reversed(lines[-2000:]):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            isinstance(item, dict)
            and item.get("action") == "tclk_first_pilot_accept"
            and item.get("did") == value["did"]
            and item.get("room") == tclk_watch.OFFER_ROOM
            and str(item.get("nonce")) == value["nonce"]
            and item.get("text") == accept_line
        ):
            return True
    return False


def _ensure_activity(value: dict, accept_line: str, matched: dict) -> None:
    if _activity_exists(value, accept_line):
        return
    activity = {
        "action": "tclk_first_pilot_accept",
        "did": value["did"],
        "room": tclk_watch.OFFER_ROOM,
        "seq": matched["seq"],
        "ts": matched["ts"],
        "nonce": value["nonce"],
        "text": accept_line,
        "git_commit_sha": value["git_commit_sha"],
        "executed_at": value["executed_at"],
        "official_commit": core.UPSTREAM_COMMIT,
    }
    try:
        core.append_activity(activity)
    except Exception as error:
        raise AcceptError("activity_persistence_failed") from error


def _mark_posted(value: dict, accept_line: str, matched: dict) -> dict:
    _ensure_activity(value, accept_line, matched)
    value["state"] = "posted"
    value["posted_at"] = datetime.now(UTC).isoformat()
    value["seq"] = matched["seq"]
    value["ts"] = matched["ts"]
    value["last_error"] = None
    _save_state(value)
    return value


def _reconcile(value: dict, accept_line: str) -> dict:
    matched = _find_exact_message(value, accept_line)
    if matched is not None:
        _mark_posted(value, accept_line, matched)
        return {"action": "reconciled", "state": value}
    if value["state"] == "attempting":
        value["state"] = "ambiguous"
        value["last_error"] = "submission_unknown"
        _save_state(value)
    return {"action": "ambiguous", "state": value}


def _sign_exact(did: str, nonce: str, accept_line: str) -> str:
    if core.clean_text(accept_line) != accept_line:
        raise AcceptError("accept_line_not_canonical_transport_text")
    try:
        expected = oracle_signer.expected_did()
        if not hmac.compare_digest(expected, did):
            raise AcceptError("stage_did_mismatch")
        core.require_verified_did(did)
        if not core.signer_matches_pinned():
            raise AcceptError("signer_not_pinned")

        def operation() -> str:
            lines = core.invoke_signer("say", tclk_watch.OFFER_ROOM, nonce, accept_line)
            if len(lines) != 2 or not hmac.compare_digest(lines[0], did) or not _SIG.fullmatch(lines[1]):
                raise AcceptError("signature_invalid")
            return lines[1]

        return oracle_signer.with_vault_seed(operation)
    except AcceptError:
        raise
    except RuntimeError as error:
        raise AcceptError("signing_failed") from error


def _new_prepared_state(stage: dict, approval: dict, preview: dict, *, now_ms: int) -> dict:
    did = stage["our_did"]
    try:
        nonce = core.make_nonce(tclk_watch.OFFER_ROOM, did)
        sig = _sign_exact(did, nonce, preview["accept_line"])
        git_sha = core.git_commit_sha()
    except AcceptError:
        raise
    except Exception as error:
        raise AcceptError("prepare_transport_failed") from error
    stamp = datetime.fromtimestamp(now_ms / 1000, UTC).isoformat()
    value = {
        "schema_version": SCHEMA_VERSION,
        "state": "prepared",
        "stage_id": stage["stage_id"],
        "approval_digest": approval["approval_digest"],
        "offer_id": stage["offer_id"],
        "accept_line": preview["accept_line"],
        "accept_sha256": preview["accept_sha256"],
        "contract_id": preview["contract_id"],
        "deal_room": preview["deal_room"],
        "did": did,
        "nonce": nonce,
        "sig": sig,
        "prepared_at": stamp,
        "attempted_at": None,
        "posted_at": None,
        "seq": None,
        "ts": None,
        "last_error": None,
        "git_commit_sha": git_sha,
        "executed_at": stamp,
    }
    _save_state(value)
    return value


def _validate_transport_response(value: dict, accept_line: str, response) -> dict:
    response.raise_for_status()
    try:
        payload = response.json()
    except Exception as error:
        raise core.SubmissionAmbiguityError("signed POST receipt is invalid") from error
    matched = payload.get("posted") if isinstance(payload, dict) else None
    if not isinstance(matched, dict) or not isinstance(matched.get("seq"), int) or matched["seq"] < 0 or not isinstance(matched.get("ts"), str) or not isinstance(matched.get("sig"), str):
        raise core.SubmissionAmbiguityError("signed POST receipt is invalid")
    try:
        datetime.fromisoformat(matched["ts"].replace("Z", "+00:00"))
    except ValueError as error:
        raise core.SubmissionAmbiguityError("signed POST receipt is invalid") from error
    if (
        matched.get("from") != value["did"]
        or str(matched.get("nonce")) != value["nonce"]
        or matched.get("text") != accept_line
        or matched.get("sig") != value["sig"]
    ):
        raise core.SubmissionAmbiguityError("signed POST receipt mismatches")
    return matched


def _post_once(value: dict, accept_line: str):
    body = {"did": value["did"], "sig": value["sig"], "nonce": value["nonce"], "text": accept_line}
    return core.httpx.post(
        f"{core.BASE_URL}/r/{quote(tclk_watch.OFFER_ROOM, safe='')}?format=json",
        json=body,
        timeout=20,
    )


def accept_stage(stage_id: str, *, now_ms: int | None = None) -> dict:
    current = _now_ms() if now_ms is None else now_ms
    value = _load_state(stage_id)

    # Once an irreversible POST may have been attempted, reconciliation must stay
    # available even after expiry, source-note changes, or a later health incident.
    if value is not None and value["state"] == "posted":
        return {"action": "already_posted", "state": value}
    if value is not None and value["state"] in {"attempting", "ambiguous"}:
        return _reconcile(value, value["accept_line"])

    # First gate: no new transport signature/Vault use unless the current read-side
    # safety state is exact. This is intentionally after reconciliation shortcuts.
    _require_write_interlock()

    stage, preview, approval, _ = _exact_prepared(stage_id, now_ms=current)
    if value is not None:
        if (
            value["approval_digest"] != approval["approval_digest"]
            or value["accept_sha256"] != preview["accept_sha256"]
            or value["accept_line"] != preview["accept_line"]
        ):
            raise AcceptError("accept_state_binding_mismatch")
    else:
        value = _new_prepared_state(stage, approval, preview, now_ms=current)

    if value["state"] != "prepared":
        raise AcceptError("accept_state_invalid")
    if stage["expires_ms"] - current < MIN_POST_SECONDS * 1000:
        raise AcceptError("accept_window_elapsed")

    # Second gate closes the signing-to-POST TOCTOU window. A health/core change after
    # signature preparation leaves only local prepared state and performs no POST.
    _require_write_interlock()

    value["state"] = "attempting"
    value["attempted_at"] = datetime.now(UTC).isoformat()
    value["last_error"] = None
    _save_state(value)

    try:
        response = _post_once(value, value["accept_line"])
        matched = _validate_transport_response(value, value["accept_line"], response)
        _mark_posted(value, value["accept_line"], matched)
    except Exception as error:
        value["state"] = "ambiguous"
        value["last_error"] = "submission_unknown"
        try:
            _save_state(value)
        except AcceptError:
            pass
        # One immediate read-only reconciliation is safe. Never retry the POST.
        try:
            reconciled = _reconcile(value, value["accept_line"])
            if reconciled["action"] == "reconciled":
                return reconciled
        except AcceptError:
            pass
        raise AcceptError("submission_unknown") from error
    return {"action": "posted", "state": value}


def public_result(result: dict) -> dict:
    value = result.get("state")
    if not isinstance(value, dict):
        return {"ok": True, "action": result.get("action")}
    return {
        "ok": True,
        "action": result.get("action"),
        "stage_id": value["stage_id"],
        "offer_id": value["offer_id"],
        "accept_sha256": value["accept_sha256"],
        "contract_id": value["contract_id"],
        "deal_room": value["deal_room"],
        "state": value["state"],
    }


def main() -> None:
    if len(sys.argv) != 2 or not _HEX32.fullmatch(sys.argv[1]):
        raise SystemExit("usage: tclk_pilot_accept <stage-id>")
    try:
        result = accept_stage(sys.argv[1])
    except AcceptError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        raise SystemExit(1)
    print(json.dumps(public_result(result), sort_keys=True))


if __name__ == "__main__":
    main()
