"""One exact idempotent Sonnet-2 registration replay to re-surface referee receipt.

This lane is intentionally NOT generic registration. It can only replay the already
posted MARU writer registration with its existing immutable request_id. It first
checks for a currently visible signed referee receipt, requires the original local
posted registration state, persists an attempt marker before one POST, and never
blindly retries an ambiguous write.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime

from . import core, observer, oracle_signer, sonnet_registration as registration
from .public_record import verify_signed_record

ROOM = "mb-sonnet-2-registration"
DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
REFEREE_DID = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
REQUEST_ID = "32c15433c6d73af1cea5d6467dece016"
PAYLOAD = {
    "type": "sonnet.register.v1",
    "contest_id": "sonnet-2",
    "role": "writer",
    "x_account_url": "https://x.com/MinerMaru73",
    "request_id": REQUEST_ID,
}
OPEN = datetime(2026, 9, 11, 12, tzinfo=UTC)
CLOSE = datetime(2026, 9, 18, 12, tzinfo=UTC)


class ReplayError(RuntimeError):
    pass


def render() -> str:
    return json.dumps(PAYLOAD, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def state_path():
    return core.STATE / "signer" / "sonnet-2-registration-receipt-replay.json"


def new_state() -> dict:
    text = render()
    return {
        "schema_version": 1,
        "room": ROOM,
        "did": DID,
        "request_id": REQUEST_ID,
        "payload": dict(PAYLOAD),
        "text_hash": hashlib.sha256(text.encode()).hexdigest(),
        "state": "new",
        "nonce": None,
        "attempted_at": None,
        "post_seq": None,
        "post_ts": None,
        "receipt": None,
    }


def validate(value: object) -> dict:
    fields = {
        "schema_version", "room", "did", "request_id", "payload", "text_hash",
        "state", "nonce", "attempted_at", "post_seq", "post_ts", "receipt",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ReplayError("replay_state_invalid")
    if (
        value["schema_version"] != 1
        or value["room"] != ROOM
        or value["did"] != DID
        or value["request_id"] != REQUEST_ID
        or value["payload"] != PAYLOAD
        or value["text_hash"] != hashlib.sha256(render().encode()).hexdigest()
        or value["state"] not in {"new", "prepared", "attempting", "replay_posted", "resolved", "ambiguous"}
    ):
        raise ReplayError("replay_state_invalid")
    nonce = value["nonce"]
    if nonce is not None and (not isinstance(nonce, str) or not re.fullmatch(r"[0-9]{1,19}", nonce)):
        raise ReplayError("replay_state_invalid")
    if value["state"] != "new" and nonce is None and value["state"] != "resolved":
        raise ReplayError("replay_state_invalid")
    if value["state"] in {"attempting", "replay_posted", "ambiguous"} and not isinstance(value["attempted_at"], str):
        raise ReplayError("replay_state_invalid")
    if value["state"] in {"replay_posted"}:
        if type(value["post_seq"]) is not int or not isinstance(value["post_ts"], str):
            raise ReplayError("replay_state_invalid")
    if value["state"] == "resolved":
        receipt = value["receipt"]
        if not isinstance(receipt, dict) or receipt.get("status") not in {"accepted", "rejected"}:
            raise ReplayError("replay_state_invalid")
    return value


def save(value: dict) -> None:
    observer.atomic_json_write(state_path(), validate(value), compact=True, mode=0o600)


def load() -> dict | None:
    try:
        return validate(json.loads(state_path().read_text("utf-8")))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError) as error:
        raise ReplayError("replay_state_invalid") from error


@contextmanager
def replay_lock():
    if os.name != "posix":
        raise ReplayError("isolated_linux_signer_required")
    import fcntl
    import pwd
    if pwd.getpwuid(os.geteuid()).pw_name != "technocore-signer":
        raise ReplayError("isolated_signer_user_required")
    path = state_path().with_suffix(".lock")
    with path.open("a") as handle:
        os.fchmod(handle.fileno(), 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ReplayError("replay_busy") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def require_identity() -> None:
    if oracle_signer.expected_did() != DID:
        raise ReplayError("did_mismatch")
    core.require_verified_did(DID)
    if not core.signer_matches_pinned():
        raise ReplayError("signer_not_pinned")


def require_original_posted_registration() -> None:
    try:
        value = registration.load()
    except Exception as error:
        raise ReplayError("original_registration_unavailable") from error
    if value is None or value.get("state") != "posted" or value.get("did") != DID:
        raise ReplayError("original_registration_not_posted")
    if value.get("registration") != PAYLOAD:
        raise ReplayError("original_registration_mismatch")
    if type(value.get("seq")) is not int or not isinstance(value.get("ts"), str):
        raise ReplayError("original_registration_invalid")


def require_prepost() -> None:
    require_identity()
    require_original_posted_registration()
    try:
        registration.require_health()
    except Exception as error:
        raise ReplayError("strict_safety_gate_failed") from error
    if not OPEN <= datetime.now(UTC) < CLOSE:
        raise ReplayError("registration_window_closed")


def _receipt_item(payload: object) -> dict | None:
    if not isinstance(payload, dict):
        return None
    if payload.get("type") == "sonnet.receipt.v1":
        candidates = [payload]
    elif payload.get("type") == "sonnet.receipts.v1" and isinstance(payload.get("receipts"), list):
        candidates = [item for item in payload["receipts"] if isinstance(item, dict)]
    else:
        return None
    for item in candidates:
        if str(item.get("request_id", "")) != REQUEST_ID:
            continue
        participant = item.get("participant_did", item.get("sender_did", item.get("did")))
        if participant is not None and str(participant) != DID:
            continue
        status = str(item.get("status", "")).lower()
        if status in {"accepted", "rejected"}:
            return item
    return None


def _official_receipt(row: dict) -> dict | None:
    if not isinstance(row, dict) or row.get("from") != REFEREE_DID:
        return None
    try:
        verify_signed_record(ROOM, row)
        payload = json.loads(row.get("text", ""))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    item = _receipt_item(payload)
    if item is None:
        return None
    return {
        "status": str(item["status"]).lower(),
        "room_seq": row.get("seq"),
        "room_ts": row.get("ts"),
        "intake_seq": item.get("intake_seq"),
        "reason": item.get("reason") or item.get("reason_code") or item.get("error"),
    }


def _read_tail(since: int | None = None, *, wait: int = 0) -> tuple[list[dict], int, int | None]:
    params = ["format=json", "limit=200", f"n={secrets.token_hex(8)}"]
    if since is not None:
        params.append(f"since={since}")
        params.append(f"wait={wait}")
    response = core.httpx.get(f"{core.BASE_URL}/r/{ROOM}?" + "&".join(params), timeout=max(10, wait + 5))
    response.raise_for_status()
    view = response.json()
    rows = view if isinstance(view, list) else view.get("messages", [])
    if not isinstance(rows, list):
        raise ReplayError("receipt_read_failed")
    last_seq = view.get("last_seq") if isinstance(view, dict) else None
    if type(last_seq) is not int:
        last_seq = max((row.get("seq", 0) for row in rows if type(row.get("seq")) is int), default=since or 0)
    first_seq = view.get("first_seq") if isinstance(view, dict) else None
    if type(first_seq) is not int:
        first_seq = None
    return rows, last_seq, first_seq


def _find_receipt(rows: list[dict]) -> dict | None:
    for row in rows:
        receipt = _official_receipt(row)
        if receipt is not None:
            return receipt
    return None


def _resolve(state: dict, receipt: dict) -> dict:
    state["state"] = "resolved"
    state["receipt"] = receipt
    save(state)
    return {"action": "resolved", "request_id": REQUEST_ID, **receipt}


def _sign(nonce: str, text: str) -> list[str]:
    last: RuntimeError | None = None
    for delay in (0, 3, 8):
        if delay:
            time.sleep(delay)
        try:
            return oracle_signer.with_vault_seed(lambda: core.invoke_signer("say", ROOM, nonce, text))
        except RuntimeError as error:
            if str(error) != "signer Vault retrieval failed closed":
                raise
            last = error
    raise ReplayError("vault_retrieval_failed") from last


def run_once() -> dict:
    with replay_lock():
        require_identity()
        state = load()
        if state is None:
            state = new_state()
            save(state)
        if state["state"] == "resolved":
            return {"action": "already_resolved", "request_id": REQUEST_ID, **state["receipt"]}
        if state["state"] in {"attempting", "ambiguous", "replay_posted"}:
            raise ReplayError("replay_already_consumed")

        rows, cursor, _ = _read_tail()
        visible = _find_receipt(rows)
        if visible is not None:
            return _resolve(state, visible)

        require_prepost()
        text = render()
        if core.clean_text(text) != text:
            raise ReplayError("registration_text_invalid")
        if state["nonce"] is None:
            state["nonce"] = core.make_nonce(ROOM, DID)
        state["state"] = "prepared"
        save(state)

        signed = _sign(state["nonce"], text)
        if len(signed) != 2 or signed[0] != DID:
            raise ReplayError("did_mismatch")
        verify_signed_record(ROOM, {"from": DID, "nonce": state["nonce"], "text": text, "sig": signed[1]})

        require_prepost()
        state["state"] = "attempting"
        state["attempted_at"] = oracle_signer.now()
        save(state)
        try:
            response = core.httpx.post(
                f"{core.BASE_URL}/r/{ROOM}?format=json",
                json={"did": DID, "nonce": state["nonce"], "text": text, "sig": signed[1]},
                timeout=20,
            )
            response.raise_for_status()
            posted = response.json().get("posted")
            if (
                not isinstance(posted, dict)
                or posted.get("from") != DID
                or str(posted.get("nonce")) != state["nonce"]
                or posted.get("text") != text
                or posted.get("sig") != signed[1]
                or type(posted.get("seq")) is not int
                or not isinstance(posted.get("ts"), str)
            ):
                raise ReplayError("post_receipt_mismatch")
            verify_signed_record(ROOM, posted)
        except BaseException:
            state["state"] = "ambiguous"
            save(state)
            raise ReplayError("registration_replay_submission_unknown") from None

        state["state"] = "replay_posted"
        state["post_seq"] = posted["seq"]
        state["post_ts"] = posted["ts"]
        save(state)

        poll_cursor = max(cursor, posted["seq"])
        for _ in range(30):
            rows, last_seq, first_seq = _read_tail(poll_cursor, wait=2)
            if first_seq is not None and first_seq > poll_cursor + 1:
                return {
                    "action": "replay_posted_receipt_gap",
                    "request_id": REQUEST_ID,
                    "post_seq": posted["seq"],
                    "post_ts": posted["ts"],
                }
            receipt = _find_receipt(rows)
            if receipt is not None:
                return _resolve(state, receipt)
            poll_cursor = max(poll_cursor, last_seq)

        return {
            "action": "replay_posted_receipt_pending",
            "request_id": REQUEST_ID,
            "post_seq": posted["seq"],
            "post_ts": posted["ts"],
        }


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("registration receipt replay accepts no arguments")
    try:
        print(json.dumps(run_once(), sort_keys=True))
    except ReplayError as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        raise SystemExit(1) from None
    except Exception:
        print(json.dumps({"ok": False, "error": "receipt_replay_failed_closed"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
