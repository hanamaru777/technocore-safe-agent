"""One exactly-once fresh Sonnet-2 MARU writer registration recovery.

This lane exists only for the deadline-critical #257 section 18C recovery decision.
It keeps the already-bound DID / writer role / X account unchanged and uses one
fixed fresh request_id. It never mutates the canonical historical registration
state and never blindly retries an ambiguous POST.
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
OLD_REQUEST_ID = "32c15433c6d73af1cea5d6467dece016"
REQUEST_ID = "maru-sonnet2-writer-fresh-20260917-1"
BASE_BINDING = {
    "type": "sonnet.register.v1",
    "contest_id": "sonnet-2",
    "role": "writer",
    "x_account_url": "https://x.com/MinerMaru73",
}
PAYLOAD = {**BASE_BINDING, "request_id": REQUEST_ID}
OLD_PAYLOAD = {**BASE_BINDING, "request_id": OLD_REQUEST_ID}
OPEN = datetime(2026, 9, 11, 12, tzinfo=UTC)
CLOSE = datetime(2026, 9, 18, 12, tzinfo=UTC)


class FreshRegistrationError(RuntimeError):
    pass


def render(payload: dict = PAYLOAD) -> str:
    if (
        not isinstance(payload, dict)
        or set(payload) != set(BASE_BINDING) | {"request_id"}
        or any(payload.get(key) != value for key, value in BASE_BINDING.items())
        or payload.get("request_id") not in {OLD_REQUEST_ID, REQUEST_ID}
    ):
        raise FreshRegistrationError("registration_binding_invalid")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def state_path():
    return core.STATE / "signer" / "sonnet-2-registration-fresh-recovery-20260917.json"


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
        raise FreshRegistrationError("fresh_state_invalid")
    if (
        value["schema_version"] != 1
        or value["room"] != ROOM
        or value["did"] != DID
        or value["request_id"] != REQUEST_ID
        or value["payload"] != PAYLOAD
        or value["text_hash"] != hashlib.sha256(render().encode()).hexdigest()
        or value["state"] not in {"new", "prepared", "attempting", "fresh_posted", "resolved", "ambiguous"}
    ):
        raise FreshRegistrationError("fresh_state_invalid")
    nonce = value["nonce"]
    if nonce is not None and (not isinstance(nonce, str) or not re.fullmatch(r"[0-9]{1,19}", nonce)):
        raise FreshRegistrationError("fresh_state_invalid")
    if value["state"] != "new" and nonce is None and value["state"] != "resolved":
        raise FreshRegistrationError("fresh_state_invalid")
    if value["state"] in {"attempting", "fresh_posted", "ambiguous"} and not isinstance(value["attempted_at"], str):
        raise FreshRegistrationError("fresh_state_invalid")
    if value["state"] == "fresh_posted":
        if type(value["post_seq"]) is not int or not isinstance(value["post_ts"], str):
            raise FreshRegistrationError("fresh_state_invalid")
    if value["state"] == "resolved":
        receipt = value["receipt"]
        if not isinstance(receipt, dict) or receipt.get("status") not in {"accepted", "rejected"}:
            raise FreshRegistrationError("fresh_state_invalid")
    elif value["receipt"] is not None:
        raise FreshRegistrationError("fresh_state_invalid")
    return value


def save(value: dict) -> None:
    observer.atomic_json_write(state_path(), validate(value), compact=True, mode=0o600)


def load() -> dict | None:
    try:
        return validate(json.loads(state_path().read_text("utf-8")))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError) as error:
        raise FreshRegistrationError("fresh_state_invalid") from error


@contextmanager
def fresh_lock():
    if os.name != "posix":
        raise FreshRegistrationError("isolated_linux_signer_required")
    import fcntl
    import pwd
    if pwd.getpwuid(os.geteuid()).pw_name != "technocore-signer":
        raise FreshRegistrationError("isolated_signer_user_required")
    path = state_path().with_suffix(".lock")
    with path.open("a") as handle:
        os.fchmod(handle.fileno(), 0o600)
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise FreshRegistrationError("fresh_registration_busy") from error
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def require_identity() -> None:
    if oracle_signer.expected_did() != DID:
        raise FreshRegistrationError("did_mismatch")
    core.require_verified_did(DID)
    if not core.signer_matches_pinned():
        raise FreshRegistrationError("signer_not_pinned")


def require_original_posted_registration() -> None:
    try:
        value = registration.load()
    except Exception as error:
        raise FreshRegistrationError("original_registration_unavailable") from error
    if value is None or value.get("state") != "posted" or value.get("did") != DID:
        raise FreshRegistrationError("original_registration_not_posted")
    if value.get("registration") != OLD_PAYLOAD:
        raise FreshRegistrationError("original_registration_mismatch")
    if type(value.get("seq")) is not int or not isinstance(value.get("ts"), str):
        raise FreshRegistrationError("original_registration_invalid")


def require_prepost() -> None:
    require_identity()
    require_original_posted_registration()
    try:
        registration.require_health()
    except Exception as error:
        raise FreshRegistrationError("strict_safety_gate_failed") from error
    if not OPEN <= datetime.now(UTC) < CLOSE:
        raise FreshRegistrationError("registration_window_closed")


def _receipt_item(payload: object, request_id: str) -> dict | None:
    if not isinstance(payload, dict):
        return None
    if payload.get("type") == "sonnet.receipt.v1":
        candidates = [payload]
    elif payload.get("type") == "sonnet.receipts.v1" and isinstance(payload.get("receipts"), list):
        candidates = [item for item in payload["receipts"] if isinstance(item, dict)]
    else:
        return None
    for item in candidates:
        if str(item.get("request_id", "")) != request_id:
            continue
        participant = item.get("participant_did", item.get("sender_did", item.get("did")))
        if str(participant) != DID:
            continue
        status = str(item.get("status", "")).lower()
        if status in {"accepted", "rejected"}:
            return item
    return None


def _official_receipt(row: dict, request_id: str) -> dict | None:
    if not isinstance(row, dict) or row.get("from") != REFEREE_DID:
        return None
    try:
        verify_signed_record(ROOM, row)
        payload = json.loads(row.get("text", ""))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    item = _receipt_item(payload, request_id)
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
    response = core.httpx.get(
        f"{core.BASE_URL}/r/{ROOM}?" + "&".join(params),
        timeout=max(10, wait + 5),
    )
    response.raise_for_status()
    view = response.json()
    rows = view if isinstance(view, list) else view.get("messages", [])
    if not isinstance(rows, list):
        raise FreshRegistrationError("registration_read_failed")
    last_seq = view.get("last_seq") if isinstance(view, dict) else None
    if type(last_seq) is not int:
        last_seq = max(
            (row.get("seq", 0) for row in rows if isinstance(row, dict) and type(row.get("seq")) is int),
            default=since or 0,
        )
    first_seq = view.get("first_seq") if isinstance(view, dict) else None
    if type(first_seq) is not int:
        first_seq = None
    return rows, last_seq, first_seq


def _find_receipt(rows: list[dict], request_id: str) -> dict | None:
    for row in rows:
        receipt = _official_receipt(row, request_id)
        if receipt is not None:
            return receipt
    return None


def _fresh_post_visible(rows: list[dict]) -> bool:
    for row in rows:
        if not isinstance(row, dict) or row.get("from") != DID:
            continue
        try:
            verify_signed_record(ROOM, row)
            payload = json.loads(row.get("text", ""))
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
        if payload == PAYLOAD:
            return True
    return False


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
    raise FreshRegistrationError("vault_retrieval_failed") from last


def _prewrite_authority_check(rows: list[dict]) -> None:
    if _find_receipt(rows, OLD_REQUEST_ID) is not None:
        raise FreshRegistrationError("old_request_authority_visible")
    if _find_receipt(rows, REQUEST_ID) is not None or _fresh_post_visible(rows):
        raise FreshRegistrationError("fresh_request_authority_already_visible")


def run_once() -> dict:
    with fresh_lock():
        require_identity()
        state = load()
        if state is None:
            state = new_state()
            save(state)
        if state["state"] == "resolved":
            return {"action": "already_resolved", "request_id": REQUEST_ID, **state["receipt"]}
        if state["state"] in {"attempting", "ambiguous", "fresh_posted"}:
            raise FreshRegistrationError("fresh_registration_already_consumed")

        rows, cursor, _ = _read_tail()
        _prewrite_authority_check(rows)

        require_prepost()
        text = render()
        if core.clean_text(text) != text:
            raise FreshRegistrationError("registration_text_invalid")
        if state["nonce"] is None:
            state["nonce"] = core.make_nonce(ROOM, DID)
        state["state"] = "prepared"
        save(state)

        signed = _sign(state["nonce"], text)
        if len(signed) != 2 or signed[0] != DID:
            raise FreshRegistrationError("did_mismatch")
        verify_signed_record(
            ROOM,
            {"from": DID, "nonce": state["nonce"], "text": text, "sig": signed[1]},
        )

        # Re-read authority after signing so a just-arrived old disposition wins.
        rows, cursor2, _ = _read_tail()
        _prewrite_authority_check(rows)
        cursor = max(cursor, cursor2)

        require_prepost()
        state["state"] = "attempting"
        state["attempted_at"] = oracle_signer.now()
        save(state)  # any interruption from here permanently forbids blind retry
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
                raise FreshRegistrationError("post_receipt_mismatch")
            verify_signed_record(ROOM, posted)
        except BaseException:
            state["state"] = "ambiguous"
            save(state)
            raise FreshRegistrationError("fresh_registration_submission_unknown") from None

        state["state"] = "fresh_posted"
        state["post_seq"] = posted["seq"]
        state["post_ts"] = posted["ts"]
        save(state)

        poll_cursor = max(cursor, posted["seq"])
        for _ in range(45):
            rows, last_seq, first_seq = _read_tail(poll_cursor, wait=2)
            if first_seq is not None and first_seq > poll_cursor + 1:
                return {
                    "action": "fresh_posted_receipt_gap",
                    "request_id": REQUEST_ID,
                    "post_seq": posted["seq"],
                    "post_ts": posted["ts"],
                }
            receipt = _find_receipt(rows, REQUEST_ID)
            if receipt is not None:
                return _resolve(state, receipt)
            poll_cursor = max(poll_cursor, last_seq)

        return {
            "action": "fresh_posted_receipt_pending",
            "request_id": REQUEST_ID,
            "post_seq": posted["seq"],
            "post_ts": posted["ts"],
        }


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("fresh registration recovery accepts no arguments")
    try:
        print(json.dumps(run_once(), sort_keys=True))
    except FreshRegistrationError as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        raise SystemExit(1) from None
    except Exception:
        print(json.dumps({"ok": False, "error": "fresh_registration_failed_closed"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
