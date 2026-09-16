"""One fixed non-binding Sonnet-2 discovery broadcast for MARU.

This module is execution-only support for Issue #253.  It can post exactly one
fixed ``sonnet.note.v1`` and cannot create roster consent, words, publication or
submission records.  The writer registration is treated only as an already-posted
local request; acceptance is never claimed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime

from . import core, oracle_signer, sonnet_nonbinding_policy as policy
from . import sonnet_registration as registration
from .public_record import verify_signed_record

ROOM = "mb-sonnet-2-discovery"
DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
CLOSE = datetime(2026, 9, 18, 12, tzinfo=UTC)
REGISTRATION_REQUEST = "32c15433c6d73af1cea5d6467dece016"
REQUEST_ID = "maru-open-seat-broadcast-20260916-1"

PAYLOAD = {
    "type": "sonnet.note.v1",
    "contest_id": "sonnet-2",
    "request_id": REQUEST_ID,
    "did": DID,
    "role": "writer",
    "x_account_url": "https://x.com/MinerMaru73",
    "no_live_roster_consent": True,
    "text": (
        "MARU is available to consider one Sonnet-2 writer seat. This is a non-binding "
        "discovery broadcast only: no roster consent, no word proposal, no publication, "
        "and no submission. Existing writer registration request "
        f"{REGISTRATION_REQUEST} was replayed once and still awaits the authoritative "
        "referee/operator disposition; this note does not claim writer acceptance. If your "
        "team has a live seat, please reply directly to MARU DID with the referee-accepted "
        "setup receipt/request_id, actual poem room and room_generation, the exact current "
        "4-8 member roster including MARU, and whether any first word has already been "
        "accepted. MARU can validate a viable current roster promptly."
    ),
}


class BroadcastError(RuntimeError):
    pass


def _render(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def state_path():
    return core.STATE / "signer" / "sonnet-2-open-seat-broadcast-20260916.json"


def new_state() -> dict:
    text = _render(PAYLOAD)
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
        "seq": None,
        "ts": None,
        "posted_record": None,
    }


def validate(value: object) -> dict:
    fields = {
        "schema_version", "room", "did", "request_id", "payload", "text_hash",
        "state", "nonce", "attempted_at", "seq", "ts", "posted_record",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise BroadcastError("broadcast_state_invalid")
    text = _render(PAYLOAD)
    if (
        value["schema_version"] != 1
        or value["room"] != ROOM
        or value["did"] != DID
        or value["request_id"] != REQUEST_ID
        or value["payload"] != PAYLOAD
        or value["text_hash"] != hashlib.sha256(text.encode()).hexdigest()
        or value["state"] not in {"new", "prepared", "attempting", "ambiguous", "posted"}
    ):
        raise BroadcastError("broadcast_state_invalid")
    nonce = value["nonce"]
    if nonce is not None and (not isinstance(nonce, str) or not re.fullmatch(r"[0-9]{1,19}", nonce)):
        raise BroadcastError("broadcast_state_invalid")
    if value["state"] != "new" and nonce is None:
        raise BroadcastError("broadcast_state_invalid")
    if value["state"] in {"attempting", "ambiguous", "posted"} and not isinstance(value["attempted_at"], str):
        raise BroadcastError("broadcast_state_invalid")
    if value["state"] == "posted":
        row = value["posted_record"]
        if (
            type(value["seq"]) is not int
            or value["seq"] < 0
            or not isinstance(value["ts"], str)
            or not isinstance(row, dict)
            or row.get("from") != DID
            or row.get("seq") != value["seq"]
            or row.get("ts") != value["ts"]
            or str(row.get("nonce")) != nonce
            or row.get("text") != text
        ):
            raise BroadcastError("broadcast_state_invalid")
        verify_signed_record(ROOM, row)
    elif value["seq"] is not None or value["ts"] is not None or value["posted_record"] is not None:
        raise BroadcastError("broadcast_state_invalid")
    return value


def save(value: dict) -> None:
    from . import observer
    observer.atomic_json_write(state_path(), validate(value), compact=True, mode=0o600)


def load() -> dict | None:
    try:
        return validate(json.loads(state_path().read_text("utf-8")))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError) as error:
        raise BroadcastError("broadcast_state_invalid") from error


@contextmanager
def broadcast_lock():
    if os.name != "posix":
        raise BroadcastError("isolated_linux_signer_required")
    import fcntl
    import pwd
    if pwd.getpwuid(os.geteuid()).pw_name != "technocore-signer":
        raise BroadcastError("isolated_signer_user_required")
    lock_path = state_path().with_suffix(".lock")
    with lock_path.open("a") as handle:
        os.fchmod(handle.fileno(), 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise BroadcastError("broadcast_busy") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def require_identity() -> None:
    if oracle_signer.expected_did() != DID:
        raise BroadcastError("did_mismatch")
    core.require_verified_did(DID)
    if not core.signer_matches_pinned():
        raise BroadcastError("signer_not_pinned")


def require_registration_posted() -> None:
    try:
        value = registration.load()
    except Exception as error:
        raise BroadcastError("writer_registration_unavailable") from error
    if value is None or value.get("state") != "posted" or value.get("did") != DID:
        raise BroadcastError("writer_registration_not_posted")
    reg = value.get("registration")
    if not isinstance(reg, dict) or any(reg.get(key) != expected for key, expected in registration.FIXED.items()):
        raise BroadcastError("writer_registration_invalid")


def require_prepost() -> None:
    require_identity()
    require_registration_posted()
    try:
        policy.require_nonbinding_safety()
    except policy.NonBindingPolicyError as error:
        raise BroadcastError(str(error)) from error
    if datetime.now(UTC) >= CLOSE:
        raise BroadcastError("contest_closed")


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
    raise BroadcastError("vault_retrieval_failed") from last


def run_once() -> dict:
    with broadcast_lock():
        require_prepost()
        state = load()
        if state is None:
            state = new_state()
            save(state)
        elif state["state"] == "posted":
            return {
                "status": "already_posted",
                "request_id": state["request_id"],
                "seq": state["seq"],
                "ts": state["ts"],
            }
        elif state["state"] in {"attempting", "ambiguous"}:
            raise BroadcastError("broadcast_submission_ambiguous")

        text = _render(PAYLOAD)
        if core.clean_text(text) != text:
            raise BroadcastError("broadcast_text_invalid")
        if state["nonce"] is None:
            state["nonce"] = core.make_nonce(ROOM, DID)
        state["state"] = "prepared"
        save(state)

        signed = _sign(state["nonce"], text)
        if len(signed) != 2 or signed[0] != DID:
            raise BroadcastError("did_mismatch")
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
            body = response.json()
            row = body.get("posted") if isinstance(body, dict) else None
            if (
                not isinstance(row, dict)
                or row.get("from") != DID
                or str(row.get("nonce")) != state["nonce"]
                or row.get("text") != text
                or row.get("sig") != signed[1]
                or type(row.get("seq")) is not int
                or row["seq"] < 0
                or not isinstance(row.get("ts"), str)
            ):
                raise BroadcastError("receipt_mismatch")
            datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
            verify_signed_record(ROOM, row)
            state.update(
                state="posted",
                seq=row["seq"],
                ts=row["ts"],
                posted_record={key: row[key] for key in ("from", "nonce", "text", "sig", "seq", "ts")},
            )
            save(state)
            return {
                "status": "posted",
                "request_id": REQUEST_ID,
                "seq": row["seq"],
                "ts": row["ts"],
            }
        except BaseException:
            state["state"] = "ambiguous"
            state["posted_record"] = None
            save(state)
            raise BroadcastError("broadcast_submission_unknown") from None


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("MARU open-seat broadcast accepts no arguments")
    try:
        print(json.dumps(run_once(), sort_keys=True))
    except BroadcastError as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        raise SystemExit(1) from None
    except Exception:
        print(json.dumps({"ok": False, "error": "broadcast_failed_closed"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
