"""One-shot sonnet-2 writer registration, executable only by the isolated signer.

No text, room, URL, role or contest is accepted from CLI input. The durable
attempt marker precedes POST; an interrupted attempt can only reconcile.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
from contextlib import contextmanager
from datetime import UTC, datetime

from . import core, observer, oracle_signer
from .public_record import verify_signed_record

ROOM = "mb-sonnet-2-registration"
DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
FIXED = {"type": "sonnet.register.v1", "contest_id": "sonnet-2", "role": "writer", "x_account_url": "https://x.com/MinerMaru73"}
OPEN = datetime(2026, 9, 11, 12, tzinfo=UTC)
CLOSE = datetime(2026, 9, 18, 12, tzinfo=UTC)


class RegistrationError(RuntimeError):
    """Only fixed, non-secret error codes reach command output."""


def render(registration: dict, room: str = ROOM) -> str:
    if (room != ROOM or not isinstance(registration, dict)
            or set(registration) != set(FIXED) | {"request_id"}
            or any(registration.get(k) != v for k, v in FIXED.items())
            or not isinstance(registration.get("request_id"), str)
            or not re.fullmatch(r"[a-f0-9]{32}", registration["request_id"])):
        raise RegistrationError("registration_binding_invalid")
    return json.dumps(registration, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def state_path():
    return core.STATE / "signer" / "sonnet-2-registration.json"


def validate(value: dict) -> dict:
    required = {"schema_version", "room", "did", "registration", "state", "nonce", "text_hash", "git_commit_sha", "attempted_at", "seq", "ts", "posted_record"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != 1 or value.get("did") != DID:
        raise RegistrationError("registration_state_invalid")
    text = render(value["registration"], value["room"])
    if value["text_hash"] != hashlib.sha256(text.encode()).hexdigest() or value["state"] not in {"new", "prepared", "attempting", "ambiguous", "posted"}:
        raise RegistrationError("registration_state_invalid")
    if value["nonce"] is not None and (not isinstance(value["nonce"], str) or not re.fullmatch(r"[0-9]{1,19}", value["nonce"])):
        raise RegistrationError("registration_state_invalid")
    if value["state"] != "new" and value["nonce"] is None:
        raise RegistrationError("registration_state_invalid")
    if value["git_commit_sha"] is not None and not re.fullmatch(r"[0-9a-f]{40}", str(value["git_commit_sha"])):
        raise RegistrationError("registration_state_invalid")
    if value["state"] in {"attempting", "ambiguous"} and not isinstance(value["attempted_at"], str):
        raise RegistrationError("registration_state_invalid")
    if value["state"] == "posted" and (type(value["seq"]) is not int or value["seq"] < 0 or not isinstance(value["ts"], str)):
        raise RegistrationError("registration_state_invalid")
    if value["state"] == "posted":
        row = value["posted_record"]
        if not isinstance(row, dict) or row.get("from") != DID or row.get("seq") != value["seq"] or row.get("ts") != value["ts"] or str(row.get("nonce")) != value["nonce"]:
            raise RegistrationError("registration_state_invalid")
        render(json.loads(row["text"]))
        verify_signed_record(ROOM, row)
        datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
        if value["attempted_at"] is not None and row["text"] != text:
            raise RegistrationError("registration_state_invalid")
    elif value["posted_record"] is not None:
        raise RegistrationError("registration_state_invalid")
    return value


def save(value: dict) -> None:
    observer.atomic_json_write(state_path(), validate(value), compact=True, mode=0o600)


def load() -> dict | None:
    try:
        return validate(json.loads(state_path().read_text("utf-8")))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError) as error:
        raise RegistrationError("registration_state_invalid") from error


@contextmanager
def registration_lock():
    if os.name != "posix":
        raise RegistrationError("isolated_linux_signer_required")
    import fcntl
    import pwd
    if pwd.getpwuid(os.geteuid()).pw_name != "technocore-signer":
        raise RegistrationError("isolated_signer_user_required")
    # Existing signer-owned directory; do not create or broaden permissions.
    with state_path().with_suffix(".lock").open("a") as handle:
        os.fchmod(handle.fileno(), 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RegistrationError("registration_busy") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def require_health() -> None:
    # Same read-side safety evidence as the existing typed isolated lane.
    # Missing permissions/state fail closed; this code grants no Observer access.
    try:
        value = observer.load_state()
        stamp = datetime.fromisoformat(value["updated_at"])
        age = (datetime.now(UTC) - stamp).total_seconds()
    except Exception as error:
        raise RegistrationError("observer_state_unavailable") from error
    if not 0 <= age <= 300 or value.get("health", {}).get("current") != "ok":
        raise RegistrationError("observer_health_not_ok")
    metrics = value.get("metrics", {})
    if (metrics.get("unrecoverable_core_gap_events"), metrics.get("unrecoverable_core_gap_messages")) != (117, 5_083_155):
        raise RegistrationError("protected_core_baseline_changed")


def require_identity() -> None:
    if oracle_signer.expected_did() != DID:
        raise RegistrationError("did_mismatch")
    core.require_verified_did(DID)
    if not core.signer_matches_pinned():
        raise RegistrationError("signer_not_pinned")


def existing_record(value: dict) -> dict | None:
    payload = core.read_room(ROOM, limit=200, cache_buster=secrets.token_hex(16))
    rows = payload if isinstance(payload, list) else payload.get("messages")
    if not isinstance(rows, list):
        raise RegistrationError("reconcile_read_failed")
    for row in rows:
        if not isinstance(row, dict) or row.get("from") != DID:
            continue
        try:
            registration = json.loads(row.get("text", ""))
            render(registration)
            verify_signed_record(ROOM, row)
        except (ValueError, TypeError, RuntimeError):
            continue
        # Even another request ID with the same fixed writer binding suppresses
        # a second registration. Never change the locally persisted request ID.
        if value["state"] in {"attempting", "ambiguous"} and (
            registration != value["registration"] or str(row.get("nonce")) != value["nonce"]
        ):
            raise RegistrationError("existing_registration_conflict")
        if type(row.get("seq")) is int and row["seq"] >= 0 and isinstance(row.get("ts"), str):
            return row
    return None


def mark_posted(value: dict, row: dict) -> dict:
    record = {key: row[key] for key in ("from", "nonce", "text", "sig", "seq", "ts")}
    value.update(state="posted", nonce=str(row["nonce"]), seq=row["seq"], ts=row["ts"], posted_record=record)
    save(value)
    return {"action": "posted", "request_id": value["registration"]["request_id"], "seq": row["seq"]}


def _run_locked() -> dict:
    require_identity()
    value = load()
    if value is None:
        registration = {**FIXED, "request_id": secrets.token_hex(16)}
        value = {"schema_version": 1, "room": ROOM, "did": DID, "registration": registration,
                 "state": "new", "nonce": None, "text_hash": hashlib.sha256(render(registration).encode()).hexdigest(),
                 "git_commit_sha": None, "attempted_at": None, "seq": None, "ts": None, "posted_record": None}
        save(value)
    if value["state"] == "posted":
        return {"action": "already_posted", "request_id": value["registration"]["request_id"], "seq": value["seq"]}
    row = existing_record(value)
    if row is not None:
        result = mark_posted(value, row)
        result["action"] = "reconciled"
        return result
    if value["state"] in {"attempting", "ambiguous"}:
        return {"action": "ambiguous", "request_id": value["registration"]["request_id"]}
    require_health()
    if not OPEN <= datetime.now(UTC) < CLOSE:
        raise RegistrationError("registration_window_closed")
    text = render(value["registration"], value["room"])
    if core.clean_text(text) != text:
        raise RegistrationError("registration_text_invalid")
    if value["nonce"] is None:
        value["nonce"] = core.make_nonce(ROOM, DID)
    value["git_commit_sha"] = core.git_commit_sha()
    value["state"] = "prepared"
    save(value)
    signed = oracle_signer.with_vault_seed(lambda: core.invoke_signer("say", ROOM, value["nonce"], text))
    if len(signed) != 2 or signed[0] != DID:
        raise RegistrationError("did_mismatch")
    # Verify the actual signature using the continuing public DID as well.
    verify_signed_record(ROOM, {"from": DID, "nonce": value["nonce"], "text": text, "sig": signed[1]})
    require_identity()
    require_health()
    if not OPEN <= datetime.now(UTC) < CLOSE:
        raise RegistrationError("registration_window_closed")
    value["state"] = "attempting"
    value["attempted_at"] = oracle_signer.now()
    save(value)  # crash here or at any later point can never permit a second POST
    try:
        response = core.httpx.post(f"{core.BASE_URL}/r/{ROOM}?format=json", json={"did": DID, "nonce": value["nonce"], "text": text, "sig": signed[1]}, timeout=20)
        response.raise_for_status()
        row = response.json().get("posted")
        if not isinstance(row, dict) or any(row.get(k) != v for k, v in {"from": DID, "text": text, "sig": signed[1]}.items()) or str(row.get("nonce")) != value["nonce"] or type(row.get("seq")) is not int or row["seq"] < 0:
            raise RegistrationError("receipt_mismatch")
        datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
        return mark_posted(value, row)
    except Exception:
        value["state"] = "ambiguous"
        value["posted_record"] = None
        save(value)
        raise RegistrationError("submission_unknown") from None


def run_once() -> dict:
    with registration_lock():
        return _run_locked()


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("sonnet registration accepts no arguments")
    try:
        result = run_once()
    except Exception:
        # Never print SDK, HTTP, filesystem or signer-child exception text.
        print(json.dumps({"ok": False, "error": "registration_failed_closed"}))
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
