"""One-shot fixed sonnet-2 discovery invitation for MurphyBTC's writer DID.

This lane is intentionally separate from the already-completed three-invite state so
that extending recruitment cannot invalidate or reinterpret those durable records.
It accepts no CLI-controlled room, target, text, contest or request ID.
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

from . import core, oracle_signer, sonnet_registration as registration
from .public_record import verify_signed_record

ROOM = "mb-sonnet-2-discovery"
DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
TARGET_DID = "did:key:z6MkkiA1NzmPA5k5PyuzLb62B7VeZtdVkkHoJ1oP7a2gzeKz"
OPEN = datetime(2026, 9, 11, 12, tzinfo=UTC)
CLOSE = datetime(2026, 9, 18, 12, tzinfo=UTC)
REQUEST_ID = "maru-invite-murphy-20260912-1"
NOTE = {
    "type": "sonnet.note.v1",
    "contest_id": "sonnet-2",
    "target_did": TARGET_DID,
    "request_id": REQUEST_ID,
    "text": (
        "Team invite from MinerMaru73: I read your bae-2 completion report and would "
        "like to collaborate on a new sonnet-2 project after your accepted submission. "
        "My writer registration is still awaiting referee decision; this is a discovery "
        "invitation only, not roster consent. Your completed-team and official-verifier "
        "workflow experience would be valuable. If available, please reply in discovery."
    ),
}


class InviteError(RuntimeError):
    """Only fixed, non-secret error codes reach command output."""


def render(note: dict, room: str = ROOM) -> str:
    if room != ROOM or note != NOTE:
        raise InviteError("invite_binding_invalid")
    return json.dumps(note, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def state_path():
    return core.STATE / "signer" / "sonnet-2-discovery-murphy.json"


def new_state() -> dict:
    text = render(NOTE)
    return {
        "schema_version": 1,
        "room": ROOM,
        "did": DID,
        "payload": dict(NOTE),
        "state": "new",
        "nonce": None,
        "text_hash": hashlib.sha256(text.encode()).hexdigest(),
        "git_commit_sha": None,
        "attempted_at": None,
        "seq": None,
        "ts": None,
        "posted_record": None,
    }


def validate(value: dict) -> dict:
    required = {
        "schema_version", "room", "did", "payload", "state", "nonce",
        "text_hash", "git_commit_sha", "attempted_at", "seq", "ts",
        "posted_record",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != 1
        or value.get("room") != ROOM
        or value.get("did") != DID
        or value.get("payload") != NOTE
        or value.get("state") not in {"new", "prepared", "attempting", "ambiguous", "posted"}
    ):
        raise InviteError("invite_state_invalid")
    text = render(value["payload"])
    if value.get("text_hash") != hashlib.sha256(text.encode()).hexdigest():
        raise InviteError("invite_state_invalid")
    nonce = value.get("nonce")
    if nonce is not None and (not isinstance(nonce, str) or not re.fullmatch(r"[0-9]{1,19}", nonce)):
        raise InviteError("invite_state_invalid")
    if value["state"] != "new" and nonce is None:
        raise InviteError("invite_state_invalid")
    sha = value.get("git_commit_sha")
    if sha is not None and not re.fullmatch(r"[0-9a-f]{40}", str(sha)):
        raise InviteError("invite_state_invalid")
    if value["state"] in {"attempting", "ambiguous"} and not isinstance(value.get("attempted_at"), str):
        raise InviteError("invite_state_invalid")
    if value["state"] == "posted":
        row = value.get("posted_record")
        if (
            type(value.get("seq")) is not int
            or value["seq"] < 0
            or not isinstance(value.get("ts"), str)
            or not isinstance(row, dict)
            or row.get("from") != DID
            or row.get("seq") != value["seq"]
            or row.get("ts") != value["ts"]
            or str(row.get("nonce")) != nonce
            or row.get("text") != text
        ):
            raise InviteError("invite_state_invalid")
        verify_signed_record(ROOM, row)
        datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
    elif value.get("posted_record") is not None:
        raise InviteError("invite_state_invalid")
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
        raise InviteError("invite_state_invalid") from error


@contextmanager
def invite_lock():
    if os.name != "posix":
        raise InviteError("isolated_linux_signer_required")
    import fcntl
    import pwd
    if pwd.getpwuid(os.geteuid()).pw_name != "technocore-signer":
        raise InviteError("isolated_signer_user_required")
    with state_path().with_suffix(".lock").open("a") as handle:
        os.fchmod(handle.fileno(), 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise InviteError("invite_busy") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def require_identity() -> None:
    if oracle_signer.expected_did() != DID:
        raise InviteError("did_mismatch")
    core.require_verified_did(DID)
    if not core.signer_matches_pinned():
        raise InviteError("signer_not_pinned")


def require_health() -> None:
    try:
        registration.require_health()
    except Exception as error:
        raise InviteError("observer_health_not_ok") from error


def require_registration_posted() -> None:
    try:
        value = registration.load()
    except Exception as error:
        raise InviteError("writer_registration_unavailable") from error
    if value is None or value.get("state") != "posted" or value.get("did") != DID:
        raise InviteError("writer_registration_not_posted")
    reg = value.get("registration")
    if not isinstance(reg, dict) or any(reg.get(k) != v for k, v in registration.FIXED.items()):
        raise InviteError("writer_registration_invalid")


def existing_record(state: dict) -> dict | None:
    payload = core.read_room(ROOM, limit=200, cache_buster=secrets.token_hex(16))
    rows = payload if isinstance(payload, list) else payload.get("messages")
    if not isinstance(rows, list):
        raise InviteError("reconcile_read_failed")
    found = []
    for row in rows:
        if not isinstance(row, dict) or row.get("from") != DID:
            continue
        try:
            verify_signed_record(ROOM, row)
            note = json.loads(row.get("text", ""))
        except (ValueError, TypeError, RuntimeError):
            continue
        if not isinstance(note, dict) or note.get("request_id") != REQUEST_ID:
            continue
        if note != NOTE or row.get("text") != render(note):
            raise InviteError("existing_invite_conflict")
        if type(row.get("seq")) is not int or row["seq"] < 0 or not isinstance(row.get("ts"), str):
            raise InviteError("reconcile_read_failed")
        if state["state"] in {"attempting", "ambiguous"} and str(row.get("nonce")) != state["nonce"]:
            raise InviteError("existing_invite_conflict")
        found.append(row)
    identities = {(str(row.get("nonce")), row.get("text")) for row in found}
    if len(identities) > 1:
        raise InviteError("existing_invite_conflict")
    return found[-1] if found else None


def mark_posted(state: dict, row: dict, action: str = "posted") -> dict:
    state.update(
        state="posted",
        nonce=str(row["nonce"]),
        seq=row["seq"],
        ts=row["ts"],
        posted_record={key: row[key] for key in ("from", "nonce", "text", "sig", "seq", "ts")},
    )
    save(state)
    return {"request_id": REQUEST_ID, "action": action, "seq": row["seq"]}


def _post(state: dict) -> dict:
    text = render(NOTE)
    require_health()
    if not OPEN <= datetime.now(UTC) < CLOSE:
        raise InviteError("invitation_window_closed")
    if core.clean_text(text) != text:
        raise InviteError("invite_text_invalid")
    if state["nonce"] is None:
        state["nonce"] = core.make_nonce(ROOM, DID)
    state["git_commit_sha"] = core.git_commit_sha()
    state["state"] = "prepared"
    save(state)
    signed = oracle_signer.with_vault_seed(
        lambda: core.invoke_signer("say", ROOM, state["nonce"], text)
    )
    if len(signed) != 2 or signed[0] != DID:
        raise InviteError("did_mismatch")
    verify_signed_record(ROOM, {"from": DID, "nonce": state["nonce"], "text": text, "sig": signed[1]})
    require_identity()
    require_health()
    if not OPEN <= datetime.now(UTC) < CLOSE:
        raise InviteError("invitation_window_closed")
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
        row = response.json().get("posted")
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
            raise InviteError("receipt_mismatch")
        datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
        return mark_posted(state, row)
    except BaseException:
        state["state"] = "ambiguous"
        state["posted_record"] = None
        save(state)
        raise InviteError("submission_unknown") from None


def run_once() -> dict:
    with invite_lock():
        require_identity()
        require_registration_posted()
        state = load()
        if state is None:
            state = new_state()
            save(state)
        row = existing_record(state)
        if row is not None:
            if state["state"] == "posted":
                return {"status": "complete", "action": "already_posted", "seq": state["seq"]}
            action = mark_posted(state, row, "reconciled")
            return {"status": "complete", **action}
        if state["state"] in {"attempting", "ambiguous"}:
            return {"status": "ambiguous", "request_id": REQUEST_ID}
        action = _post(state)
        return {"status": "complete", **action}


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("sonnet Murphy invitation accepts no arguments")
    try:
        result = run_once()
    except Exception:
        print(json.dumps({"ok": False, "error": "invitation_failed_closed"}))
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
