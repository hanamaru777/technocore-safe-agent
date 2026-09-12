"""One-shot fixed sonnet-2 discovery invitations for three approved writers.

No text, room, target DID, URL, contest or request ID is accepted from CLI input.
Each invitation has a stable request ID. A durable attempt marker precedes POST;
an interrupted attempt can only reconcile and is never blindly retried.
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
OPEN = datetime(2026, 9, 11, 12, tzinfo=UTC)
CLOSE = datetime(2026, 9, 18, 12, tzinfo=UTC)
NOTE_TEXT = (
    "Team invite from MinerMaru73: forming a 4-writer sonnet-2 team. "
    "Your accepted writer DID complements our letter coverage. My writer registration "
    "is still awaiting referee decision; this is a discovery invitation only, not roster "
    "consent. If interested, please reply in discovery."
)
INVITATIONS = (
    {
        "type": "sonnet.note.v1",
        "contest_id": "sonnet-2",
        "target_did": "did:key:z6MkuEVGgRAqUR3KyBFLMHqE15dosbpFPoqpjz5b1VrUgatq",
        "request_id": "maru-invite-hunte-20260912-1",
        "text": NOTE_TEXT,
    },
    {
        "type": "sonnet.note.v1",
        "contest_id": "sonnet-2",
        "target_did": "did:key:z6Mkt1dE2bNSCEti4oVvjvuWzQAdEAG98t3T9naCQFLHoenj",
        "request_id": "maru-invite-shrimp-20260912-1",
        "text": NOTE_TEXT,
    },
    {
        "type": "sonnet.note.v1",
        "contest_id": "sonnet-2",
        "target_did": "did:key:z6MkmVhZbUKWmg3r6TTi3SVM3myYJ9BLbWYPSdc5iWPuPhb6",
        "request_id": "maru-invite-noob-20260912-1",
        "text": NOTE_TEXT,
    },
)
BY_REQUEST = {item["request_id"]: item for item in INVITATIONS}


class InviteError(RuntimeError):
    """Only fixed, non-secret error codes reach command output."""


def render(invitation: dict, room: str = ROOM) -> str:
    if room != ROOM or not isinstance(invitation, dict):
        raise InviteError("invite_binding_invalid")
    request_id = invitation.get("request_id")
    fixed = BY_REQUEST.get(str(request_id))
    if fixed is None or invitation != fixed:
        raise InviteError("invite_binding_invalid")
    return json.dumps(invitation, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def state_path():
    return core.STATE / "signer" / "sonnet-2-discovery-invites.json"


def _new_entry(payload: dict) -> dict:
    text = render(payload)
    return {
        "payload": dict(payload),
        "state": "new",
        "nonce": None,
        "text_hash": hashlib.sha256(text.encode()).hexdigest(),
        "git_commit_sha": None,
        "attempted_at": None,
        "seq": None,
        "ts": None,
        "posted_record": None,
    }


def new_state() -> dict:
    return {
        "schema_version": 1,
        "room": ROOM,
        "did": DID,
        "entries": {item["request_id"]: _new_entry(item) for item in INVITATIONS},
    }


def validate(value: dict) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "room", "did", "entries"}
        or value.get("schema_version") != 1
        or value.get("room") != ROOM
        or value.get("did") != DID
        or not isinstance(value.get("entries"), dict)
        or set(value["entries"]) != set(BY_REQUEST)
    ):
        raise InviteError("invite_state_invalid")
    required = {"payload", "state", "nonce", "text_hash", "git_commit_sha", "attempted_at", "seq", "ts", "posted_record"}
    for request_id, entry in value["entries"].items():
        if not isinstance(entry, dict) or set(entry) != required:
            raise InviteError("invite_state_invalid")
        payload = entry["payload"]
        text = render(payload, value["room"])
        if payload["request_id"] != request_id:
            raise InviteError("invite_state_invalid")
        if entry["text_hash"] != hashlib.sha256(text.encode()).hexdigest():
            raise InviteError("invite_state_invalid")
        if entry["state"] not in {"new", "prepared", "attempting", "ambiguous", "posted"}:
            raise InviteError("invite_state_invalid")
        if entry["nonce"] is not None and (not isinstance(entry["nonce"], str) or not re.fullmatch(r"[0-9]{1,19}", entry["nonce"])):
            raise InviteError("invite_state_invalid")
        if entry["state"] != "new" and entry["nonce"] is None:
            raise InviteError("invite_state_invalid")
        if entry["git_commit_sha"] is not None and not re.fullmatch(r"[0-9a-f]{40}", str(entry["git_commit_sha"])):
            raise InviteError("invite_state_invalid")
        if entry["state"] in {"attempting", "ambiguous"} and not isinstance(entry["attempted_at"], str):
            raise InviteError("invite_state_invalid")
        if entry["state"] == "posted":
            if type(entry["seq"]) is not int or entry["seq"] < 0 or not isinstance(entry["ts"], str):
                raise InviteError("invite_state_invalid")
            row = entry["posted_record"]
            if (
                not isinstance(row, dict)
                or row.get("from") != DID
                or row.get("seq") != entry["seq"]
                or row.get("ts") != entry["ts"]
                or str(row.get("nonce")) != entry["nonce"]
                or row.get("text") != text
            ):
                raise InviteError("invite_state_invalid")
            verify_signed_record(ROOM, row)
            datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
        elif entry["posted_record"] is not None:
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


def existing_records(state: dict) -> dict[str, dict]:
    payload = core.read_room(ROOM, limit=200, cache_buster=secrets.token_hex(16))
    rows = payload if isinstance(payload, list) else payload.get("messages")
    if not isinstance(rows, list):
        raise InviteError("reconcile_read_failed")
    matches: dict[str, list[dict]] = {request_id: [] for request_id in BY_REQUEST}
    for row in rows:
        if not isinstance(row, dict) or row.get("from") != DID:
            continue
        try:
            verify_signed_record(ROOM, row)
            note = json.loads(row.get("text", ""))
        except (ValueError, TypeError, RuntimeError):
            continue
        if not isinstance(note, dict):
            continue
        request_id = note.get("request_id")
        if request_id not in BY_REQUEST:
            continue
        if note != BY_REQUEST[request_id] or row.get("text") != render(note):
            raise InviteError("existing_invite_conflict")
        if type(row.get("seq")) is not int or row["seq"] < 0 or not isinstance(row.get("ts"), str) or not isinstance(row.get("sig"), str):
            raise InviteError("reconcile_read_failed")
        datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
        entry = state["entries"][request_id]
        if entry["state"] in {"attempting", "ambiguous"} and str(row.get("nonce")) != entry["nonce"]:
            raise InviteError("existing_invite_conflict")
        matches[request_id].append(row)
    result = {}
    for request_id, found in matches.items():
        identities = {(str(row.get("nonce")), row.get("text")) for row in found}
        if len(identities) > 1:
            raise InviteError("existing_invite_conflict")
        if found:
            result[request_id] = found[-1]
    return result


def mark_posted(state: dict, request_id: str, row: dict) -> dict:
    entry = state["entries"][request_id]
    entry.update(
        state="posted",
        nonce=str(row["nonce"]),
        seq=row["seq"],
        ts=row["ts"],
        posted_record={key: row[key] for key in ("from", "nonce", "text", "sig", "seq", "ts")},
    )
    save(state)
    return {"request_id": request_id, "action": "posted", "seq": row["seq"]}


def _post_one(state: dict, request_id: str) -> dict:
    entry = state["entries"][request_id]
    payload = entry["payload"]
    text = render(payload)
    require_health()
    if not OPEN <= datetime.now(UTC) < CLOSE:
        raise InviteError("invitation_window_closed")
    if core.clean_text(text) != text:
        raise InviteError("invite_text_invalid")
    if entry["nonce"] is None:
        entry["nonce"] = core.make_nonce(ROOM, DID)
    entry["git_commit_sha"] = core.git_commit_sha()
    entry["state"] = "prepared"
    save(state)
    signed = oracle_signer.with_vault_seed(lambda: core.invoke_signer("say", ROOM, entry["nonce"], text))
    if len(signed) != 2 or signed[0] != DID:
        raise InviteError("did_mismatch")
    verify_signed_record(ROOM, {"from": DID, "nonce": entry["nonce"], "text": text, "sig": signed[1]})
    require_identity()
    require_health()
    if not OPEN <= datetime.now(UTC) < CLOSE:
        raise InviteError("invitation_window_closed")
    entry["state"] = "attempting"
    entry["attempted_at"] = oracle_signer.now()
    save(state)
    try:
        response = core.httpx.post(
            f"{core.BASE_URL}/r/{ROOM}?format=json",
            json={"did": DID, "nonce": entry["nonce"], "text": text, "sig": signed[1]},
            timeout=20,
        )
        response.raise_for_status()
        row = response.json().get("posted")
        if (
            not isinstance(row, dict)
            or row.get("from") != DID
            or str(row.get("nonce")) != entry["nonce"]
            or row.get("text") != text
            or row.get("sig") != signed[1]
            or type(row.get("seq")) is not int
            or row["seq"] < 0
            or not isinstance(row.get("ts"), str)
        ):
            raise InviteError("receipt_mismatch")
        datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
        return mark_posted(state, request_id, row)
    except BaseException:
        entry["state"] = "ambiguous"
        entry["posted_record"] = None
        save(state)
        raise InviteError("submission_unknown") from None


def _run_locked() -> dict:
    require_identity()
    require_registration_posted()
    state = load()
    if state is None:
        state = new_state()
        save(state)
    existing = existing_records(state)
    actions = []
    for request_id, row in existing.items():
        if state["entries"][request_id]["state"] != "posted":
            action = mark_posted(state, request_id, row)
            action["action"] = "reconciled"
            actions.append(action)
    if any(entry["state"] == "ambiguous" for entry in state["entries"].values()):
        return {"actions": actions, "status": "ambiguous"}
    for item in INVITATIONS:
        request_id = item["request_id"]
        entry = state["entries"][request_id]
        if entry["state"] == "posted":
            if not any(a["request_id"] == request_id for a in actions):
                actions.append({"request_id": request_id, "action": "already_posted", "seq": entry["seq"]})
            continue
        if entry["state"] == "attempting":
            return {"actions": actions, "status": "ambiguous"}
        actions.append(_post_one(state, request_id))
    return {"actions": actions, "status": "complete"}


def run_once() -> dict:
    with invite_lock():
        return _run_locked()


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("sonnet discovery invitations accept no arguments")
    try:
        result = run_once()
    except Exception:
        print(json.dumps({"ok": False, "error": "invitation_failed_closed"}))
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
