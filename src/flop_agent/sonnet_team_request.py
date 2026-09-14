"""One-shot fixed MARU sonnet-2 team request from the isolated Linux signer.

The durable attempting marker precedes the only possible POST. A later run
may reconcile an uncertain attempt, but can never retransmit it.
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

from . import core, observer, oracle_signer, sonnet_registration as registration
from .public_record import verify_signed_record

ROOM = "mb-sonnet-2-discovery"
DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
PAYLOAD = {
    "type": "sonnet.team-request.v1",
    "contest_id": "sonnet-2",
    "game_id": "maru73s2",
    "request_id": "maru-team-maru73s2-20260914-1",
}
OPEN, CLOSE = registration.OPEN, registration.CLOSE
RECORD_KEYS = ("from", "nonce", "text", "sig", "seq", "ts")
STATE_KEYS = {
    "schema_version", "room", "did", "payload", "state", "nonce", "text_hash",
    "git_commit_sha", "attempted_at", "seq", "ts", "posted_record",
}


class TeamRequestError(RuntimeError):
    """A fixed, non-secret failure code for this one-shot lane."""


def render(payload: dict = PAYLOAD, room: str = ROOM) -> str:
    if room != ROOM or type(payload) is not dict or payload != PAYLOAD:
        raise TeamRequestError("team_request_binding_invalid")
    return json.dumps(PAYLOAD, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def state_path():
    return core.STATE / "signer" / "sonnet-2-team-request-maru73s2.json"


def _valid_record(row: dict, *, nonce: str | None = None) -> bool:
    try:
        if (row.get("from") != DID or row.get("text") != render()
                or type(row.get("seq")) is not int or row["seq"] < 0
                or not isinstance(row.get("ts"), str)
                or (nonce is not None and str(row.get("nonce")) != nonce)):
            return False
        datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
        verify_signed_record(ROOM, row)
        return True
    except (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
        return False


def validate(value: dict) -> dict:
    if (type(value) is not dict or set(value) != STATE_KEYS
            or type(value.get("schema_version")) is not int or value["schema_version"] != 1
            or value.get("room") != ROOM or value.get("did") != DID):
        raise TeamRequestError("team_request_state_invalid")
    render(value["payload"], value["room"])
    text_hash = hashlib.sha256(render().encode()).hexdigest()
    if value["text_hash"] != text_hash or value["state"] not in {"new", "prepared", "attempting", "ambiguous", "posted"}:
        raise TeamRequestError("team_request_state_invalid")
    nonce = value["nonce"]
    if nonce is not None and (not isinstance(nonce, str) or re.fullmatch(r"[0-9]{1,19}", nonce) is None):
        raise TeamRequestError("team_request_state_invalid")
    if value["state"] != "new" and nonce is None:
        raise TeamRequestError("team_request_state_invalid")
    sha = value["git_commit_sha"]
    if sha is not None and (not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None):
        raise TeamRequestError("team_request_state_invalid")
    if value["state"] in {"prepared", "attempting", "ambiguous"} and sha is None:
        raise TeamRequestError("team_request_state_invalid")
    if value["state"] in {"attempting", "ambiguous"} and not isinstance(value["attempted_at"], str):
        raise TeamRequestError("team_request_state_invalid")
    if value["state"] == "posted":
        row = value["posted_record"]
        if (type(row) is not dict or set(row) != set(RECORD_KEYS)
                or not _valid_record(row, nonce=nonce)
                or row["seq"] != value["seq"] or row["ts"] != value["ts"]):
            raise TeamRequestError("team_request_state_invalid")
    elif value["posted_record"] is not None or value["seq"] is not None or value["ts"] is not None:
        raise TeamRequestError("team_request_state_invalid")
    return value


def save(value: dict) -> None:
    observer.atomic_json_write(state_path(), validate(value), compact=True, mode=0o600)


def load() -> dict | None:
    try:
        return validate(json.loads(state_path().read_text("utf-8")))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise TeamRequestError("team_request_state_invalid") from error


def require_signer_user(username: str) -> None:
    if username != "technocore-signer":
        raise TeamRequestError("isolated_signer_user_required")


@contextmanager
def team_request_lock():
    if os.name != "posix":
        raise TeamRequestError("isolated_linux_signer_required")
    import fcntl
    import pwd

    require_signer_user(pwd.getpwuid(os.geteuid()).pw_name)
    with state_path().with_suffix(".lock").open("a") as handle:
        os.fchmod(handle.fileno(), 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise TeamRequestError("team_request_busy") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def require_identity() -> None:
    if oracle_signer.expected_did() != DID:
        raise TeamRequestError("did_mismatch")
    core.require_verified_did(DID)
    if not core.signer_matches_pinned():
        raise TeamRequestError("signer_not_pinned")


def require_writer_registration() -> None:
    try:
        value = registration.load()
    except Exception as error:
        raise TeamRequestError("writer_registration_unavailable") from error
    if (value is None or value.get("state") != "posted" or value.get("did") != DID
            or value.get("room") != registration.ROOM):
        raise TeamRequestError("writer_registration_not_posted")
    binding = value.get("registration")
    if (type(binding) is not dict or binding.get("role") != "writer"
            or binding.get("x_account_url") != "https://x.com/MinerMaru73"
            or any(binding.get(key) != expected for key, expected in registration.FIXED.items())):
        raise TeamRequestError("writer_registration_invalid")


def require_preflight() -> None:
    require_identity()
    require_writer_registration()
    try:
        registration.require_health()
    except Exception as error:
        raise TeamRequestError("observer_safety_not_ok") from error
    if not OPEN <= datetime.now(UTC) < CLOSE:
        raise TeamRequestError("team_request_window_closed")


def new_state() -> dict:
    return {
        "schema_version": 1, "room": ROOM, "did": DID, "payload": dict(PAYLOAD),
        "state": "new", "nonce": None,
        "text_hash": hashlib.sha256(render().encode()).hexdigest(),
        "git_commit_sha": None, "attempted_at": None, "seq": None, "ts": None,
        "posted_record": None,
    }


def existing_record(value: dict) -> dict | None:
    try:
        payload = core.read_room(ROOM, limit=200, cache_buster=secrets.token_hex(16))
        rows = payload if isinstance(payload, list) else payload.get("messages")
    except (AttributeError, TypeError) as error:
        raise TeamRequestError("reconcile_read_failed") from error
    if not isinstance(rows, list):
        raise TeamRequestError("reconcile_read_failed")

    matches = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            verify_signed_record(ROOM, row)
            message = json.loads(row.get("text", ""))
        except (ValueError, TypeError, RuntimeError):
            continue
        if not isinstance(message, dict):
            continue
        # A signed conflicting use of the fixed request ID (even by another
        # DID), or another request from our DID for this game, is terminal.
        same_id = message.get("request_id") == PAYLOAD["request_id"]
        same_binding = (
            row.get("from") == DID and message.get("type") == PAYLOAD["type"]
            and message.get("game_id") == PAYLOAD["game_id"]
        )
        if not (same_id or same_binding):
            continue
        if not _valid_record(row, nonce=value["nonce"] if value["state"] != "new" else None):
            raise TeamRequestError("existing_team_request_conflict")
        matches.append(row)
    if len({(str(row["nonce"]), row["text"]) for row in matches}) > 1:
        raise TeamRequestError("existing_team_request_conflict")
    return matches[-1] if matches else None


def mark_posted(value: dict, row: dict) -> dict:
    if not _valid_record(row, nonce=value["nonce"] if value["state"] != "new" else None):
        raise TeamRequestError("receipt_mismatch")
    value.update(
        state="posted", nonce=str(row["nonce"]), seq=row["seq"], ts=row["ts"],
        posted_record={key: row[key] for key in RECORD_KEYS},
    )
    save(value)
    return {"action": "posted", "request_id": PAYLOAD["request_id"], "seq": row["seq"]}


def _run_locked() -> dict:
    require_identity()
    require_writer_registration()
    value = load()
    if value is None:
        value = new_state()
        save(value)
    if value["state"] == "posted":
        return {"action": "already_posted", "request_id": PAYLOAD["request_id"], "seq": value["seq"]}
    row = existing_record(value)
    if row is not None:
        result = mark_posted(value, row)
        result["action"] = "reconciled"
        return result
    if value["state"] in {"attempting", "ambiguous"}:
        return {"action": "ambiguous", "request_id": PAYLOAD["request_id"]}

    require_preflight()
    text = render(value["payload"], value["room"])
    if core.clean_text(text) != text:
        raise TeamRequestError("team_request_text_invalid")
    if value["nonce"] is None:
        value["nonce"] = core.make_nonce(ROOM, DID)
    value["git_commit_sha"] = core.git_commit_sha()
    value["state"] = "prepared"
    save(value)
    signed = oracle_signer.with_vault_seed(
        lambda: core.invoke_signer("say", ROOM, value["nonce"], text)
    )
    if len(signed) != 2 or signed[0] != DID:
        raise TeamRequestError("did_mismatch")
    verify_signed_record(ROOM, {"from": DID, "nonce": value["nonce"], "text": text, "sig": signed[1]})

    require_preflight()
    value["state"] = "attempting"
    value["attempted_at"] = oracle_signer.now()
    save(value)
    try:
        response = core.httpx.post(
            f"{core.BASE_URL}/r/{ROOM}?format=json",
            json={"did": DID, "nonce": value["nonce"], "text": text, "sig": signed[1]},
            timeout=20,
        )
        response.raise_for_status()
        row = response.json().get("posted")
        if (not isinstance(row, dict) or row.get("sig") != signed[1]
                or not _valid_record(row, nonce=value["nonce"])):
            raise TeamRequestError("receipt_mismatch")
        return mark_posted(value, row)
    except Exception:
        value["state"] = "ambiguous"
        value["posted_record"] = None
        save(value)
        raise TeamRequestError("submission_unknown") from None


def run_once() -> dict:
    with team_request_lock():
        return _run_locked()


def main() -> None:
    if len(sys.argv) != 1:
        print(json.dumps({"ok": False, "error": "arguments_rejected"}))
        raise SystemExit(1)
    try:
        result = run_once()
    except Exception:
        print(json.dumps({"ok": False, "error": "team_request_failed_closed"}))
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
