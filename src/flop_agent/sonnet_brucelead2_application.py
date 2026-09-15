"""Fixed one-shot non-binding Sonnet-2 application for the live BRUCELEAD-2 seat offer.

This execution-only lane has no CLI-controlled payload fields. It answers one
specific signed discovery offer with a fixed ``sonnet.application.v1`` record.
The record is explicitly not roster consent, not a word proposal, not a writer
acceptance claim, and not a submission. A durable attempting marker is written
before the only possible POST; ambiguous outcomes are terminal and must never be
blindly retried.
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
GAME_ID = "brucelead-2"
REQUEST_ID = "maru-brucelead2-apply-20260915-1"
SOURCE_REQUEST_ID = "brucelead-2-rescout-663LWegUyEAB-1789469662751"
SOURCE_SEQ = 105235
OPEN = datetime(2026, 9, 11, 12, tzinfo=UTC)
CLOSE = datetime(2026, 9, 18, 12, tzinfo=UTC)
MAX_OFFER_AGE_SECONDS = 6 * 60 * 60
MAX_SAFETY_AGE_SECONDS = 300
PROTECTED_CORE = (117, 5_083_155)

PAYLOAD = {
    "type": "sonnet.application.v1",
    "contest_id": "sonnet-2",
    "game_id": GAME_ID,
    "request_id": REQUEST_ID,
    "did": DID,
    "role": "writer",
    "x_account_url": "https://x.com/MinerMaru73",
    "no_live_roster_consent": True,
    "text": (
        "YES — MARU is interested and currently available to review a BRUCELEAD-2 "
        "seat. This is a non-binding application only: it is not sonnet.roster.v1 "
        "consent, not a word proposal, and not a claim that my writer registration "
        "has been accepted. My existing writer registration request "
        "32c15433c6d73af1cea5d6467dece016 is still awaiting the official operator "
        "disposition. Source seat-offer request: "
        "brucelead-2-rescout-663LWegUyEAB-1789469662751. Please send the exact "
        "accepted setup receipt/request_id, poem_room, room_generation, and proposed "
        "canonical roster for review. If the writer receipt is confirmed and the seat "
        "is still open, MARU can review the binding roster promptly."
    ),
}


class ApplicationError(RuntimeError):
    pass


def render(payload: dict = PAYLOAD) -> str:
    if payload != PAYLOAD:
        raise ApplicationError("application_binding_invalid")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def state_path():
    return core.STATE / "signer" / "sonnet-2-brucelead2-application.json"


def safety_path():
    return core.STATE / "observer-safety.json"


def _stamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ApplicationError("timestamp_invalid")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ApplicationError("timestamp_invalid") from error
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return stamp.astimezone(UTC)


def require_nonbinding_safety(*, now: datetime | None = None) -> None:
    """Risk-tier gate for a structurally non-binding discovery application."""
    try:
        value = json.loads(safety_path().read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ApplicationError("safety_snapshot_unavailable") from error
    if not isinstance(value, dict) or value.get("health") not in {"ok", "degraded"}:
        raise ApplicationError("safety_health_not_allowed")
    if (
        value.get("unrecoverable_core_gap_events"),
        value.get("unrecoverable_core_gap_messages"),
    ) != PROTECTED_CORE:
        raise ApplicationError("protected_core_changed")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    age = (current - _stamp(value.get("updated_at"))).total_seconds()
    if not 0 <= age <= MAX_SAFETY_AGE_SECONDS:
        raise ApplicationError("safety_stale")


def require_identity() -> None:
    if oracle_signer.expected_did() != DID:
        raise ApplicationError("did_mismatch")
    core.require_verified_did(DID)
    if not core.signer_matches_pinned():
        raise ApplicationError("signer_not_pinned")


def require_registration_posted() -> None:
    """Require MARU's existing local signed registration, without claiming acceptance."""
    try:
        value = registration.load()
    except Exception as error:
        raise ApplicationError("writer_registration_unavailable") from error
    if value is None or value.get("state") != "posted" or value.get("did") != DID:
        raise ApplicationError("writer_registration_not_posted")
    reg = value.get("registration")
    if not isinstance(reg, dict) or any(
        reg.get(key) != expected for key, expected in registration.FIXED.items()
    ):
        raise ApplicationError("writer_registration_invalid")


def _room_rows(payload: object) -> list[dict]:
    rows = payload if isinstance(payload, list) else payload.get("messages") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise ApplicationError("offer_read_failed")
    return [row for row in rows if isinstance(row, dict)]


def _decode(row: dict) -> dict | None:
    try:
        value = json.loads(row.get("text", ""))
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def require_live_offer(*, now: datetime | None = None) -> dict:
    """Bind this write to the exact signed current-seat offer and reject a later close."""
    try:
        source_payload = core.read_room(
            ROOM,
            since=SOURCE_SEQ - 1,
            limit=200,
            cache_buster=secrets.token_hex(16),
        )
    except Exception as error:
        raise ApplicationError("offer_read_failed") from error

    source = None
    source_body = None
    for row in _room_rows(source_payload):
        if row.get("seq") != SOURCE_SEQ:
            continue
        try:
            verify_signed_record(ROOM, row)
        except Exception as error:
            raise ApplicationError("offer_signature_invalid") from error
        body = _decode(row)
        if body is None or body.get("request_id") != SOURCE_REQUEST_ID:
            raise ApplicationError("offer_binding_invalid")
        target = body.get("target_did")
        if target is not None and target != DID:
            raise ApplicationError("offer_target_mismatch")
        visible = (str(body.get("text") or "") + " " + row.get("text", "")).lower()
        for required in ("brucelead-2", "current seat offer", "d-sonnet-2-team-brucelead-2"):
            if required not in visible:
                raise ApplicationError("offer_binding_invalid")
        source, source_body = row, body
        break
    if source is None or source_body is None:
        raise ApplicationError("offer_not_visible")
    sender = source.get("from")
    if not isinstance(sender, str) or sender == DID:
        raise ApplicationError("offer_sender_invalid")
    source_time = _stamp(source.get("ts"))
    current = (now or datetime.now(UTC)).astimezone(UTC)
    age = (current - source_time).total_seconds()
    if not 0 <= age <= MAX_OFFER_AGE_SECONDS:
        raise ApplicationError("offer_stale")

    # A later signed message from the same sender that clearly closes this game
    # cancels the fixed application before any signature/write occurs.
    try:
        latest_payload = core.read_room(ROOM, limit=200, cache_buster=secrets.token_hex(16))
    except Exception as error:
        raise ApplicationError("offer_read_failed") from error
    close_terms = ("team full", "seats filled", "no seats", "offer closed", "offer withdrawn")
    for row in _room_rows(latest_payload):
        if row.get("from") != sender or type(row.get("seq")) is not int or row["seq"] <= SOURCE_SEQ:
            continue
        try:
            verify_signed_record(ROOM, row)
        except Exception:
            continue
        body = _decode(row)
        text = (str(body.get("text") if body else "") + " " + str(row.get("text") or "")).lower()
        if GAME_ID in text and any(term in text for term in close_terms):
            raise ApplicationError("offer_withdrawn_or_full")
    return source


def new_state() -> dict:
    text = render()
    return {
        "schema_version": 1,
        "room": ROOM,
        "did": DID,
        "game_id": GAME_ID,
        "request_id": REQUEST_ID,
        "source_request_id": SOURCE_REQUEST_ID,
        "payload": dict(PAYLOAD),
        "state": "new",
        "nonce": None,
        "text_hash": hashlib.sha256(text.encode()).hexdigest(),
        "attempted_at": None,
        "seq": None,
        "ts": None,
        "posted_record": None,
    }


def validate(value: dict) -> dict:
    required = {
        "schema_version", "room", "did", "game_id", "request_id", "source_request_id",
        "payload", "state", "nonce", "text_hash", "attempted_at", "seq", "ts",
        "posted_record",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ApplicationError("application_state_invalid")
    if (
        value["schema_version"] != 1
        or value["room"] != ROOM
        or value["did"] != DID
        or value["game_id"] != GAME_ID
        or value["request_id"] != REQUEST_ID
        or value["source_request_id"] != SOURCE_REQUEST_ID
        or value["payload"] != PAYLOAD
        or value["text_hash"] != hashlib.sha256(render().encode()).hexdigest()
        or value["state"] not in {"new", "prepared", "attempting", "ambiguous", "posted"}
    ):
        raise ApplicationError("application_state_invalid")
    nonce = value["nonce"]
    if nonce is not None and (not isinstance(nonce, str) or not re.fullmatch(r"[0-9]{1,19}", nonce)):
        raise ApplicationError("application_state_invalid")
    if value["state"] != "new" and nonce is None:
        raise ApplicationError("application_state_invalid")
    if value["state"] in {"attempting", "ambiguous"} and not isinstance(value["attempted_at"], str):
        raise ApplicationError("application_state_invalid")
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
            or row.get("text") != render()
        ):
            raise ApplicationError("application_state_invalid")
        verify_signed_record(ROOM, row)
        _stamp(row["ts"])
    elif value["posted_record"] is not None or value["seq"] is not None or value["ts"] is not None:
        raise ApplicationError("application_state_invalid")
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
        raise ApplicationError("application_state_invalid") from error


@contextmanager
def application_lock():
    if os.name != "posix":
        raise ApplicationError("isolated_linux_signer_required")
    import fcntl
    import pwd
    if pwd.getpwuid(os.geteuid()).pw_name != "technocore-signer":
        raise ApplicationError("isolated_signer_user_required")
    with state_path().with_suffix(".lock").open("a") as handle:
        os.fchmod(handle.fileno(), 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ApplicationError("application_busy") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def reconcile_existing(state: dict) -> dict | None:
    try:
        payload = core.read_room(ROOM, limit=200, cache_buster=secrets.token_hex(16))
    except Exception as error:
        raise ApplicationError("reconcile_read_failed") from error
    found = []
    for row in _room_rows(payload):
        if row.get("from") != DID:
            continue
        try:
            verify_signed_record(ROOM, row)
            body = _decode(row)
        except Exception:
            continue
        if body is None or body.get("request_id") != REQUEST_ID:
            continue
        if body != PAYLOAD or row.get("text") != render():
            raise ApplicationError("existing_application_conflict")
        if type(row.get("seq")) is not int or not isinstance(row.get("ts"), str):
            raise ApplicationError("reconcile_read_failed")
        found.append(row)
    if len({(str(row.get("nonce")), row.get("text")) for row in found}) > 1:
        raise ApplicationError("existing_application_conflict")
    if not found:
        return None
    row = found[-1]
    if state["state"] in {"attempting", "ambiguous"} and str(row.get("nonce")) != state["nonce"]:
        raise ApplicationError("existing_application_conflict")
    return row


def mark_posted(state: dict, row: dict) -> dict:
    state.update(
        state="posted",
        nonce=str(row["nonce"]),
        seq=row["seq"],
        ts=row["ts"],
        posted_record={key: row[key] for key in ("from", "nonce", "text", "sig", "seq", "ts")},
    )
    save(state)
    return {"status": "posted", "request_id": REQUEST_ID, "seq": row["seq"], "ts": row["ts"]}


def run_once() -> dict:
    with application_lock():
        require_identity()
        require_registration_posted()
        require_nonbinding_safety()
        if not OPEN <= datetime.now(UTC) < CLOSE:
            raise ApplicationError("application_window_closed")
        state = load()
        if state is None:
            state = new_state()
            save(state)
        existing = reconcile_existing(state)
        if existing is not None:
            result = mark_posted(state, existing)
            result["status"] = "reconciled"
            return result
        if state["state"] == "posted":
            return {"status": "already_posted", "request_id": REQUEST_ID, "seq": state["seq"], "ts": state["ts"]}
        if state["state"] in {"attempting", "ambiguous"}:
            return {"status": "ambiguous", "request_id": REQUEST_ID}

        require_live_offer()
        text = render()
        if core.clean_text(text) != text:
            raise ApplicationError("application_text_invalid")
        if state["nonce"] is None:
            state["nonce"] = core.make_nonce(ROOM, DID)
        state["state"] = "prepared"
        save(state)

        signed = oracle_signer.with_vault_seed(
            lambda: core.invoke_signer("say", ROOM, state["nonce"], text)
        )
        if len(signed) != 2 or signed[0] != DID:
            raise ApplicationError("did_mismatch")
        verify_signed_record(ROOM, {"from": DID, "nonce": state["nonce"], "text": text, "sig": signed[1]})

        # Recheck the relevant safety and offer immediately before the irreversible write.
        require_identity()
        require_registration_posted()
        require_nonbinding_safety()
        require_live_offer()
        if not OPEN <= datetime.now(UTC) < CLOSE:
            raise ApplicationError("application_window_closed")
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
                raise ApplicationError("receipt_mismatch")
            _stamp(row["ts"])
            verify_signed_record(ROOM, row)
            return mark_posted(state, row)
        except BaseException:
            state["state"] = "ambiguous"
            state["posted_record"] = None
            save(state)
            raise ApplicationError("submission_unknown") from None


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("BRUCELEAD-2 application accepts no arguments")
    try:
        print(json.dumps(run_once(), sort_keys=True))
    except ApplicationError as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        raise SystemExit(1) from None
    except Exception:
        print(json.dumps({"ok": False, "error": "application_failed_closed"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
