"""Fixed-function, one-shot Close Call owner registration.

This module can sign and post exactly one immutable registration for the
continuing Production DID. It accepts no CLI parameters and never exposes the
signature, Vault identifier, or private seed. Ambiguous submission is terminal:
the module may reconcile the exact attempted message, but it never retries POST.
"""
from __future__ import annotations

import json
import os
import pwd
import secrets
import sys
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from flop_agent import core, observer, oracle_signer
from flop_agent.public_record import verify_signed_record

ROOM = "close1"
DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
REGISTRATION = {"key": DID, "season": "close-1", "t": "owner"}
TEXT = json.dumps(REGISTRATION, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
LOCK = datetime(2026, 10, 4, 9, 0, 0, tzinfo=UTC)
CORE_BASELINE = (124, 5_651_120)
STATE_NAME = "close1-registration.json"
SAFETY_KEYS = {
    "schema_version",
    "updated_at",
    "health",
    "unrecoverable_core_gap_events",
    "unrecoverable_core_gap_messages",
}


class RegistrationError(RuntimeError):
    def __init__(self, code: str, *, post_attempted: bool = False):
        super().__init__(code)
        self.code = code
        self.post_attempted = post_attempted


def state_path() -> Path:
    return core.STATE / "signer" / STATE_NAME


def safety_path() -> Path:
    return core.STATE / "observer-safety.json"


def render() -> str:
    value = json.dumps(REGISTRATION, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if value != TEXT or core.clean_text(value) != value:
        raise RegistrationError("registration_text_invalid")
    return value


def validate_state(value: dict) -> dict:
    required = {
        "schema_version",
        "room",
        "did",
        "text",
        "state",
        "nonce",
        "attempted_at",
        "seq",
        "ts",
        "posted_record",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != 1
        or value.get("room") != ROOM
        or value.get("did") != DID
        or value.get("text") != TEXT
        or value.get("state") not in {"new", "prepared", "attempting", "ambiguous", "posted"}
    ):
        raise RegistrationError("registration_state_invalid")
    nonce = value.get("nonce")
    if nonce is not None and (not isinstance(nonce, str) or not nonce.isascii() or not nonce.isdecimal() or not 1 <= len(nonce) <= 19):
        raise RegistrationError("registration_state_invalid")
    if value["state"] != "new" and nonce is None:
        raise RegistrationError("registration_state_invalid")
    if value["state"] in {"attempting", "ambiguous"} and not isinstance(value.get("attempted_at"), str):
        raise RegistrationError("registration_state_invalid")
    if value["state"] == "posted":
        row = value.get("posted_record")
        if (
            not isinstance(row, dict)
            or row.get("from") != DID
            or row.get("text") != TEXT
            or str(row.get("nonce")) != nonce
            or row.get("seq") != value.get("seq")
            or row.get("ts") != value.get("ts")
        ):
            raise RegistrationError("registration_state_invalid")
        validate_row(row, nonce=nonce)
    elif value.get("posted_record") is not None:
        raise RegistrationError("registration_state_invalid")
    return value


def save(value: dict) -> None:
    observer.atomic_json_write(state_path(), validate_state(value), compact=True, mode=0o600)


def load() -> dict | None:
    try:
        return validate_state(json.loads(state_path().read_text("utf-8")))
    except FileNotFoundError:
        return None
    except RegistrationError:
        raise
    except Exception as error:
        raise RegistrationError("registration_state_invalid") from error


@contextmanager
def registration_lock():
    if os.name != "posix" or pwd.getpwuid(os.geteuid()).pw_name != "technocore-signer":
        raise RegistrationError("isolated_signer_user_required")
    lock_path = state_path().with_suffix(".lock")
    import fcntl
    with lock_path.open("a") as handle:
        os.fchmod(handle.fileno(), 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RegistrationError("registration_busy") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def require_window() -> None:
    if datetime.now(UTC) >= LOCK:
        raise RegistrationError("registration_window_closed")


def require_identity() -> None:
    try:
        if oracle_signer.expected_did() != DID:
            raise RegistrationError("did_mismatch")
        core.require_verified_did(DID)
        if not core.signer_matches_pinned():
            raise RegistrationError("signer_not_pinned")
    except RegistrationError:
        raise
    except Exception as error:
        raise RegistrationError("identity_preflight_failed") from error


def require_safety() -> None:
    try:
        value = json.loads(safety_path().read_text("utf-8"))
        if (
            not isinstance(value, dict)
            or set(value) != SAFETY_KEYS
            or value.get("schema_version") != 1
            or not isinstance(value.get("updated_at"), str)
            or not isinstance(value.get("health"), str)
            or type(value.get("unrecoverable_core_gap_events")) is not int
            or type(value.get("unrecoverable_core_gap_messages")) is not int
        ):
            raise RegistrationError("observer_state_unavailable")
        stamp = datetime.fromisoformat(value["updated_at"].replace("Z", "+00:00"))
        age = (datetime.now(UTC) - stamp).total_seconds()
    except RegistrationError:
        raise
    except Exception as error:
        raise RegistrationError("observer_state_unavailable") from error
    if not 0 <= age <= 300 or value["health"] != "ok":
        raise RegistrationError("observer_health_not_ok")
    if (
        value["unrecoverable_core_gap_events"],
        value["unrecoverable_core_gap_messages"],
    ) != CORE_BASELINE:
        raise RegistrationError("protected_core_baseline_changed")


def validate_row(
    row: dict,
    *,
    nonce: str | None = None,
    sig: str | None = None,
    post_attempted: bool = False,
) -> dict:
    if (
        not isinstance(row, dict)
        or row.get("from") != DID
        or row.get("text") != TEXT
        or type(row.get("seq")) is not int
        or row["seq"] < 0
        or not isinstance(row.get("ts"), str)
        or not isinstance(row.get("nonce"), (str, int))
        or not isinstance(row.get("sig"), str)
    ):
        raise RegistrationError("receipt_mismatch", post_attempted=post_attempted)
    if nonce is not None and str(row.get("nonce")) != nonce:
        raise RegistrationError("receipt_mismatch", post_attempted=post_attempted)
    if sig is not None and row.get("sig") != sig:
        raise RegistrationError("receipt_mismatch", post_attempted=post_attempted)
    try:
        datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
        verify_signed_record(ROOM, row)
    except Exception as error:
        raise RegistrationError("receipt_mismatch", post_attempted=post_attempted) from error
    return row


def room_rows() -> list[dict]:
    try:
        payload = core.read_room(ROOM, limit=200, cache_buster=secrets.token_hex(16))
    except Exception as error:
        raise RegistrationError("reconcile_read_failed") from error
    rows = payload if isinstance(payload, list) else payload.get("messages")
    if not isinstance(rows, list):
        raise RegistrationError("reconcile_read_failed")
    return [row for row in rows if isinstance(row, dict)]


def find_existing_record(*, nonce: str | None = None) -> dict | None:
    matches: list[dict] = []
    for row in room_rows():
        if row.get("from") != DID:
            continue
        try:
            verify_signed_record(ROOM, row)
            parsed = json.loads(row.get("text", ""))
        except Exception:
            continue
        if not isinstance(parsed, dict) or parsed.get("season") != "close-1" or parsed.get("t") != "owner":
            continue
        if parsed != REGISTRATION or row.get("text") != TEXT:
            raise RegistrationError("existing_registration_conflict")
        if nonce is not None and str(row.get("nonce")) != nonce:
            continue
        matches.append(validate_row(row, nonce=nonce))
    if len(matches) > 1:
        raise RegistrationError("existing_registration_conflict")
    return matches[0] if matches else None


def initial_state() -> dict:
    return {
        "schema_version": 1,
        "room": ROOM,
        "did": DID,
        "text": TEXT,
        "state": "new",
        "nonce": None,
        "attempted_at": None,
        "seq": None,
        "ts": None,
        "posted_record": None,
    }


def mark_posted(value: dict, row: dict) -> dict:
    validate_row(row, nonce=str(row["nonce"]))
    record = {key: row[key] for key in ("from", "nonce", "text", "sig", "seq", "ts")}
    value.update(
        state="posted",
        nonce=str(row["nonce"]),
        seq=row["seq"],
        ts=row["ts"],
        posted_record=record,
    )
    save(value)
    return value


def readback(row: dict) -> bool:
    try:
        payload = core.read_room(
            ROOM,
            since=max(int(row["seq"]) - 1, 0),
            limit=20,
            cache_buster=secrets.token_hex(16),
        )
        rows = payload if isinstance(payload, list) else payload.get("messages")
        if not isinstance(rows, list):
            return False
        for candidate in rows:
            if (
                isinstance(candidate, dict)
                and candidate.get("seq") == row["seq"]
                and candidate.get("from") == DID
                and str(candidate.get("nonce")) == str(row["nonce"])
                and candidate.get("text") == TEXT
                and candidate.get("sig") == row["sig"]
            ):
                validate_row(candidate, nonce=str(row["nonce"]), sig=row["sig"])
                return True
    except Exception:
        return False
    return False


def _run_locked() -> dict:
    require_identity()
    require_window()
    require_safety()

    value = load()
    if value is not None and value["state"] == "posted":
        return {
            "action": "already_posted",
            "row": value["posted_record"],
            "readback": readback(value["posted_record"]),
            "post_attempted": False,
        }

    if value is not None and value["state"] in {"attempting", "ambiguous"}:
        try:
            row = find_existing_record(nonce=value["nonce"])
        except RegistrationError as error:
            if error.code == "reconcile_read_failed":
                raise RegistrationError("ambiguous_no_retry", post_attempted=True) from None
            raise
        if row is None:
            raise RegistrationError("ambiguous_no_retry", post_attempted=True)
        mark_posted(value, row)
        return {
            "action": "reconciled_existing_attempt",
            "row": row,
            "readback": True,
            "post_attempted": False,
        }

    if value is not None and value["state"] == "prepared":
        raise RegistrationError("prepared_state_requires_new_task")

    try:
        existing = find_existing_record()
    except RegistrationError as error:
        if error.code == "reconcile_read_failed":
            raise RegistrationError("preflight_room_read_failed") from None
        raise
    if existing is not None:
        if value is None:
            value = initial_state()
        mark_posted(value, existing)
        return {
            "action": "preexisting_reconciled",
            "row": existing,
            "readback": True,
            "post_attempted": False,
        }

    if value is None:
        value = initial_state()
        save(value)

    require_window()
    require_safety()
    value["nonce"] = core.make_nonce(ROOM, DID)
    value["state"] = "prepared"
    save(value)

    try:
        signed = oracle_signer.with_vault_seed(
            lambda: core.invoke_signer("say", ROOM, value["nonce"], render())
        )
    except Exception as error:
        raise RegistrationError("signing_failed") from error
    if len(signed) != 2 or signed[0] != DID:
        raise RegistrationError("did_mismatch")
    signature = signed[1]
    try:
        verify_signed_record(
            ROOM,
            {"from": DID, "nonce": value["nonce"], "text": TEXT, "sig": signature},
        )
    except Exception as error:
        raise RegistrationError("signature_verification_failed") from error

    require_identity()
    require_window()
    require_safety()

    value["state"] = "attempting"
    value["attempted_at"] = oracle_signer.now()
    save(value)

    try:
        response = core.httpx.post(
            f"{core.BASE_URL}/r/{ROOM}?format=json",
            json={"did": DID, "nonce": value["nonce"], "text": TEXT, "sig": signature},
            timeout=20,
        )
        response.raise_for_status()
        response_row = response.json().get("posted")
        row = validate_row(response_row, nonce=value["nonce"], sig=signature, post_attempted=True)
    except Exception:
        try:
            row = find_existing_record(nonce=value["nonce"])
        except Exception:
            row = None
        if row is None:
            value["state"] = "ambiguous"
            save(value)
            raise RegistrationError("submission_unknown", post_attempted=True) from None
        mark_posted(value, row)
        return {
            "action": "reconciled_after_post_error",
            "row": row,
            "readback": True,
            "post_attempted": True,
        }

    mark_posted(value, row)
    return {
        "action": "posted",
        "row": row,
        "readback": readback(row),
        "post_attempted": True,
    }


def run_once() -> dict:
    with registration_lock():
        return _run_locked()


def main() -> None:
    if len(sys.argv) != 1:
        print("CLOSE1_REGISTER=STOP:arguments_forbidden")
        print("POST_ATTEMPTED=NO")
        print("DO_NOT_RERUN=YES")
        return
    try:
        result = run_once()
    except RegistrationError as error:
        print(f"CLOSE1_REGISTER=STOP:{error.code}")
        print(f"POST_ATTEMPTED={'YES' if error.post_attempted else 'NO'}")
        print("DO_NOT_RERUN=YES")
        return
    except Exception:
        print("CLOSE1_REGISTER=ERROR:internal_fail_closed")
        print("POST_ATTEMPTED=UNKNOWN")
        print("DO_NOT_RERUN=YES")
        return

    row = result["row"]
    print(f"PUBLIC_DID={DID}")
    print(f"REGISTRATION_ROOM={ROOM}")
    print(f"REGISTRATION_TEXT={TEXT}")
    print(f"NONCE={row['nonce']}")
    print(f"SEQ={row['seq']}")
    print(f"TS={row['ts']}")
    print(f"ACTION={result['action']}")
    print(f"READBACK={'YES' if result['readback'] else 'NO'}")
    if result["post_attempted"]:
        print("BINDING_ACTION_EXECUTED=YES")
    else:
        print("BINDING_ACTION_EXECUTED=NO_NEW_POST")
    print("SECRET_OR_VAULT_OUTPUT=NO")
    print("CLOSE1_REGISTER=PASS")
    print("DO_NOT_RERUN=YES")


if __name__ == "__main__":
    main()
