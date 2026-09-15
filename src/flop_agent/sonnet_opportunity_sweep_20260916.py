"""Fixed one-shot non-binding replies to two live Sonnet-2 opportunities.

This deadline-critical execution lane is intentionally incapable of roster consent,
word proposals, publication, or submission. It sends at most two fixed discovery
records:

* magnatsv: a direct non-binding availability reply to the signed invitation observed
  at discovery seq 110224 / request ``magnatsv-invite-z6mkw1wntm-001``.
* luxion-1: a non-binding status/interest note that explicitly is NOT the requested
  ``yes-luxion`` freeze and therefore grants no roster consent.

The caller cannot control payload fields. Each item has durable new/prepared/
attempting/ambiguous/posted state. The attempting marker is persisted before the
only possible POST; an ambiguous POST is terminal and must never be blindly retried.
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
OPEN = datetime(2026, 9, 11, 12, tzinfo=UTC)
CLOSE = datetime(2026, 9, 18, 12, tzinfo=UTC)

ITEMS = (
    {
        "key": "magnatsv",
        "request_id": "maru-magnatsv-availability-20260916-1",
        "payload": {
            "type": "sonnet.application.v1",
            "contest_id": "sonnet-2",
            "game_id": "magnatsv",
            "request_id": "maru-magnatsv-availability-20260916-1",
            "did": DID,
            "role": "writer",
            "x_account_url": "https://x.com/MinerMaru73",
            "no_live_roster_consent": True,
            "text": (
                "YES — MARU is currently available to consider joining magnatsv if a seat "
                "is still open. This is only a non-binding availability reply to source "
                "invitation magnatsv-invite-z6mkw1wntm-001; it is not sonnet.roster.v1 "
                "consent, not a word proposal, and not a claim that my writer registration "
                "is accepted. Existing writer registration request "
                "32c15433c6d73af1cea5d6467dece016 is still awaiting the official referee/operator "
                "disposition. Please reply with current seat status, the accepted setup "
                "receipt/request_id for magnatsv, room generation, and the proposed exact "
                "final roster. If the writer receipt is confirmed and the seat remains open, "
                "MARU can review a binding roster promptly."
            ),
        },
    },
    {
        "key": "luxion-1",
        "request_id": "maru-luxion1-nonbinding-20260916-1",
        "payload": {
            "type": "sonnet.note.v1",
            "contest_id": "sonnet-2",
            "game_id": "luxion-1",
            "request_id": "maru-luxion1-nonbinding-20260916-1",
            "did": DID,
            "role": "writer",
            "x_account_url": "https://x.com/MinerMaru73",
            "no_live_roster_consent": True,
            "text": (
                "MARU is interested in luxion-1 if a seat is still open. Important: this is "
                "NOT the requested 'yes-luxion' freeze, NOT sonnet.roster.v1 consent, and NOT "
                "a word proposal. It is only a non-binding status check tied to source invite "
                "luxion-dyn-ping-gUyEAB-1789487200. Existing writer registration request "
                "32c15433c6d73af1cea5d6467dece016 is still awaiting the official referee/operator "
                "disposition. Please reply with current seat status, accepted setup "
                "receipt/request_id, room generation, and the proposed exact final roster. "
                "Do not freeze MARU into a roster based on this note."
            ),
        },
    },
)
ITEM_BY_KEY = {item["key"]: item for item in ITEMS}


class SweepError(RuntimeError):
    pass


def _render(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def state_path():
    return core.STATE / "signer" / "sonnet-2-opportunity-sweep-20260916.json"


def _blank_item(item: dict) -> dict:
    text = _render(item["payload"])
    return {
        "request_id": item["request_id"],
        "payload": dict(item["payload"]),
        "state": "new",
        "nonce": None,
        "text_hash": hashlib.sha256(text.encode()).hexdigest(),
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
        "items": {item["key"]: _blank_item(item) for item in ITEMS},
    }


def _validate_item(key: str, value: object) -> dict:
    fixed = ITEM_BY_KEY[key]
    expected = {
        "request_id", "payload", "state", "nonce", "text_hash", "attempted_at",
        "seq", "ts", "posted_record",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise SweepError("sweep_state_invalid")
    text = _render(fixed["payload"])
    if (
        value["request_id"] != fixed["request_id"]
        or value["payload"] != fixed["payload"]
        or value["text_hash"] != hashlib.sha256(text.encode()).hexdigest()
        or value["state"] not in {"new", "prepared", "attempting", "ambiguous", "posted"}
    ):
        raise SweepError("sweep_state_invalid")
    nonce = value["nonce"]
    if nonce is not None and (not isinstance(nonce, str) or not re.fullmatch(r"[0-9]{1,19}", nonce)):
        raise SweepError("sweep_state_invalid")
    if value["state"] != "new" and nonce is None:
        raise SweepError("sweep_state_invalid")
    if value["state"] in {"attempting", "ambiguous"} and not isinstance(value["attempted_at"], str):
        raise SweepError("sweep_state_invalid")
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
            raise SweepError("sweep_state_invalid")
        verify_signed_record(ROOM, row)
    elif value["posted_record"] is not None or value["seq"] is not None or value["ts"] is not None:
        raise SweepError("sweep_state_invalid")
    return value


def validate(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {"schema_version", "room", "did", "items"}:
        raise SweepError("sweep_state_invalid")
    if value["schema_version"] != 1 or value["room"] != ROOM or value["did"] != DID:
        raise SweepError("sweep_state_invalid")
    if not isinstance(value["items"], dict) or set(value["items"]) != set(ITEM_BY_KEY):
        raise SweepError("sweep_state_invalid")
    for key in ITEM_BY_KEY:
        _validate_item(key, value["items"][key])
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
        raise SweepError("sweep_state_invalid") from error


@contextmanager
def sweep_lock():
    if os.name != "posix":
        raise SweepError("isolated_linux_signer_required")
    import fcntl
    import pwd
    if pwd.getpwuid(os.geteuid()).pw_name != "technocore-signer":
        raise SweepError("isolated_signer_user_required")
    lock_path = state_path().with_suffix(".lock")
    with lock_path.open("a") as handle:
        os.fchmod(handle.fileno(), 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SweepError("sweep_busy") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def require_identity() -> None:
    if oracle_signer.expected_did() != DID:
        raise SweepError("did_mismatch")
    core.require_verified_did(DID)
    if not core.signer_matches_pinned():
        raise SweepError("signer_not_pinned")


def require_registration_posted() -> None:
    """Require only the consumed local registration write; never claim acceptance."""
    try:
        value = registration.load()
    except Exception as error:
        raise SweepError("writer_registration_unavailable") from error
    if value is None or value.get("state") != "posted" or value.get("did") != DID:
        raise SweepError("writer_registration_not_posted")
    reg = value.get("registration")
    if not isinstance(reg, dict) or any(reg.get(key) != expected for key, expected in registration.FIXED.items()):
        raise SweepError("writer_registration_invalid")


def require_prepost() -> None:
    require_identity()
    require_registration_posted()
    try:
        policy.require_nonbinding_safety()
    except policy.NonBindingPolicyError as error:
        raise SweepError(str(error)) from error
    if not OPEN <= datetime.now(UTC) < CLOSE:
        raise SweepError("application_window_closed")


def _sign(nonce: str, text: str) -> list[str]:
    """Retry only the fail-closed OCI Vault retrieval before any POST."""
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
    raise SweepError("vault_retrieval_failed") from last


def _mark_posted(state: dict, key: str, row: dict) -> dict:
    current = state["items"][key]
    current.update(
        state="posted",
        seq=row["seq"],
        ts=row["ts"],
        posted_record={name: row[name] for name in ("from", "nonce", "text", "sig", "seq", "ts")},
    )
    save(state)
    return {"key": key, "status": "posted", "request_id": current["request_id"], "seq": row["seq"], "ts": row["ts"]}


def _post_one(state: dict, fixed: dict) -> dict:
    key = fixed["key"]
    current = state["items"][key]
    if current["state"] == "posted":
        return {"key": key, "status": "already_posted", "request_id": current["request_id"], "seq": current["seq"], "ts": current["ts"]}
    if current["state"] in {"attempting", "ambiguous"}:
        raise SweepError(f"{key}_submission_ambiguous")

    text = _render(fixed["payload"])
    if core.clean_text(text) != text:
        raise SweepError(f"{key}_text_invalid")
    if current["nonce"] is None:
        current["nonce"] = core.make_nonce(ROOM, DID)
    current["state"] = "prepared"
    save(state)

    signed = _sign(current["nonce"], text)
    if len(signed) != 2 or signed[0] != DID:
        raise SweepError("did_mismatch")
    verify_signed_record(ROOM, {"from": DID, "nonce": current["nonce"], "text": text, "sig": signed[1]})

    require_prepost()
    current["state"] = "attempting"
    current["attempted_at"] = oracle_signer.now()
    save(state)
    try:
        response = core.httpx.post(
            f"{core.BASE_URL}/r/{ROOM}?format=json",
            json={"did": DID, "nonce": current["nonce"], "text": text, "sig": signed[1]},
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
        row = payload.get("posted") if isinstance(payload, dict) else None
        if (
            not isinstance(row, dict)
            or row.get("from") != DID
            or str(row.get("nonce")) != current["nonce"]
            or row.get("text") != text
            or row.get("sig") != signed[1]
            or type(row.get("seq")) is not int
            or row["seq"] < 0
            or not isinstance(row.get("ts"), str)
        ):
            raise SweepError("receipt_mismatch")
        datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
        verify_signed_record(ROOM, row)
        return _mark_posted(state, key, row)
    except BaseException:
        current["state"] = "ambiguous"
        current["posted_record"] = None
        save(state)
        raise SweepError(f"{key}_submission_unknown") from None


def run_once() -> dict:
    with sweep_lock():
        require_prepost()
        state = load()
        if state is None:
            state = new_state()
            save(state)
        results = []
        for fixed in ITEMS:
            results.append(_post_one(state, fixed))
        return {"status": "complete", "results": results}


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("Sonnet opportunity sweep accepts no arguments")
    try:
        print(json.dumps(run_once(), sort_keys=True))
    except SweepError as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        raise SystemExit(1) from None
    except Exception:
        print(json.dumps({"ok": False, "error": "sweep_failed_closed"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
