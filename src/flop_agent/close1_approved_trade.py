"""One fixed, locally approved Close Call trade; isolated signer entry point.

No trade arguments or approval writer. Approval expires after five minutes.
Only public metadata is persisted; a durable attempt fence is never removed.
Deployment/permissions and writing the exact approval are separate operations.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import secrets
import sys
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import close1_account_reconciliation as account
from . import close_call, core, observer, oracle_signer, public_record

OWNER_DID = account.OWNER_DID
MAX_APPROVAL_AGE_SECONDS = 300
SETTLEMENT_MARGIN_SECONDS = 30
FIELDS = {
    "schema_version", "owner_did", "offer_room", "offer_seq", "trade_id",
    "maker", "maker_side", "taker_side", "qty", "px", "until", "maker_sig",
    "approved_at",
}


class TradeError(RuntimeError):
    """Contains only a fixed local error code, never upstream exception text."""


def _now():
    return datetime.now(UTC)


def approval_path():
    return core.STATE / "signer" / "close1-approved-trade.json"


def _time(value):
    if not isinstance(value, str):
        raise TradeError("invalid_time")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise TradeError("invalid_time")
    return parsed.astimezone(UTC)


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise TradeError("duplicate_field")
        value[key] = item
    return value


def _terms(approval):
    return {
        "id": approval["trade_id"], "maker": approval["maker"],
        "side": approval["maker_side"], "qty": approval["qty"],
        "px": approval["px"], "until": approval["until"], "taker": "any",
    }


def load_approval():
    path = approval_path()
    if path.is_symlink():
        raise TradeError("approval_invalid")
    with path.open("rb") as handle:
        raw = handle.read(8193)
    if len(raw) > 8192:
        raise TradeError("approval_invalid")
    value = json.loads(raw, object_pairs_hook=_unique)
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise TradeError("approval_schema_invalid")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise TradeError("approval_schema_invalid")
    if value["owner_did"] != OWNER_DID or value["maker"] == OWNER_DID:
        raise TradeError("approval_identity_mismatch")
    if value["offer_room"] not in ("close1", "close1-offers"):
        raise TradeError("approval_room_invalid")
    if type(value["offer_seq"]) is not int or value["offer_seq"] <= 0:
        raise TradeError("approval_seq_invalid")
    terms = _terms(value)
    close_call.canonical_terms(terms)
    if value["taker_side"] != ("buy" if value["maker_side"] == "sell" else "sell"):
        raise TradeError("approval_side_mismatch")
    public_record.verify_did_signature(
        value["maker"], value["maker_sig"], close_call.maker_signature_preimage(terms)
    )
    normalized = base64.urlsafe_b64encode(base64.urlsafe_b64decode(value["maker_sig"] + "==")).rstrip(b"=").decode("ascii")
    if normalized != value["maker_sig"]:
        raise TradeError("approval_signature_invalid")
    age = (_now() - _time(value["approved_at"])).total_seconds()
    if not 0 <= age <= MAX_APPROVAL_AGE_SECONDS:
        raise TradeError("approval_stale")
    return value, hashlib.sha256(raw).hexdigest()


def _account(trade_id):
    ledger = account.reconcile_pending(owner_did=OWNER_DID)
    account._validate_ledger(ledger, owner_did=OWNER_DID)
    if ledger["pending_trades"] or ledger["pending_trade_ids"]:
        raise TradeError("own_state_pending")
    if trade_id in ledger["settled_trade_ids"] or trade_id in ledger["void_trades"]:
        raise TradeError("already_attempted")
    cash, position = account.scanner_account(ledger)
    return ledger, cash, position


def _fresh_preflight(approval, cash, position):
    room = approval["offer_room"]
    response = core.read_room(room, since=approval["offer_seq"] - 1, limit=200,
                              cache_buster=secrets.token_hex(16))
    rows = response.get("messages")
    if not isinstance(rows, list):
        raise TradeError("offer_missing")
    matches = [row for row in rows if isinstance(row, dict)
               and type(row.get("seq")) is int and row["seq"] == approval["offer_seq"]]
    if len(matches) != 1:
        raise TradeError("offer_missing")
    offer = matches[0]
    payload = json.loads(offer["text"], object_pairs_hook=_unique)
    if payload.get("terms") != _terms(approval) or payload.get("maker_sig") != approval["maker_sig"]:
        raise TradeError("offer_changed")

    response = core.read_room("d-close1-price", limit=1, cache_buster=secrets.token_hex(16))
    rows = response.get("messages")
    if not isinstance(rows, list) or len(rows) != 1:
        raise TradeError("price_missing")
    public_record.verify_signed_record("d-close1-price", rows[0])
    # Reject duplicate keys before using the existing referee validator.
    json.loads(rows[0]["text"], object_pairs_hook=_unique)
    price = close_call._referee_payload(rows[0], "price")
    now = _now()
    sweep = price.get("n")
    wall_sweep = int((now - close_call.OPENING).total_seconds() // 300)
    if type(sweep) is not int or not 0 <= sweep <= wall_sweep <= sweep + 1:
        raise TradeError("price_sweep_invalid")
    if wall_sweep >= close_call.LOCK_SWEEP:
        raise TradeError("contest_locked")
    deadline = min(close_call.LOCK, close_call.OPENING + timedelta(seconds=300 * approval["until"]))
    if approval["until"] < wall_sweep + 1 or (deadline - now).total_seconds() < SETTLEMENT_MARGIN_SECONDS:
        raise TradeError("offer_expired")
    age = price.get("age_s")
    if type(age) is not int or age < 0:
        raise TradeError("price_age_invalid")
    elapsed = (now - _time(price["ref"]["time"])).total_seconds()
    if elapsed < 0:
        raise TradeError("price_age_invalid")
    risk = close_call.evaluate_verified_offer_as_taker(
        offer, current_sweep=wall_sweep, our_did=OWNER_DID, room=room,
        reference_price=price["ref"]["px"],
        reference_age_seconds=max(age, math.ceil(elapsed)),
        available_cash=cash, current_position=position,
    )
    if risk["enough_cash_for_base_fee_and_collateral"] is not True:
        raise TradeError("insufficient_cash")
    # Start at the signed referee's next sweep, even if the wall clock crossed
    # a boundary. Searching an extra sweep is safer than skipping settlement.
    return payload["terms"], sweep + 1


def _sign(terms, maker_sig, nonce):
    """Both signatures in one short Vault window; no environment or child argv."""
    material = bytearray()
    decoded = bytearray()
    key = None
    try:
        material = oracle_signer.vault_seed()
        decoded = bytearray.fromhex(material.decode("ascii"))
        key = Ed25519PrivateKey.from_private_bytes(decoded)
        # Compare the derived Ed25519 public key to the continuing DID itself.
        if key.public_key().public_bytes_raw() != public_record._public_key(OWNER_DID).public_bytes_raw():
            raise TradeError("signer_identity_mismatch")
        preimage = close_call.taker_signature_preimage(terms, OWNER_DID)
        taker_sig = base64.urlsafe_b64encode(key.sign(preimage.encode())).rstrip(b"=").decode("ascii")
        text = close_call._compact({
            "t": "trade", "season": close_call.CONTEST_ID, "terms": terms,
            "taker": OWNER_DID, "maker_sig": maker_sig, "taker_sig": taker_sig,
        })
        if core.clean_text(text) != text:
            raise TradeError("trade_text_invalid")
        signature = base64.urlsafe_b64encode(
            key.sign(f"close1|{nonce}|{text}".encode())
        ).rstrip(b"=").decode("ascii")
        public_record.verify_did_signature(OWNER_DID, taker_sig, preimage)
        public_record.verify_signed_record("close1", {
            "from": OWNER_DID, "nonce": nonce, "text": text, "sig": signature,
        })
        return {"did": OWNER_DID, "nonce": nonce, "text": text, "sig": signature}
    finally:
        material[:] = b"\0" * len(material)
        decoded[:] = b"\0" * len(decoded)
        key = None


def _sync_directory(path):
    if os.name == "posix":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


@contextmanager
def _lock():
    # This Vault-backed entry point follows the existing isolated signer boundary.
    if os.name != "posix":
        raise TradeError("isolated_linux_signer_required")
    import fcntl
    import pwd
    if pwd.getpwuid(os.geteuid()).pw_name != "technocore-signer":
        raise TradeError("isolated_signer_user_required")
    directory = approval_path().parent
    info = directory.stat()
    if directory.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise TradeError("signer_directory_invalid")
    info = approval_path().lstat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise TradeError("approval_permissions_invalid")
    with (directory / "close1-approved-trade.lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _run_locked():
    if oracle_signer.expected_did() != OWNER_DID:
        raise TradeError("signer_expected_did_mismatch")
    try:
        core.require_verified_did(OWNER_DID)
    except RuntimeError as error:
        raise TradeError("signer_did_not_verified") from error
    if not core.signer_matches_pinned():
        raise TradeError("signer_not_pinned")
    approval, digest = load_approval()
    ledger, cash, position = _account(approval["trade_id"])
    token = hashlib.sha256(approval["trade_id"].encode()).hexdigest()
    directory = approval_path().parent
    fence = directory / f"close1-attempt-{token}.json"
    receipt_path = directory / f"close1-receipt-{token}.json"
    if fence.exists() or receipt_path.exists():
        raise TradeError("already_attempted")
    terms, anchor = _fresh_preflight(approval, cash, position)
    if load_approval()[1] != digest:
        raise TradeError("approval_changed")
    nonce = core.make_nonce("close1", OWNER_DID)
    body = _sign(terms, approval["maker_sig"], nonce)
    # Recheck after potentially slow Vault access, with no signing authority
    # remaining. No approval, account, offer, or price may drift before POST.
    if load_approval()[1] != digest:
        raise TradeError("approval_changed")
    latest, cash, position = _account(approval["trade_id"])
    if latest != ledger:
        raise TradeError("own_state_changed")
    _, next_anchor = _fresh_preflight(approval, cash, position)
    anchor = min(anchor, next_anchor)
    if load_approval()[1] != digest:
        raise TradeError("approval_changed")
    metadata = {
        "schema_version": 1, "owner_did": OWNER_DID, "trade_id": approval["trade_id"],
        "approval_sha256": digest, "offer_room": approval["offer_room"],
        "offer_seq": approval["offer_seq"], "room": "close1", "nonce": nonce,
    }
    # Exclusive, permanent fence also covers a crash/ledger rollback. It grants
    # no retry authority, even if marking pending or persisting a receipt fails.
    with fence.open("x", encoding="utf-8") as handle:
        json.dump(metadata, handle)
        handle.flush()
        os.fsync(handle.fileno())
    _sync_directory(directory)
    if account.load_ledger(owner_did=OWNER_DID) != ledger:
        raise TradeError("own_state_changed")
    pending = account.mark_pending(approval["trade_id"], search_start_sweep=anchor, owner_did=OWNER_DID)
    if account.load_ledger(owner_did=OWNER_DID) != pending or approval["trade_id"] not in pending["pending_trades"]:
        raise TradeError("pending_not_durable")
    _sync_directory(account.state_path().parent)
    try:
        response = core.httpx.post(f"{core.BASE_URL}/r/close1?format=json", json=body,
                                   timeout=20, follow_redirects=False)
        response.raise_for_status()
        row = response.json().get("posted")
        if not isinstance(row, dict) or type(row.get("seq")) is not int or row["seq"] <= 0:
            raise TradeError("ambiguous")
        posted_at = _time(row.get("ts")).isoformat()
        if any(row.get(k) != v for k, v in {
            "from": OWNER_DID, "text": body["text"], "sig": body["sig"],
        }.items()) or str(row.get("nonce")) != nonce:
            raise TradeError("ambiguous")
        receipt = {**metadata, "status": "posted", "seq": row["seq"], "ts": posted_at}
        observer.atomic_json_write(receipt_path, receipt, mode=0o600)
        _sync_directory(directory)
        return receipt
    except Exception:
        # Never echo HTTP/SDK bodies (they can contain signatures). Pending is
        # intentionally retained even on an explicit error response.
        raise TradeError("ambiguous") from None


def run_once():
    try:
        with _lock():
            return _run_locked()
    except TradeError:
        raise
    except Exception:
        raise TradeError("preflight_failed") from None


def main():
    if len(sys.argv) != 1:
        print(json.dumps({"status": "blocked", "reason": "arguments_forbidden"}))
        return 1
    try:
        result = run_once()
    except TradeError as error:
        print(json.dumps({"status": "ambiguous" if str(error) == "ambiguous" else "blocked", "reason": str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
