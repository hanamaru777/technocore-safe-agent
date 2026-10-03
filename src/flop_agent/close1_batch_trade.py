"""Fail-closed same-sweep Close Call batch executor.

This is a separate execution path from ``close1_approved_trade``.  It accepts
only a short-lived exact batch approval artifact, requires a flat reconciled
account, same-side unique-maker legs, aggregate base-fee collateral coverage,
and reuses the audited one-shot offer/signature/POST primitives.  Every leg
gets its own permanent attempt fence and durable pending marker before POST.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from contextlib import contextmanager
from datetime import UTC, datetime
from decimal import Decimal

from . import close1_account_reconciliation as account
from . import close1_approved_trade as single
from . import close_call, core, observer, oracle_signer, public_record

OWNER_DID = account.OWNER_DID
MAX_LEGS = 16
MAX_APPROVAL_BYTES = 32768
TOP_FIELDS = {"schema_version", "owner_did", "legs", "approved_at"}
LEG_FIELDS = {
    "offer_room", "offer_seq", "trade_id", "maker", "maker_side",
    "taker_side", "qty", "px", "until", "maker_sig",
}


class BatchTradeError(RuntimeError):
    """Fixed local reason only; never expose upstream exception bodies."""


def _now() -> datetime:
    return datetime.now(UTC)


def approval_path():
    return core.STATE / "signer" / "close1-approved-batch.json"


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise BatchTradeError("duplicate_field")
        value[key] = item
    return value


def _time(value):
    try:
        return single._time(value)
    except Exception as error:
        raise BatchTradeError("invalid_time") from error


def _terms(leg):
    return {
        "id": leg["trade_id"],
        "maker": leg["maker"],
        "side": leg["maker_side"],
        "qty": leg["qty"],
        "px": leg["px"],
        "until": leg["until"],
        "taker": "any",
    }


def _single_approval(leg, approved_at):
    return {
        "schema_version": 1,
        "owner_did": OWNER_DID,
        **leg,
        "approved_at": approved_at,
    }


def load_approval():
    path = approval_path()
    if path.is_symlink():
        raise BatchTradeError("approval_invalid")
    with path.open("rb") as handle:
        raw = handle.read(MAX_APPROVAL_BYTES + 1)
    if len(raw) > MAX_APPROVAL_BYTES:
        raise BatchTradeError("approval_invalid")
    value = json.loads(raw, object_pairs_hook=_unique)
    if not isinstance(value, dict) or set(value) != TOP_FIELDS:
        raise BatchTradeError("approval_schema_invalid")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["owner_did"] != OWNER_DID:
        raise BatchTradeError("approval_identity_mismatch")
    legs = value["legs"]
    if not isinstance(legs, list) or not 2 <= len(legs) <= MAX_LEGS:
        raise BatchTradeError("approval_legs_invalid")

    ids, makers, sides = set(), set(), set()
    for leg in legs:
        if not isinstance(leg, dict) or set(leg) != LEG_FIELDS:
            raise BatchTradeError("approval_leg_schema_invalid")
        if leg["offer_room"] not in ("close1", "close1-offers"):
            raise BatchTradeError("approval_room_invalid")
        if type(leg["offer_seq"]) is not int or leg["offer_seq"] <= 0:
            raise BatchTradeError("approval_seq_invalid")
        if leg["maker"] == OWNER_DID:
            raise BatchTradeError("approval_identity_mismatch")
        terms = _terms(leg)
        try:
            close_call.canonical_terms(terms)
        except Exception as error:
            raise BatchTradeError("approval_terms_invalid") from error
        expected_taker = "buy" if leg["maker_side"] == "sell" else "sell"
        if leg["taker_side"] != expected_taker:
            raise BatchTradeError("approval_side_mismatch")
        try:
            public_record.verify_did_signature(
                leg["maker"], leg["maker_sig"], close_call.maker_signature_preimage(terms)
            )
            normalized = base64.urlsafe_b64encode(
                base64.urlsafe_b64decode(leg["maker_sig"] + "==")
            ).rstrip(b"=").decode("ascii")
        except Exception as error:
            raise BatchTradeError("approval_signature_invalid") from error
        if normalized != leg["maker_sig"]:
            raise BatchTradeError("approval_signature_invalid")
        if leg["trade_id"] in ids or leg["maker"] in makers:
            raise BatchTradeError("approval_duplicate_leg")
        ids.add(leg["trade_id"])
        makers.add(leg["maker"])
        sides.add(leg["taker_side"])
    if len(sides) != 1:
        raise BatchTradeError("approval_mixed_side")
    age = (_now() - _time(value["approved_at"])).total_seconds()
    if not 0 <= age <= single.MAX_APPROVAL_AGE_SECONDS:
        raise BatchTradeError("approval_stale")
    return value, hashlib.sha256(raw).hexdigest()


def _flat_account():
    ledger = account.reconcile_pending(owner_did=OWNER_DID)
    account._validate_ledger(ledger, owner_did=OWNER_DID)
    if ledger["pending_trades"] or ledger["pending_trade_ids"]:
        raise BatchTradeError("own_state_pending")
    cash_text, position_text = account.scanner_account(ledger)
    cash, position = Decimal(cash_text), Decimal(position_text)
    if position != 0:
        raise BatchTradeError("own_position_not_flat")
    return ledger, cash, position_text


def _aggregate_required(legs):
    total = Decimal("0")
    for leg in legs:
        qty = close_call._amount(leg["qty"], label="qty")
        px = close_call._amount(leg["px"], label="px")
        total += qty * px * (Decimal("1") + close_call.FEE_RATE)
    return total


def _preflight_leg(leg, approved_at, cash, position_text):
    try:
        return single._fresh_preflight(
            _single_approval(leg, approved_at),
            str(cash),
            position_text,
        )
    except single.TradeError as error:
        raise BatchTradeError(str(error)) from error


def _preflight_all(approval, cash, position_text):
    if _aggregate_required(approval["legs"]) > cash:
        raise BatchTradeError("aggregate_insufficient_cash")
    results = [
        _preflight_leg(leg, approval["approved_at"], cash, position_text)
        for leg in approval["legs"]
    ]
    anchors = [anchor for _, anchor in results]
    if len(set(anchors)) != 1:
        raise BatchTradeError("batch_sweep_changed")
    return [terms for terms, _ in results], anchors[0]


def _balance_fingerprint(ledger):
    return json.dumps(
        {
            "cash": ledger["cash"],
            "lots": ledger["lots"],
            "position": ledger["position"],
            "cumulative_fees": ledger["cumulative_fees"],
            "settled_trade_ids": ledger["settled_trade_ids"],
            "void_trades": ledger["void_trades"],
            "trade_evidence": ledger["trade_evidence"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _pending_batch_state(baseline, allowed_ids):
    current = account.load_ledger(owner_did=OWNER_DID)
    account._validate_ledger(current, owner_did=OWNER_DID)
    if _balance_fingerprint(current) != _balance_fingerprint(baseline):
        raise BatchTradeError("own_state_changed")
    if not set(current["pending_trades"]).issubset(set(allowed_ids)):
        raise BatchTradeError("own_state_changed")
    return current


def _paths(leg):
    token = hashlib.sha256(leg["trade_id"].encode()).hexdigest()
    directory = single.approval_path().parent
    return (
        directory,
        directory / f"close1-attempt-{token}.json",
        directory / f"close1-receipt-{token}.json",
    )


def _write_fence(leg, digest, nonce):
    directory, fence, receipt = _paths(leg)
    if fence.exists() or receipt.exists():
        raise BatchTradeError("already_attempted")
    metadata = {
        "schema_version": 1,
        "owner_did": OWNER_DID,
        "trade_id": leg["trade_id"],
        "approval_sha256": digest,
        "offer_room": leg["offer_room"],
        "offer_seq": leg["offer_seq"],
        "room": "close1",
        "nonce": nonce,
        "batch": True,
    }
    with fence.open("x", encoding="utf-8") as handle:
        json.dump(metadata, handle)
        handle.flush()
        os.fsync(handle.fileno())
    single._sync_directory(directory)
    return metadata, receipt

    
def _post_one(body, metadata, receipt_path):
    try:
        response = core.httpx.post(
            f"{core.BASE_URL}/r/close1?format=json",
            json=body,
            timeout=20,
            follow_redirects=False,
        )
        response.raise_for_status()
        row = response.json().get("posted")
        if not isinstance(row, dict) or type(row.get("seq")) is not int or row["seq"] <= 0:
            raise BatchTradeError("ambiguous")
        posted_at = _time(row.get("ts")).isoformat()
        if any(
            row.get(key) != value
            for key, value in {
                "from": OWNER_DID,
                "text": body["text"],
                "sig": body["sig"],
            }.items()
        ) or str(row.get("nonce")) != body["nonce"]:
            raise BatchTradeError("ambiguous")
        receipt = {**metadata, "status": "posted", "seq": row["seq"], "ts": posted_at}
        observer.atomic_json_write(receipt_path, receipt, mode=0o600)
        single._sync_directory(receipt_path.parent)
        return receipt
    except Exception:
        raise BatchTradeError("ambiguous") from None


@contextmanager
def _lock():
    if os.name != "posix":
        raise BatchTradeError("isolated_linux_signer_required")
    import fcntl
    import pwd

    if pwd.getpwuid(os.geteuid()).pw_name != "technocore-signer":
        raise BatchTradeError("isolated_signer_user_required")
    path = approval_path()
    directory = path.parent
    d_info = directory.stat()
    if directory.is_symlink() or d_info.st_uid != os.geteuid() or d_info.st_mode & 0o022:
        raise BatchTradeError("signer_directory_invalid")
    info = path.lstat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise BatchTradeError("approval_permissions_invalid")
    with (directory / "close1-approved-trade.lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _run_locked():
    if oracle_signer.expected_did() != OWNER_DID:
        raise BatchTradeError("signer_expected_did_mismatch")
    try:
        core.require_verified_did(OWNER_DID)
    except RuntimeError as error:
        raise BatchTradeError("signer_did_not_verified") from error
    if not core.signer_matches_pinned():
        raise BatchTradeError("signer_not_pinned")

    approval, digest = load_approval()
    ledger, cash, position_text = _flat_account()
    allowed_ids = [leg["trade_id"] for leg in approval["legs"]]
    for leg in approval["legs"]:
        _, fence, receipt = _paths(leg)
        if fence.exists() or receipt.exists():
            raise BatchTradeError("already_attempted")

    terms, anchor = _preflight_all(approval, cash, position_text)
    nonces = [core.make_nonce("close1", OWNER_DID) for _ in approval["legs"]]
    try:
        bodies = [
            single._sign(term, leg["maker_sig"], nonce)
            for leg, term, nonce in zip(approval["legs"], terms, nonces, strict=True)
        ]
    except single.TradeError as error:
        raise BatchTradeError(str(error)) from error

    if load_approval()[1] != digest:
        raise BatchTradeError("approval_changed")
    if account.load_ledger(owner_did=OWNER_DID) != ledger:
        raise BatchTradeError("own_state_changed")
    _, second_anchor = _preflight_all(approval, cash, position_text)
    if second_anchor != anchor:
        raise BatchTradeError("batch_sweep_changed")
    if load_approval()[1] != digest:
        raise BatchTradeError("approval_changed")

    receipts = []
    for leg, body, nonce in zip(approval["legs"], bodies, nonces, strict=True):
        if load_approval()[1] != digest:
            raise BatchTradeError("approval_changed")
        _pending_batch_state(ledger, allowed_ids)
        _, current_anchor = _preflight_leg(leg, approval["approved_at"], cash, position_text)
        if current_anchor != anchor:
            raise BatchTradeError("batch_sweep_changed")
        metadata, receipt_path = _write_fence(leg, digest, nonce)
        try:
            pending = account.mark_pending_batch_leg(
                leg["trade_id"],
                search_start_sweep=anchor,
                allowed_trade_ids=allowed_ids,
                owner_did=OWNER_DID,
            )
        except Exception as error:
            raise BatchTradeError("pending_not_durable") from error
        if leg["trade_id"] not in pending["pending_trades"]:
            raise BatchTradeError("pending_not_durable")
        single._sync_directory(account.state_path().parent)
        receipts.append(_post_one(body, metadata, receipt_path))
    return {"status": "posted", "batch": True, "receipts": receipts}


def run_once():
    try:
        with _lock():
            return _run_locked()
    except BatchTradeError:
        raise
    except Exception:
        raise BatchTradeError("preflight_failed") from None


def main():
    if len(sys.argv) != 1:
        print(json.dumps({"status": "blocked", "reason": "arguments_forbidden"}))
        return 1
    try:
        result = run_once()
    except BatchTradeError as error:
        state = "ambiguous" if str(error) == "ambiguous" else "blocked"
        print(json.dumps({"status": state, "reason": str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
