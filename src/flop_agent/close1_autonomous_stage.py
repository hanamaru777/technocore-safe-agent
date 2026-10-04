"""Unprivileged resident-side staging for short-lived Close Call offers.

This module is intentionally read-only with respect to Technocore. It reads public
rooms and the shared owner ledger, selects one bounded material candidate from a
single captured snapshot, and writes only an exact local stage artifact. It has
no signer/Vault access and no network write path.
"""
from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from . import close1_account_reconciliation as account
from . import close1_candidate_scanner as scanner
from . import close_call, core, observer

SCHEMA_VERSION = 1
OWNER_DID = account.OWNER_DID
MIN_MATERIAL_QTY = Decimal("10")
MAX_CASH_FRACTION = Decimal("0.60")
MIN_EDGE_BPS = Decimal("0")
MAX_SKIP_IDS = 1024

STAGE_FIELDS = {
    "schema_version", "owner_did", "offer_room", "offer_seq", "trade_id",
    "maker", "maker_side", "taker_side", "qty", "px", "until", "maker_sig",
    "detected_sweep", "reference", "reference_age_s", "current_cash",
    "current_position", "required_cash", "price_edge_bps", "detected_at",
    "raw_captured_at", "staged_at",
}


def _now() -> datetime:
    return datetime.now(UTC)


def stage_path() -> Path:
    return core.STATE / "close1" / "close1-autonomous-stage.json"


def skip_path() -> Path:
    return core.STATE / "close1" / "close1-autonomous-skips.json"


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("close1_auto_time_timezone_required")
    return value.astimezone(UTC).isoformat()


def _edge_bps(*, taker_side: str, px: Decimal, reference: Decimal) -> Decimal:
    if taker_side == "buy":
        return (reference - px) / reference * Decimal("10000")
    if taker_side == "sell":
        return (px - reference) / reference * Decimal("10000")
    raise ValueError("close1_auto_side_invalid")


def _load_skips() -> set[str]:
    path = skip_path()
    if not path.exists():
        return set()
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise RuntimeError("close1_auto_skip_state_invalid") from None
    if not isinstance(value, dict) or set(value) != {"schema_version", "trade_ids"}:
        raise RuntimeError("close1_auto_skip_state_invalid")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("close1_auto_skip_state_invalid")
    rows = value.get("trade_ids")
    if (
        not isinstance(rows, list)
        or len(rows) > MAX_SKIP_IDS
        or len(set(rows)) != len(rows)
        or any(not isinstance(item, str) or not close_call.TRADE_ID_RE.fullmatch(item) for item in rows)
    ):
        raise RuntimeError("close1_auto_skip_state_invalid")
    return set(rows)


def _select_candidate(
    scan: scanner.CandidateScan,
    *,
    cash: Decimal,
    skip_ids: set[str],
) -> scanner.CandidateView | None:
    eligible: list[tuple[Decimal, scanner.CandidateView]] = []
    budget = cash * MAX_CASH_FRACTION
    for candidate in scan.candidates:
        if candidate.trade_id in skip_ids:
            continue
        if candidate.qty < MIN_MATERIAL_QTY:
            continue
        if candidate.required_cash > budget:
            continue
        if candidate.until < scan.sweep + 1:
            continue
        edge = _edge_bps(
            taker_side=candidate.taker_side,
            px=candidate.px,
            reference=scan.reference,
        )
        if edge < MIN_EDGE_BPS:
            continue
        eligible.append((edge, candidate))
    if not eligible:
        return None
    eligible.sort(key=lambda row: (-row[1].qty, -row[0], row[1].required_cash, row[1].seq))
    return eligible[0][1]


def _exact_raw_offer(
    *,
    room_payloads: dict[str, dict],
    candidate: scanner.CandidateView,
    current_sweep: int,
) -> tuple[dict, dict]:
    payload = room_payloads.get(candidate.room)
    if not isinstance(payload, dict) or not isinstance(payload.get("messages"), list):
        raise RuntimeError("close1_auto_room_missing")
    matches = [
        row for row in payload["messages"]
        if isinstance(row, dict) and row.get("seq") == candidate.seq
    ]
    if len(matches) != 1:
        raise RuntimeError("close1_auto_offer_missing")
    message = matches[0]
    verified = close_call.parse_verified_public_offer(
        message,
        current_sweep=current_sweep,
        our_did=OWNER_DID,
        room=candidate.room,
    )
    try:
        raw = json.loads(message["text"])
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("close1_auto_offer_invalid") from error
    if not isinstance(raw, dict) or not isinstance(raw.get("terms"), dict):
        raise RuntimeError("close1_auto_offer_invalid")
    terms = raw["terms"]
    if (
        terms.get("id") != candidate.trade_id
        or verified.maker != candidate.maker
        or verified.taker_side != candidate.taker_side
        or verified.qty != candidate.qty
        or verified.px != candidate.px
        or verified.until != candidate.until
    ):
        raise RuntimeError("close1_auto_candidate_drift")
    maker_sig = raw.get("maker_sig")
    if not isinstance(maker_sig, str):
        raise RuntimeError("close1_auto_offer_invalid")
    return terms, {"maker_sig": maker_sig}


def build_stage(*, now: datetime | None = None) -> dict | None:
    detected = now or _now()
    if detected.tzinfo is None:
        raise ValueError("close1_auto_time_timezone_required")
    detected = detected.astimezone(UTC)
    if detected >= close_call.LOCK:
        raise RuntimeError("close1_auto_contest_locked")
    if stage_path().exists():
        raise RuntimeError("close1_auto_stage_inflight")

    ledger = account.load_ledger(owner_did=OWNER_DID)
    account._validate_ledger(ledger, owner_did=OWNER_DID)
    if ledger["pending_trade_ids"] or ledger["pending_trades"]:
        raise RuntimeError("close1_auto_pending_reconcile_first")
    cash_text, position = account.scanner_account(ledger)
    cash = Decimal(cash_text)
    skip_ids = _load_skips()
    if set(ledger["settled_trade_ids"]) | set(ledger["void_trades"]):
        skip_ids |= set(ledger["settled_trade_ids"]) | set(ledger["void_trades"])

    nonce = secrets.token_hex(16)
    price_room = core.read_room("d-close1-price", limit=2, cache_buster=nonce)
    pnl_room = core.read_room("d-close1-pnl", limit=120, cache_buster=nonce)
    positions_room = core.read_room("d-close1-positions", limit=2, cache_buster=nonce)
    room_payloads = {
        "close1": core.read_room("close1", limit=200, cache_buster=nonce),
        "close1-offers": core.read_room("close1-offers", limit=200, cache_buster=nonce),
    }
    raw_captured = _now()
    scan = scanner.build_candidate_scan(
        our_did=OWNER_DID,
        price_room=price_room,
        pnl_room=pnl_room,
        positions_room=positions_room,
        negotiation_rooms=room_payloads,
        available_cash=cash_text,
        current_position=position,
    )
    candidate = _select_candidate(scan, cash=cash, skip_ids=skip_ids)
    if candidate is None:
        return None
    terms, extra = _exact_raw_offer(
        room_payloads=room_payloads,
        candidate=candidate,
        current_sweep=scan.sweep,
    )
    edge = _edge_bps(
        taker_side=candidate.taker_side,
        px=candidate.px,
        reference=scan.reference,
    )
    staged = _now()
    result = {
        "schema_version": SCHEMA_VERSION,
        "owner_did": OWNER_DID,
        "offer_room": candidate.room,
        "offer_seq": candidate.seq,
        "trade_id": candidate.trade_id,
        "maker": candidate.maker,
        "maker_side": terms["side"],
        "taker_side": candidate.taker_side,
        "qty": terms["qty"],
        "px": terms["px"],
        "until": terms["until"],
        "maker_sig": extra["maker_sig"],
        "detected_sweep": scan.sweep,
        "reference": str(scan.reference),
        "reference_age_s": scan.reference_age_seconds,
        "current_cash": cash_text,
        "current_position": position,
        "required_cash": format(candidate.required_cash, "f"),
        "price_edge_bps": format(edge, "f"),
        "detected_at": _utc(detected),
        "raw_captured_at": _utc(raw_captured),
        "staged_at": _utc(staged),
    }
    if set(result) != STAGE_FIELDS:
        raise RuntimeError("close1_auto_stage_schema_invalid")
    return result


def run_once() -> dict:
    stage = build_stage()
    if stage is None:
        return {"status": "no_candidate"}
    observer.atomic_json_write(stage_path(), stage, compact=True, mode=0o660)
    return {
        "status": "staged",
        "trade_id": stage["trade_id"],
        "offer_seq": stage["offer_seq"],
        "qty": stage["qty"],
        "taker_side": stage["taker_side"],
    }


def main() -> int:
    try:
        result = run_once()
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
