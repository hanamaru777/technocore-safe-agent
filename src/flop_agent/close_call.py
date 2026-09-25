"""Safe, non-binding Close Call (close-1) contest preflight.

This module pins the live FLOP Labs launch authority and provides deterministic
parsing/planning only. It never signs, posts, registers, accepts a trade, or
moves value.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation

from . import core

CONTEST_ID = "close-1"
OFFICIAL_REPO_COMMIT = "66c1da36538e4b1c685417d2f66922906b13fea0"
LAUNCH_MANIFEST_SHA256 = ("bae09812e25eb6f1369c611f24964f7e" "a0acafddfc45301a16f33f941296dafa")
REFEREE_DID = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
TRADING_ROOM = "close1"
REFEREE_ROOMS = (
    "d-close1-flow",
    "d-close1-state",
    "d-close1-price",
    "d-close1-positions",
    "d-close1-pnl",
)
OPENING = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
LOCK = datetime(2026, 10, 4, 9, 0, tzinfo=UTC)
FINAL_PRICE_TIME = datetime(2026, 10, 4, 10, 0, tzinfo=UTC)
LOCK_SWEEP = 2556
MINT = Decimal("10000")
MIN_QTY = Decimal("0.1")
LIMIT_WINDOW = Decimal("0.05")
FEE_RATE = Decimal("0.01")
SAFE_MAX_REFERENCE_AGE_SECONDS = 120

DID_RE = re.compile(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}")
TRADE_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
AMOUNT_RE = re.compile(r"[0-9]{1,7}(?:\.[0-9]{1,2})?")


@dataclass(frozen=True)
class LiveSnapshot:
    sweep: int
    reference: Decimal
    reference_age_seconds: int
    reference_fresh_for_strategy: bool
    owners: int
    pnl_top: tuple[tuple[str, Decimal], ...]
    top3_cutoff: Decimal | None
    longs: int
    shorts: int
    open_notional: Decimal


def _compact(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _amount(value: object, *, label: str) -> Decimal:
    if not isinstance(value, str) or not AMOUNT_RE.fullmatch(value):
        raise ValueError(f"close1_{label}_invalid")
    try:
        amount = Decimal(value)
    except InvalidOperation as error:
        raise ValueError(f"close1_{label}_invalid") from error
    if amount <= 0:
        raise ValueError(f"close1_{label}_invalid")
    return amount


def _did(value: object, *, label: str = "did") -> str:
    if not isinstance(value, str) or not DID_RE.fullmatch(value):
        raise ValueError(f"close1_{label}_invalid")
    return value


def _referee_payload(message: object, expected_type: str) -> dict:
    if not isinstance(message, dict) or message.get("from") != REFEREE_DID:
        raise ValueError("close1_referee_sender_invalid")
    text = message.get("text")
    if not isinstance(text, str):
        raise ValueError("close1_referee_text_invalid")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError("close1_referee_json_invalid") from error
    if not isinstance(payload, dict) or payload.get("t") != expected_type:
        raise ValueError("close1_referee_type_invalid")
    return payload


def validate_seed_message(message: object) -> dict:
    payload = _referee_payload(message, "seed")
    if payload.get("season") != CONTEST_ID:
        raise ValueError("close1_seed_season_invalid")
    if payload.get("package") != LAUNCH_MANIFEST_SHA256:
        raise ValueError("close1_seed_package_mismatch")
    rooms = payload.get("rooms")
    if not isinstance(rooms, list) or tuple(rooms) != REFEREE_ROOMS:
        raise ValueError("close1_seed_rooms_mismatch")
    _amount(payload.get("price"), label="seed_price")
    trade = payload.get("trade")
    if (
        not isinstance(trade, dict)
        or not isinstance(trade.get("time"), str)
        or not isinstance(trade.get("tid"), int)
    ):
        raise ValueError("close1_seed_trade_invalid")
    return payload


def registration_text(did: str) -> str:
    did = _did(did)
    return _compact({"t": "owner", "season": CONTEST_ID, "key": did})


def canonical_terms(terms: object) -> str:
    if not isinstance(terms, dict) or set(terms) != {
        "id", "maker", "side", "qty", "px", "taker", "until"
    }:
        raise ValueError("close1_terms_shape_invalid")
    if not isinstance(terms.get("id"), str) or not TRADE_ID_RE.fullmatch(terms["id"]):
        raise ValueError("close1_trade_id_invalid")
    maker = _did(terms.get("maker"), label="maker")
    side = terms.get("side")
    if side not in {"buy", "sell"}:
        raise ValueError("close1_side_invalid")
    qty = _amount(terms.get("qty"), label="qty")
    if qty < MIN_QTY:
        raise ValueError("close1_qty_below_min")
    _amount(terms.get("px"), label="price")
    taker = terms.get("taker")
    if taker != "any":
        taker = _did(taker, label="taker")
        if taker == maker:
            raise ValueError("close1_self_trade_forbidden_by_local_policy")
    until = terms.get("until")
    if type(until) is not int or not 1 <= until <= LOCK_SWEEP:
        raise ValueError("close1_until_invalid")
    return _compact(terms)


def maker_signature_preimage(terms: object) -> str:
    return f"{CONTEST_ID}|terms|{canonical_terms(terms)}"


def taker_signature_preimage(terms: object, taker_did: str) -> str:
    taker_did = _did(taker_did, label="taker")
    canonical = canonical_terms(terms)
    maker = terms["maker"]  # validated above
    if taker_did == maker:
        raise ValueError("close1_self_trade_forbidden_by_local_policy")
    named = terms["taker"]
    if named != "any" and named != taker_did:
        raise ValueError("close1_taker_mismatch")
    return f"{CONTEST_ID}|accept|{canonical}|{taker_did}"


def validate_trade_plan(
    terms: object,
    *,
    current_sweep: int,
    reference_price: str,
    reference_age_seconds: int,
    available_cash: str | None = None,
    current_position: str = "0",
) -> dict:
    canonical = canonical_terms(terms)
    if type(current_sweep) is not int or current_sweep < 0 or current_sweep >= LOCK_SWEEP:
        raise ValueError("close1_current_sweep_invalid")
    if terms["until"] < current_sweep + 1:
        raise ValueError("close1_trade_would_be_expired")
    if type(reference_age_seconds) is not int or reference_age_seconds < 0:
        raise ValueError("close1_reference_age_invalid")
    if reference_age_seconds > SAFE_MAX_REFERENCE_AGE_SECONDS:
        raise RuntimeError("close1_reference_stale_for_local_strategy")

    ref = _amount(reference_price, label="reference")
    px = _amount(terms["px"], label="price")
    qty = _amount(terms["qty"], label="qty")
    lower = ref * (Decimal("1") - LIMIT_WINDOW)
    upper = ref * (Decimal("1") + LIMIT_WINDOW)
    if px < lower or px > upper:
        raise ValueError("close1_price_outside_limit")

    side = Decimal("1") if terms["side"] == "buy" else Decimal("-1")
    try:
        held = Decimal(current_position)
    except InvalidOperation as error:
        raise ValueError("close1_position_invalid") from error
    if not held.is_finite():
        raise ValueError("close1_position_invalid")
    closing = min(qty, max(-side * held, Decimal("0")))
    opening = qty - closing
    base_fee = FEE_RATE * qty * px
    required_before_unknown_clawback = opening * px + base_fee

    enough_base_cash = None
    if available_cash is not None:
        cash = _amount(available_cash, label="available_cash")
        enough_base_cash = cash >= required_before_unknown_clawback

    return {
        "canonical_terms": canonical,
        "reference": str(ref),
        "limit_low": str(lower),
        "limit_high": str(upper),
        "reference_age_seconds": reference_age_seconds,
        "reference_fresh_for_strategy": True,
        "opening_qty": str(opening),
        "base_fee": str(base_fee),
        "required_cash_before_unknown_clawback": str(required_before_unknown_clawback),
        "enough_cash_for_base_fee_and_collateral": enough_base_cash,
        "warning": "sweep close is not known before settlement; clawback can exceed the 1% base fee",
    }


def side_fees(*, maker_side: str, qty: str, px: str, sweep_close: str) -> tuple[Decimal, Decimal]:
    if maker_side not in {"buy", "sell"}:
        raise ValueError("close1_side_invalid")
    q = _amount(qty, label="qty")
    p = _amount(px, label="price")
    close = _amount(sweep_close, label="sweep_close")
    base = FEE_RATE * q * p
    gap = (close - p) * q
    buyer = max(base, gap)
    seller = max(base, -gap)
    return (buyer, seller) if maker_side == "buy" else (seller, buyer)


def _latest_message(room_payload: object, expected_type: str) -> dict:
    if not isinstance(room_payload, dict) or not isinstance(room_payload.get("messages"), list):
        raise ValueError("close1_room_payload_invalid")
    messages = room_payload["messages"]
    if not messages:
        raise ValueError("close1_room_empty")
    return _referee_payload(messages[-1], expected_type)


def build_live_snapshot(
    *,
    price_room: object,
    state_room: object,
    pnl_room: object,
    positions_room: object,
) -> LiveSnapshot:
    price = _latest_message(price_room, "price")
    state = _latest_message(state_room, "state")
    pnl = _latest_message(pnl_room, "pnl")
    positions = _latest_message(positions_room, "positions")

    sweeps = [price.get("n"), state.get("n"), pnl.get("n"), positions.get("n")]
    if not all(type(value) is int for value in sweeps) or len(set(sweeps)) != 1:
        raise ValueError("close1_snapshot_sweep_mismatch")
    sweep = sweeps[0]

    ref = price.get("ref")
    if not isinstance(ref, dict):
        raise ValueError("close1_price_ref_invalid")
    reference = _amount(ref.get("px"), label="reference")
    age = price.get("age_s")
    if type(age) is not int or age < 0:
        raise ValueError("close1_reference_age_invalid")

    owners = state.get("owners")
    if type(owners) is not int or owners < 0:
        raise ValueError("close1_owner_count_invalid")

    top_raw = pnl.get("top")
    if not isinstance(top_raw, list):
        raise ValueError("close1_pnl_top_invalid")
    top: list[tuple[str, Decimal]] = []
    for row in top_raw:
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError("close1_pnl_top_invalid")
        did = _did(row[0], label="leader")
        try:
            score = Decimal(str(row[1]))
        except InvalidOperation as error:
            raise ValueError("close1_pnl_score_invalid") from error
        if not score.is_finite():
            raise ValueError("close1_pnl_score_invalid")
        top.append((did, score))

    longs = positions.get("longs")
    shorts = positions.get("shorts")
    if type(longs) is not int or longs < 0 or type(shorts) is not int or shorts < 0:
        raise ValueError("close1_positions_count_invalid")
    open_notional = _amount(str(positions.get("open")), label="open_notional")

    cutoff = top[2][1] if len(top) >= 3 else None
    return LiveSnapshot(
        sweep=sweep,
        reference=reference,
        reference_age_seconds=age,
        reference_fresh_for_strategy=age <= SAFE_MAX_REFERENCE_AGE_SECONDS,
        owners=owners,
        pnl_top=tuple(top),
        top3_cutoff=cutoff,
        longs=longs,
        shorts=shorts,
        open_notional=open_notional,
    )


def fetch_live_snapshot() -> LiveSnapshot:
    """Read only the official referee rooms; no signing or posting."""
    payloads = {}
    for room in ("d-close1-price", "d-close1-state", "d-close1-pnl", "d-close1-positions"):
        payloads[room] = core.read_room(room, limit=5)
    return build_live_snapshot(
        price_room=payloads["d-close1-price"],
        state_room=payloads["d-close1-state"],
        pnl_room=payloads["d-close1-pnl"],
        positions_room=payloads["d-close1-positions"],
    )
