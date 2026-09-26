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

from . import core, public_record

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


@dataclass(frozen=True)
class VerifiedPublicOffer:
    """A verified public negotiation offer; not a referee-settled trade."""

    room: str
    seq: int
    ts: str
    maker: str
    maker_side: str
    taker_side: str
    qty: Decimal
    px: Decimal
    until: int
    canonical_terms: str
    taker_signature_preimage: str


@dataclass(frozen=True)
class ExposureEstimate:
    """Provisional score-vs-mark exposure inferred from successive PnL posts."""

    did: str
    intervals: int
    consistent_intervals: int
    exposure: Decimal | None
    stable: bool
    min_mark_move: Decimal


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


def parse_verified_public_offer(
    message: object,
    *,
    current_sweep: int,
    our_did: str,
    room: str = TRADING_ROOM,
) -> VerifiedPublicOffer:
    """Verify one observed t=offer convention without signing or posting.

    t=offer is a public negotiation convention seen in close1. It is not an
    official referee-counted message; only a fully countersigned t=trade can
    settle.
    """
    our_did = _did(our_did, label="taker")
    if type(current_sweep) is not int or current_sweep < 0 or current_sweep >= LOCK_SWEEP:
        raise ValueError("close1_current_sweep_invalid")
    if not isinstance(message, dict):
        raise ValueError("close1_offer_record_invalid")
    if not isinstance(room, str) or not room or len(room) > 128:
        raise ValueError("close1_offer_room_invalid")

    public_record.verify_signed_record(room, message)
    text = message.get("text")
    try:
        payload = json.loads(text)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("close1_offer_json_invalid") from error
    required = {"t", "season", "terms", "maker_sig"}
    allowed = required | {"how"}
    if (
        not isinstance(payload, dict)
        or not required.issubset(payload)
        or not set(payload).issubset(allowed)
        or payload.get("t") != "offer"
        or payload.get("season") != CONTEST_ID
    ):
        raise ValueError("close1_offer_shape_invalid")
    if "how" in payload and not isinstance(payload["how"], str):
        raise ValueError("close1_offer_shape_invalid")

    terms = payload.get("terms")
    canonical = canonical_terms(terms)
    maker = terms["maker"]
    if message.get("from") != maker:
        raise ValueError("close1_offer_author_mismatch")
    if maker == our_did:
        raise ValueError("close1_self_trade_forbidden_by_local_policy")
    if terms["taker"] != "any":
        raise ValueError("close1_offer_not_public")
    if terms["until"] < current_sweep + 1:
        raise ValueError("close1_offer_expired")

    maker_sig = payload.get("maker_sig")
    if not isinstance(maker_sig, str):
        raise ValueError("close1_offer_maker_sig_invalid")
    public_record.verify_did_signature(
        maker,
        maker_sig,
        maker_signature_preimage(terms),
    )

    seq = message.get("seq")
    ts = message.get("ts")
    if type(seq) is not int or seq <= 0 or not isinstance(ts, str):
        raise ValueError("close1_offer_record_invalid")

    maker_side = terms["side"]
    taker_side = "sell" if maker_side == "buy" else "buy"
    return VerifiedPublicOffer(
        room=room,
        seq=seq,
        ts=ts,
        maker=maker,
        maker_side=maker_side,
        taker_side=taker_side,
        qty=_amount(terms["qty"], label="qty"),
        px=_amount(terms["px"], label="price"),
        until=terms["until"],
        canonical_terms=canonical,
        taker_signature_preimage=taker_signature_preimage(terms, our_did),
    )


def evaluate_verified_offer_as_taker(
    message: object,
    *,
    current_sweep: int,
    our_did: str,
    reference_price: str,
    room: str = TRADING_ROOM,
    reference_age_seconds: int,
    available_cash: str | None = None,
    current_position: str = "0",
) -> dict:
    """Read-only taker-side risk preflight for one verified public offer."""
    offer = parse_verified_public_offer(
        message,
        current_sweep=current_sweep,
        our_did=our_did,
        room=room,
    )
    if type(reference_age_seconds) is not int or reference_age_seconds < 0:
        raise ValueError("close1_reference_age_invalid")
    if reference_age_seconds > SAFE_MAX_REFERENCE_AGE_SECONDS:
        raise RuntimeError("close1_reference_stale_for_local_strategy")

    ref = _amount(reference_price, label="reference")
    lower = ref * (Decimal("1") - LIMIT_WINDOW)
    upper = ref * (Decimal("1") + LIMIT_WINDOW)
    if offer.px < lower or offer.px > upper:
        raise ValueError("close1_price_outside_limit")

    try:
        held = Decimal(current_position)
    except InvalidOperation as error:
        raise ValueError("close1_position_invalid") from error
    if not held.is_finite():
        raise ValueError("close1_position_invalid")
    side = Decimal("1") if offer.taker_side == "buy" else Decimal("-1")
    closing = min(offer.qty, max(-side * held, Decimal("0")))
    opening = offer.qty - closing
    base_fee = FEE_RATE * offer.qty * offer.px
    required_before_unknown_clawback = opening * offer.px + base_fee

    enough_base_cash = None
    if available_cash is not None:
        cash = _amount(available_cash, label="available_cash")
        enough_base_cash = cash >= required_before_unknown_clawback

    return {
        "offer_seq": offer.seq,
        "maker": offer.maker,
        "maker_side": offer.maker_side,
        "taker_side": offer.taker_side,
        "canonical_terms": offer.canonical_terms,
        "taker_signature_preimage": offer.taker_signature_preimage,
        "reference": str(ref),
        "limit_low": str(lower),
        "limit_high": str(upper),
        "reference_age_seconds": reference_age_seconds,
        "reference_fresh_for_strategy": True,
        "opening_qty": str(opening),
        "base_fee": str(base_fee),
        "required_cash_before_unknown_clawback": str(required_before_unknown_clawback),
        "enough_cash_for_base_fee_and_collateral": enough_base_cash,
        "warning": "offer is negotiation only until countersigned; sweep close is unknown and clawback can exceed the 1% base fee",
    }


def _signed_decimal(value: object, *, label: str) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise ValueError(f"close1_{label}_invalid") from error
    if not parsed.is_finite():
        raise ValueError(f"close1_{label}_invalid")
    return parsed


def estimate_pnl_exposure(
    pnl_room: object,
    *,
    did: str,
    min_mark_move: str = "0.10",
    min_intervals: int = 4,
) -> ExposureEstimate:
    """Infer current exposure from score-vs-mark changes conservatively.

    A stable account with no intervening trade changes score by approximately
    position times mark_change. Rounded public values make tiny moves noisy,
    so this requires a robust median and a consistency gate.
    """
    did = _did(did, label="leader")
    threshold = _amount(min_mark_move, label="min_mark_move")
    if type(min_intervals) is not int or min_intervals < 2:
        raise ValueError("close1_min_intervals_invalid")
    if not isinstance(pnl_room, dict) or not isinstance(pnl_room.get("messages"), list):
        raise ValueError("close1_pnl_room_invalid")

    points: list[tuple[int, Decimal, Decimal]] = []
    for message in pnl_room["messages"]:
        payload = _referee_payload(message, "pnl")
        n = payload.get("n")
        if type(n) is not int:
            raise ValueError("close1_pnl_sweep_invalid")
        mark = _amount(str(payload.get("mark")), label="pnl_mark")
        top = payload.get("top")
        if not isinstance(top, list):
            raise ValueError("close1_pnl_top_invalid")
        score = None
        for row in top:
            if isinstance(row, list) and len(row) == 2 and row[0] == did:
                score = _signed_decimal(row[1], label="pnl_score")
                break
        if score is not None:
            points.append((n, mark, score))

    slopes: list[Decimal] = []
    for previous, current in zip(points, points[1:]):
        prev_n, prev_mark, prev_score = previous
        cur_n, cur_mark, cur_score = current
        if cur_n != prev_n + 1:
            continue
        delta_mark = cur_mark - prev_mark
        if abs(delta_mark) < threshold:
            continue
        slopes.append((cur_score - prev_score) / delta_mark)

    if len(slopes) < min_intervals:
        return ExposureEstimate(
            did=did,
            intervals=len(slopes),
            consistent_intervals=0,
            exposure=None,
            stable=False,
            min_mark_move=threshold,
        )

    ordered = sorted(slopes)
    middle = len(ordered) // 2
    median = ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / Decimal("2")
    tolerance = max(Decimal("1.50"), abs(median) * Decimal("0.08"))
    consistent = sum(1 for slope in slopes if abs(slope - median) <= tolerance)
    required = max(3, (len(slopes) * 3 + 3) // 4)
    stable = consistent >= required

    return ExposureEstimate(
        did=did,
        intervals=len(slopes),
        consistent_intervals=consistent,
        exposure=median if stable else None,
        stable=stable,
        min_mark_move=threshold,
    )


def candidate_score_at_final(
    *,
    side: str,
    qty: str,
    px: str,
    final_price: str,
    fee: str | None = None,
) -> Decimal:
    """Projected score for one fresh opening trade and no later trades."""
    if side not in {"buy", "sell"}:
        raise ValueError("close1_side_invalid")
    q = _amount(qty, label="qty")
    p = _amount(px, label="price")
    final = _amount(final_price, label="final_price")
    paid_fee = FEE_RATE * q * p if fee is None else _amount(fee, label="fee")
    exposure = q if side == "buy" else -q
    return exposure * (final - p) - paid_fee


def dynamic_crossover_with_leader(
    *,
    leader_score: str,
    leader_exposure: str,
    current_mark: str,
    candidate_side: str,
    qty: str,
    px: str,
    fee: str | None = None,
) -> dict:
    """Solve the final price where a fresh candidate ties a current leader."""
    if candidate_side not in {"buy", "sell"}:
        raise ValueError("close1_side_invalid")
    leader = _signed_decimal(leader_score, label="leader_score")
    leader_pos = _signed_decimal(leader_exposure, label="leader_exposure")
    mark = _amount(current_mark, label="current_mark")
    q = _amount(qty, label="qty")
    p = _amount(px, label="price")
    paid_fee = FEE_RATE * q * p if fee is None else _amount(fee, label="fee")
    candidate_pos = q if candidate_side == "buy" else -q
    denominator = candidate_pos - leader_pos
    if denominator == 0:
        raise ValueError("close1_crossover_parallel_exposure")

    crossover = (leader + candidate_pos * p + paid_fee - leader_pos * mark) / denominator
    beats_if = "above" if denominator > 0 else "below"
    return {
        "crossover_final_price": str(crossover),
        "beats_leader_if_final": beats_if,
        "candidate_exposure": str(candidate_pos),
        "leader_exposure": str(leader_pos),
        "base_or_supplied_fee": str(paid_fee),
        "warning": "projection assumes fixed leader exposure/no later trades and does not know sweep-close clawback",
    }

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
