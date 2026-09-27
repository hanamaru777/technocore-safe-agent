"""Read-only live Close Call candidate scanner.

Combines official referee PnL/price history with verified public negotiation
offers. It never signs, posts, accepts, or mutates contest state.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal

from . import close1_strategy, close_call, core, public_record


@dataclass(frozen=True)
class LeaderView:
    did: str
    score: Decimal
    position: Decimal | None
    stable: bool
    reason: str


@dataclass(frozen=True)
class CandidateView:
    room: str
    seq: int
    trade_id: str
    taker_side: str
    qty: Decimal
    px: Decimal
    until: int
    base_fee: Decimal
    required_cash: Decimal
    dynamic_top3_price: Decimal | None
    dynamic_condition: str | None
    move_percent_from_mark: Decimal | None
    visible_leader_coverage: int
    visible_leaders: int
    warning: str
    flat_target_score: Decimal | None = None
    base_fee_flat_exit_price: Decimal | None = None
    base_fee_flat_move_percent: Decimal | None = None


@dataclass(frozen=True)
class BasketLegView:
    room: str
    seq: int
    trade_id: str
    qty: Decimal
    px: Decimal
    until: int
    base_fee: Decimal
    required_cash: Decimal


@dataclass(frozen=True)
class BasketCandidateView:
    taker_side: str
    legs: tuple[BasketLegView, ...]
    qty: Decimal
    weighted_px: Decimal
    until: int
    base_fee: Decimal
    required_cash: Decimal
    dynamic_top3_price: Decimal | None
    dynamic_condition: str | None
    move_percent_from_mark: Decimal | None
    visible_leader_coverage: int
    visible_leaders: int
    warning: str
    flat_target_score: Decimal | None = None
    base_fee_flat_exit_price: Decimal | None = None
    base_fee_flat_move_percent: Decimal | None = None


@dataclass(frozen=True)
class CandidateScan:
    sweep: int
    reference: Decimal
    reference_age_seconds: int
    mark: Decimal
    top3_cutoff: Decimal | None
    visible_leaders: tuple[LeaderView, ...]
    verified_offers: int
    sampled_trade_ids: int
    rejected_offers: int
    candidates: tuple[CandidateView, ...]
    strategy_gate: str
    baskets: tuple[BasketCandidateView, ...] = ()


def _signed_decimal(value: object, *, label: str) -> Decimal:
    return close1_strategy._signed_decimal(value, label=label)


def _pnl_snapshots(pnl_room: object) -> list[dict]:
    if not isinstance(pnl_room, dict) or not isinstance(pnl_room.get("messages"), list):
        raise ValueError("close1_scanner_pnl_room_invalid")
    snapshots = []
    for message in pnl_room["messages"]:
        public_record.verify_signed_record("d-close1-pnl", message)
        snapshots.append(close_call._referee_payload(message, "pnl"))
    if not snapshots:
        raise ValueError("close1_scanner_pnl_room_empty")
    return snapshots


def _latest_price(price_room: object) -> dict:
    if not isinstance(price_room, dict) or not isinstance(price_room.get("messages"), list):
        raise ValueError("close1_scanner_price_room_invalid")
    if not price_room["messages"]:
        raise ValueError("close1_scanner_price_room_empty")
    message = price_room["messages"][-1]
    public_record.verify_signed_record("d-close1-price", message)
    return close_call._referee_payload(message, "price")


def _project_candidate_score(*, side: str, qty: Decimal, px: Decimal, fee: Decimal, final: Decimal) -> Decimal:
    return close1_strategy.single_position_score(
        side=side,
        qty=qty,
        px=px,
        fee=fee,
        final_price=final,
    )


def _score_for_did(snapshot: dict, did: str) -> Decimal | None:
    top = snapshot.get("top")
    if not isinstance(top, list):
        raise ValueError("close1_scanner_pnl_top_invalid")
    for row in top:
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError("close1_scanner_pnl_top_invalid")
        if row[0] == did:
            return _signed_decimal(row[1], label="leader_score")
    return None


def _leader_universe(
    *,
    snapshots: list[dict],
    current_mark: Decimal,
) -> list[LeaderView]:
    """Current top rows plus stable historically-visible shadow leaders.

    A DID that fell out of the latest top list can still become a future top3
    competitor after a price reversal.  When its score/mark slope is stable,
    project its most recent observed score to the current mark and keep it in
    the conservative competitor envelope.
    """
    if not snapshots:
        raise ValueError("close1_scanner_pnl_room_empty")
    latest = snapshots[-1]
    latest_top = latest.get("top")
    if not isinstance(latest_top, list):
        raise ValueError("close1_scanner_pnl_top_invalid")

    current_order: list[str] = []
    current_scores: dict[str, Decimal] = {}
    for row in latest_top:
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError("close1_scanner_pnl_top_invalid")
        did = close_call._did(row[0], label="leader")
        if did in current_scores:
            raise ValueError("close1_scanner_duplicate_leader")
        current_order.append(did)
        current_scores[did] = _signed_decimal(row[1], label="leader_score")

    historical_order: list[str] = []
    historical_seen: set[str] = set(current_order)
    for snapshot in reversed(snapshots[:-1]):
        top = snapshot.get("top")
        if not isinstance(top, list):
            raise ValueError("close1_scanner_pnl_top_invalid")
        for row in top:
            if not isinstance(row, list) or len(row) != 2:
                raise ValueError("close1_scanner_pnl_top_invalid")
            did = close_call._did(row[0], label="leader")
            if did not in historical_seen:
                historical_seen.add(did)
                historical_order.append(did)

    leaders: list[LeaderView] = []
    for did in current_order:
        estimate = close1_strategy.infer_exposure(did, snapshots)
        leaders.append(LeaderView(
            did=did,
            score=current_scores[did],
            position=estimate.position,
            stable=estimate.stable,
            reason=estimate.reason,
        ))

    for did in historical_order:
        estimate = close1_strategy.infer_exposure(did, snapshots)
        if not estimate.stable or estimate.position is None:
            continue
        latest_observation: tuple[Decimal, Decimal] | None = None
        for snapshot in reversed(snapshots[:-1]):
            score = _score_for_did(snapshot, did)
            if score is None:
                continue
            mark = close_call._amount(str(snapshot.get("mark")), label="pnl_mark")
            latest_observation = (mark, score)
            break
        if latest_observation is None:
            continue
        observed_mark, observed_score = latest_observation
        projected_score = close1_strategy.project_score(
            current_score=observed_score,
            current_mark=observed_mark,
            position=estimate.position,
            final_price=current_mark,
        )
        leaders.append(LeaderView(
            did=did,
            score=projected_score,
            position=estimate.position,
            stable=True,
            reason="stable_shadow_leader",
        ))
    return leaders


def _visible_top3_at_price(
    *,
    final: Decimal,
    current_mark: Decimal,
    leaders: list[LeaderView],
) -> Decimal:
    scores = [
        close1_strategy.project_score(
            current_score=leader.score,
            current_mark=current_mark,
            position=leader.position,
            final_price=final,
        )
        for leader in leaders
        if leader.stable and leader.position is not None
    ]
    if len(scores) < 3:
        raise ValueError("close1_scanner_insufficient_stable_leaders")
    # Conservative floor: registered accounts that never trade score exactly 0.
    # Keep three synthetic zero-score competitors so a rebound that makes all
    # visible leaders negative never creates a false "top3 with a loss" signal.
    scores.extend((Decimal("0"), Decimal("0"), Decimal("0")))
    scores.sort(reverse=True)
    return scores[2]


def _nearest_dynamic_top3(
    *,
    side: str,
    qty: Decimal,
    px: Decimal,
    fee: Decimal,
    current_mark: Decimal,
    leaders: list[LeaderView],
) -> tuple[Decimal, str, Decimal] | None:
    """Nearest positive final price where candidate reaches visible projected top3."""
    stable = [leader for leader in leaders if leader.stable and leader.position is not None]
    if len(stable) != len(leaders) or len(stable) < 3:
        return None

    def qualifies(price: Decimal) -> bool:
        ours = _project_candidate_score(side=side, qty=qty, px=px, fee=fee, final=price)
        hurdle = _visible_top3_at_price(final=price, current_mark=current_mark, leaders=stable)
        return ours >= hurdle

    if qualifies(current_mark):
        return current_mark, "at", Decimal("0")

    crossings: set[Decimal] = set()
    candidate_position = qty if side == "buy" else -qty
    zero_crossing = px + fee / candidate_position
    if zero_crossing > 0:
        crossings.add(zero_crossing)

    for leader in stable:
        try:
            cross = close1_strategy.crossover_vs_competitor(
                side=side,
                qty=qty,
                px=px,
                current_mark=current_mark,
                competitor_score=leader.score,
                competitor_position=leader.position,
                fee=fee,
            )
        except ValueError:
            continue
        if cross.price > 0:
            crossings.add(cross.price)

    qualifying = [price for price in crossings if qualifies(price)]
    if not qualifying:
        return None
    price = min(qualifying, key=lambda value: abs(value - current_mark))
    condition = "above" if price > current_mark else "below"
    return price, condition, (price - current_mark) / current_mark


def _flat_target_plan(
    *,
    side: str,
    qty: Decimal,
    entry_px: Decimal,
    entry_fee: Decimal,
    target_score: Decimal,
) -> tuple[Decimal, Decimal] | None:
    try:
        exit_px = close1_strategy.base_fee_roundtrip_exit_price(
            side=side,
            qty=qty,
            entry_px=entry_px,
            entry_fee=entry_fee,
            target_score=target_score,
        )
    except ValueError:
        return None
    return exit_px, (exit_px - entry_px) / entry_px


def _build_same_side_basket(
    *,
    side: str,
    candidates: list[CandidateView],
    available_cash: Decimal,
    current_mark: Decimal,
    leaders: list[LeaderView],
    flat_target_score: Decimal,
) -> BasketCandidateView | None:
    """Build one conservative full-offer basket for a single taker side.

    This is deliberately not an execution plan.  It greedily takes distinct
    verified offers in best-price order while staying within the current cash
    budget.  Individual offer acceptance still requires separate exact approval.
    """
    if side not in {"buy", "sell"}:
        raise ValueError("close1_scanner_basket_side_invalid")
    if available_cash <= 0:
        raise ValueError("close1_scanner_basket_cash_invalid")

    rows = [candidate for candidate in candidates if candidate.taker_side == side]
    rows.sort(key=lambda candidate: (
        candidate.px if side == "buy" else -candidate.px,
        -candidate.qty,
        candidate.until,
        candidate.seq,
        candidate.trade_id,
    ))

    chosen: list[CandidateView] = []
    seen_ids: set[str] = set()
    required_cash = Decimal("0")
    for candidate in rows:
        if candidate.trade_id in seen_ids:
            continue
        next_cash = required_cash + candidate.required_cash
        if next_cash > available_cash:
            continue
        chosen.append(candidate)
        seen_ids.add(candidate.trade_id)
        required_cash = next_cash

    if len(chosen) < 2:
        return None

    qty = sum((candidate.qty for candidate in chosen), Decimal("0"))
    if qty <= 0:
        return None
    notional = sum((candidate.qty * candidate.px for candidate in chosen), Decimal("0"))
    weighted_px = notional / qty
    base_fee = sum((candidate.base_fee for candidate in chosen), Decimal("0"))
    until = min(candidate.until for candidate in chosen)
    stable_count = sum(1 for leader in leaders if leader.stable and leader.position is not None)
    dynamic = _nearest_dynamic_top3(
        side=side,
        qty=qty,
        px=weighted_px,
        fee=base_fee,
        current_mark=current_mark,
        leaders=leaders,
    )
    if dynamic is None:
        dynamic_top3_price = None
        condition = None
        move = None
    else:
        dynamic_top3_price, condition, move = dynamic

    legs = tuple(BasketLegView(
        room=candidate.room,
        seq=candidate.seq,
        trade_id=candidate.trade_id,
        qty=candidate.qty,
        px=candidate.px,
        until=candidate.until,
        base_fee=candidate.base_fee,
        required_cash=candidate.required_cash,
    ) for candidate in chosen)
    flat_plan = _flat_target_plan(
        side=side,
        qty=qty,
        entry_px=weighted_px,
        entry_fee=base_fee,
        target_score=flat_target_score,
    )
    if flat_plan is None:
        flat_exit = None
        flat_move = None
    else:
        flat_exit, flat_move = flat_plan

    return BasketCandidateView(
        taker_side=side,
        legs=legs,
        qty=qty,
        weighted_px=weighted_px,
        until=until,
        base_fee=base_fee,
        required_cash=required_cash,
        dynamic_top3_price=dynamic_top3_price,
        dynamic_condition=condition,
        move_percent_from_mark=move,
        visible_leader_coverage=stable_count,
        visible_leaders=len(leaders),
        warning=(
            "heuristic full-offer basket in best-price order; every leg remains a separate "
            "binding trade, all legs must still be live at execution time, and favorable-price "
            "clawback plus leader/future trades can worsen the projected outcome"
        ),
        flat_target_score=flat_target_score,
        base_fee_flat_exit_price=flat_exit,
        base_fee_flat_move_percent=flat_move,
    )


def _verified_trade_id(room: str, message: object) -> str | None:
    """Return a trade id only after outer, maker and taker signatures verify."""
    if not isinstance(message, dict):
        return None
    try:
        public_record.verify_signed_record(room, message)
    except ValueError:
        return None
    payload = _message_payload(message)
    if (
        not isinstance(payload, dict)
        or set(payload) != {"t", "season", "terms", "taker", "maker_sig", "taker_sig"}
        or payload.get("t") != "trade"
        or payload.get("season") != close_call.CONTEST_ID
    ):
        return None
    terms = payload.get("terms")
    try:
        canonical = close_call.canonical_terms(terms)
        maker = terms["maker"]
        taker = close_call._did(payload.get("taker"), label="taker")
        if maker == taker:
            return None
        named = terms["taker"]
        if named != "any" and named != taker:
            return None
        public_record.verify_did_signature(
            maker,
            payload.get("maker_sig"),
            close_call.maker_signature_preimage(terms),
        )
        public_record.verify_did_signature(
            taker,
            payload.get("taker_sig"),
            close_call.taker_signature_preimage(terms, taker),
        )
    except (KeyError, TypeError, ValueError):
        return None
    if message.get("from") not in {maker, taker}:
        return None
    trade_id = terms.get("id")
    if not isinstance(trade_id, str):
        return None
    if canonical != close_call.canonical_terms(terms):
        return None
    return trade_id


def _message_payload(message: object) -> dict | None:
    if not isinstance(message, dict):
        return None
    text = message.get("text")
    if not isinstance(text, str):
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def build_candidate_scan(
    *,
    our_did: str,
    price_room: object,
    pnl_room: object,
    negotiation_rooms: dict[str, object],
    available_cash: str = "10000",
    current_position: str = "0",
) -> CandidateScan:
    """Build one read-only candidate report from already fetched public data."""
    our_did = close_call._did(our_did)
    price = _latest_price(price_room)
    snapshots = _pnl_snapshots(pnl_room)
    pnl = snapshots[-1]
    if price.get("n") != pnl.get("n"):
        raise ValueError("close1_scanner_sweep_mismatch")

    sweep = price["n"]
    age = price.get("age_s")
    if type(age) is not int or age < 0:
        raise ValueError("close1_scanner_reference_age_invalid")
    ref = price.get("ref")
    if not isinstance(ref, dict):
        raise ValueError("close1_scanner_reference_invalid")
    reference = close_call._amount(ref.get("px"), label="reference")
    mark = close_call._amount(str(pnl.get("mark")), label="pnl_mark")

    top = pnl.get("top")
    if not isinstance(top, list):
        raise ValueError("close1_scanner_pnl_top_invalid")
    current_scores = []
    for row in top:
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError("close1_scanner_pnl_top_invalid")
        current_scores.append(_signed_decimal(row[1], label="leader_score"))
    top3_cutoff = current_scores[2] if len(current_scores) >= 3 else None
    flat_target_score = max(
        Decimal("100"),
        (top3_cutoff + Decimal("25")) if top3_cutoff is not None else Decimal("100"),
    )
    leaders = _leader_universe(snapshots=snapshots, current_mark=mark)
    seen_trade_ids: set[str] = set()
    offer_records: list[tuple[str, dict]] = []
    rejected = 0

    for room, payload in negotiation_rooms.items():
        if not isinstance(room, str) or not isinstance(payload, dict) or not isinstance(payload.get("messages"), list):
            raise ValueError("close1_scanner_negotiation_room_invalid")
        for message in payload["messages"]:
            parsed = _message_payload(message)
            if parsed is None:
                continue
            kind = parsed.get("t")
            if kind == "trade":
                trade_id = _verified_trade_id(room, message)
                if trade_id is not None:
                    seen_trade_ids.add(trade_id)
            elif kind == "offer":
                offer_records.append((room, message))

    verified = []
    for room, message in offer_records:
        try:
            offer = close_call.parse_verified_public_offer(
                message,
                current_sweep=sweep,
                our_did=our_did,
                room=room,
            )
        except ValueError:
            rejected += 1
            continue
        terms = json.loads(offer.canonical_terms)
        if terms["id"] in seen_trade_ids:
            continue
        verified.append((room, message, offer, terms["id"]))

    if age > close_call.SAFE_MAX_REFERENCE_AGE_SECONDS:
        return CandidateScan(
            sweep=sweep,
            reference=reference,
            reference_age_seconds=age,
            mark=mark,
            top3_cutoff=top3_cutoff,
            visible_leaders=tuple(leaders),
            verified_offers=len(verified),
            sampled_trade_ids=len(seen_trade_ids),
            rejected_offers=rejected,
            candidates=(),
            strategy_gate="reference_stale",
        )

    candidate_rows: list[CandidateView] = []
    stable_count = sum(1 for leader in leaders if leader.stable and leader.position is not None)
    for room, message, offer, trade_id in verified:
        try:
            plan = close_call.evaluate_verified_offer_as_taker(
                message,
                current_sweep=sweep,
                our_did=our_did,
                reference_price=str(reference),
                reference_age_seconds=age,
                room=room,
                available_cash=available_cash,
                current_position=current_position,
            )
        except (ValueError, RuntimeError):
            rejected += 1
            continue
        if plan["enough_cash_for_base_fee_and_collateral"] is not True:
            continue
        fee = Decimal(plan["base_fee"])
        required_cash = Decimal(plan["required_cash_before_unknown_clawback"])
        dynamic = _nearest_dynamic_top3(
            side=offer.taker_side,
            qty=offer.qty,
            px=offer.px,
            fee=fee,
            current_mark=mark,
            leaders=leaders,
        )
        if dynamic is None:
            price_value = None
            condition = None
            move = None
        else:
            price_value, condition, move = dynamic
        flat_plan = _flat_target_plan(
            side=offer.taker_side,
            qty=offer.qty,
            entry_px=offer.px,
            entry_fee=fee,
            target_score=flat_target_score,
        )
        if flat_plan is None:
            flat_exit = None
            flat_move = None
        else:
            flat_exit, flat_move = flat_plan
        candidate_rows.append(CandidateView(
            room=room,
            seq=offer.seq,
            trade_id=trade_id,
            taker_side=offer.taker_side,
            qty=offer.qty,
            px=offer.px,
            until=offer.until,
            base_fee=fee,
            required_cash=required_cash,
            dynamic_top3_price=price_value,
            dynamic_condition=condition,
            move_percent_from_mark=move,
            visible_leader_coverage=stable_count,
            visible_leaders=len(leaders),
            warning=(
                "recent-history leader envelope with conservative zero-score floor; leader/future "
                "trades, accounts never visible in sampled history and sweep-close clawback can "
                "change the actual top3 outcome"
            ),
            flat_target_score=flat_target_score,
            base_fee_flat_exit_price=flat_exit,
            base_fee_flat_move_percent=flat_move,
        ))

    candidate_rows.sort(key=lambda item: (
        item.dynamic_top3_price is None,
        abs(item.move_percent_from_mark) if item.move_percent_from_mark is not None else Decimal("999"),
        -item.qty,
        item.seq,
    ))

    basket_rows: list[BasketCandidateView] = []
    parsed_position = _signed_decimal(current_position, label="current_position")
    if parsed_position == 0:
        cash_budget = close_call._amount(available_cash, label="available_cash")
        for side in ("buy", "sell"):
            basket = _build_same_side_basket(
                side=side,
                candidates=candidate_rows,
                available_cash=cash_budget,
                current_mark=mark,
                leaders=leaders,
                flat_target_score=flat_target_score,
            )
            if basket is not None:
                basket_rows.append(basket)
    basket_rows.sort(key=lambda item: (
        item.dynamic_top3_price is None,
        abs(item.move_percent_from_mark) if item.move_percent_from_mark is not None else Decimal("999"),
        -item.qty,
        item.until,
    ))

    return CandidateScan(
        sweep=sweep,
        reference=reference,
        reference_age_seconds=age,
        mark=mark,
        top3_cutoff=top3_cutoff,
        visible_leaders=tuple(leaders),
        verified_offers=len(verified),
        sampled_trade_ids=len(seen_trade_ids),
        rejected_offers=rejected,
        candidates=tuple(candidate_rows),
        strategy_gate="ready" if stable_count == len(leaders) and len(leaders) >= 3 else "leader_coverage_incomplete",
        baskets=tuple(basket_rows),
    )


def fetch_candidate_scan(
    *,
    our_did: str,
    available_cash: str = "10000",
    current_position: str = "0",
) -> CandidateScan:
    """Read public rooms only; no signing, posting, or contest mutation."""
    return build_candidate_scan(
        our_did=our_did,
        price_room=core.read_room("d-close1-price", limit=2),
        pnl_room=core.read_room("d-close1-pnl", limit=36),
        negotiation_rooms={
            "close1": core.read_room("close1", limit=200),
            "close1-offers": core.read_room("close1-offers", limit=200),
        },
        available_cash=available_cash,
        current_position=current_position,
    )
