"""Read-only two-stage Close Call victory planning.

The planner starts from a verified scanner candidate, hypothetically closes
that position, then models one new maximum-affordable position.  It never
fetches, signs, posts, accepts, or mutates contest state.  All results use only
the 1% base fee; favorable-price clawback remains unknown.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR

from . import close1_candidate_scanner, close1_strategy, close_call

PRICE_STEP = Decimal("0.01")
QUANTITY_STEP = Decimal("0.01")
VICTORY_MARGIN = Decimal("25")
VICTORY_FLOOR = Decimal("100")
DEFAULT_HORIZON_MULTIPLIER = Decimal("2")
ROUNDING_TOLERANCE = Decimal("1e-18")
BASE_FEE_WARNING = (
    "base-fee-only lower-bound planning; favorable-price clawback is unknown, "
    "leader/future trades and hidden accounts can worsen or invalidate the path; "
    "not executable before authoritative own-account reconciliation (#629)"
)


@dataclass(frozen=True)
class StageOneRealization:
    side: str
    qty: Decimal
    entry_price: Decimal
    close_price: Decimal
    move_from_entry: Decimal
    move_from_current_mark: Decimal
    realised_score: Decimal
    entry_fee: Decimal
    exit_fee: Decimal
    post_close_cash: Decimal


@dataclass(frozen=True)
class TwoStageVictoryPlan:
    status: str
    reason: str
    stage1_side: str | None
    stage1_qty: Decimal | None
    stage1_entry_price: Decimal | None
    stage1_close_price: Decimal | None
    stage1_move_from_entry: Decimal | None
    stage1_move_from_current_mark: Decimal | None
    stage1_realised_score: Decimal | None
    stage1_entry_fee: Decimal | None
    stage1_exit_fee: Decimal | None
    post_close_cash: Decimal | None
    stage2_side: str | None
    stage2_entry_price: Decimal | None
    stage2_max_affordable_qty: Decimal | None
    stage2_entry_fee: Decimal | None
    stage2_required_cash: Decimal | None
    stage2_projected_score: Decimal | None
    dynamic_victory_price: Decimal | None
    dynamic_victory_condition: str | None
    stage2_move_required: Decimal | None
    stage2_move_percent: Decimal | None
    total_path_move: Decimal | None
    total_path_move_percent: Decimal | None
    leader_coverage: int
    leader_universe: int
    planning_price_floor: Decimal
    planning_price_ceiling: Decimal
    favorable_price_clawback: None
    clawback_risk: str
    warning: str


def _decimal(value: object, *, label: str, allow_zero: bool = False) -> Decimal:
    return close1_strategy._decimal(value, label=f"two_stage_{label}", allow_zero=allow_zero)


def _floor_step(value: Decimal, step: Decimal) -> Decimal:
    return (value / step).to_integral_value(rounding=ROUND_FLOOR) * step


def _ceil_step(value: Decimal, step: Decimal) -> Decimal:
    return (value / step).to_integral_value(rounding=ROUND_CEILING) * step


def _candidate_terms(
    candidate: close1_candidate_scanner.CandidateView
    | close1_candidate_scanner.BasketCandidateView,
) -> tuple[str, Decimal, Decimal, Decimal]:
    if isinstance(candidate, close1_candidate_scanner.CandidateView):
        return candidate.taker_side, candidate.qty, candidate.px, candidate.base_fee
    if isinstance(candidate, close1_candidate_scanner.BasketCandidateView):
        return (
            candidate.taker_side,
            candidate.qty,
            candidate.weighted_px,
            candidate.base_fee,
        )
    raise TypeError("close1_two_stage_verified_candidate_required")


def realize_stage_one(
    candidate: close1_candidate_scanner.CandidateView
    | close1_candidate_scanner.BasketCandidateView,
    *,
    close_price: object,
    current_mark: object,
    starting_cash: object = close_call.MINT,
) -> StageOneRealization:
    """Close a verified candidate hypothetically using base fees only."""
    side, qty, entry, entry_fee = _candidate_terms(candidate)
    close = _decimal(close_price, label="close_price")
    mark = _decimal(current_mark, label="current_mark")
    cash = _decimal(starting_cash, label="starting_cash", allow_zero=True)
    exit_fee = close1_strategy.base_fee(qty=qty, px=close)
    position = qty if side == "buy" else -qty
    realised = position * (close - entry) - entry_fee - exit_fee
    return StageOneRealization(
        side=side,
        qty=qty,
        entry_price=entry,
        close_price=close,
        move_from_entry=close - entry,
        move_from_current_mark=close - mark,
        realised_score=realised,
        entry_fee=entry_fee,
        exit_fee=exit_fee,
        post_close_cash=cash + realised,
    )


def maximum_affordable_quantity(*, cash: object, entry_price: object) -> Decimal:
    """Maximum opening quantity affordable with collateral plus entry base fee."""
    available = _decimal(cash, label="cash", allow_zero=True)
    entry = _decimal(entry_price, label="stage2_entry_price")
    per_unit = entry * (Decimal("1") + close_call.FEE_RATE)
    quantity = _floor_step(available / per_unit, QUANTITY_STEP)
    return quantity if quantity >= close_call.MIN_QTY else Decimal("0")


def _leader_coverage(
    leaders: list[close1_candidate_scanner.LeaderView],
) -> tuple[list[close1_candidate_scanner.LeaderView], bool]:
    stable = [leader for leader in leaders if leader.stable and leader.position is not None]
    return stable, len(stable) == len(leaders) and len(stable) >= 3


def _victory_hurdle(
    *,
    final_price: Decimal,
    current_mark: Decimal,
    leaders: list[close1_candidate_scanner.LeaderView],
) -> Decimal:
    projected = [
        close1_strategy.project_score(
            current_score=leader.score,
            current_mark=current_mark,
            position=leader.position,
            final_price=final_price,
        ) + VICTORY_MARGIN
        for leader in leaders
    ]
    return max([VICTORY_FLOOR, *projected])


def _stage2_score(
    *,
    realised_score: Decimal,
    side: str,
    qty: Decimal,
    entry_price: Decimal,
    entry_fee: Decimal,
    final_price: Decimal,
) -> Decimal:
    position = qty if side == "buy" else -qty
    return realised_score + position * (final_price - entry_price) - entry_fee


def _nearest_stage2_victory(
    *,
    realised_score: Decimal,
    side: str,
    qty: Decimal,
    entry_price: Decimal,
    entry_fee: Decimal,
    current_mark: Decimal,
    leaders: list[close1_candidate_scanner.LeaderView],
    price_floor: Decimal,
    price_ceiling: Decimal,
) -> tuple[Decimal, str, Decimal, Decimal] | None:
    """Intersect exact linear victory inequalities, then validate the nearest tick."""
    stable, complete = _leader_coverage(leaders)
    if not complete or side not in {"buy", "sell"} or qty <= 0:
        return None
    position = qty if side == "buy" else -qty
    constant = realised_score - position * entry_price - entry_fee

    def score(price: Decimal) -> Decimal:
        return constant + position * price

    def qualifies(price: Decimal) -> bool:
        ours = score(price)
        hurdle = _victory_hurdle(
            final_price=price,
            current_mark=current_mark,
            leaders=stable,
        )
        return ours >= hurdle or hurdle - ours <= ROUNDING_TOLERANCE

    lower = price_floor
    upper = price_ceiling

    def tighten(denominator: Decimal, rhs: Decimal) -> bool:
        nonlocal lower, upper
        if denominator > 0:
            lower = max(lower, rhs / denominator)
        elif denominator < 0:
            upper = min(upper, rhs / denominator)
        elif rhs > ROUNDING_TOLERANCE:
            return False
        return lower <= upper + ROUNDING_TOLERANCE

    if not tighten(position, VICTORY_FLOOR - constant):
        return None

    for leader in stable:
        rhs = (
            leader.score
            + VICTORY_MARGIN
            - leader.position * current_mark
            - constant
        )
        if not tighten(position - leader.position, rhs):
            return None

    first_tick = _ceil_step(max(lower, price_floor), PRICE_STEP)
    last_tick = _floor_step(min(upper, price_ceiling), PRICE_STEP)
    if first_tick > last_tick:
        return None

    entry_floor = _floor_step(entry_price, PRICE_STEP)
    entry_ceil = _ceil_step(entry_price, PRICE_STEP)
    candidates = {
        first_tick,
        last_tick,
        entry_floor,
        entry_ceil,
        entry_floor - PRICE_STEP,
        entry_ceil + PRICE_STEP,
    }
    valid = [
        price
        for price in candidates
        if first_tick <= price <= last_tick and price > 0 and qualifies(price)
    ]
    if not valid:
        return None
    final = min(valid, key=lambda price: (abs(price - entry_price), price))
    condition = "at" if final == entry_price else ("above" if final > entry_price else "below")
    return final, condition, final - entry_price, score(final)

def _no_path(
    *,
    reason: str,
    coverage: int,
    universe: int,
    price_floor: Decimal,
    price_ceiling: Decimal,
) -> TwoStageVictoryPlan:
    return TwoStageVictoryPlan(
        status="NO_PATH",
        reason=reason,
        stage1_side=None,
        stage1_qty=None,
        stage1_entry_price=None,
        stage1_close_price=None,
        stage1_move_from_entry=None,
        stage1_move_from_current_mark=None,
        stage1_realised_score=None,
        stage1_entry_fee=None,
        stage1_exit_fee=None,
        post_close_cash=None,
        stage2_side=None,
        stage2_entry_price=None,
        stage2_max_affordable_qty=None,
        stage2_entry_fee=None,
        stage2_required_cash=None,
        stage2_projected_score=None,
        dynamic_victory_price=None,
        dynamic_victory_condition=None,
        stage2_move_required=None,
        stage2_move_percent=None,
        total_path_move=None,
        total_path_move_percent=None,
        leader_coverage=coverage,
        leader_universe=universe,
        planning_price_floor=price_floor,
        planning_price_ceiling=price_ceiling,
        favorable_price_clawback=None,
        clawback_risk="unknown favorable-price clawback; no executable amount is claimed",
        warning=BASE_FEE_WARNING,
    )


def plan_two_stage_victory(
    candidate: close1_candidate_scanner.CandidateView
    | close1_candidate_scanner.BasketCandidateView,
    *,
    current_mark: object,
    leaders: list[close1_candidate_scanner.LeaderView],
    starting_cash: object = close_call.MINT,
    horizon_multiplier: object = DEFAULT_HORIZON_MULTIPLIER,
) -> TwoStageVictoryPlan:
    """Find the minimum stage-1 tick with a valid two-stage victory path.

    The exhaustive stage-1 search is price-step aware, not a sparse grid.  Its
    explicit supported horizon is 0.01 through ``current_mark *
    horizon_multiplier`` (2x by default).  Outside that bounded planning range
    the function returns NO_PATH rather than extrapolating.
    """
    mark = _decimal(current_mark, label="current_mark")
    cash = _decimal(starting_cash, label="starting_cash", allow_zero=True)
    multiplier = _decimal(horizon_multiplier, label="horizon_multiplier")
    if multiplier < Decimal("1"):
        raise ValueError("close1_strategy_two_stage_horizon_multiplier_invalid")
    price_floor = PRICE_STEP
    price_ceiling = _floor_step(mark * multiplier, PRICE_STEP)
    stable, complete = _leader_coverage(leaders)
    if not complete:
        return _no_path(
            reason="leader_coverage_incomplete",
            coverage=len(stable),
            universe=len(leaders),
            price_floor=price_floor,
            price_ceiling=price_ceiling,
        )

    stage1_side, _, _, _ = _candidate_terms(candidate)
    if stage1_side == "buy":
        first = _ceil_step(mark, PRICE_STEP)
        last = price_ceiling
        increment = PRICE_STEP
    else:
        first = _floor_step(mark, PRICE_STEP)
        last = price_floor
        increment = -PRICE_STEP

    close_price = first
    while (increment > 0 and close_price <= last) or (increment < 0 and close_price >= last):
        stage1 = realize_stage_one(
            candidate,
            close_price=close_price,
            current_mark=mark,
            starting_cash=cash,
        )
        if stage1.post_close_cash > 0:
            quantity = maximum_affordable_quantity(
                cash=stage1.post_close_cash,
                entry_price=close_price,
            )
            if quantity > 0:
                stage2_fee = close1_strategy.base_fee(qty=quantity, px=close_price)
                required_cash = quantity * close_price + stage2_fee
                options = []
                for stage2_side in ("buy", "sell"):
                    victory = _nearest_stage2_victory(
                        realised_score=stage1.realised_score,
                        side=stage2_side,
                        qty=quantity,
                        entry_price=close_price,
                        entry_fee=stage2_fee,
                        current_mark=mark,
                        leaders=stable,
                        price_floor=price_floor,
                        price_ceiling=price_ceiling,
                    )
                    if victory is not None:
                        options.append((stage2_side, victory))
                if options:
                    stage2_side, victory = min(
                        options,
                        key=lambda item: (abs(item[1][2]), item[0]),
                    )
                    final, condition, stage2_move, final_score = victory
                    total_move = abs(stage1.move_from_current_mark) + abs(stage2_move)
                    total_move_percent = (
                        abs(stage1.move_from_current_mark) / mark
                        + abs(stage2_move) / close_price
                    )
                    return TwoStageVictoryPlan(
                        status="PATH",
                        reason="dynamic_victory_path",
                        stage1_side=stage1.side,
                        stage1_qty=stage1.qty,
                        stage1_entry_price=stage1.entry_price,
                        stage1_close_price=stage1.close_price,
                        stage1_move_from_entry=stage1.move_from_entry,
                        stage1_move_from_current_mark=stage1.move_from_current_mark,
                        stage1_realised_score=stage1.realised_score,
                        stage1_entry_fee=stage1.entry_fee,
                        stage1_exit_fee=stage1.exit_fee,
                        post_close_cash=stage1.post_close_cash,
                        stage2_side=stage2_side,
                        stage2_entry_price=close_price,
                        stage2_max_affordable_qty=quantity,
                        stage2_entry_fee=stage2_fee,
                        stage2_required_cash=required_cash,
                        stage2_projected_score=final_score,
                        dynamic_victory_price=final,
                        dynamic_victory_condition=condition,
                        stage2_move_required=stage2_move,
                        stage2_move_percent=stage2_move / close_price,
                        total_path_move=total_move,
                        total_path_move_percent=total_move_percent,
                        leader_coverage=len(stable),
                        leader_universe=len(leaders),
                        planning_price_floor=price_floor,
                        planning_price_ceiling=price_ceiling,
                        favorable_price_clawback=None,
                        clawback_risk=(
                            "unknown favorable-price clawback is excluded from all numeric fields"
                        ),
                        warning=BASE_FEE_WARNING,
                    )
        close_price += increment

    return _no_path(
        reason="no_supported_two_stage_victory_path",
        coverage=len(stable),
        universe=len(leaders),
        price_floor=price_floor,
        price_ceiling=price_ceiling,
    )
