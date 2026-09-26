"""Pure, read-only Close Call strategy math.

This module estimates current leaderboard exposure from official PnL history
and compares a hypothetical single new position with one competitor. It never
fetches, signs, posts, or mutates contest state.

Exposure estimates are deliberately provisional: a score-vs-mark slope can be
used as a position estimate only while the account is not materially changing
its own trades or fees between the compared snapshots.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from statistics import median

from . import close_call

MIN_MEANINGFUL_MARK_DELTA = Decimal("0.10")
MIN_EXPOSURE_SLOPES = 4
MAX_STABLE_EXPOSURE_SPREAD = Decimal("2.50")


@dataclass(frozen=True)
class ExposureEstimate:
    did: str
    position: Decimal | None
    slopes: tuple[Decimal, ...]
    observations: int
    spread: Decimal | None
    stable: bool
    reason: str


@dataclass(frozen=True)
class Crossover:
    price: Decimal
    condition: str
    move_from_current: Decimal
    move_percent_from_current: Decimal
    our_signed_position: Decimal
    competitor_position: Decimal
    fee: Decimal
    warning: str


def _decimal(value: object, *, label: str, allow_zero: bool = False) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise ValueError(f"close1_strategy_{label}_invalid") from error
    if not parsed.is_finite() or parsed < 0 or (parsed == 0 and not allow_zero):
        raise ValueError(f"close1_strategy_{label}_invalid")
    return parsed


def _score_by_did(snapshot: object, did: str) -> Decimal | None:
    if not isinstance(snapshot, dict):
        raise ValueError("close1_strategy_snapshot_invalid")
    top = snapshot.get("top")
    if not isinstance(top, list):
        raise ValueError("close1_strategy_snapshot_invalid")
    for row in top:
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError("close1_strategy_snapshot_invalid")
        if row[0] == did:
            try:
                score = Decimal(str(row[1]))
            except InvalidOperation as error:
                raise ValueError("close1_strategy_score_invalid") from error
            if not score.is_finite():
                raise ValueError("close1_strategy_score_invalid")
            return score
    return None


def infer_exposure(
    did: str,
    snapshots: list[dict],
    *,
    min_mark_delta: Decimal = MIN_MEANINGFUL_MARK_DELTA,
    min_slopes: int = MIN_EXPOSURE_SLOPES,
    max_stable_spread: Decimal = MAX_STABLE_EXPOSURE_SPREAD,
) -> ExposureEstimate:
    """Infer current signed position from score-vs-mark slope.

    Consecutive pairs are used only when the DID appears in both snapshots and
    the official mark moved enough to dominate the public score's 0.01 display
    precision. The median is robust to one noisy pair. Stable is a local
    strategy heuristic, not an official contest fact.
    """
    close_call._did(did)
    delta_floor = _decimal(min_mark_delta, label="min_mark_delta")
    spread_limit = _decimal(max_stable_spread, label="max_stable_spread")
    if type(min_slopes) is not int or min_slopes < 2:
        raise ValueError("close1_strategy_min_slopes_invalid")
    if len(snapshots) < 2:
        return ExposureEstimate(did, None, (), 0, None, False, "insufficient_history")

    parsed: list[tuple[Decimal, Decimal | None]] = []
    for snapshot in snapshots:
        if not isinstance(snapshot, dict):
            raise ValueError("close1_strategy_snapshot_invalid")
        mark = _decimal(snapshot.get("mark"), label="mark")
        score = _score_by_did(snapshot, did)
        parsed.append((mark, score))

    slopes: list[Decimal] = []
    for (prev_mark, prev_score), (mark, score) in zip(parsed, parsed[1:]):
        if prev_score is None or score is None:
            continue
        mark_delta = mark - prev_mark
        if abs(mark_delta) < delta_floor:
            continue
        slopes.append((score - prev_score) / mark_delta)

    if len(slopes) < min_slopes:
        return ExposureEstimate(
            did,
            None,
            tuple(slopes),
            len(slopes),
            None,
            False,
            "insufficient_meaningful_moves",
        )

    ordered = sorted(slopes)
    estimate = median(ordered)
    spread = ordered[-1] - ordered[0]
    stable = spread <= spread_limit
    return ExposureEstimate(
        did,
        estimate,
        tuple(slopes),
        len(slopes),
        spread,
        stable,
        "stable" if stable else "unstable_score_mark_slope",
    )


def project_score(
    *,
    current_score: object,
    current_mark: object,
    position: object,
    final_price: object,
) -> Decimal:
    """Project score at a hypothetical final price if exposure stays unchanged."""
    score = _decimal(current_score, label="current_score", allow_zero=True)
    mark = _decimal(current_mark, label="current_mark")
    try:
        pos = Decimal(str(position))
    except InvalidOperation as error:
        raise ValueError("close1_strategy_position_invalid") from error
    final = _decimal(final_price, label="final_price")
    if not pos.is_finite():
        raise ValueError("close1_strategy_position_invalid")
    return score + pos * (final - mark)


def single_position_score(
    *,
    side: str,
    qty: object,
    px: object,
    fee: object,
    final_price: object,
) -> Decimal:
    """Final score of a fresh account after one still-open position."""
    if side not in {"buy", "sell"}:
        raise ValueError("close1_strategy_side_invalid")
    quantity = _decimal(qty, label="qty")
    entry = _decimal(px, label="px")
    paid_fee = _decimal(fee, label="fee", allow_zero=True)
    final = _decimal(final_price, label="final_price")
    signed_position = quantity if side == "buy" else -quantity
    return signed_position * (final - entry) - paid_fee


def base_fee(*, qty: object, px: object) -> Decimal:
    quantity = _decimal(qty, label="qty")
    entry = _decimal(px, label="px")
    return close_call.FEE_RATE * quantity * entry


def crossover_vs_competitor(
    *,
    side: str,
    qty: object,
    px: object,
    current_mark: object,
    competitor_score: object,
    competitor_position: object,
    fee: object | None = None,
) -> Crossover:
    """Solve the final price where a fresh single position ties a competitor.

    Above or below the returned price, condition tells which direction makes
    our score larger if the competitor keeps the supplied position. The fee
    defaults to the 1% base fee only. Real settlement can charge a larger
    favorable-price clawback, so this is never sufficient evidence to trade.
    """
    if side not in {"buy", "sell"}:
        raise ValueError("close1_strategy_side_invalid")
    quantity = _decimal(qty, label="qty")
    entry = _decimal(px, label="px")
    mark = _decimal(current_mark, label="current_mark")
    comp_score = _decimal(competitor_score, label="competitor_score", allow_zero=True)
    try:
        comp_pos = Decimal(str(competitor_position))
    except InvalidOperation as error:
        raise ValueError("close1_strategy_competitor_position_invalid") from error
    if not comp_pos.is_finite():
        raise ValueError("close1_strategy_competitor_position_invalid")

    paid_fee = base_fee(qty=quantity, px=entry) if fee is None else _decimal(
        fee, label="fee", allow_zero=True
    )
    our_pos = quantity if side == "buy" else -quantity
    denominator = our_pos - comp_pos
    if denominator == 0:
        raise ValueError("close1_strategy_parallel_exposure_no_crossover")

    price = (
        our_pos * entry
        + paid_fee
        + comp_score
        - comp_pos * mark
    ) / denominator
    if price <= 0:
        raise ValueError("close1_strategy_nonpositive_crossover")

    move = price - mark
    condition = "above" if denominator > 0 else "below"
    return Crossover(
        price=price,
        condition=condition,
        move_from_current=move,
        move_percent_from_current=move / mark,
        our_signed_position=our_pos,
        competitor_position=comp_pos,
        fee=paid_fee,
        warning=(
            "projection assumes competitor exposure stays unchanged; default fee is "
            "1% base fee only and actual favorable-price clawback can be larger"
        ),
    )
