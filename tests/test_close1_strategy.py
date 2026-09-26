from decimal import Decimal

import pytest

from flop_agent import close1_strategy


DID = "did:key:z6MkeTcR7He7sY6imuJguhifiNKrWceKNus5HGuajbAwymdK"


def snap(mark, score):
    return {"mark": str(mark), "top": [[DID, str(score)]]}


def test_infer_exposure_from_realistic_short_leader_history():
    history = [
        snap("221.90", "190.52"),
        snap("222.04", "184.64"),
        snap("222.00", "186.16"),
        snap("222.38", "170.45"),
        snap("221.48", "208.15"),
        snap("222.78", "153.40"),
        snap("221.96", "187.96"),
        snap("221.59", "203.30"),
        snap("221.42", "210.62"),
        snap("221.51", "206.61"),
        snap("221.42", "210.29"),
        snap("221.41", "210.87"),
    ]

    estimate = close1_strategy.infer_exposure(DID, history)

    assert estimate.stable is True
    assert estimate.reason == "stable"
    assert estimate.observations == 7
    assert Decimal("-42.20") < estimate.position < Decimal("-41.20")
    assert estimate.spread < Decimal("2.50")


def test_tiny_mark_moves_are_excluded_from_exposure_estimate():
    history = [
        snap("220.00", "100.00"),
        snap("220.20", "91.60"),   # -42
        snap("220.21", "91.02"),   # noisy -58 from a tiny 0.01 move: excluded
        snap("220.41", "82.62"),   # -42
        snap("220.61", "74.22"),   # -42
        snap("220.81", "65.82"),   # -42
    ]

    estimate = close1_strategy.infer_exposure(DID, history)

    assert estimate.stable is True
    assert estimate.observations == 4
    assert estimate.position == Decimal("-42")
    assert all(slope == Decimal("-42") for slope in estimate.slopes)


def test_insufficient_or_unstable_history_does_not_claim_stable_exposure():
    insufficient = close1_strategy.infer_exposure(
        DID,
        [snap("220.00", "100.00"), snap("220.20", "91.60")],
    )
    assert insufficient.position is None
    assert insufficient.stable is False
    assert insufficient.reason == "insufficient_meaningful_moves"

    unstable = close1_strategy.infer_exposure(
        DID,
        [
            snap("220.00", "100.00"),
            snap("220.20", "92.00"),  # -40
            snap("220.40", "82.00"),  # -50
            snap("220.60", "75.00"),  # -35
            snap("220.80", "64.00"),  # -55
        ],
    )
    assert unstable.position == Decimal("-45")
    assert unstable.stable is False
    assert unstable.reason == "unstable_score_mark_slope"


def test_project_score_uses_current_position_slope():
    projected = close1_strategy.project_score(
        current_score="210.87",
        current_mark="221.41",
        position="-42",
        final_price="226.41",
    )
    assert projected == Decimal("0.87")


def test_project_score_allows_negative_current_score():
    projected = close1_strategy.project_score(
        current_score="-10.00",
        current_mark="220.00",
        position="5",
        final_price="221.00",
    )
    assert projected == Decimal("-5.00")


def test_single_position_score_matches_fold_economics():
    fee = close1_strategy.base_fee(qty="44", px="224.33")
    assert fee == Decimal("98.7052")

    long_score = close1_strategy.single_position_score(
        side="buy",
        qty="44",
        px="224.33",
        fee=fee,
        final_price="230.00",
    )
    short_score = close1_strategy.single_position_score(
        side="sell",
        qty="44",
        px="224.33",
        fee=fee,
        final_price="218.00",
    )
    assert long_score == Decimal("150.7748")
    assert short_score == Decimal("179.8148")


def test_long_crossover_against_current_short_leader_is_near_226_5():
    crossover = close1_strategy.crossover_vs_competitor(
        side="buy",
        qty="44",
        px="224.33",
        current_mark="221.41",
        competitor_score="210.87",
        competitor_position="-42",
    )

    assert crossover.condition == "above"
    assert Decimal("226.50") < crossover.price < Decimal("226.55")
    assert crossover.move_from_current > Decimal("5")
    assert Decimal("0.022") < crossover.move_percent_from_current < Decimal("0.024")
    assert crossover.our_signed_position == Decimal("44")
    assert "clawback" in crossover.warning


def test_short_crossover_against_similarly_short_leader_requires_extreme_drop():
    crossover = close1_strategy.crossover_vs_competitor(
        side="sell",
        qty="44",
        px="224.33",
        current_mark="221.41",
        competitor_score="210.87",
        competitor_position="-42",
    )

    assert crossover.condition == "below"
    assert Decimal("130") < crossover.price < Decimal("132")


def test_parallel_exposure_has_no_finite_crossover():
    with pytest.raises(ValueError, match="parallel_exposure"):
        close1_strategy.crossover_vs_competitor(
            side="sell",
            qty="42",
            px="224.33",
            current_mark="221.41",
            competitor_score="210.87",
            competitor_position="-42",
        )
