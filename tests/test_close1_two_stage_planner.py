from dataclasses import replace
from decimal import Decimal

from flop_agent import close1_candidate_scanner as scanner
from flop_agent import close1_two_stage_planner as planner


def candidate(*, side="buy", qty="10", px="100", fee="10"):
    return scanner.CandidateView(
        room="close1-offers",
        seq=1,
        trade_id="verified",
        taker_side=side,
        qty=Decimal(qty),
        px=Decimal(px),
        until=999,
        base_fee=Decimal(fee),
        required_cash=Decimal("1010"),
        dynamic_top3_price=None,
        dynamic_condition=None,
        move_percent_from_mark=None,
        visible_leader_coverage=3,
        visible_leaders=3,
        warning="verified scanner fixture",
    )


def leaders(*, position="-100", score="500"):
    return [
        scanner.LeaderView(
            did=f"leader-{index}",
            score=Decimal(score) - Decimal(index * 10),
            position=Decimal(position),
            stable=True,
            reason="visible" if index < 2 else "stable_shadow_leader",
        )
        for index in range(3)
    ]


def test_profitable_buy_round_trip_includes_both_fees_and_increases_cash():
    result = planner.realize_stage_one(
        candidate(side="buy"),
        close_price="120",
        current_mark="120",
    )

    assert result.entry_fee == Decimal("10")
    assert result.exit_fee == Decimal("12")
    assert result.realised_score == Decimal("178")
    assert result.post_close_cash == Decimal("10178")
    assert result.move_from_entry == Decimal("20")


def test_profitable_sell_round_trip_includes_both_fees_and_increases_cash():
    result = planner.realize_stage_one(
        candidate(side="sell"),
        close_price="80",
        current_mark="80",
    )

    assert result.entry_fee == Decimal("10")
    assert result.exit_fee == Decimal("8")
    assert result.realised_score == Decimal("182")
    assert result.post_close_cash == Decimal("10182")
    assert result.move_from_entry == Decimal("-20")


def test_losing_round_trip_decreases_post_close_cash():
    result = planner.realize_stage_one(
        candidate(side="buy"),
        close_price="90",
        current_mark="90",
    )

    assert result.realised_score == Decimal("-119")
    assert result.post_close_cash == Decimal("9881")


def test_stage2_quantity_is_floored_to_point_zero_one_and_affordable():
    quantity = planner.maximum_affordable_quantity(cash="1000", entry_price="3")
    fee = quantity * Decimal("3") * Decimal("0.01")

    assert quantity == Decimal("330.03")
    assert quantity * Decimal("3") + fee <= Decimal("1000")
    next_quantity = quantity + Decimal("0.01")
    assert next_quantity * Decimal("3") * Decimal("1.01") > Decimal("1000")


def test_two_stage_buy_victory_uses_realised_cash_and_dynamic_margin():
    current_leaders = leaders(position="-100", score="500")
    result = planner.plan_two_stage_victory(
        candidate(side="buy"),
        current_mark="120",
        leaders=current_leaders,
    )

    assert result.status == "PATH"
    assert result.stage1_close_price == Decimal("120")
    assert result.stage1_realised_score == Decimal("178")
    assert result.post_close_cash == Decimal("10178")
    assert result.stage2_side == "buy"
    assert result.stage2_max_affordable_qty == Decimal("83.97")
    assert result.stage2_required_cash <= result.post_close_cash
    assert result.dynamic_victory_condition == "above"
    hurdle = planner._victory_hurdle(
        final_price=result.dynamic_victory_price,
        current_mark=Decimal("120"),
        leaders=current_leaders,
    )
    assert result.stage2_projected_score >= hurdle
    projected = max(
        leader.score
        + leader.position * (result.dynamic_victory_price - Decimal("120"))
        for leader in current_leaders
    )
    assert hurdle == max(Decimal("100"), projected + Decimal("25"))


def test_two_stage_sell_victory_is_evaluated():
    current_leaders = leaders(position="100", score="500")
    result = planner.plan_two_stage_victory(
        candidate(side="sell"),
        current_mark="80",
        leaders=current_leaders,
    )

    assert result.status == "PATH"
    assert result.stage1_realised_score == Decimal("182")
    assert result.stage2_side == "sell"
    assert result.dynamic_victory_condition == "below"
    assert result.stage2_move_required < 0


def test_opposite_direction_shadow_leader_is_part_of_victory_envelope():
    current_leaders = [
        scanner.LeaderView("current-long", Decimal("90"), Decimal("10"), True, "visible"),
        scanner.LeaderView("visible", Decimal("80"), Decimal("0"), True, "visible"),
        scanner.LeaderView(
            "shadow-short",
            Decimal("300"),
            Decimal("-50"),
            True,
            "stable_shadow_leader",
        ),
    ]
    qty = planner.maximum_affordable_quantity(cash="10000", entry_price="100")
    fee = qty * Decimal("100") * Decimal("0.01")

    result = planner._nearest_stage2_victory(
        realised_score=Decimal("0"),
        side="sell",
        qty=qty,
        entry_price=Decimal("100"),
        entry_fee=fee,
        current_mark=Decimal("100"),
        leaders=current_leaders,
        price_floor=Decimal("0.01"),
        price_ceiling=Decimal("200"),
    )

    assert result is not None
    final, _, _, score = result
    assert score >= planner._victory_hurdle(
        final_price=final,
        current_mark=Decimal("100"),
        leaders=current_leaders,
    )


def test_victory_hurdle_uses_plus_25_and_100_floor():
    high = leaders(position="0", score="80")
    low = leaders(position="0", score="0")

    assert planner._victory_hurdle(
        final_price=Decimal("100"),
        current_mark=Decimal("100"),
        leaders=high,
    ) == Decimal("105")
    assert planner._victory_hurdle(
        final_price=Decimal("100"),
        current_mark=Decimal("100"),
        leaders=low,
    ) == Decimal("100")


def test_incomplete_leader_coverage_fails_closed_without_search():
    incomplete = leaders()
    incomplete[2] = replace(incomplete[2], stable=False, position=None, reason="unstable")

    result = planner.plan_two_stage_victory(
        candidate(),
        current_mark="120",
        leaders=incomplete,
    )

    assert result.status == "NO_PATH"
    assert result.reason == "leader_coverage_incomplete"
    assert result.leader_coverage == 2
    assert result.leader_universe == 3


def test_parallel_exposures_with_no_valid_crossing_return_none():
    parallel = leaders(position="99.00", score="1000")
    result = planner._nearest_stage2_victory(
        realised_score=Decimal("0"),
        side="buy",
        qty=Decimal("99.00"),
        entry_price=Decimal("100"),
        entry_fee=Decimal("99"),
        current_mark=Decimal("100"),
        leaders=parallel,
        price_floor=Decimal("0.01"),
        price_ceiling=Decimal("200"),
    )

    assert result is None


def test_complete_coverage_with_no_affordable_second_stage_returns_no_path():
    item = candidate(side="buy", qty="0.1", px="100", fee="0.1")

    result = planner.plan_two_stage_victory(
        item,
        current_mark="100",
        leaders=leaders(position="0", score="500"),
        starting_cash="0",
        horizon_multiplier="1",
    )

    assert result.status == "NO_PATH"
    assert result.reason == "no_supported_two_stage_victory_path"


def test_basket_candidate_uses_weighted_entry_and_aggregate_fee():
    single = candidate(side="buy", qty="10", px="100", fee="10")
    basket = scanner.BasketCandidateView(
        taker_side="buy",
        legs=(),
        qty=single.qty,
        weighted_px=single.px,
        until=single.until,
        base_fee=single.base_fee,
        required_cash=single.required_cash,
        dynamic_top3_price=None,
        dynamic_condition=None,
        move_percent_from_mark=None,
        visible_leader_coverage=3,
        visible_leaders=3,
        warning="verified basket fixture",
    )

    result = planner.plan_two_stage_victory(
        basket,
        current_mark="120",
        leaders=leaders(position="-100", score="500"),
    )

    assert result.status == "PATH"
    assert result.stage1_entry_price == Decimal("100")
    assert result.stage1_entry_fee == Decimal("10")


def test_warning_is_base_fee_only_and_clawback_is_never_known():
    result = planner.plan_two_stage_victory(
        candidate(),
        current_mark="120",
        leaders=leaders(position="-100", score="500"),
    )

    assert "base-fee-only lower-bound" in result.warning
    assert result.favorable_price_clawback is None
    assert "unknown" in result.clawback_risk
    assert "executable" in result.warning


def test_planner_does_not_change_existing_single_stage_candidate_or_solver():
    item = candidate()
    current_leaders = leaders(position="-100", score="500")
    before = scanner._nearest_dynamic_victory(
        side=item.taker_side,
        qty=item.qty,
        px=item.px,
        fee=item.base_fee,
        current_mark=Decimal("120"),
        leaders=current_leaders,
    )

    planner.plan_two_stage_victory(item, current_mark="120", leaders=current_leaders)
    after = scanner._nearest_dynamic_victory(
        side=item.taker_side,
        qty=item.qty,
        px=item.px,
        fee=item.base_fee,
        current_mark=Decimal("120"),
        leaders=current_leaders,
    )

    assert item.trade_id == "verified"
    assert before == after
