from __future__ import annotations

import inspect
from decimal import Decimal

from flop_agent import close1_autonomous_stage as auto
from flop_agent.close1_candidate_scanner import CandidateScan, CandidateView


def candidate(*, trade_id="t1", qty="10", px="100", required="606"):
    return CandidateView(
        room="close1-offers",
        seq=1,
        trade_id=trade_id,
        taker_side="buy",
        qty=Decimal(qty),
        px=Decimal(px),
        until=10,
        base_fee=Decimal("10"),
        required_cash=Decimal(required),
        dynamic_top3_price=None,
        dynamic_condition=None,
        move_percent_from_mark=None,
        visible_leader_coverage=0,
        visible_leaders=0,
        warning="test",
        maker="did:key:z6MktVwQqJbSVfLfDUHRVkJShspL49A2d6EbhzKvXV9zPLF5",
    )


def scan(*items):
    return CandidateScan(
        sweep=8,
        reference=Decimal("101"),
        reference_age_seconds=1,
        mark=Decimal("101"),
        top3_cutoff=None,
        visible_leaders=(),
        verified_offers=len(items),
        sampled_trade_ids=0,
        rejected_offers=0,
        candidates=tuple(items),
        strategy_gate="ready",
    )


def test_materiality_and_cash_budget_are_enforced():
    too_small = candidate(trade_id="small", qty="9.99", required="100")
    too_large = candidate(trade_id="large", qty="20", required="6000.01")
    good = candidate(trade_id="good", qty="15", required="5900")
    chosen = auto._select_candidate(
        scan(too_small, too_large, good),
        cash=Decimal("10000"),
        skip_ids=set(),
    )
    assert chosen is good


def test_exact_sixty_percent_cash_boundary_is_allowed():
    good = candidate(trade_id="edge", qty="20", required="6000")
    assert auto._select_candidate(
        scan(good), cash=Decimal("10000"), skip_ids=set()
    ) is good


def test_skipped_trade_id_is_never_selected():
    first = candidate(trade_id="old", qty="30", required="1000")
    second = candidate(trade_id="fresh", qty="20", required="1000")
    chosen = auto._select_candidate(
        scan(first, second), cash=Decimal("10000"), skip_ids={"old"}
    )
    assert chosen is second


def test_worse_than_reference_price_is_rejected():
    bad = candidate(trade_id="bad", qty="20", px="102", required="1000")
    assert auto._select_candidate(
        scan(bad), cash=Decimal("10000"), skip_ids=set()
    ) is None


def test_largest_material_candidate_wins_before_edge_tiebreak():
    bigger = candidate(trade_id="big", qty="20", px="100.8", required="1000")
    better_edge = candidate(trade_id="edge", qty="15", px="99", required="1000")
    assert auto._select_candidate(
        scan(better_edge, bigger), cash=Decimal("10000"), skip_ids=set()
    ) is bigger


def test_stage_module_has_no_signer_or_external_write_surface():
    source = inspect.getsource(auto)
    forbidden = (
        "vault_seed(",
        "oracle_signer",
        "close1_approved_trade",
        "httpx.post(",
        "post_signed(",
        "subprocess",
        "systemctl",
    )
    assert all(token not in source for token in forbidden)
