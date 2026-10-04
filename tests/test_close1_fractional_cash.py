from decimal import Decimal

import pytest

from flop_agent import close_call


DID_A = "did:key:z6MkeU5vNqNxwtmAsf8ZyeLGG5KyUSbT94cTXomQpQXZp9Ta"
DID_B = "did:key:z6MksG1pdiesyoNmqzkh7Dqxu89GjejSR9bo34p7qocuB2i9"


def test_balance_amount_accepts_reconciled_fee_precision_and_zero():
    assert close_call._balance_amount("9763.0944", label="available_cash") == Decimal("9763.0944")
    assert close_call._balance_amount("0", label="available_cash") == Decimal("0")


@pytest.mark.parametrize("value", ["-0.01", "1.0000001", "nan", "inf", "1e3"])
def test_balance_amount_rejects_invalid_or_excess_precision(value):
    with pytest.raises(ValueError, match="available_cash_invalid"):
        close_call._balance_amount(value, label="available_cash")


def test_trade_plan_accepts_fractional_reconciled_cash_without_relaxing_trade_terms():
    terms = {
        "id": "fractional-cash",
        "maker": DID_A,
        "side": "sell",
        "qty": "2.00",
        "px": "237.34",
        "taker": "any",
        "until": 2462,
    }

    plan = close_call.validate_trade_plan(
        terms,
        current_sweep=2461,
        reference_price="234.93",
        reference_age_seconds=83,
        available_cash="9763.0944",
        current_position="-1",
    )

    assert plan["opening_qty"] == "2.00"
    assert plan["required_cash_before_unknown_clawback"] == "479.426800"
    assert plan["enough_cash_for_base_fee_and_collateral"] is True

    bad_terms = dict(terms, px="237.341")
    with pytest.raises(ValueError, match="price_invalid"):
        close_call.validate_trade_plan(
            bad_terms,
            current_sweep=2461,
            reference_price="234.93",
            reference_age_seconds=83,
            available_cash="9763.0944",
            current_position="-1",
        )


def test_offer_preflight_accepts_fractional_reconciled_cash(monkeypatch):
    offer = close_call.VerifiedPublicOffer(
        seq=55264,
        ts="2026-10-04T00:00:00Z",
        maker=DID_A,
        maker_side="sell",
        taker_side="buy",
        qty=Decimal("2"),
        px=Decimal("237.34"),
        until=2462,
        canonical_terms="{}",
        taker_signature_preimage="test",
    )
    monkeypatch.setattr(close_call, "parse_verified_public_offer", lambda *args, **kwargs: offer)

    risk = close_call.evaluate_verified_offer_as_taker(
        {},
        current_sweep=2461,
        our_did=DID_B,
        reference_price="234.93",
        reference_age_seconds=83,
        available_cash="9763.0944",
        current_position="-1",
    )

    assert risk["opening_qty"] == "1"
    assert risk["required_cash_before_unknown_clawback"] == "242.0868"
    assert risk["enough_cash_for_base_fee_and_collateral"] is True
