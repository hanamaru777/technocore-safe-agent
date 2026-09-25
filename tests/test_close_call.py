import json
from decimal import Decimal

import pytest

from flop_agent import close_call


DID_A = "did:key:z6MkeU5vNqNxwtmAsf8ZyeLGG5KyUSbT94cTXomQpQXZp9Ta"
DID_B = "did:key:z6MksG1pdiesyoNmqzkh7Dqxu89GjejSR9bo34p7qocuB2i9"


def msg(kind, payload):
    return {
        "from": close_call.REFEREE_DID,
        "text": json.dumps({"t": kind, **payload}, separators=(",", ":")),
    }


def test_launch_authority_is_pinned_to_live_seed():
    assert close_call.OFFICIAL_REPO_COMMIT == "66c1da36538e4b1c685417d2f66922906b13fea0"
    assert close_call.LAUNCH_MANIFEST_SHA256 == ("bae09812e25eb6f1369c611f24964f7e" "a0acafddfc45301a16f33f941296dafa")
    assert close_call.TRADING_ROOM == "close1"
    assert close_call.LOCK_SWEEP == 2556


def test_validate_live_seed():
    seed = {
        "from": close_call.REFEREE_DID,
        "text": json.dumps({
            "for": 1,
            "limits": ["214.84", "237.44"],
            "package": close_call.LAUNCH_MANIFEST_SHA256,
            "price": "226.14",
            "rooms": list(close_call.REFEREE_ROOMS),
            "season": "close-1",
            "t": "seed",
            "trade": {"tid": 626256716983248, "time": "2026-09-25T11:59:42.666000Z"},
        }, separators=(",", ":")),
    }
    assert close_call.validate_seed_message(seed)["price"] == "226.14"


def test_seed_wrong_package_fails_closed():
    seed = {
        "from": close_call.REFEREE_DID,
        "text": json.dumps({
            "package": "0" * 64,
            "price": "226.14",
            "rooms": list(close_call.REFEREE_ROOMS),
            "season": "close-1",
            "t": "seed",
            "trade": {"tid": 1, "time": "2026-09-25T11:59:42Z"},
        }),
    }
    with pytest.raises(ValueError, match="package_mismatch"):
        close_call.validate_seed_message(seed)


def test_registration_is_deterministic_and_single_did():
    assert close_call.registration_text(DID_A) == (
        '{"key":"' + DID_A + '","season":"close-1","t":"owner"}'
    )


def sample_terms(**overrides):
    value = {
        "id": "maru1",
        "maker": DID_A,
        "side": "buy",
        "qty": "1.00",
        "px": "225.00",
        "taker": "any",
        "until": 100,
    }
    value.update(overrides)
    return value


def test_signature_preimages_are_exact_and_no_signing_occurs():
    terms = sample_terms()
    canonical = close_call.canonical_terms(terms)
    assert canonical == json.dumps(terms, sort_keys=True, separators=(",", ":"))
    assert close_call.maker_signature_preimage(terms) == f"close-1|terms|{canonical}"
    assert close_call.taker_signature_preimage(terms, DID_B) == (
        f"close-1|accept|{canonical}|{DID_B}"
    )


def test_local_policy_rejects_self_trade():
    with pytest.raises(ValueError, match="self_trade"):
        close_call.canonical_terms(sample_terms(taker=DID_A))
    with pytest.raises(ValueError, match="self_trade"):
        close_call.taker_signature_preimage(sample_terms(), DID_A)


def test_trade_plan_requires_fresh_reference_and_limits():
    plan = close_call.validate_trade_plan(
        sample_terms(),
        current_sweep=32,
        reference_price="225.03",
        reference_age_seconds=10,
        available_cash="10000",
    )
    assert plan["reference_fresh_for_strategy"] is True
    assert plan["enough_cash_for_base_fee_and_collateral"] is True
    assert plan["base_fee"] == "2.250000"

    with pytest.raises(RuntimeError, match="reference_stale"):
        close_call.validate_trade_plan(
            sample_terms(),
            current_sweep=32,
            reference_price="225.03",
            reference_age_seconds=3002,
        )

    with pytest.raises(ValueError, match="outside_limit"):
        close_call.validate_trade_plan(
            sample_terms(px="240.00"),
            current_sweep=32,
            reference_price="225.03",
            reference_age_seconds=10,
        )


def test_trade_plan_rejects_expired_until():
    with pytest.raises(ValueError, match="would_be_expired"):
        close_call.validate_trade_plan(
            sample_terms(until=32),
            current_sweep=32,
            reference_price="225.03",
            reference_age_seconds=10,
        )


def test_clawback_fee_matches_official_rule():
    maker, taker = close_call.side_fees(
        maker_side="buy",
        qty="2",
        px="220",
        sweep_close="225",
    )
    assert maker == Decimal("10")
    assert taker == Decimal("4.40")


def test_build_live_snapshot_from_latest_referee_rows():
    price = {"messages": [msg("price", {
        "n": 32,
        "age_s": 3002,
        "ref": {"px": "225.03", "time": "2026-09-25T13:49:57Z", "tid": 1},
    })]}
    state = {"messages": [msg("state", {
        "n": 32, "owners": 352876, "rooms": 51, "root": "a" * 64, "file": "b" * 64,
    })]}
    pnl = {"messages": [msg("pnl", {
        "n": 32, "mark": "224.15", "file": "b" * 64,
        "top": [[DID_A, "104.02"], [DID_B, "96.19"], [DID_A, "96.19"]],
    })]}
    positions = {"messages": [msg("positions", {
        "n": 32, "open": "87912.16", "longs": 2056, "shorts": 2571,
        "top": [], "file": "b" * 64,
    })]}

    snapshot = close_call.build_live_snapshot(
        price_room=price,
        state_room=state,
        pnl_room=pnl,
        positions_room=positions,
    )
    assert snapshot.sweep == 32
    assert snapshot.owners == 352876
    assert snapshot.reference == Decimal("225.03")
    assert snapshot.reference_fresh_for_strategy is False
    assert snapshot.top3_cutoff == Decimal("96.19")
    assert snapshot.longs == 2056
    assert snapshot.shorts == 2571


def test_fetch_live_snapshot_is_read_only(monkeypatch):
    payloads = {
        "d-close1-price": {"messages": [msg("price", {
            "n": 1, "age_s": 1,
            "ref": {"px": "225.00", "time": "2026-09-25T12:04:59Z", "tid": 1},
        })]},
        "d-close1-state": {"messages": [msg("state", {
            "n": 1, "owners": 2, "rooms": 1, "root": "a" * 64, "file": "b" * 64,
        })]},
        "d-close1-pnl": {"messages": [msg("pnl", {
            "n": 1, "mark": "225.00", "file": "b" * 64, "top": [],
        })]},
        "d-close1-positions": {"messages": [msg("positions", {
            "n": 1, "open": "1.00", "longs": 0, "shorts": 0, "top": [], "file": "b" * 64,
        })]},
    }
    calls = []
    monkeypatch.setattr(close_call.core, "read_room", lambda room, limit=5: calls.append((room, limit)) or payloads[room])
    snapshot = close_call.fetch_live_snapshot()
    assert snapshot.sweep == 1
    assert len(calls) == 4
