import base64
import json
from decimal import Decimal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = B58[remainder] + encoded
    leading = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * leading + (encoded or "1")


def _test_did(key: Ed25519PrivateKey) -> str:
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "did:key:z" + _b58encode(b"\xed\x01" + public)


def _sig(key: Ed25519PrivateKey, message: str) -> str:
    return base64.urlsafe_b64encode(key.sign(message.encode("utf-8"))).rstrip(b"=").decode("ascii")


def signed_public_offer(*, bad_maker_sig: bool = False, room: str = "close1", include_how: bool = False):
    maker_key = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
    maker = _test_did(maker_key)
    terms = {
        "id": "offer1",
        "maker": maker,
        "side": "sell",
        "qty": "3.00",
        "px": "224.70",
        "taker": "any",
        "until": 190,
    }
    maker_sig = _sig(maker_key, close_call.maker_signature_preimage(terms))
    if bad_maker_sig:
        other_key = Ed25519PrivateKey.from_private_bytes(b"\x22" * 32)
        maker_sig = _sig(other_key, close_call.maker_signature_preimage(terms))
    payload = {
        "t": "offer",
        "season": "close-1",
        "terms": terms,
        "maker_sig": maker_sig,
    }
    if include_how:
        payload["how"] = "countersign close-1|accept|| and post t=trade"
    text = json.dumps(payload, separators=(",", ":"))
    nonce = 123456
    return {
        "seq": 99,
        "ts": "2026-09-26T03:45:20Z",
        "from": maker,
        "text": text,
        "nonce": nonce,
        "sig": _sig(maker_key, f"{room}|{nonce}|{text}"),
    }


def test_verified_public_offer_checks_outer_and_maker_signatures():
    offer = close_call.parse_verified_public_offer(
        signed_public_offer(),
        current_sweep=189,
        our_did=DID_B,
    )
    assert offer.maker_side == "sell"
    assert offer.taker_side == "buy"
    assert offer.qty == Decimal("3.00")
    assert offer.px == Decimal("224.70")
    assert offer.until == 190
    assert offer.taker_signature_preimage.endswith("|" + DID_B)


def test_verified_public_offer_supports_actual_negotiation_room_and_how_metadata():
    record = signed_public_offer(room="close1-offers", include_how=True)
    offer = close_call.parse_verified_public_offer(
        record,
        current_sweep=189,
        our_did=DID_B,
        room="close1-offers",
    )
    assert offer.room == "close1-offers"
    assert offer.maker_side == "sell"

def test_verified_public_offer_rejects_bad_detached_maker_signature():
    with pytest.raises(ValueError, match="signature verification failed"):
        close_call.parse_verified_public_offer(
            signed_public_offer(bad_maker_sig=True),
            current_sweep=189,
            our_did=DID_B,
        )


def test_verified_public_offer_rejects_expired_and_self_trade():
    record = signed_public_offer()
    with pytest.raises(ValueError, match="offer_expired"):
        close_call.parse_verified_public_offer(
            record,
            current_sweep=190,
            our_did=DID_B,
        )
    with pytest.raises(ValueError, match="self_trade"):
        close_call.parse_verified_public_offer(
            record,
            current_sweep=189,
            our_did=record["from"],
        )


def test_evaluate_verified_offer_as_taker_is_read_only_and_risk_aware():
    plan = close_call.evaluate_verified_offer_as_taker(
        signed_public_offer(),
        current_sweep=189,
        our_did=DID_B,
        reference_price="224.55",
        reference_age_seconds=5,
        available_cash="10000",
    )
    assert plan["maker_side"] == "sell"
    assert plan["taker_side"] == "buy"
    assert plan["reference_fresh_for_strategy"] is True
    assert plan["enough_cash_for_base_fee_and_collateral"] is True
    assert plan["base_fee"] == "6.741000"
    assert plan["required_cash_before_unknown_clawback"] == "680.841000"
    assert "clawback" in plan["warning"]

    with pytest.raises(RuntimeError, match="reference_stale"):
        close_call.evaluate_verified_offer_as_taker(
            signed_public_offer(),
            current_sweep=189,
            our_did=DID_B,
            reference_price="224.55",
            reference_age_seconds=305,
            available_cash="10000",
        )

def pnl_room(points, did=DID_A):
    messages = []
    for n, mark, score in points:
        messages.append(msg("pnl", {
            "n": n,
            "mark": mark,
            "file": "b" * 64,
            "top": [[did, score]],
        }))
    return {"messages": messages}


def test_estimate_pnl_exposure_detects_stable_short_from_multiple_sweeps():
    room = pnl_room([
        (1, "222.04", "184.64"),
        (2, "222.38", "170.45"),
        (3, "221.48", "208.15"),
        (4, "222.78", "153.40"),
        (5, "221.96", "187.96"),
        (6, "221.59", "203.30"),
        (7, "221.42", "210.62"),
    ])
    estimate = close_call.estimate_pnl_exposure(room, did=DID_A)
    assert estimate.stable is True
    assert estimate.exposure is not None
    assert Decimal("-44") < estimate.exposure < Decimal("-39")
    assert estimate.consistent_intervals >= 4


def test_estimate_pnl_exposure_ignores_tiny_moves_and_fails_closed_when_sparse():
    room = pnl_room([
        (1, "221.42", "210.62"),
        (2, "221.51", "206.61"),
        (3, "221.42", "210.29"),
        (4, "221.41", "210.87"),
    ])
    estimate = close_call.estimate_pnl_exposure(room, did=DID_A)
    assert estimate.stable is False
    assert estimate.exposure is None


def test_candidate_score_at_final_matches_official_fold_economics_for_fresh_open():
    score = close_call.candidate_score_at_final(
        side="buy",
        qty="44.10",
        px="224.33",
        final_price="226.50",
    )
    assert score == Decimal("44.10") * (Decimal("226.50") - Decimal("224.33")) - Decimal("44.10") * Decimal("224.33") * Decimal("0.01")


def test_dynamic_crossover_with_short_leader_reduces_required_long_hurdle():
    result = close_call.dynamic_crossover_with_leader(
        leader_score="210.87",
        leader_exposure="-42",
        current_mark="221.41",
        candidate_side="buy",
        qty="44.10",
        px="224.33",
    )
    crossover = Decimal(result["crossover_final_price"])
    assert Decimal("226.49") < crossover < Decimal("226.52")
    assert result["beats_leader_if_final"] == "above"
    assert result["candidate_exposure"] == "44.10"
    assert "clawback" in result["warning"]


def test_dynamic_crossover_rejects_parallel_exposure():
    with pytest.raises(ValueError, match="parallel_exposure"):
        close_call.dynamic_crossover_with_leader(
            leader_score="10",
            leader_exposure="4",
            current_mark="220",
            candidate_side="buy",
            qty="4",
            px="220",
        )