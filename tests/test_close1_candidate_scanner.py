import base64
import json
from decimal import Decimal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flop_agent import close1_candidate_scanner as scanner
from flop_agent import close_call, public_record


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
LEADERS = [
    "did:key:z6MkgTDg3hEz4pwiFcJCDjRvR3hZbVWwy23oGuqFbFxu7Hne",
    "did:key:z6MkeTcR7He7sY6imuJguhifiNKrWceKNus5HGuajbAwymdK",
    "did:key:z6MkeVj5ofGVVYiBgBL2se7GHN7TkgTPP4vPAJpYB8n5bh3G",
    "did:key:z6Mkedxe1yacwZyNB1tyyuW71PFvU9Y8YDrFmirDrkZ5hZDY",
]
OUR_DID = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
SHADOW_LONGS = [
    "did:key:z6MkjyBG1Br9k8MFUXMmNzkYyH6h4JAe8hPv3oqWhdDT7tav",
    "did:key:z6Mkq38Zv4xKX2YEL9H4WcwpZMLBpXFAVHfUULVj74yPVaJh",
    "did:key:z6MktvZPUUeoNsND7eMAD7Pgo4XuRHkESfQxDmoyTxemUdya",
]


def _b58encode(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = B58[remainder] + encoded
    leading = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * leading + (encoded or "1")


def _did(key: Ed25519PrivateKey) -> str:
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "did:key:z" + _b58encode(b"\xed\x01" + public)


def _sig(key: Ed25519PrivateKey, value: str) -> str:
    return base64.urlsafe_b64encode(key.sign(value.encode("utf-8"))).rstrip(b"=").decode("ascii")


def _referee(kind: str, payload: dict, *, nonce: int) -> dict:
    text = json.dumps({"t": kind, **payload}, separators=(",", ":"))
    return {
        "from": close_call.REFEREE_DID,
        "text": text,
        "nonce": nonce,
        "sig": "A" * 86,
    }


def _rooms(*, age=10, newest_only_leader=None):
    marks = [Decimal("220.00"), Decimal("220.20"), Decimal("220.40"), Decimal("220.60"), Decimal("220.80")]
    latest_scores = [Decimal("218.00"), Decimal("210.00"), Decimal("210.00"), Decimal("210.00")]
    positions = [Decimal("-40"), Decimal("-42"), Decimal("-42"), Decimal("-42")]
    pnl_messages = []
    for index, mark in enumerate(marks, 1):
        top = []
        for did, final_score, position in zip(LEADERS, latest_scores, positions):
            if newest_only_leader == did and index < len(marks):
                continue
            score = final_score + position * (mark - marks[-1])
            top.append([did, str(score)])
        pnl_messages.append(_referee("pnl", {
            "n": index,
            "mark": str(mark),
            "file": "b" * 64,
            "top": top,
        }, nonce=100 + index))
    price = _referee("price", {
        "n": len(marks),
        "for": len(marks) + 1,
        "age_s": age,
        "ref": {"px": "224.33", "time": "2026-09-26T12:09:59Z", "tid": 1},
        "limits": ["213.12", "235.54"],
        "global": "221.41",
        "file": "c" * 64,
    }, nonce=999)
    return {"messages": [price]}, {"messages": pnl_messages}


def _positions_room(*, n=5, values=("-46.30", "45.99")):
    top = [[LEADERS[index], value] for index, value in enumerate(values)]
    return {"messages": [_referee("positions", {
        "n": n,
        "file": "f" * 64,
        "longs": 1,
        "shorts": 1,
        "open": "100.00",
        "top": top,
    }, nonce=1000 + n)]}


def _rooms_with_shadow_longs(*, age=10):
    marks = [
        Decimal("220.00"),
        Decimal("220.20"),
        Decimal("220.40"),
        Decimal("220.60"),
        Decimal("220.80"),
        Decimal("221.00"),
    ]
    short_scores = [Decimal("218.00"), Decimal("210.00"), Decimal("210.00"), Decimal("210.00")]
    short_positions = [Decimal("-40"), Decimal("-42"), Decimal("-42"), Decimal("-42")]
    pnl_messages = []
    for index, mark in enumerate(marks, 1):
        top = []
        for did, final_score, position in zip(LEADERS, short_scores, short_positions):
            score = final_score + position * (mark - marks[-1])
            top.append([did, str(score)])
        if index < len(marks):
            for did in SHADOW_LONGS:
                score = Decimal("180.00") + Decimal("42") * (mark - Decimal("220.80"))
                top.append([did, str(score)])
        pnl_messages.append(_referee("pnl", {
            "n": index,
            "mark": str(mark),
            "file": "d" * 64,
            "top": top,
        }, nonce=300 + index))
    price = _referee("price", {
        "n": len(marks),
        "for": len(marks) + 1,
        "age_s": age,
        "ref": {"px": "224.33", "time": "2026-09-27T13:45:00Z", "tid": 2},
        "limits": ["213.12", "235.54"],
        "global": "221.00",
        "file": "e" * 64,
    }, nonce=399)
    return {"messages": [price]}, {"messages": pnl_messages}


def _offer(*, trade_id="live1", qty="44.00", px="224.33", side="sell", until=10, key_byte=0x33):
    key = Ed25519PrivateKey.from_private_bytes(bytes([key_byte]) * 32)
    maker = _did(key)
    terms = {
        "id": trade_id,
        "maker": maker,
        "side": side,
        "qty": qty,
        "px": px,
        "taker": "any",
        "until": until,
    }
    maker_sig = _sig(key, close_call.maker_signature_preimage(terms))
    payload = {
        "t": "offer",
        "season": "close-1",
        "terms": terms,
        "maker_sig": maker_sig,
        "how": "countersign close-1|accept|| and post t=trade",
    }
    text = json.dumps(payload, separators=(",", ":"))
    nonce = 12345
    return {
        "seq": 50,
        "ts": "2026-09-26T12:10:00Z",
        "from": maker,
        "text": text,
        "nonce": nonce,
        "sig": _sig(key, f"close1-offers|{nonce}|{text}"),
    }, key, terms


def _trade_for_offer(
    offer,
    key,
    terms,
    *,
    valid_taker_sig=True,
    taker_key_byte=0x44,
    seq=51,
    ts="2026-09-26T12:10:01Z",
):
    taker_key = Ed25519PrivateKey.from_private_bytes(bytes([taker_key_byte]) * 32)
    taker = _did(taker_key)
    taker_sig = _sig(
        taker_key,
        close_call.taker_signature_preimage(terms, taker),
    )
    if not valid_taker_sig:
        taker_sig = "A" * 86
    payload = {
        "t": "trade",
        "season": "close-1",
        "terms": terms,
        "taker": taker,
        "maker_sig": json.loads(offer["text"])["maker_sig"],
        "taker_sig": taker_sig,
    }
    text = json.dumps(payload, separators=(",", ":"))
    nonce = 12346
    return {
        "seq": seq,
        "ts": ts,
        "from": offer["from"],
        "text": text,
        "nonce": nonce,
        "sig": _sig(key, f"close1-offers|{nonce}|{text}"),
    }


def _verify_referee_with_fixture(monkeypatch):
    original = public_record.verify_signed_record

    def verify(room, message):
        if room in {"d-close1-price", "d-close1-pnl", "d-close1-positions"}:
            assert message["from"] == close_call.REFEREE_DID
            return None
        return original(room, message)

    monkeypatch.setattr(public_record, "verify_signed_record", verify)


def test_top3_delta_10m_uses_latest_and_two_snapshots_back():
    snapshots = [
        {"top": [[LEADERS[0], "500"], [LEADERS[1], "490"], [LEADERS[2], "480"]]},
        {"top": [[LEADERS[0], "530"], [LEADERS[1], "520"], [LEADERS[2], "510"]]},
        {"top": [[LEADERS[0], "580"], [LEADERS[1], "570"], [LEADERS[2], "560"]]},
    ]

    assert scanner._top3_delta_10m(snapshots) == Decimal("80")


def test_top3_delta_10m_fails_safe_without_three_rows_or_history():
    assert scanner._top3_delta_10m([]) is None
    assert scanner._top3_delta_10m([
        {"top": [[LEADERS[0], "1"], [LEADERS[1], "0"]]},
        {"top": [[LEADERS[0], "2"], [LEADERS[1], "1"]]},
        {"top": [[LEADERS[0], "3"], [LEADERS[1], "2"]]},
    ]) is None


def test_scanner_carries_sweep_aligned_visible_position_scale(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms()
    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        positions_room=_positions_room(),
        negotiation_rooms={"close1": {"messages": []}, "close1-offers": {"messages": []}},
    )
    assert report.max_visible_abs_position == Decimal("46.30")


def test_scanner_ignores_positions_context_from_another_sweep(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms()
    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        positions_room=_positions_room(n=4),
        negotiation_rooms={"close1": {"messages": []}, "close1-offers": {"messages": []}},
    )
    assert report.max_visible_abs_position is None


def test_scanner_ranks_verified_long_candidate_against_dynamic_short_leaders(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms()
    offer, _, _ = _offer()

    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        negotiation_rooms={"close1": {"messages": []}, "close1-offers": {"messages": [offer]}},
    )

    assert report.strategy_gate == "ready"
    assert report.reference == Decimal("224.33")
    assert report.reference_age_seconds == 10
    assert report.top3_cutoff == Decimal("210.00")
    assert report.flat_target_score == Decimal("235.00")
    assert report.victory_target_score == Decimal("243.00")
    assert len(report.visible_leaders) == 4
    assert all(item.stable for item in report.visible_leaders)
    assert all(item.position is not None and item.position < 0 for item in report.visible_leaders)
    assert len(report.candidates) == 1
    candidate = report.candidates[0]
    assert candidate.taker_side == "buy"
    assert candidate.qty == Decimal("44.00")
    assert candidate.visible_leader_coverage == 4
    assert candidate.dynamic_condition == "above"
    assert Decimal("226") < candidate.dynamic_top3_price < Decimal("227")
    assert candidate.required_cash < Decimal("10000")
    assert candidate.flat_target_score == Decimal("235.00")
    assert candidate.base_fee_flat_exit_price is not None
    assert candidate.base_fee_flat_exit_price > candidate.px
    assert candidate.base_fee_flat_move_percent > Decimal("0")
    assert candidate.victory_target_score == Decimal("243.00")
    assert candidate.base_fee_victory_exit_price is not None
    assert candidate.base_fee_victory_move_percent is not None
    assert candidate.base_fee_victory_exit_price > candidate.base_fee_flat_exit_price
    assert candidate.base_fee_victory_move_percent > candidate.base_fee_flat_move_percent
    assert "clawback" in candidate.warning


def test_scanner_keeps_stable_shadow_longs_after_they_fall_out_of_latest_top(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms_with_shadow_longs()
    offer, _, _ = _offer()

    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        negotiation_rooms={"close1-offers": {"messages": [offer]}},
    )

    shadow = [item for item in report.visible_leaders if item.reason == "stable_shadow_leader"]
    assert {item.did for item in shadow} == set(SHADOW_LONGS)
    assert all(item.position is not None and Decimal("41") < item.position < Decimal("43") for item in shadow)
    assert all(Decimal("188") < item.score < Decimal("189") for item in shadow)

    candidate = report.candidates[0]
    assert candidate.taker_side == "buy"
    assert candidate.dynamic_condition == "above"
    # Without the omitted long cluster this fixture looks like a ~226-227 top3
    # crossover. Keeping three stable shadow longs correctly pushes the hurdle
    # far away because they re-enter the top3 on a rally.
    assert candidate.dynamic_top3_price > Decimal("400")


def test_scanner_builds_same_side_basket_from_verified_offers(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms()
    offers = [
        _offer(trade_id="leg-a", qty="10.00", px="220.00", side="sell", key_byte=0x34)[0],
        _offer(trade_id="leg-b", qty="10.00", px="221.00", side="sell", key_byte=0x35)[0],
        _offer(trade_id="leg-c", qty="10.00", px="222.00", side="sell", key_byte=0x36)[0],
    ]

    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        negotiation_rooms={"close1-offers": {"messages": offers}},
    )

    assert report.strategy_gate == "ready"
    assert len(report.baskets) == 1
    basket = report.baskets[0]
    assert basket.taker_side == "buy"
    assert basket.qty == Decimal("30.00")
    assert basket.weighted_px == Decimal("221.00")
    assert len(basket.legs) == 3
    assert [leg.trade_id for leg in basket.legs] == ["leg-a", "leg-b", "leg-c"]
    assert basket.required_cash < Decimal("10000")
    assert basket.dynamic_top3_price is not None
    assert basket.flat_target_score == Decimal("235.00")
    assert basket.base_fee_flat_exit_price is not None
    assert basket.base_fee_flat_exit_price > basket.weighted_px
    assert basket.base_fee_flat_move_percent > Decimal("0")
    assert basket.victory_target_score == Decimal("243.00")
    assert basket.base_fee_victory_exit_price is not None
    assert basket.base_fee_victory_move_percent is not None
    assert basket.base_fee_victory_exit_price > basket.base_fee_flat_exit_price
    assert basket.base_fee_victory_move_percent > basket.base_fee_flat_move_percent
    assert abs(basket.move_percent_from_mark) < min(
        abs(candidate.move_percent_from_mark)
        for candidate in report.candidates
        if candidate.move_percent_from_mark is not None
    )
    assert "separate binding trade" in basket.warning


def test_basket_stays_within_cash_and_uses_at_most_one_leg_per_maker(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms()
    offers = [
        # Same maker: the better-priced offer should win and the other must not
        # be stacked as independent collateral.
        _offer(trade_id="maker-a-best", qty="10.00", px="220.00", side="sell", key_byte=0x34)[0],
        _offer(trade_id="maker-a-worse", qty="10.00", px="221.50", side="sell", key_byte=0x34)[0],
        _offer(trade_id="leg-b", qty="10.00", px="221.00", side="sell", key_byte=0x35)[0],
        _offer(trade_id="leg-c", qty="10.00", px="222.00", side="sell", key_byte=0x36)[0],
        _offer(trade_id="leg-d", qty="10.00", px="223.00", side="sell", key_byte=0x37)[0],
        _offer(trade_id="leg-e", qty="10.00", px="224.00", side="sell", key_byte=0x38)[0],
    ]

    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        negotiation_rooms={"close1-offers": {"messages": offers}},
    )

    basket = report.baskets[0]
    assert basket.required_cash <= Decimal("10000")
    assert basket.qty == Decimal("40.00")
    assert len(basket.legs) == 4
    assert len({leg.trade_id for leg in basket.legs}) == 4
    assert len({leg.maker for leg in basket.legs}) == 4
    ids = {leg.trade_id for leg in basket.legs}
    assert "maker-a-best" in ids
    assert "maker-a-worse" not in ids
    assert "leg-e" not in ids
    assert "one leg per maker" in basket.warning


def test_scanner_omits_baskets_when_current_position_is_nonzero(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms()
    offers = [
        _offer(trade_id="leg-a", qty="4.00", px="220.00", side="sell", key_byte=0x34)[0],
        _offer(trade_id="leg-b", qty="4.00", px="221.00", side="sell", key_byte=0x35)[0],
    ]

    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        negotiation_rooms={"close1-offers": {"messages": offers}},
        current_position="1.00",
    )

    assert report.baskets == ()


def test_dynamic_top3_never_drops_below_zero_score_floor(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms()
    offer, _, _ = _offer(qty="4.00", px="227.40", side="sell")

    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        negotiation_rooms={"close1-offers": {"messages": [offer]}},
    )

    candidate = report.candidates[0]
    assert candidate.taker_side == "buy"
    # A 4-contract long cannot be called top3 while its own projected score is
    # negative merely because the currently visible short leaders turn negative.
    # Base-fee break-even is 227.40 * 1.01 = 229.674.
    assert Decimal("229.67") <= candidate.dynamic_top3_price < Decimal("229.68")
    assert candidate.dynamic_condition == "above"
    assert "zero-score floor" in candidate.warning


def test_scanner_excludes_offer_id_already_seen_as_countersigned_trade(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms()
    offer, key, terms = _offer()
    trade = _trade_for_offer(offer, key, terms)

    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        negotiation_rooms={"close1-offers": {"messages": [offer, trade]}},
    )

    assert report.sampled_trade_ids == 1
    assert report.verified_offers == 0
    assert report.candidates == ()


def test_fake_trade_with_invalid_taker_signature_does_not_suppress_offer(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms()
    offer, key, terms = _offer()
    fake_trade = _trade_for_offer(offer, key, terms, valid_taker_sig=False)

    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        negotiation_rooms={"close1-offers": {"messages": [offer, fake_trade]}},
    )

    assert report.sampled_trade_ids == 0
    assert report.verified_offers == 1
    assert len(report.candidates) == 1


def test_scanner_aggregates_recent_verified_gross_taker_flow(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms()

    offer_a, key_a, terms_a = _offer(
        trade_id="flow-a",
        qty="20.00",
        px="223.50",
        side="sell",
        key_byte=0x34,
    )
    offer_b, key_b, terms_b = _offer(
        trade_id="flow-b",
        qty="25.00",
        px="223.70",
        side="sell",
        key_byte=0x35,
    )
    offer_old, key_old, terms_old = _offer(
        trade_id="flow-old",
        qty="99.00",
        px="223.60",
        side="sell",
        key_byte=0x36,
    )
    trade_a = _trade_for_offer(
        offer_a, key_a, terms_a,
        taker_key_byte=0x45,
        seq=60,
        ts="2026-09-26T12:20:00Z",
    )
    trade_b = _trade_for_offer(
        offer_b, key_b, terms_b,
        taker_key_byte=0x45,
        seq=61,
        ts="2026-09-26T12:24:00Z",
    )
    trade_old = _trade_for_offer(
        offer_old, key_old, terms_old,
        taker_key_byte=0x45,
        seq=10,
        ts="2026-09-26T11:00:00Z",
    )

    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        negotiation_rooms={
            "close1": {"messages": [trade_a]},
            "close1-offers": {"messages": [trade_a, trade_b, trade_old]},
        },
    )

    assert report.sampled_trade_ids == 3
    assert len(report.recent_flows) == 1
    flow = report.recent_flows[0]
    assert flow.taker_side == "buy"
    assert flow.qty == Decimal("45.00")
    assert flow.trades == 2
    assert flow.min_px == Decimal("223.50")
    assert flow.max_px == Decimal("223.70")
    assert flow.latest_ts == "2026-09-26T12:24:00Z"


def test_scanner_separates_opposite_taker_directions(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms()

    sell_offer, sell_key, sell_terms = _offer(
        trade_id="flow-buy",
        qty="20.00",
        px="223.50",
        side="sell",
        key_byte=0x34,
    )
    buy_offer, buy_key, buy_terms = _offer(
        trade_id="flow-sell",
        qty="22.00",
        px="224.50",
        side="buy",
        key_byte=0x35,
    )
    trade_buy = _trade_for_offer(
        sell_offer, sell_key, sell_terms,
        taker_key_byte=0x45,
        seq=60,
        ts="2026-09-26T12:20:00Z",
    )
    trade_sell = _trade_for_offer(
        buy_offer, buy_key, buy_terms,
        taker_key_byte=0x45,
        seq=61,
        ts="2026-09-26T12:21:00Z",
    )

    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        negotiation_rooms={"close1-offers": {"messages": [trade_buy, trade_sell]}},
    )

    assert {(row.taker_side, row.qty) for row in report.recent_flows} == {
        ("buy", Decimal("20.00")),
        ("sell", Decimal("22.00")),
    }


def test_scanner_stops_candidates_when_reference_is_stale(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms(age=121)
    offer, _, _ = _offer()

    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        negotiation_rooms={"close1-offers": {"messages": [offer]}},
    )

    assert report.strategy_gate == "reference_stale"
    assert report.verified_offers == 1
    assert report.candidates == ()


def test_scanner_does_not_claim_dynamic_hurdle_with_incomplete_leader_history(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms(newest_only_leader=LEADERS[2])
    offer, _, _ = _offer()

    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        negotiation_rooms={"close1-offers": {"messages": [offer]}},
    )

    assert report.strategy_gate == "leader_coverage_incomplete"
    assert len(report.candidates) == 1
    assert report.candidates[0].dynamic_top3_price is None
    assert report.candidates[0].visible_leader_coverage == 3


def test_scanner_skips_offer_that_cannot_cover_collateral_and_base_fee(monkeypatch):
    _verify_referee_with_fixture(monkeypatch)
    price, pnl = _rooms()
    offer, _, _ = _offer(qty="45.00")

    report = scanner.build_candidate_scan(
        our_did=OUR_DID,
        price_room=price,
        pnl_room=pnl,
        negotiation_rooms={"close1-offers": {"messages": [offer]}},
    )

    assert report.verified_offers == 1
    assert report.candidates == ()


def test_fetch_candidate_scan_reads_only_expected_public_rooms(monkeypatch):
    price, pnl = _rooms()
    calls = []
    payloads = {
        "d-close1-price": price,
        "d-close1-pnl": pnl,
        "d-close1-positions": _positions_room(),
        "close1": {"messages": []},
        "close1-offers": {"messages": []},
    }

    monkeypatch.setattr(scanner.core, "read_room", lambda room, limit: calls.append((room, limit)) or payloads[room])
    monkeypatch.setattr(scanner.public_record, "verify_signed_record", lambda room, message: None)

    report = scanner.fetch_candidate_scan(our_did=OUR_DID)

    assert report.candidates == ()
    assert report.recent_flows == ()
    assert report.max_visible_abs_position == Decimal("46.30")
    assert calls == [
        ("d-close1-price", 2),
        ("d-close1-pnl", 36),
        ("d-close1-positions", 2),
        ("close1", 200),
        ("close1-offers", 200),
    ]
