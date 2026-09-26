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


def _offer(*, trade_id="live1", qty="44.00", px="224.33", side="sell", until=10):
    key = Ed25519PrivateKey.from_private_bytes(b"\x33" * 32)
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


def _trade_for_offer(offer, key, terms):
    payload = {
        "t": "trade",
        "season": "close-1",
        "terms": terms,
        "taker": OUR_DID,
        "maker_sig": json.loads(offer["text"])["maker_sig"],
        "taker_sig": "A" * 86,
    }
    text = json.dumps(payload, separators=(",", ":"))
    nonce = 12346
    return {
        "seq": 51,
        "ts": "2026-09-26T12:10:01Z",
        "from": offer["from"],
        "text": text,
        "nonce": nonce,
        "sig": _sig(key, f"close1-offers|{nonce}|{text}"),
    }


def _verify_referee_with_fixture(monkeypatch):
    original = public_record.verify_signed_record

    def verify(room, message):
        if room in {"d-close1-price", "d-close1-pnl"}:
            assert message["from"] == close_call.REFEREE_DID
            return None
        return original(room, message)

    monkeypatch.setattr(public_record, "verify_signed_record", verify)


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
    assert "clawback" in candidate.warning


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
        "close1": {"messages": []},
        "close1-offers": {"messages": []},
    }

    monkeypatch.setattr(scanner.core, "read_room", lambda room, limit: calls.append((room, limit)) or payloads[room])
    monkeypatch.setattr(scanner.public_record, "verify_signed_record", lambda room, message: None)

    report = scanner.fetch_candidate_scan(our_did=OUR_DID)

    assert report.candidates == ()
    assert calls == [
        ("d-close1-price", 2),
        ("d-close1-pnl", 12),
        ("close1", 200),
        ("close1-offers", 200),
    ]
