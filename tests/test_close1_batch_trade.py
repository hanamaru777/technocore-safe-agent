import base64
import json
from contextlib import nullcontext
from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flop_agent import close1_account_reconciliation as account
from flop_agent import close1_approved_trade as single
from flop_agent import close1_batch_trade as batch
from flop_agent import close_call, core, oracle_signer, public_record


def did(key):
    raw = b"\xed\x01" + key.public_key().public_bytes_raw()
    number, encoded = int.from_bytes(raw, "big"), ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = public_record.B58[remainder] + encoded
    return "did:key:z" + encoded


def sig(key, text):
    return base64.urlsafe_b64encode(key.sign(text.encode())).rstrip(b"=").decode()


def room_record(key, room, payload, seq):
    text = json.dumps(payload, separators=(",", ":"))
    return {
        "from": did(key), "text": text, "nonce": str(seq), "seq": seq,
        "sig": sig(key, f"{room}|{seq}|{text}"),
        "ts": "2026-09-26T04:40:00Z",
    }


def make_leg(key, trade_id, seq, px="200.00", side="sell", qty="2.00"):
    terms = {
        "id": trade_id, "maker": did(key), "side": side, "qty": qty,
        "px": px, "taker": "any", "until": 205,
    }
    return {
        "offer_room": "close1-offers", "offer_seq": seq, "trade_id": trade_id,
        "maker": terms["maker"], "maker_side": side,
        "taker_side": "buy" if side == "sell" else "sell",
        "qty": qty, "px": px, "until": 205,
        "maker_sig": sig(key, close_call.maker_signature_preimage(terms)),
    }


@pytest.fixture
def env(monkeypatch, tmp_path):
    owner_key, maker1, maker2, referee = (Ed25519PrivateKey.generate() for _ in range(4))
    owner = did(owner_key)
    monkeypatch.setattr(batch, "OWNER_DID", owner)
    monkeypatch.setattr(single, "OWNER_DID", owner)
    monkeypatch.setattr(account, "OWNER_DID", owner)
    monkeypatch.setattr(close_call, "REFEREE_DID", did(referee))
    monkeypatch.setattr(core, "STATE", tmp_path)
    (tmp_path / "close1").mkdir()
    monkeypatch.setattr(batch, "_lock", nullcontext)
    monkeypatch.setattr(oracle_signer, "expected_did", lambda: owner)
    monkeypatch.setattr(core, "require_verified_did", lambda value: None)
    monkeypatch.setattr(core, "signer_matches_pinned", lambda: True)
    now = close_call.OPENING + timedelta(seconds=300 * 200 + 60)
    monkeypatch.setattr(batch, "_now", lambda: now)
    monkeypatch.setattr(single, "_now", lambda: now)
    legs = [make_leg(maker1, "batch-one", 12), make_leg(maker2, "batch-two", 13, px="201.00")]
    approval = {
        "schema_version": 1, "owner_did": owner, "legs": legs,
        "approved_at": now.isoformat(),
    }
    price = {
        "t": "price", "n": 200, "age_s": 10,
        "ref": {"px": "200.00", "time": (now - timedelta(seconds=10)).isoformat()},
    }
    state = SimpleNamespace(
        owner=owner, owner_key=owner_key, makers=[maker1, maker2],
        approval=approval, price=price, posts=[], materials=[], post_fail_at=None,
    )

    def write():
        batch.approval_path().parent.mkdir(parents=True, exist_ok=True)
        batch.approval_path().write_text(json.dumps(state.approval), encoding="utf-8")
    state.write = write
    write()

    def read(room, **kwargs):
        if room == "d-close1-price":
            return {"messages": [room_record(referee, room, state.price, 99)]}
        rows = []
        for key, leg in zip(state.makers, state.approval["legs"], strict=True):
            terms = {
                "id": leg["trade_id"], "maker": leg["maker"], "side": leg["maker_side"],
                "qty": leg["qty"], "px": leg["px"], "taker": "any", "until": leg["until"],
            }
            payload = {"t": "offer", "season": "close-1", "terms": terms, "maker_sig": leg["maker_sig"]}
            rows.append(room_record(key, room, payload, leg["offer_seq"]))
        return {"messages": rows}
    monkeypatch.setattr(core, "read_room", read)
    def vault():
        material = bytearray(owner_key.private_bytes_raw().hex().encode())
        state.materials.append(material)
        return material
    monkeypatch.setattr(oracle_signer, "vault_seed", vault)

    def post(url, **kwargs):
        body = deepcopy(kwargs["json"])
        trade_id = json.loads(body["text"])["terms"]["id"]
        state.posts.append(trade_id)
        assert trade_id in account.load_ledger(owner_did=owner)["pending_trades"]
        if state.post_fail_at == len(state.posts):
            raise RuntimeError("network")
        row = {
            "from": body["did"], "text": body["text"], "nonce": body["nonce"],
            "sig": body["sig"], "seq": 50 + len(state.posts), "ts": now.isoformat(),
        }
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"posted": row})
    monkeypatch.setattr(core.httpx, "post", post)
    return state


def blocked(env):
    with pytest.raises(batch.BatchTradeError):
        batch.run_once()


def test_two_leg_happy_path_posts_once_each_and_marks_both_pending(env):
    result = batch.run_once()
    assert result["status"] == "posted"
    assert env.posts == ["batch-one", "batch-two"]
    ledger = account.load_ledger(owner_did=env.owner)
    assert ledger["pending_trade_ids"] == ["batch-one", "batch-two"]
    assert len(result["receipts"]) == 2
    assert env.materials and all(not any(material) for material in env.materials)


def test_aggregate_insufficient_cash_fails_before_sign_or_post(env):
    env.approval["legs"][0]["qty"] = "30.00"
    env.approval["legs"][1]["qty"] = "30.00"
    for key, leg in zip(env.makers, env.approval["legs"], strict=True):
        terms = {
            "id": leg["trade_id"], "maker": leg["maker"], "side": leg["maker_side"],
            "qty": leg["qty"], "px": leg["px"], "taker": "any", "until": leg["until"],
        }
        leg["maker_sig"] = sig(key, close_call.maker_signature_preimage(terms))
    env.write()
    blocked(env)
    assert not env.posts
    assert not env.materials


def test_duplicate_maker_fails_before_sign_or_post(env):
    env.approval["legs"][1]["maker"] = env.approval["legs"][0]["maker"]
    env.approval["legs"][1]["maker_sig"] = env.approval["legs"][0]["maker_sig"]
    env.write()
    blocked(env)
    assert not env.posts
    assert not env.materials


def test_mixed_side_fails_before_sign_or_post(env):
    leg = env.approval["legs"][1]
    leg["maker_side"] = "buy"
    leg["taker_side"] = "sell"
    terms = {
        "id": leg["trade_id"], "maker": leg["maker"], "side": "buy",
        "qty": leg["qty"], "px": leg["px"], "taker": "any", "until": leg["until"],
    }
    leg["maker_sig"] = sig(env.makers[1], close_call.maker_signature_preimage(terms))
    env.write()
    blocked(env)
    assert not env.posts
    assert not env.materials


def test_ambiguous_first_leg_stops_before_later_leg(env):
    env.post_fail_at = 1
    with pytest.raises(batch.BatchTradeError, match="ambiguous"):
        batch.run_once()
    assert env.posts == ["batch-one"]
    ledger = account.load_ledger(owner_did=env.owner)
    assert ledger["pending_trade_ids"] == ["batch-one"]


def test_ambiguous_second_leg_stops_without_retry(env):
    env.post_fail_at = 2
    with pytest.raises(batch.BatchTradeError, match="ambiguous"):
        batch.run_once()
    assert env.posts == ["batch-one", "batch-two"]
    ledger = account.load_ledger(owner_did=env.owner)
    assert ledger["pending_trade_ids"] == ["batch-one", "batch-two"]


def test_stale_batch_approval_blocks_before_sign(env):
    env.approval["approved_at"] = (batch._now() - timedelta(seconds=301)).isoformat()
    env.write()
    blocked(env)
    assert not env.posts
    assert not env.materials

def test_invalid_terms_fail_closed_before_sign(env):
    env.approval["legs"][0]["maker_side"] = "BUY"
    env.write()
    blocked(env)
    assert not env.posts
    assert not env.materials


def test_batch_service_is_static_fixed_function_and_installed():
    from pathlib import Path
    root = Path("packaging/oracle")
    unit = (root / "technocore-safe-agent-close1-batch-trade.service").read_text("utf-8")
    assert "Type=oneshot" in unit
    assert "User=technocore-signer" in unit
    assert "SupplementaryGroups=technocore-autopilot" in unit
    assert "python -m flop_agent.close1_batch_trade" in unit
    assert "NoNewPrivileges=true" in unit
    assert "ProtectSystem=strict" in unit
    prepare = (root / "prepare-signer.sh").read_text("utf-8")
    assert "technocore-safe-agent-close1-batch-trade.service" in prepare
