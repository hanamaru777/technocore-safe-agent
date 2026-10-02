import base64
import json
import sys
import traceback
from contextlib import nullcontext
from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flop_agent import close1_approved_trade as executor
from flop_agent import close1_account_reconciliation as account
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


def record(key, room, payload, seq=12):
    text = json.dumps(payload, separators=(",", ":"))
    return {"from": did(key), "text": text, "nonce": "123", "seq": seq,
            "sig": sig(key, f"{room}|123|{text}"), "ts": "2026-09-26T04:40:00Z"}


@pytest.fixture
def env(monkeypatch, tmp_path):
    owner_key, maker_key, referee_key = (Ed25519PrivateKey.generate() for _ in range(3))
    owner = did(owner_key)
    monkeypatch.setattr(executor, "OWNER_DID", owner)
    monkeypatch.setattr(account, "OWNER_DID", owner)
    monkeypatch.setattr(close_call, "REFEREE_DID", did(referee_key))
    monkeypatch.setattr(core, "STATE", tmp_path)
    (tmp_path / "close1").mkdir()
    monkeypatch.setattr(executor, "_lock", nullcontext)
    monkeypatch.setattr(oracle_signer, "expected_did", lambda: owner)
    monkeypatch.setattr(core, "require_verified_did", lambda value: None if value == owner else pytest.fail("wrong DID"))
    monkeypatch.setattr(core, "signer_matches_pinned", lambda: True)
    now = close_call.OPENING + timedelta(seconds=300 * 200 + 60)
    monkeypatch.setattr(executor, "_now", lambda: now)
    terms = {"id": "exact-offer", "maker": did(maker_key), "side": "sell",
             "qty": "2.00", "px": "200.00", "taker": "any", "until": 205}
    maker_sig = sig(maker_key, close_call.maker_signature_preimage(terms))
    approval = {"schema_version": 1, "owner_did": owner, "offer_room": "close1-offers",
                "offer_seq": 12, "trade_id": terms["id"], "maker": terms["maker"],
                "maker_side": "sell", "taker_side": "buy", "qty": terms["qty"],
                "px": terms["px"], "until": terms["until"], "maker_sig": maker_sig,
                "approved_at": now.isoformat()}
    payload = {"t": "offer", "season": "close-1", "terms": terms, "maker_sig": maker_sig}
    price = {"t": "price", "n": 200, "age_s": 10,
             "ref": {"px": "200.00", "time": (now - timedelta(seconds=10)).isoformat()}}
    value = SimpleNamespace(approval=approval, terms=terms, payload=payload, price=price,
                            now=now, owner=owner, owner_key=owner_key, maker_key=maker_key,
                            referee_key=referee_key, calls=[], posts=[], events=[], materials=[],
                            reads=[], offer_override=None)
    def write():
        executor.approval_path().parent.mkdir(parents=True, exist_ok=True)
        executor.approval_path().write_text(json.dumps(value.approval), encoding="utf-8")
    value.write = write
    write()
    def read(room, **kwargs):
        value.reads.append((room, kwargs))
        value.events.append("read")
        if room == "d-close1-price":
            return {"messages": [record(referee_key, room, value.price)]}
        if value.offer_override is not None:
            return {"messages": value.offer_override}
        return {"messages": [record(maker_key, room, value.payload)]}
    monkeypatch.setattr(core, "read_room", read)
    def vault():
        value.events.append("sign")
        material = bytearray(owner_key.private_bytes_raw().hex().encode())
        value.materials.append(material)
        return material
    monkeypatch.setattr(oracle_signer, "vault_seed", vault)
    monkeypatch.setattr(account, "_read_bounded", lambda *_: (_ for _ in ()).throw(OSError("offline")))
    original_mark = account.mark_pending
    def mark(*args, **kwargs):
        value.events.append("pending")
        assert value.materials and not any(value.materials[-1])
        return original_mark(*args, **kwargs)
    monkeypatch.setattr(account, "mark_pending", mark)
    def post(url, **kwargs):
        value.events.append("post")
        assert url == "https://technocore.chat/r/close1?format=json"
        assert kwargs["follow_redirects"] is False
        assert value.terms["id"] in account.load_ledger(owner_did=owner)["pending_trades"]
        body = deepcopy(kwargs["json"])
        value.posts.append(body)
        row = {"from": body["did"], **{k: body[k] for k in ("text", "nonce", "sig")},
               "seq": 55, "ts": now.isoformat()}
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"posted": row})
    monkeypatch.setattr(core.httpx, "post", post)
    return value


def blocked(env):
    with pytest.raises(executor.TradeError):
        executor.run_once()
    assert not env.posts


@pytest.mark.parametrize("field", sorted(executor.FIELDS))
def test_missing_fields(env, field):
    del env.approval[field]
    env.write()
    blocked(env)
    assert not env.materials


@pytest.mark.parametrize("changes", [
    {"extra": True}, {"schema_version": True}, {"schema_version": 2},
    {"owner_did": "did:key:wrong"}, {"maker_side": "BUY"}, {"taker_side": "sell"},
    {"maker": "did:key:wrong"}, {"trade_id": "bad/id"}, {"qty": "0.01"},
    {"qty": 2}, {"qty": "NaN"}, {"px": "200.001"}, {"px": "0"},
    {"maker_sig": "bad"}, {"offer_seq": True}, {"offer_seq": 0},
    {"offer_room": "lobby"}, {"until": True}, {"until": 2557},
    {"approved_at": "2026-09-26T04:40:00"},
])
def test_strict_approval_validation(env, changes):
    env.approval.update(changes)
    env.write()
    blocked(env)
    assert not env.materials


def test_self_trade_and_wrong_owner(env):
    env.approval["maker"] = env.owner
    env.write()
    blocked(env)
    env.approval["maker"] = did(env.maker_key)
    env.approval["owner_did"] = did(env.maker_key)
    env.write()
    blocked(env)


@pytest.mark.parametrize("seconds", [-1, 301])
def test_stale_or_future_approval(env, seconds):
    env.approval["approved_at"] = (env.now - timedelta(seconds=seconds)).isoformat()
    env.write()
    blocked(env)


def test_duplicate_approval_field(env):
    text = executor.approval_path().read_text()
    executor.approval_path().write_text(text[:-1] + ',"schema_version":1}')
    blocked(env)


@pytest.mark.parametrize("change", ["missing", "seq", "id", "qty", "sig", "outer", "named", "expired"])
def test_exact_offer_blocks_missing_changed_or_bad_signatures(env, change):
    row = record(env.maker_key, "close1-offers", env.payload)
    if change == "missing":
        env.offer_override = []
    elif change == "seq":
        row["seq"] = 13
        env.offer_override = [row]
    elif change == "outer":
        row["sig"] = sig(env.owner_key, "wrong")
        env.offer_override = [row]
    elif change == "sig":
        env.payload["maker_sig"] = sig(env.owner_key, "wrong")
    else:
        key, value = {"id": ("id", "another"), "qty": ("qty", "2.0"),
                      "named": ("taker", env.owner), "expired": ("until", 200)}[change]
        env.payload["terms"][key] = value
    blocked(env)
    assert not env.materials


@pytest.mark.parametrize("change", ["stale", "clock_stale", "future", "limit", "sweep", "signature"])
def test_bad_price_blocks(env, monkeypatch, change):
    if change == "stale":
        env.price["age_s"] = 121
    elif change == "clock_stale":
        env.price["ref"]["time"] = (env.now - timedelta(seconds=121)).isoformat()
    elif change == "future":
        env.price["ref"]["time"] = (env.now + timedelta(seconds=1)).isoformat()
    elif change == "limit":
        env.price["ref"]["px"] = "180"
    elif change == "sweep":
        env.price["n"] = 198
    else:
        monkeypatch.setattr(close_call, "REFEREE_DID", env.owner)
    blocked(env)


@pytest.mark.parametrize("kind", ["pending", "unreconciled", "cash", "settled", "void"])
def test_own_account_blocks(env, kind):
    ledger = account.checkpoint_ledger(owner_did=env.owner)
    if kind == "pending":
        # Use the real implementation; the fixture wrapper requires signing first.
        ledger["pending_trades"]["other"] = {"search_start_sweep": 201,
            "next_search_sweep": 201, "marked_at": env.now.isoformat()}
        ledger["pending_trade_ids"] = ["other"]
        ledger["status"] = "own_state_pending"
    elif kind == "unreconciled":
        ledger["status"] = "own_state_unreconciled"
    elif kind == "cash":
        ledger["cash"] = "403.99"
    else:
        ledger["status"] = "reconciled"
        ledger["trade_evidence"][env.terms["id"]] = "a" * 64
        if kind == "settled":
            ledger["settled_trade_ids"] = [env.terms["id"]]
        else:
            ledger["void_trades"][env.terms["id"]] = "expired"
    account.save_ledger(ledger)
    blocked(env)
    assert not env.materials


def test_success_exact_signatures_order_receipt_and_second_invocation(env, tmp_path, capsys, caplog):
    result = executor.run_once()
    assert result["status"] == "posted"
    assert len(env.posts) == 1
    body = env.posts[0]
    trade = json.loads(body["text"])
    assert trade["terms"] == env.terms and trade["terms"]["taker"] == "any"
    assert trade["taker"] == env.owner and trade["maker_sig"] == env.approval["maker_sig"]
    public_record.verify_did_signature(env.owner, trade["taker_sig"],
        close_call.taker_signature_preimage(env.terms, env.owner))
    public_record.verify_signed_record("close1", {"from": env.owner, **body})
    assert env.events.index("sign") < env.events.index("pending") < env.events.index("post")
    assert len([x for x in env.events if x == "post"]) == 1
    assert len(env.reads) == 4
    assert all(kwargs["since"] == 11 and kwargs["cache_buster"] for room, kwargs in env.reads if room == "close1-offers")
    ledger = account.load_ledger(owner_did=env.owner)
    assert ledger["pending_trades"][env.terms["id"]]["search_start_sweep"] == 201
    receipts = list(executor.approval_path().parent.glob("close1-receipt-*.json"))
    assert len(receipts) == 1 and json.loads(receipts[0].read_text()) == result
    assert set(result) == {"schema_version", "owner_did", "trade_id", "approval_sha256",
                           "offer_room", "offer_seq", "room", "nonce", "status", "seq", "ts"}
    with pytest.raises(executor.TradeError):
        executor.run_once()
    assert len(env.posts) == 1
    output = capsys.readouterr()
    assert output.out == output.err == caplog.text == ""
    for path in tmp_path.rglob("*.json"):
        if path == executor.approval_path():
            continue
        text = path.read_text()
        assert body["sig"] not in text and trade["taker_sig"] not in text
        assert env.approval["maker_sig"] not in text
        assert env.owner_key.private_bytes_raw().hex() not in text


@pytest.mark.parametrize("failure", ["transport", "http", "json", "missing", "mismatch", "bool_seq", "time", "save"])
def test_ambiguous_once_pending_and_never_retry(env, monkeypatch, failure):
    original = core.httpx.post
    def post(*args, **kwargs):
        response = original(*args, **kwargs)
        if failure == "transport":
            raise core.httpx.TimeoutException("sensitive transport body")
        if failure == "http":
            response.raise_for_status = lambda: (_ for _ in ()).throw(RuntimeError("sensitive HTTP body"))
        elif failure == "json":
            response.json = lambda: (_ for _ in ()).throw(ValueError("sensitive JSON body"))
        else:
            row = response.json()["posted"]
            if failure == "missing":
                response.json = lambda: {}
            elif failure == "mismatch":
                row["text"] = "changed"
            elif failure == "bool_seq":
                row["seq"] = True
            elif failure == "time":
                row["ts"] = "invalid"
        return response
    monkeypatch.setattr(core.httpx, "post", post)
    if failure == "save":
        original_write = executor.observer.atomic_json_write
        def write(path, *args, **kwargs):
            if path.name.startswith("close1-receipt-"):
                raise OSError("disk full")
            return original_write(path, *args, **kwargs)
        monkeypatch.setattr(executor.observer, "atomic_json_write", write)
    with pytest.raises(executor.TradeError, match="^ambiguous$"):
        executor.run_once()
    assert env.terms["id"] in account.load_ledger(owner_did=env.owner)["pending_trades"]
    with pytest.raises(executor.TradeError):
        executor.run_once()
    assert len(env.posts) == 1
    assert not list(executor.approval_path().parent.glob("close1-receipt-*.json"))


def test_attempt_fence_survives_account_rollback(env):
    executor.run_once()
    account.save_ledger(account.checkpoint_ledger(owner_did=env.owner))
    for path in executor.approval_path().parent.glob("close1-receipt-*.json"):
        path.unlink()
    with pytest.raises(executor.TradeError, match="already_attempted"):
        executor.run_once()
    assert len(env.posts) == 1


def test_receipt_alone_prevents_retry(env):
    executor.run_once()
    account.save_ledger(account.checkpoint_ledger(owner_did=env.owner))
    for path in executor.approval_path().parent.glob("close1-attempt-*.json"):
        path.unlink()
    with pytest.raises(executor.TradeError, match="already_attempted"):
        executor.run_once()
    assert len(env.posts) == 1


@pytest.mark.parametrize("change", ["approval", "offer", "price", "account", "time"])
def test_changes_during_signing_block_before_pending(env, monkeypatch, change):
    original = executor._sign
    def sign(*args):
        result = original(*args)
        if change == "approval":
            executor.approval_path().write_text(executor.approval_path().read_text() + " ")
        elif change == "offer":
            env.offer_override = []
        elif change == "price":
            env.price["age_s"] = 121
        elif change == "time":
            monkeypatch.setattr(executor, "_now", lambda: env.now + timedelta(seconds=301))
        else:
            ledger = account.checkpoint_ledger(owner_did=env.owner)
            ledger["cash"] = "9999"
            account.save_ledger(ledger)
        return result
    monkeypatch.setattr(executor, "_sign", sign)
    blocked(env)
    assert "pending" not in env.events


def test_wrong_derived_did_zeroes_material_and_blocks(env, monkeypatch):
    material = bytearray(Ed25519PrivateKey.generate().private_bytes_raw().hex().encode())
    monkeypatch.setattr(oracle_signer, "vault_seed", lambda: material)
    blocked(env)
    assert not any(material)
    assert "pending" not in env.events


def test_pending_persistence_failure_never_posts(env, monkeypatch):
    monkeypatch.setattr(account, "mark_pending", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")))
    blocked(env)
    blocked(env)
    assert len(env.materials) == 1


def test_exact_reconciled_position_and_cash_are_used(env):
    ledger = account.checkpoint_ledger(owner_did=env.owner)
    ledger.update(status="reconciled", cash="4", position="-2", lots=[["-2", "200"]],
                  settled_trade_ids=["prior"], trade_evidence={"prior": "a" * 64})
    account.save_ledger(ledger)
    assert executor.run_once()["status"] == "posted"


def test_main_suppresses_sdk_material_and_arguments(env, monkeypatch, capsys, caplog):
    sensitive = env.owner_key.private_bytes_raw().hex() + env.approval["maker_sig"] + "ocid1.vaultsecret.example"
    monkeypatch.setattr(oracle_signer, "vault_seed", lambda: (_ for _ in ()).throw(RuntimeError(sensitive)))
    monkeypatch.setattr(sys, "argv", ["executor"])
    assert executor.main() == 1
    assert json.loads(capsys.readouterr().out) == {"status": "blocked", "reason": "preflight_failed"}
    with pytest.raises(executor.TradeError) as error:
        executor.run_once()
    assert sensitive not in "".join(traceback.format_exception(error.value))
    monkeypatch.setattr(sys, "argv", ["executor", sensitive])
    assert executor.main() == 1
    assert sensitive not in capsys.readouterr().out + caplog.text


def test_approval_rejects_valid_shape_but_wrong_maker_signature(env):
    env.approval["maker_sig"] = sig(env.owner_key, close_call.maker_signature_preimage(env.terms))
    env.write()
    blocked(env)
    assert not env.materials


def test_noncanonical_signature_encoding_rejected(env):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    original = env.approval["maker_sig"]
    env.approval["maker_sig"] = original[:-1] + alphabet[alphabet.index(original[-1]) + 1]
    env.write()
    blocked(env)


@pytest.mark.parametrize("scenario", ["expired", "margin", "locked"])
def test_signed_expired_offer_and_settlement_window(env, monkeypatch, scenario):
    env.terms["until"] = 200 if scenario == "expired" else 201
    if scenario == "margin":
        now = close_call.OPENING + timedelta(seconds=300 * 201 - 29)
    elif scenario == "locked":
        now = close_call.LOCK
        env.terms["until"] = close_call.LOCK_SWEEP
        env.price["n"] = close_call.LOCK_SWEEP
    else:
        now = env.now
    monkeypatch.setattr(executor, "_now", lambda: now)
    env.price["ref"]["time"] = now.isoformat()
    env.payload["maker_sig"] = sig(env.maker_key, close_call.maker_signature_preimage(env.terms))
    env.approval.update(until=env.terms["until"], maker_sig=env.payload["maker_sig"], approved_at=now.isoformat())
    env.write()
    blocked(env)
    assert not env.materials


def test_unsigned_price_blocks(env, monkeypatch):
    original = core.read_room
    def read(room, **kwargs):
        response = original(room, **kwargs)
        if room == "d-close1-price":
            del response["messages"][0]["sig"]
        return response
    monkeypatch.setattr(core, "read_room", read)
    blocked(env)


def test_conservative_anchor_across_sweep_boundary(env, monkeypatch):
    now = close_call.OPENING + timedelta(seconds=300 * 201 + 1)
    monkeypatch.setattr(executor, "_now", lambda: now)
    env.price["ref"]["time"] = (now - timedelta(seconds=5)).isoformat()
    assert executor.run_once()["status"] == "posted"
    ledger = account.load_ledger(owner_did=env.owner)
    assert ledger["pending_trades"][env.terms["id"]]["search_start_sweep"] == 201


def test_pending_failure_to_persist_blocks(env, monkeypatch):
    def pretend_mark(*args, **kwargs):
        ledger = account.load_ledger(owner_did=env.owner)
        ledger["pending_trades"][env.terms["id"]] = {}
        return ledger
    monkeypatch.setattr(account, "mark_pending", pretend_mark)
    blocked(env)
    assert len(env.materials) == 1


def test_exclusive_fence_prevents_competing_attempt(env, monkeypatch):
    original = executor._sign
    def sign(*args):
        result = original(*args)
        token = executor.hashlib.sha256(env.terms["id"].encode()).hexdigest()
        path = executor.approval_path().parent / f"close1-attempt-{token}.json"
        path.write_text("{}")
        return result
    monkeypatch.setattr(executor, "_sign", sign)
    blocked(env)
    assert "pending" not in env.events


def test_sell_side_with_original_public_terms(env):
    env.terms["side"] = "buy"
    env.payload["maker_sig"] = sig(env.maker_key, close_call.maker_signature_preimage(env.terms))
    env.approval.update(maker_side="buy", taker_side="sell", maker_sig=env.payload["maker_sig"])
    env.write()
    assert executor.run_once()["status"] == "posted"
    assert json.loads(env.posts[0]["text"])["terms"] == env.terms


def test_close1_room_is_supported(env):
    env.approval["offer_room"] = "close1"
    env.write()
    assert executor.run_once()["status"] == "posted"


def test_success_stdout_is_only_safe_receipt(env, monkeypatch, capsys, caplog):
    monkeypatch.setattr(sys, "argv", ["executor"])
    assert executor.main() == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == "posted"
    trade = json.loads(env.posts[0]["text"])
    for forbidden in [env.owner_key.private_bytes_raw().hex(), env.posts[0]["sig"],
                      trade["taker_sig"], env.approval["maker_sig"], "ocid1."]:
        assert forbidden not in output.out + output.err + caplog.text


def test_runtime_requires_isolated_linux_signer(monkeypatch):
    monkeypatch.setattr(executor, "os", SimpleNamespace(name="nt"))
    with pytest.raises(executor.TradeError, match="isolated_linux_signer_required"):
        executor.run_once()


def test_runtime_rejects_observer_user(monkeypatch):
    monkeypatch.setattr(executor, "os", SimpleNamespace(name="posix", geteuid=lambda: 1001))
    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwuid=lambda _: SimpleNamespace(pw_name="technocore")))
    with pytest.raises(executor.TradeError, match="isolated_signer_user_required"):
        executor.run_once()


def test_identity_provenance_blocks_before_vault(env, monkeypatch):
    monkeypatch.setattr(oracle_signer, "expected_did", lambda: env.terms["maker"])
    blocked(env)
    assert not env.materials
    monkeypatch.setattr(oracle_signer, "expected_did", lambda: env.owner)
    monkeypatch.setattr(core, "signer_matches_pinned", lambda: False)
    blocked(env)
    assert not env.materials


def test_approved_trade_service_is_static_fixed_function():
    from pathlib import Path
    root = Path("packaging/oracle")
    unit = (root / "technocore-safe-agent-close1-approved-trade.service").read_text("utf-8")
    assert "Type=oneshot" in unit
    assert "User=technocore-signer" in unit
    assert "SupplementaryGroups=technocore-autopilot" in unit
    assert "EnvironmentFile=/etc/technocore-safe-agent/signer.env" in unit
    assert "python -m flop_agent.close1_approved_trade" in unit
    assert "Restart=" not in unit
    paths = next(line for line in unit.splitlines() if line.startswith("ReadWritePaths=")).split("=", 1)[1].split()
    assert paths == [
        "/var/lib/technocore-safe-agent/signer",
        "/var/lib/technocore-safe-agent/nonces.json",
        "/var/lib/technocore-safe-agent/close1",
    ]
    assert all("observer" not in path and "autopilot" not in path for path in paths)
    prepare = (root / "prepare-signer.sh").read_text("utf-8")
    assert "technocore-safe-agent-close1-approved-trade.service" in prepare
