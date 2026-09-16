import json
from contextlib import nullcontext

import pytest

from flop_agent import sonnet_registration_receipt_replay_20260916 as replay


@pytest.fixture
def state_root(monkeypatch, tmp_path):
    (tmp_path / "signer").mkdir()
    monkeypatch.setattr(replay.core, "STATE", tmp_path)
    monkeypatch.setattr(replay, "verify_signed_record", lambda room, row: None)
    monkeypatch.setattr(replay, "replay_lock", lambda: nullcontext())
    return tmp_path


def test_payload_is_exact_existing_registration():
    assert replay.PAYLOAD == {
        "type": "sonnet.register.v1",
        "contest_id": "sonnet-2",
        "role": "writer",
        "x_account_url": "https://x.com/MinerMaru73",
        "request_id": "32c15433c6d73af1cea5d6467dece016",
    }
    assert replay.REFEREE_DID == "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"


def test_individual_and_batch_receipt_matching_is_exact():
    individual = {
        "type": "sonnet.receipt.v1",
        "request_id": replay.REQUEST_ID,
        "sender_did": replay.DID,
        "status": "accepted",
        "intake_seq": 123,
    }
    assert replay._receipt_item(individual) == individual
    wrong = dict(individual, sender_did="did:key:z6MkWrong")
    assert replay._receipt_item(wrong) is None
    missing_did = {k: v for k, v in individual.items() if k != "sender_did"}
    assert replay._receipt_item(missing_did) is None

    target = {
        "request_id": replay.REQUEST_ID,
        "participant_did": replay.DID,
        "status": "rejected",
        "reason": "example",
    }
    batch = {"type": "sonnet.receipts.v1", "receipts": [{"request_id": "x"}, target]}
    assert replay._receipt_item(batch) == target


def test_new_state_is_pre_attempt(state_root):
    state = replay.new_state()
    replay.save(state)
    loaded = replay.load()
    assert loaded["state"] == "new"
    assert loaded["nonce"] is None
    assert loaded["attempted_at"] is None
    assert loaded["post_seq"] is None
    assert loaded["receipt"] is None


def test_visible_official_receipt_resolves_without_sign_or_post(monkeypatch, state_root):
    row = {
        "from": replay.REFEREE_DID,
        "nonce": "1",
        "sig": "s" * 86,
        "seq": 900,
        "ts": "2026-09-16T00:00:00Z",
        "text": json.dumps({
            "type": "sonnet.receipt.v1",
            "request_id": replay.REQUEST_ID,
            "participant_did": replay.DID,
            "status": "accepted",
            "intake_seq": 800,
        }),
    }
    monkeypatch.setattr(replay, "require_identity", lambda: None)
    monkeypatch.setattr(replay, "_read_tail", lambda *args, **kwargs: ([row], 900, 900))
    monkeypatch.setattr(replay, "_sign", lambda *args: (_ for _ in ()).throw(AssertionError("must not sign")))
    result = replay.run_once()
    assert result["action"] == "resolved"
    assert result["status"] == "accepted"
    assert replay.load()["state"] == "resolved"


def test_attempt_marker_precedes_single_post_and_receipt_resolves(monkeypatch, state_root):
    replay.save(replay.new_state())
    monkeypatch.setattr(replay, "require_identity", lambda: None)
    monkeypatch.setattr(replay, "require_prepost", lambda: None)
    monkeypatch.setattr(replay.core, "clean_text", lambda value: value)
    monkeypatch.setattr(replay.core, "make_nonce", lambda room, did: "12345")
    monkeypatch.setattr(replay, "_sign", lambda nonce, text: [replay.DID, "sig"])

    polls = {"n": 0}
    receipt_row = {
        "from": replay.REFEREE_DID,
        "nonce": "222",
        "sig": "r" * 86,
        "seq": 1002,
        "ts": "2026-09-16T00:00:02Z",
        "text": json.dumps({
            "type": "sonnet.receipt.v1",
            "request_id": replay.REQUEST_ID,
            "sender_did": replay.DID,
            "status": "accepted",
            "intake_seq": 1001,
        }),
    }

    def read_tail(since=None, *, wait=0):
        if since is None:
            return [], 1000, None
        polls["n"] += 1
        return [receipt_row], 1002, 1002

    monkeypatch.setattr(replay, "_read_tail", read_tail)

    class Response:
        def raise_for_status(self): return None
        def json(self):
            return {"posted": {
                "from": replay.DID,
                "nonce": "12345",
                "text": replay.render(),
                "sig": "sig",
                "seq": 1001,
                "ts": "2026-09-16T00:00:01Z",
            }}

    calls = []
    def post(*args, **kwargs):
        durable = replay.load()
        assert durable["state"] == "attempting"
        assert durable["attempted_at"] is not None
        calls.append((args, kwargs))
        return Response()

    monkeypatch.setattr(replay.core.httpx, "post", post)
    result = replay.run_once()
    assert len(calls) == 1
    assert polls["n"] == 1
    assert result["action"] == "resolved"
    assert result["status"] == "accepted"
    assert replay.load()["state"] == "resolved"


def test_transport_failure_is_terminal_ambiguous(monkeypatch, state_root):
    replay.save(replay.new_state())
    monkeypatch.setattr(replay, "require_identity", lambda: None)
    monkeypatch.setattr(replay, "require_prepost", lambda: None)
    monkeypatch.setattr(replay, "_read_tail", lambda *args, **kwargs: ([], 1000, None))
    monkeypatch.setattr(replay.core, "clean_text", lambda value: value)
    monkeypatch.setattr(replay.core, "make_nonce", lambda room, did: "12345")
    monkeypatch.setattr(replay, "_sign", lambda nonce, text: [replay.DID, "sig"])
    monkeypatch.setattr(replay.core.httpx, "post", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(replay.ReplayError, match="submission_unknown"):
        replay.run_once()
    assert replay.load()["state"] == "ambiguous"
    with pytest.raises(replay.ReplayError, match="already_consumed"):
        replay.run_once()


def test_source_has_no_generic_cli_or_new_request_id_generation():
    source = open("src/flop_agent/sonnet_registration_receipt_replay_20260916.py", encoding="utf-8").read()
    assert "secrets.token_hex(16)" not in source
    assert "registration receipt replay accepts no arguments" in source
    assert "REQUEST_ID = \"32c15433c6d73af1cea5d6467dece016\"" in source
