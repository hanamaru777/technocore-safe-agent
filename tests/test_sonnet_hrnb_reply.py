import json
import sys
from contextlib import nullcontext
from datetime import UTC, datetime

import pytest

from flop_agent import core, oracle_signer
from flop_agent import sonnet_hrnb_reply as lane


@pytest.fixture
def environment(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    (tmp_path / "signer").mkdir()
    monkeypatch.setattr(lane, "reply_lock", nullcontext)
    monkeypatch.setattr(lane, "require_identity", lambda: None)
    monkeypatch.setattr(lane, "require_health", lambda: None)
    monkeypatch.setattr(lane, "require_registration_posted", lambda: None)
    monkeypatch.setattr(lane, "verify_signed_record", lambda *args, **kwargs: None)
    monkeypatch.setattr(oracle_signer, "with_vault_seed", lambda callback: callback())

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 9, 15, 4, 30, tzinfo=UTC)

    monkeypatch.setattr(lane, "datetime", Clock)

    source = {
        "from": lane.TARGET_DID,
        "nonce": "1789446281418",
        "text": json.dumps(lane.SOURCE_PAYLOAD, separators=(",", ":")),
        "sig": "source-sig",
        "seq": lane.SOURCE_SEQ,
        "ts": "2026-09-15T04:24:43.212561Z",
    }
    rows, posts, signs = [], [], []

    def read(room, **kwargs):
        assert room == lane.ROOM
        assert kwargs.get("cache_buster")
        if "since" in kwargs:
            assert kwargs["since"] == lane.SOURCE_SEQ - 1
            assert kwargs["limit"] == 20
            return {"messages": [source]}
        assert kwargs["limit"] == 200
        return {"messages": rows}

    monkeypatch.setattr(core, "read_room", read)

    def sign(*args):
        assert args[0] == "say" and args[1] == lane.ROOM
        signs.append(args)
        return [lane.DID, "reply-sig"]

    monkeypatch.setattr(core, "invoke_signer", sign)

    seq = {"value": 99000}

    def post(url, *, json, timeout):
        assert url == f"{core.BASE_URL}/r/{lane.ROOM}?format=json"
        assert lane.load()["state"] == "attempting"
        posts.append(json)
        seq["value"] += 1
        row = {
            "from": lane.DID,
            "nonce": json["nonce"],
            "text": json["text"],
            "sig": json["sig"],
            "seq": seq["value"],
            "ts": Clock.now().isoformat(),
        }
        rows.append(row)
        return core.httpx.Response(
            200,
            json={"posted": row},
            request=core.httpx.Request("POST", url),
        )

    monkeypatch.setattr(core.httpx, "post", post)
    return source, rows, posts, signs


def test_fixed_payload_is_nonbinding_and_does_not_claim_acceptance():
    assert lane.REQUEST_ID == "maru-hrnb-reply-20260915-1"
    assert lane.SOURCE_SEQ == 98320
    assert lane.SOURCE_REQUEST_ID == "hrnb-hunt-1789446281-152"
    assert lane.PAYLOAD["target_did"] == lane.TARGET_DID
    assert lane.PAYLOAD["no_live_roster_consent"] is True
    assert "not claiming accepted status" in lane.PAYLOAD["text"]
    assert "not roster consent" in lane.PAYLOAD["text"]
    assert "registration_receipt_seq" not in lane.PAYLOAD


def test_source_offer_is_exactly_bound(environment):
    source, _, _, _ = environment
    assert lane.require_source_offer() == source


def test_source_offer_mismatch_blocks_before_sign(environment, monkeypatch):
    _, _, posts, signs = environment

    def bad_read(room, **kwargs):
        if "since" in kwargs:
            return {"messages": []}
        return {"messages": []}

    monkeypatch.setattr(core, "read_room", bad_read)
    with pytest.raises(lane.ReplyError, match="source_offer_missing"):
        lane.run_once()
    assert posts == signs == []


def test_posts_exactly_once(environment):
    _, _, posts, signs = environment
    result = lane.run_once()
    assert result["status"] == "posted"
    assert len(posts) == len(signs) == 1
    assert json.loads(posts[0]["text"]) == lane.PAYLOAD

    second = lane.run_once()
    assert second["status"] in {"reconciled", "already_posted"}
    assert len(posts) == len(signs) == 1


def test_ambiguity_is_terminal(environment, monkeypatch):
    _, _, posts, signs = environment

    def fail(*args, **kwargs):
        posts.append(kwargs["json"])
        raise core.httpx.ConnectTimeout("dummy")

    monkeypatch.setattr(core.httpx, "post", fail)
    with pytest.raises(lane.ReplyError, match="submission_unknown"):
        lane.run_once()
    assert lane.load()["state"] == "ambiguous"
    before = (len(posts), len(signs))
    result = lane.run_once()
    assert result["status"] == "ambiguous"
    assert (len(posts), len(signs)) == before


def test_cli_args_rejected(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["sonnet_hrnb_reply", "extra"])
    monkeypatch.setattr(lane, "run_once", lambda: pytest.fail("must not execute"))
    with pytest.raises(SystemExit):
        lane.main()
