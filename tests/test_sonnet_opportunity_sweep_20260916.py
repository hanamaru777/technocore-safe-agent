import json
from pathlib import Path

import pytest

from flop_agent import sonnet_opportunity_sweep_20260916 as sweep


@pytest.fixture
def state_root(monkeypatch, tmp_path):
    (tmp_path / "signer").mkdir()
    monkeypatch.setattr(sweep.core, "STATE", tmp_path)
    monkeypatch.setattr(sweep, "verify_signed_record", lambda room, row: None)
    return tmp_path


def test_payloads_are_fixed_nonbinding_and_do_not_freeze_luxion():
    items = {item["key"]: item for item in sweep.ITEMS}
    assert set(items) == {"magnatsv", "luxion-1"}
    magnatsv = items["magnatsv"]["payload"]
    luxion = items["luxion-1"]["payload"]
    assert magnatsv["type"] == "sonnet.application.v1"
    assert magnatsv["no_live_roster_consent"] is True
    assert "magnatsv-invite-z6mkw1wntm-001" in magnatsv["text"]
    assert "not sonnet.roster.v1 consent" in magnatsv["text"]
    assert luxion["type"] == "sonnet.note.v1"
    assert luxion["no_live_roster_consent"] is True
    assert "NOT the requested 'yes-luxion' freeze" in luxion["text"]
    assert "Do not freeze MARU" in luxion["text"]
    assert "luxion-dyn-ping-gUyEAB-1789487200" in luxion["text"]
    for payload in (magnatsv, luxion):
        assert payload["did"] == sweep.DID
        assert payload["role"] == "writer"
        assert "32c15433c6d73af1cea5d6467dece016" in payload["text"]
        assert "writer registration" in payload["text"]


def test_new_state_has_no_attempt_or_receipt(state_root):
    state = sweep.new_state()
    sweep.save(state)
    loaded = sweep.load()
    for current in loaded["items"].values():
        assert current["state"] == "new"
        assert current["nonce"] is None
        assert current["attempted_at"] is None
        assert current["seq"] is None
        assert current["posted_record"] is None


def test_post_one_marks_attempt_before_single_post(monkeypatch, state_root):
    state = sweep.new_state()
    sweep.save(state)
    fixed = sweep.ITEM_BY_KEY["magnatsv"]
    text = sweep._render(fixed["payload"])
    calls = []

    monkeypatch.setattr(sweep.core, "clean_text", lambda value: value)
    monkeypatch.setattr(sweep.core, "make_nonce", lambda room, did: "12345")
    monkeypatch.setattr(sweep, "_sign", lambda nonce, body: [sweep.DID, "sig"])
    monkeypatch.setattr(sweep, "require_prepost", lambda: None)

    class Response:
        def raise_for_status(self):
            return None
        def json(self):
            return {
                "posted": {
                    "from": sweep.DID,
                    "nonce": "12345",
                    "text": text,
                    "sig": "sig",
                    "seq": 111111,
                    "ts": "2026-09-16T00:00:00Z",
                }
            }

    def post(*args, **kwargs):
        durable = sweep.load()["items"]["magnatsv"]
        assert durable["state"] == "attempting"
        assert durable["attempted_at"] is not None
        calls.append((args, kwargs))
        return Response()

    monkeypatch.setattr(sweep.core.httpx, "post", post)
    result = sweep._post_one(state, fixed)
    assert result["status"] == "posted"
    assert len(calls) == 1
    durable = sweep.load()["items"]["magnatsv"]
    assert durable["state"] == "posted"
    assert durable["seq"] == 111111
    assert durable["posted_record"]["sig"] == "sig"


def test_post_transport_failure_is_terminal_ambiguous(monkeypatch, state_root):
    state = sweep.new_state()
    sweep.save(state)
    fixed = sweep.ITEM_BY_KEY["magnatsv"]
    monkeypatch.setattr(sweep.core, "clean_text", lambda value: value)
    monkeypatch.setattr(sweep.core, "make_nonce", lambda room, did: "12345")
    monkeypatch.setattr(sweep, "_sign", lambda nonce, body: [sweep.DID, "sig"])
    monkeypatch.setattr(sweep, "require_prepost", lambda: None)
    monkeypatch.setattr(sweep.core.httpx, "post", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))

    with pytest.raises(sweep.SweepError, match="magnatsv_submission_unknown"):
        sweep._post_one(state, fixed)
    durable = sweep.load()["items"]["magnatsv"]
    assert durable["state"] == "ambiguous"
    assert durable["attempted_at"] is not None
    assert durable["seq"] is None
    with pytest.raises(sweep.SweepError, match="magnatsv_submission_ambiguous"):
        sweep._post_one(durable_state := sweep.load(), fixed)
    assert durable_state["items"]["magnatsv"]["state"] == "ambiguous"


def test_module_has_no_discovery_export_or_read_before_post():
    source = Path("src/flop_agent/sonnet_opportunity_sweep_20260916.py").read_text("utf-8")
    assert "/export" not in source
    assert "read_room(" not in source
    assert "yes-luxion\"" not in source
