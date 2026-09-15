import json
from datetime import UTC, datetime

import pytest

from flop_agent import sonnet_brucelead2_application as lane


def test_payload_is_structurally_nonbinding_and_fixed():
    assert lane.PAYLOAD["type"] == "sonnet.application.v1"
    assert lane.PAYLOAD["game_id"] == "brucelead-2"
    assert lane.PAYLOAD["request_id"] == "maru-brucelead2-apply-20260915-1"
    assert lane.PAYLOAD["no_live_roster_consent"] is True
    assert "not sonnet.roster.v1 consent" in lane.PAYLOAD["text"]
    assert "not a word proposal" in lane.PAYLOAD["text"]
    assert "not a claim" in lane.PAYLOAD["text"]
    with pytest.raises(lane.ApplicationError, match="application_binding_invalid"):
        lane.render({**lane.PAYLOAD, "no_live_roster_consent": False})


def test_nonbinding_safety_allows_fresh_degraded_with_exact_core(monkeypatch, tmp_path):
    monkeypatch.setattr(lane.core, "STATE", tmp_path)
    now = datetime(2026, 9, 15, 11, 0, tzinfo=UTC)
    (tmp_path / "observer-safety.json").write_text(
        json.dumps(
            {
                "health": "degraded",
                "updated_at": "2026-09-15T10:59:00Z",
                "unrecoverable_core_gap_events": 117,
                "unrecoverable_core_gap_messages": 5_083_155,
            }
        ),
        encoding="utf-8",
    )
    lane.require_nonbinding_safety(now=now)


def test_nonbinding_safety_rejects_core_change(monkeypatch, tmp_path):
    monkeypatch.setattr(lane.core, "STATE", tmp_path)
    (tmp_path / "observer-safety.json").write_text(
        json.dumps(
            {
                "health": "ok",
                "updated_at": "2026-09-15T11:00:00Z",
                "unrecoverable_core_gap_events": 118,
                "unrecoverable_core_gap_messages": 5_083_155,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(lane.ApplicationError, match="protected_core_changed"):
        lane.require_nonbinding_safety(now=datetime(2026, 9, 15, 11, 1, tzinfo=UTC))


def _offer(*, seq=lane.SOURCE_SEQ, sender="did:key:z6MkBruce", text=None, request_id=lane.SOURCE_REQUEST_ID):
    body = {
        "type": "sonnet.reply.v1",
        "request_id": request_id,
        "target_did": lane.DID,
        "text": text
        or (
            "BRUCELEAD-2 — current seat offer. 3 external seats open. "
            "Room: d-sonnet-2-team-brucelead-2"
        ),
    }
    return {
        "from": sender,
        "seq": seq,
        "ts": "2026-09-15T10:54:00Z",
        "nonce": "123",
        "sig": "sig",
        "text": json.dumps(body),
    }


def test_live_offer_binds_exact_signed_source(monkeypatch):
    source = _offer()
    calls = []

    def read(room, **kwargs):
        calls.append(kwargs)
        if "since" in kwargs:
            return {"messages": [source]}
        return {"messages": [source]}

    monkeypatch.setattr(lane.core, "read_room", read)
    monkeypatch.setattr(lane, "verify_signed_record", lambda room, row: None)
    result = lane.require_live_offer(now=datetime(2026, 9, 15, 11, 0, tzinfo=UTC))
    assert result["seq"] == lane.SOURCE_SEQ
    assert calls[0]["since"] == lane.SOURCE_SEQ - 1
    assert calls[0]["limit"] == 200
    assert calls[1]["limit"] == 200


def test_live_offer_rejects_later_signed_full_notice(monkeypatch):
    source = _offer()
    closed = _offer(
        seq=lane.SOURCE_SEQ + 10,
        text="BRUCELEAD-2 team full — no seats remain.",
        request_id="brucelead-2-close-1",
    )

    def read(room, **kwargs):
        if "since" in kwargs:
            return {"messages": [source]}
        return {"messages": [source, closed]}

    monkeypatch.setattr(lane.core, "read_room", read)
    monkeypatch.setattr(lane, "verify_signed_record", lambda room, row: None)
    with pytest.raises(lane.ApplicationError, match="offer_withdrawn_or_full"):
        lane.require_live_offer(now=datetime(2026, 9, 15, 11, 0, tzinfo=UTC))


def test_live_offer_rejects_wrong_request_id_before_any_write(monkeypatch):
    wrong = _offer(request_id="wrong")
    monkeypatch.setattr(
        lane.core,
        "read_room",
        lambda room, **kwargs: {"messages": [wrong]},
    )
    monkeypatch.setattr(lane, "verify_signed_record", lambda room, row: None)
    with pytest.raises(lane.ApplicationError, match="offer_binding_invalid"):
        lane.require_live_offer(now=datetime(2026, 9, 15, 11, 0, tzinfo=UTC))
