import json
from datetime import UTC, datetime

import pytest

from flop_agent import sonnet_mitsuri_urgent_contact as lane


def test_payload_is_fixed_and_nonbinding():
    assert lane.PAYLOAD["type"] == "sonnet.note.v1"
    assert lane.PAYLOAD["game_id"] == "mitsuri-beacon-2"
    assert lane.PAYLOAD["request_id"] == "maru-mitsuri-live-20260915-1"
    assert lane.PAYLOAD["target_did"] == lane.TARGET_DID
    assert lane.PAYLOAD["no_live_roster_consent"] is True
    text = lane.PAYLOAD["text"]
    assert "not roster consent" in text
    assert "not a word proposal" in text
    assert "0 accepted Sonnet-2 words" in text
    assert "not claiming an accepted-writer receipt" in text


def test_new_state_is_presign_and_exact():
    state = lane.new_state()
    assert state["state"] == "new"
    assert state["nonce"] is None
    assert state["attempted_at"] is None
    assert state["seq"] is None
    assert state["ts"] is None
    assert state["posted_record"] is None
    assert state["payload"] == lane.PAYLOAD
    assert lane.validate(state) == state


def test_validate_rejects_binding_payload():
    state = lane.new_state()
    state["payload"]["no_live_roster_consent"] = False
    with pytest.raises(lane.ContactError, match="state_invalid"):
        lane.validate(state)


def test_safety_allows_fresh_degraded_exact_core(monkeypatch):
    monkeypatch.setattr(
        lane.registration,
        "load_safety_snapshot",
        lambda: {
            "health": "degraded",
            "updated_at": datetime.now(UTC).isoformat(),
            "unrecoverable_core_gap_events": 117,
            "unrecoverable_core_gap_messages": 5_083_155,
        },
    )
    lane.require_safety()


def test_safety_rejects_core_change(monkeypatch):
    monkeypatch.setattr(
        lane.registration,
        "load_safety_snapshot",
        lambda: {
            "health": "ok",
            "updated_at": datetime.now(UTC).isoformat(),
            "unrecoverable_core_gap_events": 118,
            "unrecoverable_core_gap_messages": 5_083_155,
        },
    )
    with pytest.raises(lane.ContactError, match="protected_core_changed"):
        lane.require_safety()


def test_render_is_canonical_json():
    value = json.loads(lane.render())
    assert value == lane.PAYLOAD
