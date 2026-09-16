from flop_agent import sonnet_open_seat_broadcast_20260916 as mod


def test_payload_is_structurally_nonbinding_and_fixed():
    payload = mod.PAYLOAD
    assert payload["type"] == "sonnet.note.v1"
    assert payload["contest_id"] == "sonnet-2"
    assert payload["request_id"] == "maru-open-seat-broadcast-20260916-1"
    assert payload["did"] == mod.DID
    assert payload["no_live_roster_consent"] is True
    assert "members" not in payload
    assert "poem_room" not in payload
    assert "room_generation" not in payload
    assert "word" not in payload
    assert payload["role"] == "writer"
    assert payload["x_account_url"] == "https://x.com/MinerMaru73"


def test_payload_never_claims_writer_acceptance():
    text = mod.PAYLOAD["text"].lower()
    assert "does not claim writer acceptance" in text
    assert mod.REGISTRATION_REQUEST in mod.PAYLOAD["text"]
    assert "non-binding" in text


def test_fresh_state_validates():
    state = mod.new_state()
    assert mod.validate(state) == state
    assert state["state"] == "new"
    assert state["nonce"] is None
    assert state["attempted_at"] is None
    assert state["seq"] is None
    assert state["posted_record"] is None
