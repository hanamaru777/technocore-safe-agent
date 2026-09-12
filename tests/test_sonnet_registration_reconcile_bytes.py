import json

import pytest

from flop_agent import core, sonnet_registration as lane


def test_ambiguous_reconciliation_requires_byte_exact_post(monkeypatch):
    registration = {**lane.FIXED, "request_id": "register-1"}
    value = {
        "state": "ambiguous",
        "registration": registration,
        "nonce": "123",
    }
    # Semantically identical JSON is not sufficient after an ambiguous POST.
    # The actual lane signs/posts the canonical render() bytes, so reconciliation
    # must prove those exact bytes plus the persisted nonce/request_id.
    row = {
        "from": lane.DID,
        "nonce": "123",
        "text": json.dumps(registration, sort_keys=False, separators=(", ", ": ")),
        "seq": 1,
        "ts": "2026-09-12T00:00:00+00:00",
        "sig": "dummy",
    }
    assert row["text"] != lane.render(registration)
    monkeypatch.setattr(core, "read_room", lambda *args, **kwargs: {"messages": [row]})
    monkeypatch.setattr(lane, "verify_signed_record", lambda *args, **kwargs: None)

    with pytest.raises(lane.RegistrationError, match="existing_registration_conflict"):
        lane.existing_record(value)
