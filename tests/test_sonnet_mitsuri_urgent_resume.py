from __future__ import annotations

import copy

import pytest

from flop_agent import sonnet_mitsuri_urgent_contact as lane
from flop_agent import sonnet_mitsuri_urgent_resume as resume


def prepared_state() -> dict:
    state = lane.new_state()
    state["nonce"] = "123456789"
    state["state"] = "prepared"
    return state


def test_require_exact_prepared_accepts_only_prepost_state():
    state = prepared_state()
    assert resume.require_exact_prepared(state) is state


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("state", "new"),
        ("state", "attempting"),
        ("request_id", "different"),
        ("nonce", None),
        ("attempted_at", "2026-09-15T00:00:00+00:00"),
        ("seq", 1),
        ("ts", "2026-09-15T00:00:00Z"),
        ("posted_record", {}),
    ],
)
def test_require_exact_prepared_rejects_any_boundary_crossing(field, value):
    state = prepared_state()
    state[field] = value
    with pytest.raises(resume.ResumeError, match="prepared_state_not_exact"):
        resume.require_exact_prepared(state)


def test_require_exact_prepared_rejects_payload_change():
    state = prepared_state()
    state["payload"] = copy.deepcopy(state["payload"])
    state["payload"]["no_live_roster_consent"] = False
    with pytest.raises(resume.ResumeError, match="prepared_state_not_exact"):
        resume.require_exact_prepared(state)


def test_require_exact_prepared_rejects_missing_state():
    with pytest.raises(resume.ResumeError, match="prepared_state_missing"):
        resume.require_exact_prepared(None)
