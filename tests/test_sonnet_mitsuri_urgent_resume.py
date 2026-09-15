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


def test_sign_prepared_retries_only_vault_error(monkeypatch):
    state = prepared_state()
    calls = []

    monkeypatch.setattr(resume, "VAULT_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(resume, "signing_deadline", lambda seconds=120: _nullcontext())

    def fake_with_vault_seed(operation):
        calls.append("call")
        if len(calls) < 3:
            raise RuntimeError(resume.VAULT_ERROR)
        return (lane.DID, "sig")

    monkeypatch.setattr(resume.oracle_signer, "with_vault_seed", fake_with_vault_seed)
    monkeypatch.setattr(resume.core, "invoke_signer", lambda *args: (lane.DID, "sig"))

    assert resume.sign_prepared(state, lane.render()) == (lane.DID, "sig")
    assert len(calls) == 3


def test_sign_prepared_fails_closed_after_vault_budget(monkeypatch):
    state = prepared_state()
    calls = []

    monkeypatch.setattr(resume, "VAULT_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(resume, "signing_deadline", lambda seconds=120: _nullcontext())

    def fake_with_vault_seed(operation):
        calls.append("call")
        raise RuntimeError(resume.VAULT_ERROR)

    monkeypatch.setattr(resume.oracle_signer, "with_vault_seed", fake_with_vault_seed)

    with pytest.raises(resume.ResumeError, match="vault_unavailable"):
        resume.sign_prepared(state, lane.render())
    assert len(calls) == 3


def test_sign_prepared_does_not_retry_other_errors(monkeypatch):
    state = prepared_state()
    calls = []

    monkeypatch.setattr(resume, "VAULT_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(resume, "signing_deadline", lambda seconds=120: _nullcontext())

    def fake_with_vault_seed(operation):
        calls.append("call")
        raise RuntimeError("some_other_failure")

    monkeypatch.setattr(resume.oracle_signer, "with_vault_seed", fake_with_vault_seed)

    with pytest.raises(resume.ResumeError, match="signing_failed"):
        resume.sign_prepared(state, lane.render())
    assert len(calls) == 1


class _nullcontext:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False
