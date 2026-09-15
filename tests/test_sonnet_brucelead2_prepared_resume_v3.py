from datetime import UTC, datetime

import pytest

from flop_agent import sonnet_brucelead2_prepared_resume_v3 as resume


def _state(**changes):
    value = {
        "request_id": resume.lane.REQUEST_ID,
        "payload": resume.lane.PAYLOAD,
        "state": "prepared",
        "nonce": "1234567890",
        "attempted_at": None,
        "seq": None,
        "ts": None,
        "posted_record": None,
    }
    value.update(changes)
    return value


def test_require_recent_prepared_accepts_exact_presign_state(monkeypatch, tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{}", encoding="utf-8")
    now = datetime.now(UTC)
    monkeypatch.setattr(resume.lane, "load", lambda: _state())
    monkeypatch.setattr(resume.lane, "state_path", lambda: path)
    assert resume.require_recent_prepared(now=now)["state"] == "prepared"


def test_require_recent_prepared_rejects_attempted_state(monkeypatch, tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(resume.lane, "load", lambda: _state(attempted_at="2026-09-15T12:00:00Z"))
    monkeypatch.setattr(resume.lane, "state_path", lambda: path)
    with pytest.raises(resume.ResumeError, match="prepared_state_has_post_evidence"):
        resume.require_recent_prepared()


def test_require_recent_prepared_rejects_wrong_state(monkeypatch, tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(resume.lane, "load", lambda: _state(state="attempting"))
    monkeypatch.setattr(resume.lane, "state_path", lambda: path)
    with pytest.raises(resume.ResumeError, match="prepared_state_not_prepared"):
        resume.require_recent_prepared()


def test_run_once_replaces_only_room_read_gates(monkeypatch):
    original_reconcile = resume.lane.reconcile_existing
    original_offer = resume.lane.require_live_offer
    monkeypatch.setattr(resume, "require_recent_prepared", lambda: _state())

    def fake_run_once():
        assert resume.lane.reconcile_existing(_state()) is None
        proof = resume.lane.require_live_offer()
        assert proof["seq"] == resume.lane.SOURCE_SEQ
        assert proof["provenance"] == "prepared_state_from_pr236"
        return {"status": "posted", "request_id": resume.lane.REQUEST_ID, "seq": 1, "ts": "x"}

    monkeypatch.setattr(resume.lane, "run_once", fake_run_once)
    result = resume.run_once()
    assert result["status"] == "posted"
    assert resume.lane.reconcile_existing is original_reconcile
    assert resume.lane.require_live_offer is original_offer
