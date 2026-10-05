from datetime import UTC, datetime, timedelta

from flop_agent import precontest_challenge
from flop_agent import precontest_plumbing_apply


NOW = datetime(2026, 10, 5, 6, 30, tzinfo=UTC)
DEADLINE = NOW + timedelta(days=1)


def _legacy():
    return {
        "challenge_id": "proof",
        "deadline": DEADLINE.isoformat(),
        "critical_path": [],
        "estimated_remaining_steps": 0,
        "ready_for_execution_path": True,
        "warnings": [],
    }


def _go():
    return {
        "schema_version": 1,
        "challenge_id": "proof",
        "non_binding": True,
        "status": "GO",
        "go": True,
        "evaluated_at": NOW.isoformat(),
        "gates": {"NO_LIVE_PLUMBING_GATE": True},
        "blockers": [],
        "warning": "proof",
    }


def test_strict_planner_applies_plumbing_before_readiness(monkeypatch):
    calls = []
    monkeypatch.setattr(
        precontest_challenge.airdrop_challenge,
        "build_plan",
        lambda challenge_id, now=None: _legacy(),
    )
    monkeypatch.setattr(
        precontest_challenge.precontest_plumbing_apply,
        "apply_if_present",
        lambda challenge_id, now=None: calls.append((challenge_id, now)),
    )
    monkeypatch.setattr(
        precontest_challenge.precontest_readiness,
        "evaluate_saved",
        lambda challenge_id, now=None, expected_deadline=None: _go(),
    )

    result = precontest_challenge.build_plan("proof", now=NOW)

    assert calls == [("proof", NOW)]
    assert result["ready_for_execution_path"] is True
    assert result["precontest_readiness"]["status"] == "GO"


def test_invalid_plumbing_receipt_forces_no_go_before_saved_readiness(monkeypatch):
    monkeypatch.setattr(
        precontest_challenge.airdrop_challenge,
        "build_plan",
        lambda challenge_id, now=None: _legacy(),
    )

    def fail(challenge_id, now=None):
        raise precontest_plumbing_apply.PlumbingApplyError(
            "precontest_plumbing_receipt_invalid"
        )

    monkeypatch.setattr(
        precontest_challenge.precontest_plumbing_apply,
        "apply_if_present",
        fail,
    )
    monkeypatch.setattr(
        precontest_challenge.precontest_readiness,
        "evaluate_saved",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("readiness must not bypass an invalid plumbing receipt")
        ),
    )

    result = precontest_challenge.build_plan("proof", now=NOW)

    assert result["ready_for_execution_path"] is False
    assert result["precontest_readiness"]["status"] == "NO_GO"
    assert "precontest_plumbing_receipt_invalid" in result["critical_path"]
