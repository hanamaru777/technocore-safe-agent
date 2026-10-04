from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import core, precontest_readiness as readiness


NOW = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)
DEADLINE = NOW + timedelta(days=7)


@pytest.fixture
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    return tmp_path


def evidence(**patch):
    value = {
        "schema_version": 1,
        "challenge_id": "future-challenge",
        "measured_at": NOW.isoformat(),
        "campaign_deadline": DEADLINE.isoformat(),
        "capture_to_executor_ms": 5_000,
        "requires_chat_relay": False,
        "requires_user_terminal": False,
        "control_paths": [
            {
                "id": "primary",
                "authenticated": True,
                "ready": True,
                "quota_independent": False,
                "verified_at": NOW.isoformat(),
            },
            {
                "id": "backup",
                "authenticated": True,
                "ready": True,
                "quota_independent": True,
                "verified_at": NOW.isoformat(),
            },
        ],
        "execution_modes_required": ["single", "batch"],
        "execution_modes_rehearsed": ["single", "batch"],
        "reconciliation_cases_rehearsed": [
            "settled", "void", "ambiguous", "redacted"
        ],
        "runtime_deadline_guard": True,
        "post_deadline_fail_closed": True,
        "first_leg_policy_predefined": True,
        "first_leg_risk_bounded": True,
        "zero_trade_deadlock_prevented": True,
        "execution_plumbing_complete": True,
        "production_rehearsal_passed": True,
        "live_plumbing_changes_required": False,
    }
    value.update(patch)
    return value


def result(value, *, now=NOW):
    return readiness.evaluate(
        readiness.seal_evidence(value),
        now=now,
        expected_deadline=DEADLINE.isoformat(),
    )


def test_exact_five_second_boundary_is_go():
    checked = result(evidence(capture_to_executor_ms=5_000))
    assert checked["status"] == "GO"
    assert checked["go"] is True
    assert checked["blockers"] == []
    assert all(checked["gates"].values())


def test_over_five_seconds_is_no_go():
    checked = result(evidence(capture_to_executor_ms=5_001))
    assert checked["go"] is False
    assert checked["gates"]["EXECUTION_LATENCY_GATE"] is False
    assert "EXECUTION_LATENCY_GATE" in checked["blockers"]


def test_chat_or_terminal_relay_fails_human_independence():
    for key in ("requires_chat_relay", "requires_user_terminal"):
        checked = result(evidence(**{key: True}))
        assert checked["gates"]["HUMAN_INDEPENDENCE_GATE"] is False


def test_control_path_requires_two_ready_paths_and_quota_independent_backup():
    one = evidence()
    one["control_paths"] = one["control_paths"][:1]
    checked = result(one)
    assert checked["gates"]["CONTROL_PATH_REDUNDANCY_GATE"] is False

    dependent = evidence()
    for row in dependent["control_paths"]:
        row["quota_independent"] = False
    checked = result(dependent)
    assert checked["gates"]["CONTROL_PATH_REDUNDANCY_GATE"] is False


def test_all_required_execution_modes_must_be_rehearsed():
    checked = result(evidence(execution_modes_rehearsed=["single"]))
    assert checked["gates"]["EXECUTION_LATENCY_GATE"] is False


def test_missing_redacted_reconciliation_case_is_no_go():
    checked = result(evidence(
        reconciliation_cases_rehearsed=["settled", "void", "ambiguous"]
    ))
    assert checked["gates"]["SETTLEMENT_RECONCILIATION_GATE"] is False


def test_stale_measurement_and_stale_backup_path_fail_closed():
    stale_time = NOW - timedelta(hours=24, seconds=1)
    value = evidence(measured_at=stale_time.isoformat())
    value["control_paths"][1]["verified_at"] = stale_time.isoformat()
    checked = result(value)
    assert checked["evidence_fresh"] is False
    assert "EVIDENCE_FRESHNESS" in checked["blockers"]
    assert checked["gates"]["CONTROL_PATH_REDUNDANCY_GATE"] is False


def test_deadline_mismatch_and_expiry_fail_deadline_gate():
    mismatch = readiness.evaluate(
        readiness.seal_evidence(evidence()),
        now=NOW,
        expected_deadline=(DEADLINE + timedelta(minutes=1)).isoformat(),
    )
    assert mismatch["deadline_matches_challenge"] is False
    assert mismatch["gates"]["DEADLINE_GATE"] is False

    expired = result(evidence(), now=DEADLINE)
    assert expired["gates"]["DEADLINE_GATE"] is False


def test_active_learning_and_no_live_plumbing_are_mandatory():
    active = result(evidence(zero_trade_deadlock_prevented=False))
    assert active["gates"]["ACTIVE_LEARNING_GATE"] is False

    plumbing = result(evidence(live_plumbing_changes_required=True))
    assert plumbing["gates"]["NO_LIVE_PLUMBING_GATE"] is False


def test_unknown_field_is_rejected():
    value = evidence()
    value["surprise"] = True
    with pytest.raises(ValueError, match="schema_invalid"):
        readiness.seal_evidence(value)


def test_saved_evidence_is_atomic_bound_and_tamper_evident(isolated_state):
    saved = readiness.save_evidence("future-challenge", evidence())
    loaded = readiness.load_evidence("future-challenge")
    assert loaded == saved
    assert readiness.evaluate_saved(
        "future-challenge",
        now=NOW,
        expected_deadline=DEADLINE.isoformat(),
    )["go"] is True

    path = readiness._path("future-challenge")
    raw = json.loads(path.read_text("utf-8"))
    raw["capture_to_executor_ms"] = 1
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(readiness.ReadinessError, match="integrity_invalid"):
        readiness.load_evidence("future-challenge")


def test_challenge_id_cannot_cross_state_directory(isolated_state):
    with pytest.raises(ValueError, match="challenge_id_invalid"):
        readiness.save_evidence("../escape", evidence())


def test_module_has_no_binding_execution_surface():
    source = readiness.Path(readiness.__file__).read_text("utf-8")
    forbidden = (
        "vault_seed(",
        "post_signed(",
        "httpx.post(",
        "subprocess",
        "systemctl",
        "maker_signature",
        "taker_signature",
    )
    assert all(token not in source for token in forbidden)
