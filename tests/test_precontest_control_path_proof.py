import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import precontest_challenge
from flop_agent import precontest_control_path_proof as control
from flop_agent import precontest_readiness


NOW = datetime(2026, 10, 5, 9, 0, tzinfo=UTC)
DEADLINE = NOW + timedelta(days=1)
CHALLENGE = "control-path-proof-test"


def _probe(path_id: str, *, independent: bool, kind: str) -> dict:
    return {
        "schema_version": control.PROBE_SCHEMA_VERSION,
        "challenge_id": CHALLENGE,
        "path_id": path_id,
        "authenticated": True,
        "ready": True,
        "quota_independent": independent,
        "verified_at": NOW.isoformat(),
        "evidence_kind": kind,
        "evidence_ref": f"proof:{path_id}",
    }


def _all_other_gates_evidence() -> dict:
    return {
        "schema_version": precontest_readiness.SCHEMA_VERSION,
        "challenge_id": CHALLENGE,
        "measured_at": NOW.isoformat(),
        "campaign_deadline": DEADLINE.isoformat(),
        "capture_to_executor_ms": 1000,
        "requires_chat_relay": False,
        "requires_user_terminal": False,
        "control_paths": [],
        "execution_modes_required": ["single", "batch"],
        "execution_modes_rehearsed": ["single", "batch"],
        "reconciliation_cases_rehearsed": ["settled", "void", "ambiguous", "redacted"],
        "runtime_deadline_guard": True,
        "post_deadline_fail_closed": True,
        "first_leg_policy_predefined": True,
        "first_leg_risk_bounded": True,
        "zero_trade_deadlock_prevented": True,
        "execution_plumbing_complete": True,
        "production_rehearsal_passed": True,
        "live_plumbing_changes_required": False,
    }


def test_single_quota_independent_path_is_still_no_go(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    control.save_probe(CHALLENGE, _probe("ssh-operator", independent=True, kind="ssh-session"))

    proof = control.save_proof(CHALLENGE, now=NOW)

    assert proof["status"] == "NO_GO"
    assert proof["ready_path_count"] == 1
    assert proof["quota_independent_ready"] is True


def test_two_ready_paths_with_one_quota_independent_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    control.save_probe(CHALLENGE, _probe("ssh-operator", independent=True, kind="ssh-session"))
    control.save_probe(
        CHALLENGE,
        _probe("remote-desktop", independent=False, kind="remote-desktop-connector"),
    )

    proof = control.save_proof(CHALLENGE, now=NOW)
    valid = control.validate_proof(proof, challenge_id=CHALLENGE, now=NOW)

    assert valid["status"] == "PASS"
    assert valid["ready_path_count"] == 2
    assert valid["quota_independent_ready"] is True
    assert [row["id"] for row in control.readiness_paths(valid)] == [
        "remote-desktop",
        "ssh-operator",
    ]


def test_remote_desktop_cannot_claim_quota_independence():
    with pytest.raises(
        control.ControlPathProofError,
        match="precontest_control_remote_desktop_quota_invalid",
    ):
        control.seal_probe(
            _probe("remote-desktop", independent=True, kind="remote-desktop-connector")
        )


def test_ci_and_unproven_resident_are_not_control_paths():
    with pytest.raises(
        control.ControlPathProofError,
        match="precontest_control_ci_not_production_path",
    ):
        control.seal_probe(
            _probe("ssh-operator", independent=True, kind="github-actions")
        )

    with pytest.raises(
        control.ControlPathProofError,
        match="precontest_control_resident_not_yet_eligible",
    ):
        control.seal_probe(
            _probe("resident-autonomous", independent=True, kind="resident-runtime")
        )


def test_tampered_probe_and_stale_probe_fail_closed():
    sealed = control.seal_probe(_probe("ssh-operator", independent=True, kind="ssh-session"))
    tampered = json.loads(json.dumps(sealed))
    tampered["ready"] = False
    with pytest.raises(
        control.ControlPathProofError,
        match="precontest_control_probe_integrity_invalid",
    ):
        control.validate_probe(tampered, challenge_id=CHALLENGE, now=NOW)

    stale = control.seal_probe(
        {
            **_probe("ssh-operator", independent=True, kind="ssh-session"),
            "verified_at": (NOW - precontest_readiness.MAX_EVIDENCE_AGE - timedelta(seconds=1)).isoformat(),
        }
    )
    with pytest.raises(
        control.ControlPathProofError,
        match="precontest_control_probe_stale",
    ):
        control.validate_probe(stale, challenge_id=CHALLENGE, now=NOW)


def test_strict_planner_overlays_valid_control_proof(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    precontest_readiness.save_evidence(CHALLENGE, _all_other_gates_evidence())
    control.save_probe(CHALLENGE, _probe("ssh-operator", independent=True, kind="ssh-session"))
    control.save_probe(
        CHALLENGE,
        _probe("remote-desktop", independent=False, kind="remote-desktop-connector"),
    )
    control.save_proof(CHALLENGE, now=NOW)

    monkeypatch.setattr(
        precontest_challenge.airdrop_challenge,
        "build_plan",
        lambda challenge_id, now=None: {
            "challenge_id": challenge_id,
            "deadline": DEADLINE.isoformat(),
            "critical_path": [],
            "ready_for_execution_path": True,
            "estimated_remaining_steps": 0,
            "warnings": [],
        },
    )

    result = precontest_challenge.build_plan(CHALLENGE, now=NOW)

    assert result["precontest_readiness"]["gates"]["CONTROL_PATH_REDUNDANCY_GATE"] is True
    assert result["precontest_readiness"]["control_paths_ready"] == 2
    assert result["precontest_readiness"]["quota_independent_ready"] is True
    assert result["ready_for_execution_path"] is True


def test_strict_planner_single_path_stays_no_go(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    precontest_readiness.save_evidence(CHALLENGE, _all_other_gates_evidence())
    control.save_probe(CHALLENGE, _probe("ssh-operator", independent=True, kind="ssh-session"))
    control.save_proof(CHALLENGE, now=NOW)

    monkeypatch.setattr(
        precontest_challenge.airdrop_challenge,
        "build_plan",
        lambda challenge_id, now=None: {
            "challenge_id": challenge_id,
            "deadline": DEADLINE.isoformat(),
            "critical_path": [],
            "ready_for_execution_path": True,
            "estimated_remaining_steps": 0,
            "warnings": [],
        },
    )

    result = precontest_challenge.build_plan(CHALLENGE, now=NOW)

    assert result["precontest_readiness"]["gates"]["CONTROL_PATH_REDUNDANCY_GATE"] is False
    assert result["ready_for_execution_path"] is False


def test_invalid_control_proof_forces_planner_no_go(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    precontest_readiness.save_evidence(CHALLENGE, _all_other_gates_evidence())
    control.save_probe(CHALLENGE, _probe("ssh-operator", independent=True, kind="ssh-session"))
    proof = control.save_proof(CHALLENGE, now=NOW)
    proof["ready_path_count"] = 2
    control.proof_path(CHALLENGE).write_text(json.dumps(proof), encoding="utf-8")

    monkeypatch.setattr(
        precontest_challenge.airdrop_challenge,
        "build_plan",
        lambda challenge_id, now=None: {
            "challenge_id": challenge_id,
            "deadline": DEADLINE.isoformat(),
            "critical_path": [],
            "ready_for_execution_path": True,
            "estimated_remaining_steps": 0,
            "warnings": [],
        },
    )

    result = precontest_challenge.build_plan(CHALLENGE, now=NOW)

    assert result["ready_for_execution_path"] is False
    assert "precontest_control_proof_invalid" in result["precontest_readiness"]["blockers"]
