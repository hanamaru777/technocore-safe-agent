import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import precontest_active_learning_proof as active
from flop_agent import precontest_machine_evidence as collector
from flop_agent import precontest_readiness


NOW = datetime(2026, 10, 5, 4, 0, tzinfo=UTC)
DEADLINE = NOW + timedelta(days=1)
CHALLENGE = "active-learning-proof-test"


def _plan(challenge_id=CHALLENGE):
    return {
        "challenge_id": challenge_id,
        "deadline": DEADLINE.isoformat(),
    }


def _rehearsal(now=NOW):
    return {
        "sha256": "1" * 64,
        "evaluated_at": now.isoformat(),
        "capture_to_rehearsal_ms": 1200,
        "capture_to_stage_ms": 200,
        "trade_id": "trade-1",
        "stage_sha256": "2" * 64,
    }


def _settled():
    return {
        "sha256": "3" * 64,
        "as_of_sweep": 10,
        "settled_trade_ids": ["trade-old"],
        "last_reconciled_at": NOW.isoformat(),
    }


def test_build_proof_selects_bounded_leg_without_perfect_coverage():
    proof = active.build_proof(CHALLENGE, now=NOW)

    assert proof["status"] == "PASS"
    assert proof["non_binding"] is True
    assert proof["runtime"] == "close1_autonomous_stage"
    assert proof["probes"]["leader_coverage_incomplete_selected"] == "proof-good"
    assert proof["probes"]["too_small_rejected"] is True
    assert proof["probes"]["over_budget_rejected"] is True
    assert proof["probes"]["skipped_id_rejected"] is True
    assert proof["probes"]["fresh_fallback_selected"] == "proof-fresh"
    assert proof["first_leg_policy_predefined"] is True
    assert proof["first_leg_risk_bounded"] is True
    assert proof["zero_trade_deadlock_prevented"] is True
    assert len(proof["proof_sha256"]) == 64


def test_validate_rejects_tamper_and_policy_drift():
    proof = active.build_proof(CHALLENGE, now=NOW)
    tampered = dict(proof)
    tampered["zero_trade_deadlock_prevented"] = False
    with pytest.raises(
        active.ActiveLearningProofError,
        match="precontest_active_proof_integrity_invalid",
    ):
        active.validate_proof(tampered, challenge_id=CHALLENGE, now=NOW)

    drifted = json.loads(json.dumps(proof))
    drifted["policy"]["max_cash_fraction"] = "0.99"
    unsigned = dict(drifted)
    unsigned.pop("proof_sha256")
    drifted["proof_sha256"] = active._sha(unsigned)
    with pytest.raises(
        active.ActiveLearningProofError,
        match="precontest_active_policy_changed",
    ):
        active.validate_proof(drifted, challenge_id=CHALLENGE, now=NOW)


def _collector_setup(monkeypatch, tmp_path):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    monkeypatch.setattr(
        collector.airdrop_challenge,
        "build_plan",
        lambda challenge_id, now=None: _plan(challenge_id),
    )
    monkeypatch.setattr(collector, "_fresh_rehearsal", lambda now: _rehearsal(now))
    monkeypatch.setattr(collector, "_settled_ledger_proof", _settled)
    monkeypatch.setattr(
        collector,
        "_deadline_proof",
        lambda challenge_id, expected_deadline, now: None,
    )


def test_collector_without_active_proof_keeps_gate_false(tmp_path, monkeypatch):
    _collector_setup(monkeypatch, tmp_path)

    result = collector.collect(CHALLENGE, now=NOW)

    assert result["status"] == "COLLECTED_NO_GO"
    assert result["readiness"]["gates"]["ACTIVE_LEARNING_GATE"] is False
    evidence = precontest_readiness.load_evidence(CHALLENGE)
    assert evidence["first_leg_policy_predefined"] is False
    assert evidence["first_leg_risk_bounded"] is False
    assert evidence["zero_trade_deadlock_prevented"] is False


def test_collector_valid_active_proof_passes_active_gate_only(tmp_path, monkeypatch):
    _collector_setup(monkeypatch, tmp_path)
    active.save_proof(CHALLENGE, now=NOW)

    result = collector.collect(CHALLENGE, now=NOW)

    assert result["status"] == "COLLECTED_NO_GO"
    assert result["readiness"]["gates"]["ACTIVE_LEARNING_GATE"] is True
    assert result["readiness"]["go"] is False
    assert result["readiness"]["gates"]["HUMAN_INDEPENDENCE_GATE"] is False
    assert result["readiness"]["gates"]["CONTROL_PATH_REDUNDANCY_GATE"] is False

    evidence = precontest_readiness.load_evidence(CHALLENGE)
    assert evidence["first_leg_policy_predefined"] is True
    assert evidence["first_leg_risk_bounded"] is True
    assert evidence["zero_trade_deadlock_prevented"] is True

    provenance = json.loads(
        collector.provenance_path(CHALLENGE).read_text("utf-8")
    )
    assert "active_learning" in provenance["sources"]
    assert "ACTIVE_LEARNING_GATE" not in provenance["unsupported_gates_forced_no_go"]


def test_collector_rejects_tampered_existing_active_proof(tmp_path, monkeypatch):
    _collector_setup(monkeypatch, tmp_path)
    active.save_proof(CHALLENGE, now=NOW)
    path = active.proof_path(CHALLENGE)
    value = json.loads(path.read_text("utf-8"))
    value["first_leg_risk_bounded"] = False
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(
        collector.MachineEvidenceError,
        match="precontest_machine_active_learning_proof_invalid",
    ):
        collector.collect(CHALLENGE, now=NOW)
