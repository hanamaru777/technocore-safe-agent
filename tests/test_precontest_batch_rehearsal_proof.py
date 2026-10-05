import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import precontest_batch_rehearsal_proof as batch_proof
from flop_agent import precontest_machine_evidence as collector
from flop_agent import precontest_readiness


NOW = datetime(2026, 10, 5, 5, 45, tzinfo=UTC)
DEADLINE = NOW + timedelta(days=1)
CHALLENGE = "batch-rehearsal-proof-test"


def _plan(challenge_id=CHALLENGE):
    return {"challenge_id": challenge_id, "deadline": DEADLINE.isoformat()}


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


def test_build_proof_rehearses_batch_without_binding_side_effects():
    proof = batch_proof.build_proof(CHALLENGE, now=NOW)

    assert proof["status"] == "PASS"
    assert proof["non_binding"] is True
    assert proof["execution_mode"] == "batch"
    assert proof["target_met"] is True
    assert 0 <= proof["batch_rehearsal_ms"] <= precontest_readiness.MAX_CAPTURE_TO_EXECUTOR_MS
    assert proof["probes"] == {
        "two_leg_same_sweep_preflight": True,
        "aggregate_over_budget_rejected": True,
        "mixed_sweep_rejected": True,
        "sign_called": False,
        "fence_written": False,
        "pending_marked": False,
        "post_attempted": False,
    }
    assert proof["order"] == {
        "preflight_before_sign": True,
        "sign_before_fence": True,
        "fence_before_post": True,
    }


def test_validate_rejects_tamper_and_source_drift():
    proof = batch_proof.build_proof(CHALLENGE, now=NOW)

    tampered = json.loads(json.dumps(proof))
    tampered["probes"]["post_attempted"] = True
    with pytest.raises(
        batch_proof.BatchRehearsalProofError,
        match="precontest_batch_proof_integrity_invalid",
    ):
        batch_proof.validate_proof(tampered, challenge_id=CHALLENGE, now=NOW)

    drifted = json.loads(json.dumps(proof))
    drifted["run_locked_sha256"] = "0" * 64
    unsigned = dict(drifted)
    unsigned.pop("proof_sha256")
    drifted["proof_sha256"] = batch_proof._sha(unsigned)
    with pytest.raises(
        batch_proof.BatchRehearsalProofError,
        match="precontest_batch_source_changed",
    ):
        batch_proof.validate_proof(drifted, challenge_id=CHALLENGE, now=NOW)


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
    monkeypatch.setattr(collector, "_active_learning_proof", lambda challenge_id, now: None)
    monkeypatch.setattr(collector, "_reconciliation_proof", lambda challenge_id, now: None)


def test_collector_without_batch_proof_keeps_latency_gate_false(tmp_path, monkeypatch):
    _collector_setup(monkeypatch, tmp_path)

    result = collector.collect(CHALLENGE, now=NOW)

    assert result["status"] == "COLLECTED_NO_GO"
    assert result["readiness"]["gates"]["EXECUTION_LATENCY_GATE"] is False
    evidence = precontest_readiness.load_evidence(CHALLENGE)
    assert evidence["execution_modes_rehearsed"] == ["single"]


def test_collector_valid_batch_proof_completes_modes_and_uses_worst_latency(tmp_path, monkeypatch):
    _collector_setup(monkeypatch, tmp_path)
    proof = batch_proof.save_proof(CHALLENGE, now=NOW)

    result = collector.collect(CHALLENGE, now=NOW)

    assert result["status"] == "COLLECTED_NO_GO"
    assert result["readiness"]["gates"]["EXECUTION_LATENCY_GATE"] is True
    assert result["readiness"]["go"] is False
    evidence = precontest_readiness.load_evidence(CHALLENGE)
    assert evidence["execution_modes_rehearsed"] == ["batch", "single"]
    assert evidence["capture_to_executor_ms"] == max(1200, proof["batch_rehearsal_ms"])
    provenance = json.loads(collector.provenance_path(CHALLENGE).read_text("utf-8"))
    assert "batch_rehearsal" in provenance["sources"]
    assert "EXECUTION_LATENCY_GATE" not in provenance["unsupported_gates_forced_no_go"]


def test_collector_rejects_tampered_existing_batch_proof(tmp_path, monkeypatch):
    _collector_setup(monkeypatch, tmp_path)
    batch_proof.save_proof(CHALLENGE, now=NOW)
    path = batch_proof.proof_path(CHALLENGE)
    value = json.loads(path.read_text("utf-8"))
    value["target_met"] = False
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(
        collector.MachineEvidenceError,
        match="precontest_machine_batch_rehearsal_proof_invalid",
    ):
        collector.collect(CHALLENGE, now=NOW)
