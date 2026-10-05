import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import precontest_machine_evidence as collector
from flop_agent import precontest_readiness
from flop_agent import precontest_reconciliation_proof as reconciliation


NOW = datetime(2026, 10, 5, 5, 30, tzinfo=UTC)
DEADLINE = NOW + timedelta(days=1)
CHALLENGE = "reconciliation-proof-test"


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


def test_build_proof_passes_all_four_cases():
    proof = reconciliation.build_proof(CHALLENGE, now=NOW)

    assert proof["status"] == "PASS"
    assert proof["non_binding"] is True
    assert proof["reconciliation_cases_rehearsed"] == [
        "ambiguous",
        "redacted",
        "settled",
        "void",
    ]
    assert proof["cases"]["settled"]["terminal"] == "settled"
    assert proof["cases"]["void"]["terminal"] == "void"
    assert proof["cases"]["ambiguous"]["fail_closed"] is True
    assert proof["cases"]["ambiguous"]["pending"] is True
    assert proof["cases"]["redacted"]["terminal"] == "settled"
    assert len(proof["proof_sha256"]) == 64


def test_validate_rejects_tamper_and_source_drift(monkeypatch):
    proof = reconciliation.build_proof(CHALLENGE, now=NOW)

    tampered = json.loads(json.dumps(proof))
    tampered["cases"]["ambiguous"]["fail_closed"] = False
    with pytest.raises(
        reconciliation.ReconciliationProofError,
        match="precontest_reconcile_proof_integrity_invalid",
    ):
        reconciliation.validate_proof(tampered, challenge_id=CHALLENGE, now=NOW)

    drifted = json.loads(json.dumps(proof))
    drifted["reconcile_records_sha256"] = "0" * 64
    unsigned = dict(drifted)
    unsigned.pop("proof_sha256")
    drifted["proof_sha256"] = reconciliation._sha(unsigned)
    with pytest.raises(
        reconciliation.ReconciliationProofError,
        match="precontest_reconcile_source_changed",
    ):
        reconciliation.validate_proof(drifted, challenge_id=CHALLENGE, now=NOW)


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
    monkeypatch.setattr(
        collector,
        "_active_learning_proof",
        lambda challenge_id, now: None,
    )


def test_collector_without_matrix_keeps_only_settled_and_gate_false(tmp_path, monkeypatch):
    _collector_setup(monkeypatch, tmp_path)

    result = collector.collect(CHALLENGE, now=NOW)

    assert result["status"] == "COLLECTED_NO_GO"
    assert result["readiness"]["gates"]["SETTLEMENT_RECONCILIATION_GATE"] is False
    evidence = precontest_readiness.load_evidence(CHALLENGE)
    assert evidence["reconciliation_cases_rehearsed"] == ["settled"]


def test_collector_valid_matrix_passes_settlement_gate_only(tmp_path, monkeypatch):
    _collector_setup(monkeypatch, tmp_path)
    reconciliation.save_proof(CHALLENGE, now=NOW)

    result = collector.collect(CHALLENGE, now=NOW)

    assert result["status"] == "COLLECTED_NO_GO"
    assert result["readiness"]["gates"]["SETTLEMENT_RECONCILIATION_GATE"] is True
    assert result["readiness"]["go"] is False
    assert result["readiness"]["gates"]["HUMAN_INDEPENDENCE_GATE"] is False
    assert result["readiness"]["gates"]["CONTROL_PATH_REDUNDANCY_GATE"] is False

    evidence = precontest_readiness.load_evidence(CHALLENGE)
    assert evidence["reconciliation_cases_rehearsed"] == [
        "ambiguous",
        "redacted",
        "settled",
        "void",
    ]
    provenance = json.loads(collector.provenance_path(CHALLENGE).read_text("utf-8"))
    assert "reconciliation_matrix" in provenance["sources"]
    assert "SETTLEMENT_RECONCILIATION_GATE" not in provenance["unsupported_gates_forced_no_go"]


def test_collector_rejects_tampered_existing_matrix(tmp_path, monkeypatch):
    _collector_setup(monkeypatch, tmp_path)
    reconciliation.save_proof(CHALLENGE, now=NOW)
    path = reconciliation.proof_path(CHALLENGE)
    value = json.loads(path.read_text("utf-8"))
    value["cases"]["void"]["status"] = "FAIL"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(
        collector.MachineEvidenceError,
        match="precontest_machine_reconciliation_proof_invalid",
    ):
        collector.collect(CHALLENGE, now=NOW)
