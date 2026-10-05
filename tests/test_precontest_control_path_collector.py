import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import precontest_control_path_proof as control
from flop_agent import precontest_machine_evidence as collector
from flop_agent import precontest_readiness

NOW = datetime(2026, 10, 5, 7, 15, tzinfo=UTC)
DEADLINE = NOW + timedelta(days=1)
CHALLENGE = "control-path-collector-test"


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


def _receipt(
    path_id,
    *,
    path_type="direct_ssh",
    endpoint="prod-ssh",
    domain="operator-windows-ssh",
    quota_independent=True,
):
    value = {
        "schema_version": 1,
        "path_id": path_id,
        "path_type": path_type,
        "endpoint_fingerprint": endpoint,
        "failure_domain": domain,
        "authenticated": True,
        "ready": True,
        "binding_capable": True,
        "quota_independent": quota_independent,
        "verified_at": NOW.isoformat(),
        "probe_method": "read-only-authenticated-preflight",
    }
    value["receipt_sha256"] = control._receipt_digest(value)
    return value


def _setup(monkeypatch, tmp_path):
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
    monkeypatch.setattr(collector, "_batch_rehearsal_proof", lambda challenge_id, now: None)


def _write_receipts(rows):
    path = control.receipts_path(CHALLENGE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows), encoding="utf-8")


def test_missing_control_proof_keeps_gate_false(tmp_path, monkeypatch):
    _setup(monkeypatch, tmp_path)
    result = collector.collect(CHALLENGE, now=NOW)
    assert result["readiness"]["gates"]["CONTROL_PATH_REDUNDANCY_GATE"] is False
    evidence = precontest_readiness.load_evidence(CHALLENGE)
    assert evidence["control_paths"] == []


def test_one_path_no_go_proof_is_recorded_but_not_promoted(tmp_path, monkeypatch):
    _setup(monkeypatch, tmp_path)
    _write_receipts([_receipt("direct-ssh")])
    proof = control.save_proof(CHALLENGE, now=NOW)
    assert proof["status"] == "NO_GO"

    result = collector.collect(CHALLENGE, now=NOW)
    assert result["readiness"]["gates"]["CONTROL_PATH_REDUNDANCY_GATE"] is False
    assert precontest_readiness.load_evidence(CHALLENGE)["control_paths"] == []
    provenance = json.loads(collector.provenance_path(CHALLENGE).read_text("utf-8"))
    assert provenance["sources"]["control_path_redundancy"]["status"] == "NO_GO"
    assert "CONTROL_PATH_REDUNDANCY_GATE" in provenance["unsupported_gates_forced_no_go"]


def test_two_independent_paths_promote_only_control_path_gate(tmp_path, monkeypatch):
    _setup(monkeypatch, tmp_path)
    _write_receipts([
        _receipt("direct-ssh"),
        _receipt(
            "connector",
            path_type="connector",
            endpoint="remote-desktop",
            domain="connector-service-quota",
            quota_independent=False,
        ),
    ])
    proof = control.save_proof(CHALLENGE, now=NOW)
    assert proof["status"] == "PASS"

    result = collector.collect(CHALLENGE, now=NOW)
    assert result["readiness"]["gates"]["CONTROL_PATH_REDUNDANCY_GATE"] is True
    assert result["readiness"]["go"] is False
    evidence = precontest_readiness.load_evidence(CHALLENGE)
    assert len(evidence["control_paths"]) == 2
    assert result["readiness"]["gates"]["HUMAN_INDEPENDENCE_GATE"] is False
    assert result["readiness"]["gates"]["NO_LIVE_PLUMBING_GATE"] is False


def test_receipt_change_after_proof_fails_collector_closed(tmp_path, monkeypatch):
    _setup(monkeypatch, tmp_path)
    rows = [_receipt("direct-ssh")]
    _write_receipts(rows)
    control.save_proof(CHALLENGE, now=NOW)

    changed = [_receipt("direct-ssh"), _receipt(
        "connector",
        path_type="connector",
        endpoint="remote-desktop",
        domain="connector-service-quota",
        quota_independent=False,
    )]
    _write_receipts(changed)

    with pytest.raises(
        collector.MachineEvidenceError,
        match="precontest_machine_control_path_proof_invalid",
    ):
        collector.collect(CHALLENGE, now=NOW)
