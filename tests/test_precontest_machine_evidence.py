import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import precontest_machine_evidence as collector
from flop_agent import precontest_readiness


def _rehearsal_result(now: datetime) -> dict:
    return {
        "schema_version": 1,
        "status": "WOULD_EXECUTE",
        "non_binding": True,
        "trade_id": "trade-1",
        "stage_sha256": "a" * 64,
        "capture_to_rehearsal_ms": 1200,
        "capture_to_stage_ms": 300,
        "target_capture_to_executor_ms": 5000,
        "target_met": True,
        "fresh_policy": {
            "wall_sweep": 1,
            "cash": "10000",
            "position": "0",
            "required_cash": "100",
            "price_edge_bps": "30",
            "offer_fresh": True,
            "price_fresh": True,
            "account_ready": True,
        },
        "signer_access": False,
        "approval_written": False,
        "post_attempted": False,
        "evaluated_at": now.isoformat(),
    }


def test_fresh_rehearsal_accepts_only_nonbinding_runtime_proof(tmp_path, monkeypatch):
    now = datetime(2026, 10, 5, 3, 0, tzinfo=UTC)
    path = tmp_path / "rehearsal.json"
    payload = _rehearsal_result(now)
    raw = json.dumps(payload, sort_keys=True).encode()
    path.write_bytes(raw)
    monkeypatch.setattr(collector.close1_autonomous_rehearsal, "result_path", lambda: path)

    proof = collector._fresh_rehearsal(now=now)

    assert proof["capture_to_rehearsal_ms"] == 1200
    assert proof["trade_id"] == "trade-1"
    assert proof["sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("status", "BLOCKED_PREFLIGHT", "precontest_machine_rehearsal_not_passed"),
        ("non_binding", False, "precontest_machine_rehearsal_not_passed"),
        ("target_met", False, "precontest_machine_rehearsal_sla_failed"),
        ("signer_access", True, "precontest_machine_rehearsal_signer_access"),
        ("approval_written", True, "precontest_machine_rehearsal_binding_side_effect"),
        ("post_attempted", True, "precontest_machine_rehearsal_binding_side_effect"),
        ("capture_to_rehearsal_ms", 5001, "precontest_machine_rehearsal_latency_invalid"),
    ],
)
def test_fresh_rehearsal_rejects_optimistic_or_binding_artifacts(
    tmp_path, monkeypatch, field, value, reason
):
    now = datetime(2026, 10, 5, 3, 0, tzinfo=UTC)
    path = tmp_path / "rehearsal.json"
    payload = _rehearsal_result(now)
    payload[field] = value
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(collector.close1_autonomous_rehearsal, "result_path", lambda: path)

    with pytest.raises(collector.MachineEvidenceError, match=reason):
        collector._fresh_rehearsal(now=now)


def test_fresh_rehearsal_rejects_stale_proof(tmp_path, monkeypatch):
    now = datetime(2026, 10, 5, 3, 0, tzinfo=UTC)
    path = tmp_path / "rehearsal.json"
    payload = _rehearsal_result(now - precontest_readiness.MAX_EVIDENCE_AGE - timedelta(seconds=1))
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(collector.close1_autonomous_rehearsal, "result_path", lambda: path)

    with pytest.raises(collector.MachineEvidenceError, match="precontest_machine_rehearsal_stale"):
        collector._fresh_rehearsal(now=now)


def test_collect_saves_only_machine_proven_partial_evidence(tmp_path, monkeypatch):
    now = datetime(2026, 10, 5, 3, 0, tzinfo=UTC)
    deadline = datetime(2026, 10, 6, 9, 0, tzinfo=UTC).isoformat()
    challenge_id = "future-close1"

    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path / "challenges")
    monkeypatch.setattr(
        collector.airdrop_challenge,
        "build_plan",
        lambda cid, now=None: {"challenge_id": cid, "deadline": deadline},
    )
    monkeypatch.setattr(
        collector,
        "_fresh_rehearsal",
        lambda now: {
            "sha256": "1" * 64,
            "evaluated_at": now.isoformat(),
            "capture_to_rehearsal_ms": 900,
            "capture_to_stage_ms": 250,
            "trade_id": "trade-1",
            "stage_sha256": "2" * 64,
        },
    )
    monkeypatch.setattr(
        collector,
        "_settled_ledger_proof",
        lambda: {
            "sha256": "3" * 64,
            "as_of_sweep": 2382,
            "settled_trade_ids": ["settled-1"],
            "last_reconciled_at": now.isoformat(),
        },
    )

    result = collector.collect(challenge_id, now=now)

    assert result["status"] == "COLLECTED_NO_GO"
    assert result["readiness"]["go"] is False
    assert "HUMAN_INDEPENDENCE_GATE" in result["readiness"]["blockers"]
    assert "CONTROL_PATH_REDUNDANCY_GATE" in result["readiness"]["blockers"]
    assert "SETTLEMENT_RECONCILIATION_GATE" in result["readiness"]["blockers"]
    assert "DEADLINE_GATE" in result["readiness"]["blockers"]
    assert "ACTIVE_LEARNING_GATE" in result["readiness"]["blockers"]
    assert "NO_LIVE_PLUMBING_GATE" in result["readiness"]["blockers"]

    saved = precontest_readiness.load_evidence(challenge_id)
    assert saved is not None
    assert saved["capture_to_executor_ms"] == 900
    assert saved["requires_chat_relay"] is True
    assert saved["requires_user_terminal"] is True
    assert saved["control_paths"] == []
    assert saved["execution_modes_required"] == ["batch", "single"]
    assert saved["execution_modes_rehearsed"] == ["single"]
    assert saved["reconciliation_cases_rehearsed"] == ["settled"]
    assert saved["runtime_deadline_guard"] is False
    assert saved["production_rehearsal_passed"] is False
    assert saved["live_plumbing_changes_required"] is True

    provenance_path = collector.provenance_path(challenge_id)
    provenance = json.loads(provenance_path.read_text("utf-8"))
    digest = provenance.pop("provenance_sha256")
    assert digest == collector._sha_value(provenance)
    assert provenance["sources"]["close1_autonomous_rehearsal"]["sha256"] == "1" * 64
    assert provenance["sources"]["close1_reconciled_ledger"]["sha256"] == "3" * 64


def test_collect_cannot_be_promoted_to_go_by_caller_flags(tmp_path, monkeypatch):
    now = datetime(2026, 10, 5, 3, 0, tzinfo=UTC)
    deadline = datetime(2026, 10, 6, 9, 0, tzinfo=UTC).isoformat()
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path / "challenges")
    monkeypatch.setattr(
        collector.airdrop_challenge,
        "build_plan",
        lambda cid, now=None: {"challenge_id": cid, "deadline": deadline},
    )
    monkeypatch.setattr(
        collector,
        "_fresh_rehearsal",
        lambda now: {
            "sha256": "4" * 64,
            "evaluated_at": now.isoformat(),
            "capture_to_rehearsal_ms": 1,
            "capture_to_stage_ms": 0,
            "trade_id": "trade-2",
            "stage_sha256": "5" * 64,
        },
    )
    monkeypatch.setattr(
        collector,
        "_settled_ledger_proof",
        lambda: {
            "sha256": "6" * 64,
            "as_of_sweep": 1,
            "settled_trade_ids": ["settled-2"],
            "last_reconciled_at": now.isoformat(),
        },
    )

    result = collector.collect("future-close1", now=now)

    assert result["readiness"]["go"] is False
    assert result["readiness"]["gates"]["HUMAN_INDEPENDENCE_GATE"] is False
    assert result["readiness"]["gates"]["CONTROL_PATH_REDUNDANCY_GATE"] is False
    assert result["readiness"]["gates"]["NO_LIVE_PLUMBING_GATE"] is False
