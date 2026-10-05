import json
from datetime import UTC, timedelta

import pytest

from flop_agent import close_call
from flop_agent import precontest_deadline_proof as deadline
from flop_agent import precontest_machine_evidence as collector
from flop_agent import precontest_readiness


NOW = close_call.LOCK - timedelta(hours=1)
CHALLENGE = "deadline-proof-test"


def _plan(challenge_id=CHALLENGE, *, deadline_at=close_call.LOCK):
    return {
        "challenge_id": challenge_id,
        "deadline": deadline_at.astimezone(UTC).isoformat(),
    }


def _rehearsal(now=NOW):
    return {
        "sha256": "1" * 64,
        "evaluated_at": now.astimezone(UTC).isoformat(),
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
        "last_reconciled_at": NOW.astimezone(UTC).isoformat(),
    }


def test_build_proof_dynamically_blocks_exact_and_post_lock(monkeypatch):
    monkeypatch.setattr(
        deadline.airdrop_challenge,
        "build_plan",
        lambda challenge_id, now=None: _plan(challenge_id),
    )

    proof = deadline.build_proof(CHALLENGE, now=NOW)

    assert proof["status"] == "PASS"
    assert proof["non_binding"] is True
    assert proof["campaign_deadline"] == close_call.LOCK.astimezone(UTC).isoformat()
    assert proof["runtime_lock_at"] == proof["campaign_deadline"]
    assert proof["exact_lock"]["status"] == "LOCKED"
    assert proof["exact_lock"]["stage_invocations"] == 0
    assert proof["post_lock"]["status"] == "LOCKED"
    assert proof["post_lock"]["stage_invocations"] == 0
    assert proof["runtime_deadline_guard"] is True
    assert proof["post_deadline_fail_closed"] is True
    assert proof["executor_guard"]["guard_present"] is True
    assert proof["executor_guard"]["preflight_before_sign"] is True
    assert proof["executor_guard"]["preflight_before_post"] is True
    assert len(proof["proof_sha256"]) == 64


def test_build_proof_rejects_challenge_deadline_not_bound_to_runtime(monkeypatch):
    monkeypatch.setattr(
        deadline.airdrop_challenge,
        "build_plan",
        lambda challenge_id, now=None: _plan(
            challenge_id,
            deadline_at=close_call.LOCK + timedelta(hours=1),
        ),
    )

    with pytest.raises(
        deadline.DeadlineProofError,
        match="precontest_deadline_runtime_deadline_mismatch",
    ):
        deadline.build_proof(CHALLENGE, now=NOW)


def test_saved_proof_validates_and_tamper_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    monkeypatch.setattr(
        deadline.airdrop_challenge,
        "build_plan",
        lambda challenge_id, now=None: _plan(challenge_id),
    )

    proof = deadline.save_proof(CHALLENGE, now=NOW)
    valid = deadline.validate_proof(
        proof,
        challenge_id=CHALLENGE,
        expected_deadline=close_call.LOCK.isoformat(),
        now=NOW,
    )
    assert valid["proof_sha256"] == proof["proof_sha256"]

    path = deadline.proof_path(CHALLENGE)
    tampered = json.loads(path.read_text("utf-8"))
    tampered["post_deadline_fail_closed"] = False
    path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(
        deadline.DeadlineProofError,
        match="precontest_deadline_proof_integrity_invalid",
    ):
        deadline.validate_proof(
            tampered,
            challenge_id=CHALLENGE,
            expected_deadline=close_call.LOCK.isoformat(),
            now=NOW,
        )


def _collector_setup(monkeypatch, tmp_path):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    monkeypatch.setattr(
        collector.airdrop_challenge,
        "build_plan",
        lambda challenge_id, now=None: _plan(challenge_id),
    )
    monkeypatch.setattr(
        deadline.airdrop_challenge,
        "build_plan",
        lambda challenge_id, now=None: _plan(challenge_id),
    )
    monkeypatch.setattr(collector, "_fresh_rehearsal", lambda now: _rehearsal(now))
    monkeypatch.setattr(collector, "_settled_ledger_proof", _settled)


def test_collector_without_deadline_proof_keeps_gate_false(tmp_path, monkeypatch):
    _collector_setup(monkeypatch, tmp_path)

    result = collector.collect(CHALLENGE, now=NOW)

    assert result["status"] == "COLLECTED_NO_GO"
    assert result["readiness"]["gates"]["DEADLINE_GATE"] is False
    evidence = precontest_readiness.load_evidence(CHALLENGE)
    assert evidence["runtime_deadline_guard"] is False
    assert evidence["post_deadline_fail_closed"] is False


def test_collector_valid_machine_proof_passes_deadline_gate_only(tmp_path, monkeypatch):
    _collector_setup(monkeypatch, tmp_path)
    deadline.save_proof(CHALLENGE, now=NOW)

    result = collector.collect(CHALLENGE, now=NOW)

    assert result["status"] == "COLLECTED_NO_GO"
    assert result["readiness"]["gates"]["DEADLINE_GATE"] is True
    assert result["readiness"]["go"] is False
    assert result["readiness"]["gates"]["HUMAN_INDEPENDENCE_GATE"] is False
    assert result["readiness"]["gates"]["CONTROL_PATH_REDUNDANCY_GATE"] is False
    evidence = precontest_readiness.load_evidence(CHALLENGE)
    assert evidence["runtime_deadline_guard"] is True
    assert evidence["post_deadline_fail_closed"] is True

    provenance = json.loads(
        collector.provenance_path(CHALLENGE).read_text("utf-8")
    )
    assert "deadline_fail_closed" in provenance["sources"]
    assert "DEADLINE_GATE" not in provenance["unsupported_gates_forced_no_go"]


def test_collector_rejects_tampered_existing_deadline_proof(tmp_path, monkeypatch):
    _collector_setup(monkeypatch, tmp_path)
    deadline.save_proof(CHALLENGE, now=NOW)
    path = deadline.proof_path(CHALLENGE)
    value = json.loads(path.read_text("utf-8"))
    value["runtime_deadline_guard"] = False
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(
        collector.MachineEvidenceError,
        match="precontest_machine_deadline_proof_invalid",
    ):
        collector.collect(CHALLENGE, now=NOW)
