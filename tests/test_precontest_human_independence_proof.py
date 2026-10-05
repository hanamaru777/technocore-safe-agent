import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flop_agent import precontest_human_independence_proof as human
from flop_agent import precontest_machine_evidence as collector
from flop_agent import precontest_readiness

NOW = datetime(2026, 10, 5, 8, 0, tzinfo=UTC)
CHALLENGE = "human-independence-proof-test"
DEADLINE = NOW + timedelta(days=1)


def _repo(root: Path) -> dict[str, str]:
    files = {
        human.DISPATCHER_FILE: "# fixed dispatcher\n",
        human.DISPATCHER_SERVICE: f"[Service]\nExecStart={human.DISPATCHER_EXEC_START}\n",
        human.EXECUTOR_FILE: "# fixed executor\n",
        human.EXECUTOR_SERVICE: f"[Service]\nExecStart={human.EXECUTOR_EXEC_START}\n",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    hashes = human._required_source_hashes(root)
    assert hashes is not None
    return hashes


def _receipt(source_sha256: dict[str, str], **patch) -> dict:
    value = {
        "schema_version": 1,
        "challenge_id": CHALLENGE,
        "status": "PASS",
        "non_binding": True,
        "generated_at": NOW.isoformat(),
        "path_id": "resident-fixed-handoff",
        "probe_method": human.PROBE_METHOD,
        "binding_capable": True,
        "automatic_handoff": True,
        "requires_chat_relay": False,
        "requires_user_terminal": False,
        "policy_configured_at": (NOW - timedelta(minutes=10)).isoformat(),
        "candidate_captured_at": (NOW - timedelta(seconds=2)).isoformat(),
        "signer_boundary_preserved": True,
        "fixed_function_only": True,
        "generic_privileged_rpc_exposed": False,
        "installed_dispatcher_unit": human.DISPATCHER_UNIT,
        "installed_dispatcher_exec_start": human.DISPATCHER_EXEC_START,
        "installed_executor_unit": human.EXECUTOR_UNIT,
        "installed_executor_exec_start": human.EXECUTOR_EXEC_START,
        "source_sha256": source_sha256,
    }
    value.update(patch)
    value["receipt_sha256"] = human._receipt_digest(value)
    return value


def _write_receipt(root: Path, value: dict) -> None:
    path = human.receipt_path(CHALLENGE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_missing_dispatcher_or_receipt_is_no_go(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path / "state")
    proof = human.build_proof(CHALLENGE, now=NOW, repo_root=tmp_path / "repo")
    assert proof["status"] == "NO_GO"
    assert proof["requires_chat_relay"] is True
    assert proof["requires_user_terminal"] is True
    assert proof["reason"] == "precontest_human_receipt_missing"


def test_valid_future_machine_receipt_can_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path / "state")
    repo = tmp_path / "repo"
    receipt = _receipt(_repo(repo))
    _write_receipt(tmp_path, receipt)
    valid = human.validate_receipt(receipt, challenge_id=CHALLENGE, now=NOW, repo_root=repo)
    assert valid == receipt
    proof = human.build_proof(CHALLENGE, now=NOW, repo_root=repo)
    assert proof["status"] == "PASS"
    assert proof["requires_chat_relay"] is False
    assert proof["requires_user_terminal"] is False


def test_policy_must_precede_capture_and_units_must_match(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path / "state")
    repo = tmp_path / "repo"
    hashes = _repo(repo)
    bad_time = _receipt(hashes, policy_configured_at=(NOW + timedelta(seconds=1)).isoformat())
    with pytest.raises(human.HumanIndependenceProofError, match="policy_timing_invalid"):
        human.validate_receipt(bad_time, challenge_id=CHALLENGE, now=NOW, repo_root=repo)
    bad_unit = _receipt(hashes, installed_dispatcher_unit="wrong.service")
    with pytest.raises(human.HumanIndependenceProofError, match="installed_unit_mismatch"):
        human.validate_receipt(bad_unit, challenge_id=CHALLENGE, now=NOW, repo_root=repo)


def test_receipt_source_drift_and_tamper_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path / "state")
    repo = tmp_path / "repo"
    receipt = _receipt(_repo(repo))
    tampered = json.loads(json.dumps(receipt))
    tampered["automatic_handoff"] = False
    with pytest.raises(human.HumanIndependenceProofError, match="integrity_invalid"):
        human.validate_receipt(tampered, challenge_id=CHALLENGE, now=NOW, repo_root=repo)
    (repo / human.EXECUTOR_FILE).write_text("# changed executor\n", encoding="utf-8")
    with pytest.raises(human.HumanIndependenceProofError, match="source_changed"):
        human.validate_receipt(receipt, challenge_id=CHALLENGE, now=NOW, repo_root=repo)


def _collector_setup(monkeypatch, tmp_path):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    monkeypatch.setattr(
        collector.airdrop_challenge,
        "build_plan",
        lambda challenge_id, now=None: {"challenge_id": challenge_id, "deadline": DEADLINE.isoformat()},
    )
    monkeypatch.setattr(
        collector,
        "_fresh_rehearsal",
        lambda now: {
            "sha256": "1" * 64,
            "evaluated_at": now.isoformat(),
            "capture_to_rehearsal_ms": 1000,
            "capture_to_stage_ms": 100,
            "trade_id": "trade-1",
            "stage_sha256": "2" * 64,
        },
    )
    monkeypatch.setattr(
        collector,
        "_settled_ledger_proof",
        lambda: {"sha256": "3" * 64, "as_of_sweep": 10, "settled_trade_ids": ["old"], "last_reconciled_at": NOW.isoformat()},
    )
    monkeypatch.setattr(collector, "_deadline_proof", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "_active_learning_proof", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "_reconciliation_proof", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "_batch_rehearsal_proof", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "_control_path_proof", lambda *args, **kwargs: None)


def test_collector_never_promotes_without_pass_proof(tmp_path, monkeypatch):
    _collector_setup(monkeypatch, tmp_path)
    monkeypatch.setattr(collector, "_human_independence_proof", lambda *args, **kwargs: None)
    result = collector.collect(CHALLENGE, now=NOW)
    evidence = precontest_readiness.load_evidence(CHALLENGE)
    assert evidence["requires_chat_relay"] is True
    assert evidence["requires_user_terminal"] is True
    assert result["readiness"]["gates"]["HUMAN_INDEPENDENCE_GATE"] is False


def test_collector_promotes_only_valid_pass_proof(tmp_path, monkeypatch):
    _collector_setup(monkeypatch, tmp_path)
    monkeypatch.setattr(
        collector,
        "_human_independence_proof",
        lambda *args, **kwargs: {
            "sha256": "4" * 64,
            "proof_sha256": "5" * 64,
            "generated_at": NOW.isoformat(),
            "status": "PASS",
            "path_id": "resident-fixed-handoff",
            "requires_chat_relay": False,
            "requires_user_terminal": False,
            "reason": None,
        },
    )
    result = collector.collect(CHALLENGE, now=NOW)
    evidence = precontest_readiness.load_evidence(CHALLENGE)
    assert evidence["requires_chat_relay"] is False
    assert evidence["requires_user_terminal"] is False
    assert result["readiness"]["gates"]["HUMAN_INDEPENDENCE_GATE"] is True
    assert result["readiness"]["go"] is False
