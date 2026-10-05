import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import (
    airdrop_challenge,
    core,
    precontest_challenge,
    precontest_machine_evidence as machine,
    precontest_plumbing_apply as apply,
    precontest_plumbing_receipt as receipt,
    precontest_readiness,
)


NOW = datetime(2026, 10, 5, 6, 25, tzinfo=UTC)
DEADLINE = NOW + timedelta(days=2)
CHALLENGE = "plumbing-apply-test"
COMMIT = "1" * 40


def _evidence():
    return {
        "schema_version": 1,
        "challenge_id": CHALLENGE,
        "measured_at": NOW.isoformat(),
        "campaign_deadline": DEADLINE.isoformat(),
        "capture_to_executor_ms": 1000,
        "requires_chat_relay": True,
        "requires_user_terminal": True,
        "control_paths": [],
        "execution_modes_required": ["single", "batch"],
        "execution_modes_rehearsed": ["single", "batch"],
        "reconciliation_cases_rehearsed": ["settled", "void", "ambiguous", "redacted"],
        "runtime_deadline_guard": True,
        "post_deadline_fail_closed": True,
        "first_leg_policy_predefined": True,
        "first_leg_risk_bounded": True,
        "zero_trade_deadlock_prevented": True,
        "execution_plumbing_complete": False,
        "production_rehearsal_passed": False,
        "live_plumbing_changes_required": True,
    }


def _receipt():
    return {
        "schema_version": 1,
        "challenge_id": CHALLENGE,
        "status": "PASS",
        "non_binding": True,
        "generated_at": NOW.isoformat(),
        "deployed_commit": COMMIT,
        "worktree_clean": True,
        "repo_file_sha256": {},
        "installed_units": {},
        "rehearsal": {},
        "execution_plumbing_complete": True,
        "production_rehearsal_passed": True,
        "live_plumbing_changes_required": False,
        "receipt_sha256": "a" * 64,
    }


def _write_base(tmp_path):
    saved = precontest_readiness.save_evidence(CHALLENGE, _evidence())
    machine._write_provenance(
        CHALLENGE,
        {
            "schema_version": 1,
            "challenge_id": CHALLENGE,
            "collected_at": NOW.isoformat(),
            "collector": "precontest_machine_evidence",
            "non_binding": True,
            "readiness_evidence_sha256": saved["evidence_sha256"],
            "sources": {},
            "unsupported_gates_forced_no_go": [
                "HUMAN_INDEPENDENCE_GATE",
                "CONTROL_PATH_REDUNDANCY_GATE",
                "NO_LIVE_PLUMBING_GATE",
            ],
        },
    )
    path = receipt.receipt_path(CHALLENGE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_receipt()), encoding="utf-8")


def test_valid_receipt_changes_only_no_live_plumbing_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    _write_base(tmp_path)
    monkeypatch.setattr(
        receipt,
        "validate_receipt",
        lambda value, challenge_id, now: dict(value),
    )

    result = apply.apply_if_present(CHALLENGE, now=NOW)

    assert result is not None
    assert result["gates"]["NO_LIVE_PLUMBING_GATE"] is True
    assert result["gates"]["HUMAN_INDEPENDENCE_GATE"] is False
    assert result["gates"]["CONTROL_PATH_REDUNDANCY_GATE"] is False
    assert result["go"] is False

    saved = precontest_readiness.load_evidence(CHALLENGE)
    assert saved["execution_plumbing_complete"] is True
    assert saved["production_rehearsal_passed"] is True
    assert saved["live_plumbing_changes_required"] is False
    assert saved["requires_chat_relay"] is True
    assert saved["requires_user_terminal"] is True
    assert saved["control_paths"] == []

    provenance = json.loads(machine.provenance_path(CHALLENGE).read_text("utf-8"))
    assert "production_plumbing_receipt" in provenance["sources"]
    assert "NO_LIVE_PLUMBING_GATE" not in provenance["unsupported_gates_forced_no_go"]
    assert "HUMAN_INDEPENDENCE_GATE" in provenance["unsupported_gates_forced_no_go"]


def test_missing_receipt_is_noop(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    precontest_readiness.save_evidence(CHALLENGE, _evidence())
    assert apply.apply_if_present(CHALLENGE, now=NOW) is None


def test_invalid_receipt_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    _write_base(tmp_path)

    def invalid(value, challenge_id, now):
        raise receipt.PlumbingReceiptError("precontest_plumbing_commit_mismatch")

    monkeypatch.setattr(receipt, "validate_receipt", invalid)
    with pytest.raises(apply.PlumbingApplyError, match="precontest_plumbing_receipt_invalid"):
        apply.apply_if_present(CHALLENGE, now=NOW)
