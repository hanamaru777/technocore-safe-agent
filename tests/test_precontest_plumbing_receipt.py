import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flop_agent import precontest_plumbing_receipt as receipt
from flop_agent import precontest_readiness


NOW = datetime(2026, 10, 5, 6, 20, tzinfo=UTC)
CHALLENGE = "plumbing-receipt-test"
COMMIT = "1" * 40
UNIT_BYTES = b"installed-unit"
UNIT_SHA = receipt._sha_bytes(UNIT_BYTES)


def _repo_hashes():
    return {path: "2" * 64 for path in receipt.REQUIRED_REPO_FILES}


def _units():
    return {
        unit: {
            "fragment": f"/etc/systemd/system/{unit}",
            "enabled": "enabled",
            "active": "active",
            "sha256": UNIT_SHA,
        }
        for unit in receipt.INSTALLED_UNITS
    }


def _rehearsal(now=NOW):
    return {
        "sha256": "3" * 64,
        "evaluated_at": now.isoformat(),
        "capture_to_rehearsal_ms": 1200,
        "trade_id": "proof-trade",
        "stage_sha256": "4" * 64,
        "signer_access": False,
        "approval_written": False,
        "post_attempted": False,
    }


def _patch_runtime(monkeypatch):
    monkeypatch.setattr(receipt, "_current_commit", lambda root: COMMIT)
    monkeypatch.setattr(receipt, "_worktree_clean", lambda root: True)
    monkeypatch.setattr(receipt, "_repo_hashes", lambda root: _repo_hashes())
    monkeypatch.setattr(receipt, "_installed_unit_state", lambda root: _units())
    monkeypatch.setattr(receipt, "_rehearsal_proof", lambda now: _rehearsal(now))


def test_build_receipt_requires_exact_nonbinding_production_state(tmp_path, monkeypatch):
    _patch_runtime(monkeypatch)

    value = receipt.build_receipt(CHALLENGE, now=NOW, repo_root=tmp_path)

    assert value["status"] == "PASS"
    assert value["non_binding"] is True
    assert value["deployed_commit"] == COMMIT
    assert value["worktree_clean"] is True
    assert value["execution_plumbing_complete"] is True
    assert value["production_rehearsal_passed"] is True
    assert value["live_plumbing_changes_required"] is False
    assert value["rehearsal"]["signer_access"] is False
    assert value["rehearsal"]["approval_written"] is False
    assert value["rehearsal"]["post_attempted"] is False
    assert len(value["receipt_sha256"]) == 64


def test_validate_receipt_rejects_tamper_commit_drift_and_stale(tmp_path, monkeypatch):
    _patch_runtime(monkeypatch)
    value = receipt.build_receipt(CHALLENGE, now=NOW, repo_root=tmp_path)

    monkeypatch.setattr(receipt, "_bounded_bytes", lambda path, label: UNIT_BYTES)
    valid = receipt.validate_receipt(value, challenge_id=CHALLENGE, now=NOW, repo_root=tmp_path)
    assert valid["receipt_sha256"] == value["receipt_sha256"]

    tampered = json.loads(json.dumps(value))
    tampered["live_plumbing_changes_required"] = True
    with pytest.raises(receipt.PlumbingReceiptError, match="precontest_plumbing_receipt_integrity_invalid"):
        receipt.validate_receipt(tampered, challenge_id=CHALLENGE, now=NOW, repo_root=tmp_path)

    monkeypatch.setattr(receipt, "_current_commit", lambda root: "5" * 40)
    with pytest.raises(receipt.PlumbingReceiptError, match="precontest_plumbing_commit_mismatch"):
        receipt.validate_receipt(value, challenge_id=CHALLENGE, now=NOW, repo_root=tmp_path)

    monkeypatch.setattr(receipt, "_current_commit", lambda root: COMMIT)
    stale_now = NOW + precontest_readiness.MAX_EVIDENCE_AGE + timedelta(seconds=1)
    with pytest.raises(receipt.PlumbingReceiptError, match="precontest_plumbing_receipt_stale"):
        receipt.validate_receipt(value, challenge_id=CHALLENGE, now=stale_now, repo_root=tmp_path)


def test_build_receipt_fails_when_worktree_dirty(tmp_path, monkeypatch):
    _patch_runtime(monkeypatch)
    monkeypatch.setattr(receipt, "_worktree_clean", lambda root: False)

    with pytest.raises(receipt.PlumbingReceiptError, match="precontest_plumbing_worktree_dirty"):
        receipt.build_receipt(CHALLENGE, now=NOW, repo_root=tmp_path)
