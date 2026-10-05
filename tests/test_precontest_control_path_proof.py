import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import precontest_control_path_proof as control
from flop_agent import precontest_readiness

NOW = datetime(2026, 10, 5, 7, 0, tzinfo=UTC)
CHALLENGE = "control-path-proof-test"


def _receipt(
    path_id: str,
    *,
    path_type: str = "direct_ssh",
    endpoint: str = "prod-ssh",
    failure_domain: str = "operator-windows-ssh",
    authenticated: bool = True,
    ready: bool = True,
    binding_capable: bool = True,
    quota_independent: bool = True,
    verified_at: datetime = NOW,
):
    value = {
        "schema_version": 1,
        "path_id": path_id,
        "path_type": path_type,
        "endpoint_fingerprint": endpoint,
        "failure_domain": failure_domain,
        "authenticated": authenticated,
        "ready": ready,
        "binding_capable": binding_capable,
        "quota_independent": quota_independent,
        "verified_at": verified_at.isoformat(),
        "probe_method": "read-only-authenticated-preflight",
    }
    value["receipt_sha256"] = control._receipt_digest(value)
    return value


def _write_receipts(tmp_path, monkeypatch, rows):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    path = control.receipts_path(CHALLENGE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows), encoding="utf-8")
    return path


def test_no_receipts_is_honest_no_go(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    proof = control.build_proof(CHALLENGE, now=NOW)
    assert proof["status"] == "NO_GO"
    assert proof["ready_independent_count"] == 0
    assert proof["control_paths"] == []


def test_one_ready_direct_ssh_path_is_still_no_go(tmp_path, monkeypatch):
    _write_receipts(tmp_path, monkeypatch, [_receipt("direct-ssh")])
    proof = control.build_proof(CHALLENGE, now=NOW)
    assert proof["status"] == "NO_GO"
    assert proof["ready_independent_count"] == 1
    assert proof["quota_independent_ready"] is True


def test_two_independent_ready_paths_with_quota_independent_pass(tmp_path, monkeypatch):
    rows = [
        _receipt("direct-ssh"),
        _receipt(
            "connector",
            path_type="connector",
            endpoint="remote-desktop-connector",
            failure_domain="connector-service-quota",
            quota_independent=False,
        ),
    ]
    _write_receipts(tmp_path, monkeypatch, rows)
    proof = control.build_proof(CHALLENGE, now=NOW)
    assert proof["status"] == "PASS"
    assert proof["ready_independent_count"] == 2
    assert proof["quota_independent_ready"] is True
    assert {row["path_id"] for row in proof["control_paths"]} == {"direct-ssh", "connector"}


def test_aliases_same_endpoint_and_failure_domain_do_not_double_count(tmp_path, monkeypatch):
    rows = [
        _receipt("ssh-a"),
        _receipt("ssh-b"),
    ]
    _write_receipts(tmp_path, monkeypatch, rows)
    proof = control.build_proof(CHALLENGE, now=NOW)
    assert proof["status"] == "NO_GO"
    assert proof["ready_independent_count"] == 1


def test_quota_blocked_connector_is_visible_but_not_ready(tmp_path, monkeypatch):
    rows = [
        _receipt("direct-ssh"),
        _receipt(
            "connector",
            path_type="connector",
            endpoint="remote-desktop-connector",
            failure_domain="connector-service-quota",
            ready=False,
            quota_independent=False,
        ),
    ]
    _write_receipts(tmp_path, monkeypatch, rows)
    proof = control.build_proof(CHALLENGE, now=NOW)
    assert proof["status"] == "NO_GO"
    assert proof["receipt_count"] == 2
    assert proof["ready_independent_count"] == 1


def test_non_binding_channel_cannot_be_forged_as_control_path(tmp_path, monkeypatch):
    row = _receipt("discord", path_type="direct_ssh")
    row["path_type"] = "discord"
    row["receipt_sha256"] = control._receipt_digest(row)
    _write_receipts(tmp_path, monkeypatch, [row])
    with pytest.raises(control.ControlPathProofError, match="non_binding_path_forbidden"):
        control.build_proof(CHALLENGE, now=NOW)


def test_tamper_and_stale_receipts_fail_closed(tmp_path, monkeypatch):
    row = _receipt("direct-ssh")
    row["ready"] = False
    _write_receipts(tmp_path, monkeypatch, [row])
    with pytest.raises(control.ControlPathProofError, match="receipt_integrity_invalid"):
        control.build_proof(CHALLENGE, now=NOW)

    stale = _receipt(
        "stale-ssh",
        verified_at=NOW - precontest_readiness.MAX_EVIDENCE_AGE - timedelta(seconds=1),
    )
    _write_receipts(tmp_path, monkeypatch, [stale])
    with pytest.raises(control.ControlPathProofError, match="receipt_stale"):
        control.build_proof(CHALLENGE, now=NOW)


def test_saved_proof_validation_rejects_integrity_tamper(tmp_path, monkeypatch):
    _write_receipts(tmp_path, monkeypatch, [_receipt("direct-ssh")])
    proof = control.save_proof(CHALLENGE, now=NOW)
    valid = control.validate_proof(proof, challenge_id=CHALLENGE, now=NOW)
    assert valid["status"] == "NO_GO"

    tampered = json.loads(json.dumps(proof))
    tampered["status"] = "PASS"
    with pytest.raises(control.ControlPathProofError, match="proof_integrity_invalid"):
        control.validate_proof(tampered, challenge_id=CHALLENGE, now=NOW)
