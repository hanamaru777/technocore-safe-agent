import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flop_agent import precontest_control_path_capture as capture
from flop_agent import precontest_control_path_proof as control
from flop_agent import precontest_readiness


NOW = datetime(2026, 10, 5, 9, 30, tzinfo=UTC)
CHALLENGE = "ssh-capture-test"
RAW_SSH = "203.0.113.9 50123 140.238.55.171 22"
RAW_CLIENT = "203.0.113.9 50123 22"
SYSTEMCTL = "/usr/bin/systemctl"
SUDO = "/usr/bin/sudo"
FRAGMENT = "/etc/systemd/system/technocore-safe-agent-close1-approved-trade.service"
HEAD = "a" * 40


def _completed(argv, rc=0, out=""):
    return capture.subprocess.CompletedProcess(argv, rc, stdout=out, stderr="")


def _install_good_probe(monkeypatch, calls):
    monkeypatch.setenv("SSH_CONNECTION", RAW_SSH)
    monkeypatch.setenv("SSH_CLIENT", RAW_CLIENT)
    monkeypatch.setattr(capture.shutil, "which", lambda name: SYSTEMCTL if name == "systemctl" else SUDO)
    monkeypatch.setattr(capture.socket, "gethostname", lambda: "technocore-resident")

    def fake_run(argv, *, cwd=None):
        calls.append((list(argv), cwd))
        if argv[:3] == ["git", "rev-parse", "HEAD"]:
            return _completed(argv, out=HEAD + "\n")
        if argv == [SYSTEMCTL, "show", capture.EXECUTOR_UNIT, "-p", "LoadState", "--value"]:
            return _completed(argv, out="loaded\n")
        if argv == [SYSTEMCTL, "show", capture.EXECUTOR_UNIT, "-p", "FragmentPath", "--value"]:
            return _completed(argv, out=FRAGMENT + "\n")
        if argv == [SUDO, "-n", "-l", SYSTEMCTL, "start", capture.EXECUTOR_UNIT]:
            return _completed(argv, out="allowed\n")
        raise AssertionError(f"unexpected command: {argv}")

    monkeypatch.setattr(capture, "_run", fake_run)


def _connector_receipt(*, verified_at=NOW):
    value = {
        "schema_version": control.SCHEMA_VERSION,
        "path_id": "remote-connector",
        "path_type": "connector",
        "endpoint_fingerprint": "remote-desktop-connector",
        "failure_domain": "connector-service-quota",
        "authenticated": True,
        "ready": True,
        "binding_capable": True,
        "quota_independent": False,
        "verified_at": verified_at.isoformat(),
        "probe_method": "connector-authenticated-preflight",
    }
    value["receipt_sha256"] = control._receipt_digest(value)
    return value


def test_missing_real_ssh_session_fails_before_any_probe(monkeypatch):
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_CLIENT", raising=False)
    called = []
    monkeypatch.setattr(capture, "_run", lambda *args, **kwargs: called.append(args))

    with pytest.raises(capture.ControlPathCaptureError, match="ssh_session_missing"):
        capture.build_direct_ssh_receipt(now=NOW)

    assert called == []


def test_permission_failure_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    calls = []
    _install_good_probe(monkeypatch, calls)
    good_run = capture._run

    def denied(argv, *, cwd=None):
        if argv == [SUDO, "-n", "-l", SYSTEMCTL, "start", capture.EXECUTOR_UNIT]:
            calls.append((list(argv), cwd))
            return _completed(argv, rc=1, out="not allowed\n")
        return good_run(argv, cwd=cwd)

    monkeypatch.setattr(capture, "_run", denied)

    with pytest.raises(capture.ControlPathCaptureError, match="executor_permission_missing"):
        capture.save_direct_ssh_receipt(CHALLENGE, now=NOW)

    assert not control.receipts_path(CHALLENGE).exists()


def test_successful_capture_is_nonsecret_and_one_path_remains_no_go(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    calls = []
    _install_good_probe(monkeypatch, calls)

    receipt = capture.save_direct_ssh_receipt(CHALLENGE, now=NOW)

    assert receipt["path_id"] == capture.PATH_ID
    assert receipt["path_type"] == "direct_ssh"
    assert receipt["authenticated"] is True
    assert receipt["ready"] is True
    assert receipt["binding_capable"] is True
    assert receipt["quota_independent"] is True
    assert receipt["endpoint_fingerprint"].startswith("sha256:")
    assert receipt["failure_domain"] == capture.FAILURE_DOMAIN

    artifact = control.receipts_path(CHALLENGE).read_text("utf-8")
    assert RAW_SSH not in artifact
    assert RAW_CLIENT not in artifact
    assert "203.0.113.9" not in artifact
    assert "140.238.55.171" not in artifact
    assert "technocore-resident" not in artifact

    proof = control.build_proof(CHALLENGE, now=NOW)
    assert proof["status"] == "NO_GO"
    assert proof["ready_independent_count"] == 1
    assert proof["quota_independent_ready"] is True

    direct_systemctl_mutations = [
        argv for argv, _cwd in calls
        if argv and argv[0] == SYSTEMCTL and any(word in argv for word in ("start", "stop", "restart", "enable", "disable"))
    ]
    assert direct_systemctl_mutations == []
    assert [SUDO, "-n", "-l", SYSTEMCTL, "start", capture.EXECUTOR_UNIT] in [argv for argv, _ in calls]


def test_existing_fresh_independent_receipt_is_preserved(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    path = control.receipts_path(CHALLENGE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([_connector_receipt()]), encoding="utf-8")
    calls = []
    _install_good_probe(monkeypatch, calls)

    capture.save_direct_ssh_receipt(CHALLENGE, now=NOW)

    rows = json.loads(path.read_text("utf-8"))
    assert [row["path_id"] for row in rows] == [capture.PATH_ID, "remote-connector"]
    proof = control.build_proof(CHALLENGE, now=NOW)
    assert proof["status"] == "PASS"
    assert proof["ready_independent_count"] == 2


def test_stale_receipt_is_pruned_but_tampered_receipt_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(precontest_readiness, "_root", lambda: tmp_path)
    path = control.receipts_path(CHALLENGE)
    path.parent.mkdir(parents=True, exist_ok=True)
    stale = _connector_receipt(verified_at=NOW - precontest_readiness.MAX_EVIDENCE_AGE - timedelta(seconds=1))
    path.write_text(json.dumps([stale]), encoding="utf-8")
    calls = []
    _install_good_probe(monkeypatch, calls)

    capture.save_direct_ssh_receipt(CHALLENGE, now=NOW)
    rows = json.loads(path.read_text("utf-8"))
    assert [row["path_id"] for row in rows] == [capture.PATH_ID]

    tampered = _connector_receipt()
    tampered["ready"] = False
    path.write_text(json.dumps([tampered]), encoding="utf-8")
    with pytest.raises(capture.ControlPathCaptureError, match="existing_receipt_invalid"):
        capture.save_direct_ssh_receipt(CHALLENGE, now=NOW)


def test_endpoint_fingerprint_changes_without_leaking_inputs(monkeypatch):
    monkeypatch.setattr(capture.socket, "gethostname", lambda: "private-hostname")
    a = capture._endpoint_fingerprint(fragment_path="/etc/systemd/system/a.service")
    b = capture._endpoint_fingerprint(fragment_path="/etc/systemd/system/b.service")
    assert a != b
    assert "private-hostname" not in a
    assert "/etc/systemd" not in a
