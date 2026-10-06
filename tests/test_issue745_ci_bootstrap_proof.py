from datetime import UTC, datetime
from pathlib import Path

import pytest

from flop_agent import precontest_ci_bootstrap_probe as bootstrap


NOW = datetime(2026, 10, 6, 2, 55, tzinfo=UTC)
NONCE = "a" * 32
HEAD = "b" * 40


def _ssh_env(monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "redacted")
    monkeypatch.setenv("SSH_CLIENT", "redacted")
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", f"bootstrap {NONCE}")
    monkeypatch.delenv("SSH_TTY", raising=False)


def test_bootstrap_probe_is_authenticated_ready_and_non_binding(monkeypatch):
    _ssh_env(monkeypatch)
    monkeypatch.setattr(bootstrap.direct, "_repo_head", lambda: HEAD)
    monkeypatch.setattr(bootstrap.direct, "_systemctl_path", lambda: "/usr/bin/systemctl")
    monkeypatch.setattr(bootstrap.direct, "_sudo_path", lambda: "/usr/bin/sudo")
    monkeypatch.setattr(
        bootstrap.direct,
        "_unit_facts",
        lambda systemctl: ("loaded", bootstrap.direct.EXPECTED_FRAGMENT),
    )
    calls = []
    monkeypatch.setattr(
        bootstrap.direct,
        "_fixed_start_permission",
        lambda sudo, systemctl: calls.append((sudo, systemctl)),
    )

    result = bootstrap.build_bootstrap_probe(NONCE, now=NOW)

    assert result["status"] == "BOOTSTRAP_PROOF"
    assert result["authenticated"] is True
    assert result["ready"] is True
    assert result["binding_capable"] is False
    assert result["quota_independent"] is True
    assert result["verified_at"] == NOW.isoformat()
    assert len(result["context_sha256"]) == 64
    assert NONCE not in result["context_sha256"]
    assert calls == [("/usr/bin/sudo", "/usr/bin/systemctl")]


def test_bootstrap_probe_requires_exact_non_tty_forced_ssh(monkeypatch):
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_CLIENT", raising=False)
    with pytest.raises(bootstrap.CiBootstrapProbeError, match="ssh_session_missing"):
        bootstrap.build_bootstrap_probe(NONCE, now=NOW)

    _ssh_env(monkeypatch)
    monkeypatch.setenv("SSH_TTY", "/dev/pts/1")
    with pytest.raises(bootstrap.CiBootstrapProbeError, match="tty_forbidden"):
        bootstrap.build_bootstrap_probe(NONCE, now=NOW)

    _ssh_env(monkeypatch)
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", f"bootstrap {'b' * 32}")
    with pytest.raises(bootstrap.CiBootstrapProbeError, match="forced_command_mismatch"):
        bootstrap.build_bootstrap_probe(NONCE, now=NOW)


def test_bootstrap_nonce_is_strict():
    for bad in ("", "a" * 31, "A" * 32, "g" * 32, "a" * 33):
        with pytest.raises(bootstrap.CiBootstrapProbeError, match="nonce_invalid"):
            bootstrap._nonce(bad)


def test_bootstrap_workflow_is_manual_pinned_and_never_changes_gate():
    root = Path(__file__).resolve().parents[1]
    text = (root / ".github/workflows/production-control-path-bootstrap-proof.yml").read_text("utf-8")

    assert "workflow_dispatch:" in text
    assert "\n  push:" not in text
    assert "\n  pull_request:" not in text
    assert "\n  schedule:" not in text
    assert "permissions:\n  contents: read" in text
    assert '[[ "$RUN_REF" == "refs/heads/main" ]]' in text
    assert "TECHNOCORE_CI_SSH_KEY" in text
    assert "TECHNOCORE_CI_HOST" in text
    assert "TECHNOCORE_CI_KNOWN_HOSTS" in text
    assert "StrictHostKeyChecking=yes" in text
    assert "UserKnownHostsFile=" in text
    assert "ssh-keyscan" not in text
    assert "StrictHostKeyChecking=no" not in text
    assert '"bootstrap $NONCE"' in text
    assert "CI_BOOTSTRAP_CONTROL_PATH_PROOF=PASS" in text
    assert "CONTROL_PATH_REDUNDANCY_GATE_CHANGED=NO" in text
    assert 'value["binding_capable"] is not False' in text
    assert "systemctl start" not in text
    assert "install-stdin" not in text
    assert "workflow_call:" not in text
    assert "upload-artifact" not in text


def test_bootstrap_probe_source_has_no_service_start_or_state_install():
    root = Path(__file__).resolve().parents[1]
    text = (root / "src/flop_agent/precontest_ci_bootstrap_probe.py").read_text("utf-8")

    assert "systemctl start" not in text
    assert "install_receipt" not in text
    assert "save_receipt" not in text
    assert "subprocess" not in text
    assert "os.system" not in text
