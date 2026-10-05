from datetime import UTC, datetime
from pathlib import Path

import pytest

from flop_agent import precontest_ci_control_path_probe as ci_probe


NOW = datetime(2026, 10, 5, 13, 20, tzinfo=UTC)
CHALLENGE = "ci-readonly-proof-test"
NONCE = "a" * 32
HEAD = "b" * 40


def _ssh_env(monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "redacted")
    monkeypatch.setenv("SSH_CLIENT", "redacted")
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", f"proof {CHALLENGE} {NONCE}")
    monkeypatch.delenv("SSH_TTY", raising=False)


def test_probe_is_authenticated_ready_but_intentionally_non_binding(monkeypatch):
    _ssh_env(monkeypatch)
    monkeypatch.setattr(ci_probe.direct, "_repo_head", lambda: HEAD)
    monkeypatch.setattr(ci_probe.direct, "_systemctl_path", lambda: "/usr/bin/systemctl")
    monkeypatch.setattr(ci_probe.direct, "_sudo_path", lambda: "/usr/bin/sudo")
    monkeypatch.setattr(
        ci_probe.direct,
        "_unit_facts",
        lambda systemctl: ("loaded", ci_probe.direct.EXPECTED_FRAGMENT),
    )
    calls = []
    monkeypatch.setattr(
        ci_probe.direct,
        "_fixed_start_permission",
        lambda sudo, systemctl: calls.append((sudo, systemctl)),
    )

    receipt = ci_probe.build_readonly_probe(CHALLENGE, NONCE, now=NOW)

    assert receipt["path_id"] == "github-actions-fixed-ssh-readonly"
    assert receipt["path_type"] == "ci_deploy"
    assert receipt["authenticated"] is True
    assert receipt["ready"] is True
    assert receipt["binding_capable"] is False
    assert receipt["quota_independent"] is True
    assert receipt["failure_domain"] == "github-actions-fixed-ssh"
    assert CHALLENGE not in receipt["probe_method"]
    assert NONCE not in receipt["probe_method"]
    assert calls == [("/usr/bin/sudo", "/usr/bin/systemctl")]


def test_probe_requires_exact_non_tty_forced_ssh_context(monkeypatch):
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_CLIENT", raising=False)
    with pytest.raises(ci_probe.CiControlPathProbeError, match="ssh_session_missing"):
        ci_probe.build_readonly_probe(CHALLENGE, NONCE, now=NOW)

    _ssh_env(monkeypatch)
    monkeypatch.setenv("SSH_TTY", "/dev/pts/1")
    with pytest.raises(ci_probe.CiControlPathProbeError, match="tty_forbidden"):
        ci_probe.build_readonly_probe(CHALLENGE, NONCE, now=NOW)

    _ssh_env(monkeypatch)
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", f"proof other {NONCE}")
    with pytest.raises(ci_probe.CiControlPathProbeError, match="forced_command_mismatch"):
        ci_probe.build_readonly_probe(CHALLENGE, NONCE, now=NOW)


def test_nonce_is_strict():
    for bad in ("", "a" * 31, "A" * 32, "g" * 32, "a" * 33):
        with pytest.raises(ci_probe.CiControlPathProbeError, match="nonce_invalid"):
            ci_probe._nonce(bad)


def test_forced_command_wrapper_has_no_generic_shell_or_binding_action():
    root = Path(__file__).resolve().parents[1]
    text = (root / "packaging/oracle/technocore-safe-agent-ci-control-proof").read_text("utf-8")

    assert "SSH_ORIGINAL_COMMAND" in text
    assert '[[ "$VERB" == "proof" ]]' in text
    assert "precontest_ci_control_path_probe" in text
    assert "eval " not in text
    assert "bash -c" not in text
    assert "sh -c" not in text
    assert "systemctl start" not in text
    assert "install-stdin" not in text
    assert "sudo " not in text


def test_workflow_is_manual_only_pinned_host_key_and_non_binding():
    root = Path(__file__).resolve().parents[1]
    text = (root / ".github/workflows/production-control-path-readonly-proof.yml").read_text("utf-8")

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
    assert "CONTROL_PATH_REDUNDANCY_GATE_CHANGED=NO" in text
    assert 'value["binding_capable"] is not False' in text
    assert "systemctl start" not in text
    assert "install-stdin" not in text
    assert "eval " not in text
    assert "workflow_call:" not in text


def test_workflow_does_not_echo_or_upload_secret_material():
    root = Path(__file__).resolve().parents[1]
    text = (root / ".github/workflows/production-control-path-readonly-proof.yml").read_text("utf-8")

    assert "upload-artifact" not in text
    assert "cat $RUNNER_TEMP/technocore-ci-key" not in text
    assert "cat $RUNNER_TEMP/technocore-ci-known-hosts" not in text
    assert "cat $RUNNER_TEMP/technocore-ci-ssh.err" not in text
    assert "set -x" not in text
    assert "rm -f" in text
