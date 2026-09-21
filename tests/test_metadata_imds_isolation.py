from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "block-technocore-metadata.sh"
README = core.ROOT / "packaging" / "oracle" / "README.md"


def _helper() -> str:
    return HELPER.read_text("utf-8")


def test_metadata_helper_shell_syntax() -> None:
    subprocess.run(["sh", "-n", str(HELPER)], check=True)


def test_metadata_helper_keeps_imds_jump_narrow() -> None:
    text = _helper()

    assert 'metadata=169.254.169.254/32' in text
    assert 'iptables -C OUTPUT -p tcp -d "$metadata" --dport 80 -j "$chain"' in text
    assert 'iptables -I OUTPUT 1 -p tcp -d "$metadata" --dport 80 -j "$chain"' in text

    assert 'iptables -A OUTPUT -d "$metadata" -j ACCEPT' not in text
    assert 'iptables -A "$chain" -j ACCEPT' not in text


def test_metadata_helper_allows_only_reviewed_imds_accounts_before_reject() -> None:
    text = _helper()

    root_rule = 'iptables -A "$chain" -m owner --uid-owner 0 -j RETURN'
    signer_rule = 'iptables -A "$chain" -m owner --uid-owner "$signer_uid" -j RETURN'
    oca_rule = 'iptables -A "$chain" -m owner --uid-owner "$oca_uid" -j RETURN'
    reject_rule = 'iptables -A "$chain" -j REJECT'

    assert root_rule in text
    assert signer_rule in text
    assert oca_rule in text
    assert reject_rule in text

    assert text.index(root_rule) < text.index(reject_rule)
    assert text.index(signer_rule) < text.index(reject_rule)
    assert text.index(oca_rule) < text.index(reject_rule)


def test_metadata_helper_gates_snap_daemon_on_oca_snap_unit() -> None:
    text = _helper()

    assert 'oca_service=snap.oracle-cloud-agent.oracle-cloud-agent.service' in text
    assert 'if systemctl cat "$oca_service" >/dev/null 2>&1; then' in text
    assert 'oca_uid=$(id -u snap_daemon 2>/dev/null)' in text
    assert 'snap_daemon account is required when Oracle Cloud Agent snap service exists' in text
    assert 'if [ -n "$oca_uid" ]; then' in text


def test_metadata_helper_preserves_application_denial() -> None:
    text = _helper()

    assert 'for account in technocore technocore-rpc; do' in text
    assert 'iptables -A "$chain" -j REJECT' in text

    return_lines = [
        line
        for line in text.splitlines()
        if '--uid-owner' in line and '-j RETURN' in line
    ]
    assert not any('"technocore"' in line for line in return_lines)
    assert not any('"technocore-rpc"' in line for line in return_lines)


def test_readme_documents_snap_daemon_security_scope() -> None:
    text = README.read_text("utf-8")

    assert "`snap_daemon`" in text
    assert "IMDS TCP/80" in text
    assert "does not create a general network ACCEPT" in text
    assert "any process running under that shared system UID inherits this IMDS access" in text
