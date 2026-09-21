from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = (
    core.ROOT
    / "packaging"
    / "oracle"
    / "issue387-runcommand-availability-matrix.sh"
)


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue387_matrix_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue387_requires_real_cloudshell() -> None:
    text = _text()

    assert 'OCI_CLI_AUTH:-' in text
    assert '"instance_obo_user"' in text
    assert 'OCI_CLI_CONFIG_FILE:-' in text
    assert '"/etc/oci/config"' in text
    assert 'OCI_CLI_PROFILE:-' in text
    assert "/etc/oci/delegation_token" in text
    assert "CLOUDSHELL_ENV=PASS" in text


def test_issue387_uses_authoritative_sdk_api() -> None:
    text = _text()

    assert "InstancePrincipalsDelegationTokenSigner" in text
    assert "PluginconfigClient" in text
    assert "list_instanceagent_available_plugins(" in text
    assert "NoneRetryStrategy()" in text
    assert 'TARGET = "Compute Instance Run Command"' in text


def test_issue387_has_expected_matrix() -> None:
    text = _text()

    for token in (
        '("UBUNTU_20_04", "Canonical Ubuntu", "20.04")',
        '("UBUNTU_22_04", "Canonical Ubuntu", "22.04")',
        '("UBUNTU_24_04", "Canonical Ubuntu", "24.04")',
        '("ORACLE_LINUX_8", "Oracle Linux", "8")',
        '("ORACLE_LINUX_9", "Oracle Linux", "9")',
    ):
        assert token in text


def test_issue387_emits_safe_comparison_evidence() -> None:
    text = _text()

    for token in (
        "_FILTERED_MATCHES=",
        "_UNFILTERED_TOTAL=",
        "_PLUGINSET_FINGERPRINT=",
        "_TARGET_PRESENT=",
        "_TARGET_SUPPORTED=",
        "_TARGET_ENABLED_BY_DEFAULT=",
        "MATRIX_COMPLETE=YES",
    ):
        assert token in text


def test_issue387_hides_ids_tokens_and_raw_errors() -> None:
    text = _text()

    assert "TENANCY_OUTPUT=NO" in text
    assert "OCID_OUTPUT=NO" in text
    assert "DELEGATION_TOKEN_OUTPUT=NO" in text
    assert "RAW_OCI_ERROR_OUTPUT=NO" in text
    assert 'print(tenancy)' not in text
    assert 'print(token)' not in text
    assert 'print(str(exc))' not in text


def test_issue387_is_read_only() -> None:
    text = _text().lower()

    for forbidden in (
        "oci iam policy create",
        "oci iam policy update",
        "oci compute instance update",
        "oci instance-agent command create",
        "oci instance-agent command cancel",
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "snap install",
        "snap refresh",
        "apt install",
        "pip install",
        "iptables ",
        "update_instance(",
        "create_instance_agent_command",
        "cancel_instance_agent_command",
    ):
        assert forbidden not in text


def test_issue387_no_malformed_expansion() -> None:
    text = _text()

    assert (chr(36) * 2 + "{") not in text
