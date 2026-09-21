from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = (
    core.ROOT
    / "packaging"
    / "oracle"
    / "issue381-cloudshell-sdk-available-plugin-v4.sh"
)


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue381_cloudshell_sdk_v4_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue381_cloudshell_sdk_v4_requires_real_cloudshell() -> None:
    text = _text()

    assert 'OCI_CLI_AUTH:-' in text
    assert '"instance_obo_user"' in text
    assert 'OCI_CLI_CONFIG_FILE:-' in text
    assert '"/etc/oci/config"' in text
    assert 'OCI_CLI_PROFILE:-' in text
    assert "/etc/oci/delegation_token" in text
    assert "CLOUDSHELL_ENV=PASS" in text


def test_issue381_cloudshell_sdk_v4_uses_delegation_token_signer() -> None:
    text = _text()

    assert "InstancePrincipalsDelegationTokenSigner" in text
    assert "delegation_token=token" in text
    assert "PluginconfigClient" in text
    assert "IdentityClient" in text
    assert "NoneRetryStrategy()" in text


def test_issue381_cloudshell_sdk_v4_uses_authoritative_api() -> None:
    text = _text()

    assert "list_instanceagent_available_plugins(" in text
    assert 'TARGET = "Compute Instance Run Command"' in text
    assert 'OS_NAME = "Canonical Ubuntu"' in text
    assert 'OS_VERSION = "24.04"' in text
    assert "name=TARGET" in text


def test_issue381_cloudshell_sdk_v4_confirms_empty_filter_unfiltered() -> None:
    text = _text()

    assert "Filter returned no rows. Confirm against an unfiltered authoritative list." in text
    assert "UNFILTERED_CONFIRM" in text
    assert "UNFILTERED_TOTAL=" in text
    assert "RUN_COMMAND_AVAILABLE_RESULT=ABSENT" in text


def test_issue381_cloudshell_sdk_v4_has_accessible_compartment_fallback() -> None:
    text = _text()

    assert "list_call_get_all_results" in text
    assert "identity_client.list_compartments" in text
    assert 'access_level="ACCESSIBLE"' in text
    assert "AUTHORIZED_SCOPE_SOURCE=ACCESSIBLE_COMPARTMENT" in text


def test_issue381_cloudshell_sdk_v4_hides_sensitive_values() -> None:
    text = _text()

    assert "TENANCY_OUTPUT=NO" in text
    assert "OCID_OUTPUT=NO" in text
    assert "DELEGATION_TOKEN_OUTPUT=NO" in text
    assert "RAW_OCI_ERROR_OUTPUT=NO" in text
    assert 'print(tenancy)' not in text
    assert 'print(token)' not in text
    assert 'print(cid)' not in text
    assert 'print(str(exc))' not in text


def test_issue381_cloudshell_sdk_v4_is_read_only() -> None:
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


def test_issue381_cloudshell_sdk_v4_no_malformed_expansion() -> None:
    text = _text()

    assert (chr(36) * 2 + "{") not in text
