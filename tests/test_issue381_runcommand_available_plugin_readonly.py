from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = (
    core.ROOT
    / "packaging"
    / "oracle"
    / "issue381-runcommand-available-plugin-readonly.sh"
)


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue381_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue381_uses_exact_existing_sdk_api() -> None:
    text = _text()

    assert "EXPECTED_SDK=2.185.0" in text
    assert "from oci.compute_instance_agent import PluginconfigClient" in text
    assert "InstancePrincipalsSecurityTokenSigner" in text
    assert "list_instanceagent_available_plugins(" in text
    assert "Canonical Ubuntu" in text
    assert "EXPECTED_OS_VERSION=24.04" in text
    assert "name=plugin_name" in text
    assert "NoneRetryStrategy()" in text


def test_issue381_emits_only_safe_plugin_support_fields() -> None:
    text = _text()

    for token in (
        "CONTROL_PLANE_CALL=",
        "AVAILABLE_PLUGIN_MATCHES=",
        "AVAILABLE_PLUGIN_NAME=",
        "AVAILABLE_PLUGIN_SUPPORTED=",
        "AVAILABLE_PLUGIN_ENABLED_BY_DEFAULT=",
        "RUN_COMMAND_AVAILABLE_RESULT=",
    ):
        assert token in text

    assert "OCID_OUTPUT=NO" in text
    assert "RAW_OCI_ERROR_OUTPUT=NO" in text
    assert "print(compartment_id)" not in text
    assert "print(region)" not in text
    assert "print(str(exc))" not in text


def test_issue381_is_read_only() -> None:
    text = _text().lower()

    for forbidden in (
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "snap refresh",
        "snap revert",
        "snap install",
        "snap remove",
        "apt install",
        "apt-get install",
        "pip install",
        "uv pip install",
        "iptables -a ",
        "iptables -i ",
        "iptables -d ",
        "iptables -f ",
        "update_instance(",
        "create_instance_agent_command",
        "cancel_instance_agent_command",
        "run command create",
        "instance-agent command create",
        "sqlite3.connect",
        "pragma ",
    ):
        assert forbidden not in text


def test_issue381_has_no_malformed_double_dollar_expansion() -> None:
    text = _text()

    assert (chr(36) * 2 + "{") not in text


def test_issue381_safety_tail() -> None:
    text = _text()

    for token in (
        "PACKAGE_INSTALL=NO",
        "MUTATION_COMMANDS=NONE",
        "AGENT_CONFIG_CHANGE=NO",
        "IAM_CHANGE=NO",
        "PLUGIN_ENABLE=NO",
        "RUN_COMMAND_CREATED=NO",
        "SERVICE_RESTART=NO",
        "SNAP_MUTATION=NO",
        "OCID_OUTPUT=NO",
        "RAW_OCI_ERROR_OUTPUT=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
    ):
        assert token in text
