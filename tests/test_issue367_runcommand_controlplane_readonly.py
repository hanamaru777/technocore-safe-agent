from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue367-runcommand-controlplane-readonly.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue367_probe_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue367_probe_is_read_only() -> None:
    text = _text().lower()

    for forbidden in (
        "oci compute instance update",
        "instance-agent command create",
        "run command create",
        "snap refresh",
        "snap revert",
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "iptables -a ",
        "iptables -i ",
        "iptables -d ",
        "iptables -f ",
    ):
        assert forbidden not in text

    for token in (
        "MUTATION_COMMANDS=NONE",
        "AGENT_CONFIG_CHANGE=NO",
        "PLUGIN_ENABLE=NO",
        "RUN_COMMAND_CREATED=NO",
        "SERVICE_RESTART=NO",
        "OCID_OUTPUT=NO",
        "RAW_OCI_ERROR_OUTPUT=NO",
    ):
        assert token.lower() in text


def test_issue367_probe_uses_instance_principal_and_only_plugin_list() -> None:
    text = _text()

    assert "oci instance-agent plugin list" in text
    assert "--auth instance_principal" in text
    assert "--name "$PLUGIN_NAME"" in text
    assert "Compute Instance Run Command" in text
    assert "oci instance-agent plugin get" not in text
    assert "oci instance-agent command" not in text


def test_issue367_probe_never_prints_identifiers_or_raw_error() -> None:
    text = _text()

    assert 'echo "$INSTANCE_ID"' not in text
    assert 'echo "$COMPARTMENT_ID"' not in text
    assert 'cat "$TMPDIR/imds.json"' not in text
    assert 'cat "$TMPDIR/plugin.err"' not in text
    assert "CONTROL_PLANE_ERROR_CLASS=" in text


def test_issue367_probe_outputs_only_safe_status_fields() -> None:
    text = _text()

    for token in (
        "RUN_COMMAND_PLUGIN_MATCHES=",
        "RUN_COMMAND_PLUGIN name=",
        "RUN_COMMAND_CONTROL_PLANE_STATUS=",
        "CONTROL_PLANE_LIST_RC=",
        "CONTROL_PLANE_PARSE=",
        "OCI_CLI_PRESENT=",
        "ROOT_IMDS_HTTP=",
    ):
        assert token in text
