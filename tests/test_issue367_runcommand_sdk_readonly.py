from __future__ import annotations

import subprocess
from flop_agent import core

HELPER = core.ROOT / "packaging" / "oracle" / "issue367-runcommand-sdk-readonly.sh"

def _text() -> str:
    return HELPER.read_text("utf-8")

def test_issue367_sdk_probe_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)

def test_issue367_sdk_probe_is_read_only_and_no_install() -> None:
    text=_text().lower()
    for forbidden in (
        "pip install","uv pip install","apt install","apt-get install",
        "oci compute instance update","instance-agent command create","run command create",
        "snap refresh","snap revert","systemctl restart","systemctl stop","systemctl start",
        "iptables -a ","iptables -i ","iptables -d ","iptables -f ",
    ):
        assert forbidden not in text
    for token in (
        "PACKAGE_INSTALL=NO","MUTATION_COMMANDS=NONE","AGENT_CONFIG_CHANGE=NO",
        "PLUGIN_ENABLE=NO","RUN_COMMAND_CREATED=NO","SERVICE_RESTART=NO",
        "OCID_OUTPUT=NO","RAW_OCI_ERROR_OUTPUT=NO",
    ):
        assert token.lower() in text

def test_issue367_sdk_probe_uses_existing_sdk_only() -> None:
    text=_text()
    assert "import oci" in text
    assert "PluginClient" in text
    assert "InstancePrincipalsSecurityTokenSigner" in text
    assert "list_instance_agent_plugins" in text
    assert 'name=plugin_name' in text
    assert "NoneRetryStrategy" in text

def test_issue367_sdk_probe_never_prints_identifiers_or_raw_body() -> None:
    text=_text()
    assert 'echo "$INSTANCE_ID"' not in text
    assert 'echo "$COMPARTMENT_ID"' not in text
    assert 'cat "$TMPDIR/imds.json"' not in text
    assert "instance_id=" in text
    assert "compartment_id=" in text

def test_issue367_sdk_probe_outputs_safe_classification() -> None:
    text=_text()
    for token in (
        "OCI_PYTHON_SDK_PRESENT=","OCI_PYTHON_SDK_VERSION=","CONTROL_PLANE_CALL=",
        "CONTROL_PLANE_ERROR_CLASS=","CONTROL_PLANE_HTTP_STATUS=",
        "RUN_COMMAND_PLUGIN_MATCHES=","RUN_COMMAND_CONTROL_PLANE_STATUS=",
    ):
        assert token in text
