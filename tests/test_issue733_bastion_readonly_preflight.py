import os
import subprocess
from pathlib import Path


SCRIPT = Path("packaging/oracle/issue733-bastion-readonly-preflight.sh")


def _text() -> str:
    return SCRIPT.read_text("utf-8")


def test_issue733_helper_is_shell_syntax_valid_and_fail_closed_outside_cloud_shell():
    syntax = subprocess.run(
        ["bash", "-n", str(SCRIPT)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert syntax.returncode == 0, syntax.stderr

    env = {"PATH": os.environ.get("PATH", "")}
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "CLOUDSHELL_ENV=STOP:not_instance_obo_user" in result.stdout
    assert "MUTATION_COMMANDS=NONE" in result.stdout
    assert "BASTION_CREATED=YES" not in result.stdout
    assert "SESSION_CREATED=YES" not in result.stdout


def test_issue733_requires_real_cloud_shell_delegation_environment():
    text = _text()
    assert 'OCI_CLI_AUTH:-' in text
    assert 'instance_obo_user' in text
    assert 'OCI_CLI_CONFIG_FILE:-' in text
    assert '/etc/oci/config' in text
    assert '/etc/oci/delegation_token' in text
    assert 'OCI_CLI_PROFILE:-' in text


def test_issue733_target_ocid_is_input_only_never_echoed_or_put_in_argv():
    text = _text()
    assert 'TECHNOCORE_TARGET_INSTANCE_OCID' in text
    assert "TARGET_INSTANCE_ID = os.environ.get('TECHNOCORE_TARGET_INSTANCE_OCID', '')" in text
    assert 'TARGET_INSTANCE_INPUT=ACCEPTED_PRIVATE' in text
    assert 'OCID_OUTPUT=NO' in text
    assert 'IP_OUTPUT=NO' in text
    assert 'DELEGATION_TOKEN_OUTPUT=NO' in text
    assert 'RAW_OCI_ERROR_OUTPUT=NO' in text
    assert 'echo "$TECHNOCORE_TARGET_INSTANCE_OCID"' not in text
    assert '"$OCI_CLI_PROFILE" "$TECHNOCORE_TARGET_INSTANCE_OCID"' not in text
    assert "TARGET_INSTANCE_ID = sys.argv" not in text
    assert "print(TARGET_INSTANCE_ID" not in text
    assert "+ TARGET_INSTANCE_ID" not in text


def test_issue733_uses_only_read_operations_for_oci_resources():
    text = _text()

    required_reads = (
        "compute.get_instance(",
        "compute.list_vnic_attachments(",
        "network.get_vnic(",
        "network.get_subnet(",
        "bastion.list_bastions(",
    )
    for token in required_reads:
        assert token in text

    forbidden_calls = (
        ".create_bastion(",
        ".update_bastion(",
        ".delete_bastion(",
        ".create_session(",
        ".update_session(",
        ".delete_session(",
        ".instance_action(",
        ".update_instance(",
        ".terminate_instance(",
        ".update_subnet(",
        ".update_security_list(",
        ".update_network_security_group(",
    )
    for token in forbidden_calls:
        assert token not in text


def test_issue733_never_promotes_control_path_from_read_only_preflight():
    text = _text()
    assert "SESSION_CREATE_PERMISSION=UNVERIFIED_READ_ONLY" in text
    assert "TARGET_PORT22_PATH=UNVERIFIED_READ_ONLY" in text
    assert "CONTROL_PATH_READY=NO" in text
    assert "CONTROL_PATH_REDUNDANCY_GATE_CHANGED=NO" in text
    assert "PHASE1_RESULT=EXISTING_BASTION_CANDIDATE" in text
    assert "PHASE1_RESULT=NO_EXISTING_BASTION_IN_TARGET_VCN_COMPARTMENT" in text


def test_issue733_safety_tail_forbids_all_cloud_and_production_mutations():
    text = _text()
    for marker in (
        "MUTATION_COMMANDS=NONE",
        "BASTION_CREATED=NO",
        "SESSION_CREATED=NO",
        "IAM_CHANGE=NO",
        "NETWORK_CHANGE=NO",
        "PLUGIN_CHANGE=NO",
        "INSTANCE_CHANGE=NO",
        "PRODUCTION_SSH_ACTION=NO",
    ):
        assert marker in text
