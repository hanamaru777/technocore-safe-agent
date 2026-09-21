from __future__ import annotations

# Read-only proof tests for Issue #371.

import subprocess
from flop_agent import core

HELPER = core.ROOT / "packaging" / "oracle" / "issue371-oca-imds-runtime-user-proof.sh"

def _text() -> str:
    return HELPER.read_text("utf-8")

def test_issue371_imds_proof_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)

def test_issue371_imds_proof_is_read_only() -> None:
    text=_text().lower()
    forbidden=(
        "iptables -a ","iptables -i ","iptables -d ","iptables -f ",
        "systemctl restart","systemctl stop","systemctl start",
        "snap refresh","snap revert","snap install","snap remove",
        "apt install","apt-get install","pip install","uv pip install",
        "run command create","instance-agent command create",
    )
    for token in forbidden:
        assert token not in text

def test_issue371_imds_proof_checks_actual_runtime_identity() -> None:
    text=_text()
    assert "OCA_MAIN_USER=" in text
    assert "SNAP_DAEMON_ACCOUNT_PRESENT=" in text
    assert "SNAP_DAEMON_PROCESS_COUNT=" in text
    assert "SNAP_DAEMON_PROCESS_COMM=" in text

def test_issue371_imds_proof_checks_firewall_without_uid_output() -> None:
    text=_text()
    assert "SNAP_DAEMON_IMDS_RETURN_RULE=" in text
    assert "ROOT_IMDS_RETURN_RULE=" in text
    assert "SIGNER_IMDS_RETURN_RULE=" in text
    assert "METADATA_FINAL_REJECT=" in text
    assert "UID_NUMBER_OUTPUT=NO" in text

def test_issue371_imds_proof_has_three_identity_probes() -> None:
    text=_text()
    assert "probe ROOT" in text
    assert "probe SNAP_DAEMON sudo -n -u snap_daemon --" in text
    assert "probe TECHNOCORE sudo -n -u technocore --" in text
    assert "-o /dev/null" in text
    assert "Authorization: Bearer Oracle" in text

def test_issue371_imds_proof_safety_tail() -> None:
    text=_text()
    for token in (
        "MUTATION_COMMANDS=NONE",
        "SERVICE_RESTART=NO",
        "FIREWALL_CHANGE=NO",
        "NETWORK_CHANGE=NO",
        "AGENT_CONFIG_CHANGE=NO",
        "RUN_COMMAND_CREATED=NO",
        "PACKAGE_INSTALL=NO",
        "IMDS_BODY_OUTPUT=NO",
        "OCID_OUTPUT=NO",
        "IP_OUTPUT=NO",
    ):
        assert token in text
