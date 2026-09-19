from __future__ import annotations

import subprocess
from pathlib import Path

from flop_agent import core


SCRIPT = core.ROOT / "packaging" / "oracle" / "oci-cloud-agent-diagnostic.sh"


def test_oci_cloud_agent_diagnostic_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def test_oci_cloud_agent_diagnostic_is_read_only() -> None:
    text = SCRIPT.read_text("utf-8")
    lowered = text.lower()

    forbidden = (
        "systemctl restart ",
        "systemctl stop ",
        "systemctl start ",
        "snap install ",
        "snap refresh ",
        "snap remove ",
        "apt install ",
        "apt-get install ",
        "yum install ",
        "dnf install ",
        "iptables -a ",
        "iptables -i ",
        "iptables -d ",
        "iptables -f ",
        "iptables -n ",
        "oci compute instance update",
        "instance-agent command create",
        "write_note(",
        "post_signed(",
        "sign_seed",
        "technocore_signing_key",
    )
    for token in forbidden:
        assert token not in lowered

    assert "MUTATION_PERFORMED=NO" in text
    assert "SERVICE_RESTART=NO" in text
    assert "PACKAGE_CHANGE=NO" in text
    assert "FIREWALL_CHANGE=NO" in text
    assert "RUN_COMMAND_CREATED=NO" in text
    assert "TECHNOCORE_WRITE=NO" in text


def test_oci_cloud_agent_diagnostic_never_prints_imds_body_or_raw_logs() -> None:
    text = SCRIPT.read_text("utf-8")

    assert 'echo "$tmp"' not in text
    assert 'cat "$tmp"' not in text
    assert "compartmentId" not in text
    assert "displayName" not in text
    assert '"id"' not in text
    assert "journalctl" in text
    assert "COUNTS ONLY" in text
    assert "sys.stdin.read().lower()" in text


def test_oci_cloud_agent_diagnostic_checks_security_boundary() -> None:
    text = SCRIPT.read_text("utf-8")

    assert "META_ROOT_RETURN_PRESENT" in text
    assert "META_SIGNER_RETURN_PRESENT" in text
    assert "META_FINAL_REJECT_PRESENT" in text
    assert "ROOT_IMDS_HTTP" in text
    assert "TECHNOCORE_IMDS_BLOCKED" in text
    assert "EXPECTED_SECURITY_ROOT_IMDS=200" in text
    assert "EXPECTED_SECURITY_TECHNOCORE_IMDS_BLOCKED=YES" in text


def test_oci_cloud_agent_diagnostic_checks_oracle_official_triage_inputs() -> None:
    text = SCRIPT.read_text("utf-8")

    assert "snap list oracle-cloud-agent" in text
    assert "snap.oracle-cloud-agent.oracle-cloud-agent.service" in text
    assert "snap.oracle-cloud-agent.oracle-cloud-agent-updater.service" in text
    assert "NTP_SYNCHRONIZED" in text
    assert "AGENT_CONFIG_MANAGEMENT_DISABLED" in text
    assert "AGENT_CONFIG_ALL_PLUGINS_DISABLED" in text
    assert "Compute Instance Run Command" in text
    assert "RUN_COMMAND_ADVERTISED" in text
    assert "RUN_COMMAND_LOCAL_ARTIFACT" in text
    assert "RUN_COMMAND_CONFIG_PRESENT" in text
    assert "RUN_COMMAND_LOG_PRESENT" in text


def test_oci_cloud_agent_diagnostic_log_classifier_consumes_pipe_stdin() -> None:
    text = SCRIPT.read_text("utf-8")

    assert "} | python3 -c '" in text
    assert "} | python3 - <<'PY'" not in text
    assert "LOG_CLASS_TIMEOUT" not in text  # generated dynamically, not hard-coded/faked
    assert '"timeout": ("timeout", "timed out", "deadline exceeded")' in text
