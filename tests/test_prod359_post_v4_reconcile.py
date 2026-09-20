from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "prod359-post-v4-reconcile.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_post_v4_reconcile_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_post_v4_reconcile_is_read_only() -> None:
    text = _text()
    lowered = text.lower()

    for forbidden in (
        "snap refresh",
        "snap revert",
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "iptables -a ",
        "iptables -i ",
        "iptables -d ",
        "iptables -f ",
        "client.post(",
        "client.put(",
        "client.patch(",
        "client.delete(",
        "post_signed(",
        "write_note(",
        "run command create",
        "instance-agent command create",
    ):
        assert forbidden not in lowered

    for token in (
        "MUTATION_COMMANDS=NONE",
        "SERVICE_RESTART=NO",
        "SNAP_MUTATION=NO",
        "FIREWALL_CHANGE=NO",
        "AGENT_CONFIG_CHANGE=NO",
        "RUN_COMMAND_CREATED=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "TECHNOCORE_WRITE=NO",
    ):
        assert token in text


def test_post_v4_reconcile_avoids_pipefail_early_consumers() -> None:
    text = _text()

    assert "set -Eeuo pipefail" not in text
    assert "| awk" not in text
    assert "| grep" not in text
    assert "| head" not in text
    assert "| tail" not in text


def test_post_v4_reconcile_checks_exact_accepted_baseline() -> None:
    text = _text()

    for token in (
        "EXPECTED_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe",
        "EXPECTED_ORIGIN_MAIN=43db3595a52bb2e19777a1c1c91842c06408f48b",
        "EXPECTED_OCA_VERSION=1.61.0-6",
        "EXPECTED_OCA_REVISION=126",
        "EXPECTED_TRACKING=latest/stable/ubuntu-24.04",
        "EXPECTED_HOLD=forever",
        "EXPECTED_CORE=117/5083155",
        "EXPECTED_RESIDENT=1868797/0",
        "EXPECTED_CAPTURE=1868796/0",
        "EXPECTED_SIGNER=1539554/1",
        "EXPECTED_DISCORD=1957840/0",
    ):
        assert token in text


def test_post_v4_reconcile_checks_plugin_surface_safely() -> None:
    text = _text()

    for token in (
        "AGENT_CONFIG_PARSE=",
        "AGENT_CONFIG_MANAGEMENT_DISABLED=",
        "AGENT_CONFIG_ALL_PLUGINS_DISABLED=",
        "AGENT_CONFIG_PLUGIN_COUNT=",
        "RUN_COMMAND_ADVERTISED=",
        "RUN_COMMAND_DESIRED_STATE=",
        "OCARUN_ACCOUNT_PRESENT=",
        "RUN_COMMAND_LOCAL_ARTIFACT=",
        "RUN_COMMAND_CONFIG_PRESENT=",
        "RUN_COMMAND_LOG_PRESENT=",
        "RUN_COMMAND_PROCESS_COUNT=",
    ):
        assert token in text

    assert 'doc.get("agentConfig")' in text
    assert "pluginsConfig" in text
    assert "Compute Instance Run Command" in text


def test_post_v4_reconcile_preserves_security_and_continuity_checks() -> None:
    text = _text()

    for token in (
        "ROOT_IMDS_HTTP=",
        "TECHNOCORE_IMDS_BLOCKED=",
        "METADATA_OUTPUT_JUMP=",
        "METADATA_ROOT_RETURN=",
        "METADATA_SIGNER_RETURN=",
        "METADATA_FINAL_REJECT=",
        "NTP_SYNCHRONIZED=",
        "CORE_EVENTS=",
        "CORE_MESSAGES=",
        "CAPTURE_CPU_TICKS=",
        "CAPTURE_WAL_MTIME_NS=",
        "CAPTURE_SHM_MTIME_NS=",
        "PROBE={name} HTTP=",
    ):
        assert token in text


def test_post_v4_reconcile_never_queries_active_capture_sqlite() -> None:
    lowered = _text().lower()

    assert "sqlite3.connect" not in lowered
    assert "select " not in lowered
    assert "pragma " not in lowered
