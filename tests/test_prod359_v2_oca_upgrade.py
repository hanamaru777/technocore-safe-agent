from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "prod359-v2-oca-ubuntu-runcommand-upgrade.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_prod359_v2_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod359_v2_helper_pins_reconciled_runtime_state() -> None:
    text = _text()

    for token in (
        "EXPECTED_REPO=b7bf27dbaa605971d340aa926fdffc17489c3afe",
        "EXPECTED_ORIGIN_MAIN=43db3595a52bb2e19777a1c1c91842c06408f48b",
        "EXPECTED_CORE_EVENTS=117",
        "EXPECTED_CORE_MESSAGES=5083155",
        "PRE_VERSION=1.60.0-1",
        "PRE_REVISION=121",
        "TARGET_VERSION=1.61.0-6",
        "TARGET_REVISION=126",
        "EXPECTED_TRACKING=latest/stable/ubuntu-24.04",
        "EXPECTED_HOLD=forever",
        "EXPECTED_RES_PID=1868797",
        "EXPECTED_RES_RESTARTS=0",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_CAP_RESTARTS=0",
        "EXPECTED_SIG_PID=1539554",
        "EXPECTED_SIG_RESTARTS=1",
        "EXPECTED_DIS_PID=1957840",
        "EXPECTED_DIS_RESTARTS=0",
    ):
        assert token in text


def test_prod359_v2_helper_eliminates_pipefail_early_consumer_parsers() -> None:
    text = _text()

    assert "set -Eeuo pipefail" in text
    assert "| awk" not in text
    assert "| grep" not in text
    assert "| head" not in text
    assert "| tail" not in text

    assert "read_snap_list_state()" in text
    assert "read_snap_info_state()" in text
    assert "read_snap_change_state()" in text
    assert "read_snap_free_kib()" in text

    assert "snap list oracle-cloud-agent 2>&1" in text
    assert "snap info oracle-cloud-agent 2>&1" in text
    assert "snap changes 2>&1" in text
    assert "df -Pk /var/lib/snapd 2>&1" in text


def test_prod359_v2_helper_uses_exact_revision_without_channel_mutation() -> None:
    text = _text()

    assert 'snap refresh oracle-cloud-agent --revision="$TARGET_REVISION"' in text
    assert 'snap revert oracle-cloud-agent --revision="$PRE_REVISION"' in text
    assert "snap refresh oracle-cloud-agent --channel" not in text

    assert '[[ $TRACKING == "$EXPECTED_TRACKING" ]]' in text
    assert '[[ $HOLD == "$EXPECTED_HOLD" ]]' in text
    assert '[[ $SNAP_TRACKING == "$EXPECTED_TRACKING" ]]' in text
    assert '[[ $SNAP_HOLD == "$EXPECTED_HOLD" ]]' in text
    assert "OCA_HOLD_PRESERVED=" in text


def test_prod359_v2_helper_bounds_transient_observer_degraded_state() -> None:
    text = _text()

    assert "wait_observer_ready()" in text
    assert "for attempt in {1..13}" in text
    assert "sleep 10" in text
    assert "observer_not_ready" in text
    assert "observer-heartbeat.json" in text
    assert "resident-heartbeat.json" in text
    assert "state_age -le 300" in text
    assert "observer_age -le 300" in text
    assert "resident_age -le 300" in text
    assert "refresh_age -le 300" in text
    assert "protected_core_changed" in text


def test_prod359_v2_helper_preserves_application_processes() -> None:
    text = _text()

    for token in (
        "resident_baseline_changed",
        "capture_baseline_changed",
        "signer_baseline_changed",
        "discord_baseline_changed",
        "unexpected_resident_pid_change",
        "unexpected_resident_restart_change",
        "unexpected_capture_pid_change",
        "unexpected_capture_restart_change",
        "unexpected_signer_pid_change",
        "unexpected_signer_restart_change",
        "unexpected_discord_pid_change",
        "unexpected_discord_restart_change",
        "RESIDENT_PRESERVED=",
        "CAPTURE_PRESERVED=",
        "SIGNER_PRESERVED=",
        "DISCORD_PRESERVED=",
    ):
        assert token in text

    lowered = text.lower()
    for forbidden in (
        'systemctl restart "$res"',
        'systemctl restart "$cap"',
        'systemctl restart "$sig"',
        'systemctl restart "$dis"',
    ):
        assert forbidden not in lowered


def test_prod359_v2_helper_preserves_metadata_security_boundary() -> None:
    text = _text()

    for token in (
        "metadata_output_jump_missing",
        "metadata_root_return_missing",
        "metadata_signer_return_missing",
        "metadata_final_reject_missing",
        "root_imds_not_200",
        "technocore_imds_unexpectedly_allowed",
        "ROOT_IMDS_HTTP=200",
        "TECHNOCORE_IMDS_BLOCKED=YES",
        "FIREWALL_CHANGE=NO",
    ):
        assert token in text

    lowered = text.lower()
    for forbidden in (
        "iptables -a ",
        "iptables -i ",
        "iptables -d ",
        "iptables -f ",
    ):
        assert forbidden not in lowered


def test_prod359_v2_helper_has_deterministic_revert_after_refresh() -> None:
    text = _text()

    assert "REFRESH_COMPLETED=0" in text
    assert "REFRESH_COMPLETED=1" in text
    assert 'if [[ $DONE -eq 0 && $REFRESH_COMPLETED -eq 1 ]]' in text
    assert 'snap revert oracle-cloud-agent --revision="$PRE_REVISION"' in text
    assert "PROD359V2_ROLLBACK_RC=" in text
    assert "PROD359V2_ROLLBACK_VERSION=" in text
    assert "PROD359V2_ROLLBACK_REVISION=" in text
    assert "DO_NOT_RERUN=YES" in text


def test_prod359_v2_helper_observes_runcommand_surface_without_gating_pass() -> None:
    text = _text()

    assert "OCARUN_ACCOUNT_PRESENT=" in text
    assert "RUN_COMMAND_LOCAL_ARTIFACT=" in text
    assert "*runcommand*" in text
    assert "OCARUN_PRESENT=NO" in text
    assert "RUNCOMMAND_ARTIFACT=NO" in text
    assert 'find "$base" -maxdepth 8' in text


def test_prod359_v2_helper_has_no_application_or_external_writes() -> None:
    text = _text()
    lowered = text.lower()

    for forbidden in (
        "git_owner merge ",
        "git_owner reset ",
        "write_note(",
        "post_signed(",
        "run command create",
        "instance-agent command create",
    ):
        assert forbidden.lower() not in lowered

    for token in (
        "APP_RESTART=NO",
        "FIREWALL_CHANGE=NO",
        "RUN_COMMAND_CREATED=NO",
        "OCI_AGENT_CONFIG_CHANGE=NO",
        "TECHNOCORE_WRITE=NO",
        "FLOP_EXTERNAL_WRITE=NO",
        "X_WRITE=NO",
    ):
        assert token in text
