from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "prod359-v4-oca-ubuntu-runcommand-upgrade.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_prod359_v4_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod359_v4_helper_pins_reconciled_runtime_state() -> None:
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


def test_prod359_v4_helper_has_exactly_one_refresh_and_one_revert() -> None:
    text = _text()

    assert text.count("snap refresh oracle-cloud-agent") == 1
    assert text.count("snap revert oracle-cloud-agent") == 1
    assert 'snap refresh oracle-cloud-agent --revision="$TARGET_REVISION"' in text
    assert 'snap revert oracle-cloud-agent --revision="$PRE_REVISION"' in text
    assert "snap refresh oracle-cloud-agent --channel" not in text


def test_prod359_v4_resident_maintenance_freshness_is_observational_only() -> None:
    text = _text()

    assert "resident_maintenance_observational=yes" in text
    assert "RESIDENT_MAINTENANCE_FRESHNESS_GATE=OBSERVATIONAL_ONLY" in text
    assert "RESIDENT_HEARTBEAT_AGE_FINAL=" in text
    assert "RESIDENT_REFRESH_AGE_FINAL=" in text

    for forbidden in (
        "resident_heartbeat_not_ok",
        "resident_heartbeat_stale",
        "resident_refresh_stale",
    ):
        assert forbidden not in text


def test_prod359_v4_keeps_protected_continuity_hard_gates() -> None:
    text = _text()

    for token in (
        "protected_core_changed",
        "same_user_direct_read_failed",
        "capture_no_activity",
        "unexpected_resident_pid_change",
        "unexpected_capture_pid_change",
        "unexpected_signer_pid_change",
        "unexpected_discord_pid_change",
        "root_imds_not_200",
        "technocore_imds_unexpectedly_allowed",
        "metadata_output_jump_missing",
        "metadata_root_return_missing",
        "metadata_signer_return_missing",
        "metadata_final_reject_missing",
        "ntp_not_synchronized",
    ):
        assert token in text


def test_prod359_v4_direct_probes_are_get_only_and_same_user() -> None:
    text = _text()
    lowered = text.lower()

    assert "sudo -u technocore env PYTHONPATH=" in text
    assert 'f"{core.BASE_URL}/rooms"' in text
    assert 'f"{core.BASE_URL}/r/events"' in text
    assert 'f"{core.BASE_URL}/r/lobby"' in text
    assert "response=await client.get" in text
    assert "response.status_code != 200" in text

    for forbidden in (
        "client.post(",
        "client.put(",
        "client.patch(",
        "client.delete(",
        "post_signed(",
        "write_note(",
    ):
        assert forbidden not in lowered


def test_prod359_v4_capture_liveness_is_read_only() -> None:
    text = _text()
    lowered = text.lower()

    assert "lobby-capture-service.sqlite3-wal" in text
    assert "lobby-capture-service.sqlite3-shm" in text
    assert 'pathlib.Path(f"/proc/{pid}/stat")' in text
    assert "activity_advanced=yes" in text
    assert "ACTIVE_CAPTURE_SQLITE_QUERY=NO" in text

    for forbidden in (
        "sqlite3.connect",
        "select ",
        "pragma ",
    ):
        assert forbidden not in lowered


def test_prod359_v4_revalidates_state_immediately_around_mutation() -> None:
    text = _text()

    pre = text.index("app_gate pre")
    refresh = text.index('snap refresh oracle-cloud-agent --revision="$TARGET_REVISION"')
    between = text[pre:refresh]

    assert "assert_app_processes_preserved" in between
    assert "assert_oca_services_ready" in between
    assert "assert_pre_snap_state" in between

    post = text.index("app_gate post")
    after = text[post:]

    assert "assert_app_processes_preserved" in after
    assert "assert_oca_services_ready" in after
    assert "post_wait_snap_changed" in after
    assert "post_wait_snap_metadata_changed" in after


def test_prod359_v4_preserves_tracking_hold_and_security() -> None:
    text = _text()
    lowered = text.lower()

    for token in (
        '[[ $TRACKING == "$EXPECTED_TRACKING" ]]',
        '[[ $HOLD == "$EXPECTED_HOLD" ]]',
        '[[ $SNAP_TRACKING == "$EXPECTED_TRACKING" ]]',
        '[[ $SNAP_HOLD == "$EXPECTED_HOLD" ]]',
        "OCA_HOLD_PRESERVED=",
        "ROOT_IMDS_HTTP=200",
        "TECHNOCORE_IMDS_BLOCKED=YES",
    ):
        assert token in text

    for forbidden in (
        "iptables -a ",
        "iptables -i ",
        "iptables -d ",
        "iptables -f ",
    ):
        assert forbidden not in lowered


def test_prod359_v4_has_deterministic_revert_after_applied_refresh() -> None:
    text = _text()

    assert "REFRESH_COMPLETED=0" in text
    assert "REFRESH_COMPLETED=1" in text
    assert 'if [[ $DONE -eq 0 && $REFRESH_COMPLETED -eq 1 ]]' in text
    assert "PROD359V4_ROLLBACK_RC=" in text
    assert "PROD359V4_ROLLBACK_VERSION=" in text
    assert "PROD359V4_ROLLBACK_REVISION=" in text
    assert "DO_NOT_RERUN=YES" in text


def test_prod359_v4_has_no_application_or_external_writes() -> None:
    text = _text()
    lowered = text.lower()

    assert "| awk" not in text
    assert "| grep" not in text
    assert "| head" not in text
    assert "| tail" not in text
    assert "wait_observer_ready" not in text

    for forbidden in (
        "systemctl restart",
        "git_owner fetch ",
        "git_owner pull ",
        "git_owner merge ",
        "git_owner reset ",
        "write_note(",
        "post_signed(",
        "run command create",
        "instance-agent command create",
    ):
        assert forbidden not in lowered

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


def test_prod359_v4_observes_runcommand_surface_without_gating_pass() -> None:
    text = _text()

    assert "OCARUN_ACCOUNT_PRESENT=" in text
    assert "RUN_COMMAND_LOCAL_ARTIFACT=" in text
    assert "*runcommand*" in text
    assert "RUNCOMMAND_ARTIFACT=NO" in text
    assert 'find "$base" -maxdepth 8' in text
