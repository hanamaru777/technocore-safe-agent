from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "prod359-oca-ubuntu-runcommand-upgrade.sh"


def test_prod359_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod359_helper_pins_exact_runtime_and_snap_versions() -> None:
    text = HELPER.read_text("utf-8")

    assert "EXPECTED_REPO=b7bf27dbaa605971d340aa926fdffc17489c3afe" in text
    assert "EXPECTED_CORE_EVENTS=117" in text
    assert "EXPECTED_CORE_MESSAGES=5083155" in text
    assert "PRE_VERSION=1.60.0-1" in text
    assert "PRE_REVISION=121" in text
    assert "TARGET_VERSION=1.61.0-6" in text
    assert 'stable_target_moved:expected=$TARGET_VERSION:actual=$REMOTE_STABLE' in text


def test_prod359_helper_mutates_only_oracle_cloud_agent_snap() -> None:
    text = HELPER.read_text("utf-8")
    lowered = text.lower()

    assert "snap refresh oracle-cloud-agent --channel=latest/stable" in text
    assert "snap revert oracle-cloud-agent" in text

    for token in (
        'systemctl restart "$RES"',
        'systemctl restart "$CAP"',
        'systemctl restart "$SIG"',
        'systemctl restart "$DIS"',
        "iptables -a ",
        "iptables -i ",
        "iptables -d ",
        "iptables -f ",
        "git_owner merge ",
        "git_owner reset ",
        "write_note(",
        "post_signed(",
        "run command create",
        "instance-agent command create",
    ):
        assert token.lower() not in lowered

    assert "APP_RESTART=NO" in text
    assert "FIREWALL_CHANGE=NO" in text
    assert "RUN_COMMAND_CREATED=NO" in text
    assert "OCI_AGENT_CONFIG_CHANGE=NO" in text
    assert "TECHNOCORE_WRITE=NO" in text


def test_prod359_helper_preserves_app_services_and_core() -> None:
    text = HELPER.read_text("utf-8")

    assert 'PID_PRE["$svc"]=$(svc_value "$svc" MainPID)' in text
    assert 'RESTART_PRE["$svc"]=$(svc_value "$svc" NRestarts)' in text
    assert "unexpected_app_pid_change:$svc" in text
    assert "unexpected_app_restart_change:$svc" in text
    assert "protected_core_changed" in text
    assert "RESIDENT_PRESERVED=" in text
    assert "CAPTURE_PRESERVED=" in text
    assert "SIGNER_PRESERVED=" in text
    assert "DISCORD_PRESERVED=" in text


def test_prod359_helper_preserves_metadata_security_boundary() -> None:
    text = HELPER.read_text("utf-8")

    assert "metadata_output_jump_missing" in text
    assert "metadata_root_return_missing" in text
    assert "metadata_signer_return_missing" in text
    assert "metadata_final_reject_missing" in text
    assert "root_imds_not_200" in text
    assert "technocore_imds_unexpectedly_allowed" in text
    assert "ROOT_IMDS_HTTP=200" in text
    assert "TECHNOCORE_IMDS_BLOCKED=YES" in text


def test_prod359_helper_has_guarded_revert_after_completed_refresh() -> None:
    text = HELPER.read_text("utf-8")

    assert "REFRESH_COMPLETED=0" in text
    assert "REFRESH_COMPLETED=1" in text
    assert 'if [[ $DONE -eq 0 && $REFRESH_COMPLETED -eq 1 ]]' in text
    assert "PROD359_ROLLBACK_RC=" in text
    assert "PROD359_ROLLBACK_VERSION=" in text
    assert "PROD359_ROLLBACK_REVISION=" in text
    assert "DO_NOT_RERUN=YES" in text


def test_prod359_helper_observes_runcommand_surface_without_gating_success() -> None:
    text = HELPER.read_text("utf-8")

    assert "OCARUN_ACCOUNT_PRESENT=" in text
    assert "RUN_COMMAND_LOCAL_ARTIFACT=" in text
    assert "*runcommand*" in text
    assert "OCARUN_PRESENT=NO" in text
    assert "RUNCOMMAND_ARTIFACT=NO" in text
