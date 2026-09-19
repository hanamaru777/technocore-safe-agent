from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "prod350-readiness-notice.sh"


def test_prod350_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod350_helper_pins_exact_repo_only_rollout() -> None:
    text = HELPER.read_text("utf-8")

    assert "PRE=76fbb513a1f9616865c699cd2b78fb7ccbe83f04" in text
    assert "TARGET=3fd5ce445692cc2f94a574c012c080048f96d755" in text
    assert "CORE_EVENTS=117" in text
    assert "CORE_MESSAGES=5083155" in text

    assert "src/flop_agent/airdrop_notifier.py" in text
    assert "tests/test_airdrop_readiness_notice.py" in text
    assert 'git_owner merge --ff-only "$TARGET"' in text

    for svc in (
        '"$RES"',
        '"$CAP"',
        '"$SIG"',
        '"$DIS"',
        '"$MON_TIMER"',
        '"$NOT_TIMER"',
    ):
        assert f"systemctl restart {svc}" not in text
        assert f"systemctl stop {svc}" not in text

    assert "SERVICE_RESTART=NO" in text
    assert "SYNTHETIC_DISCORD_MESSAGE=NO" in text
    assert "DO_NOT_RERUN=YES" in text


def test_prod350_helper_uses_only_isolated_fake_sender_smoke() -> None:
    text = HELPER.read_text("utf-8")
    lowered = text.lower()

    assert "/tmp/prod350-readiness-notice." in text
    assert 'FLOP_STATE_DIR="$SMOKE_DIR"' in text
    assert "_apply_readiness_notice" in text
    assert "NotifierSendError" in text
    assert "IMPLEMENTATION_READYは実行許可ではありません" in text
    assert "assert not airdrop_notifier.state_path().exists()" in text

    assert "discord_bot_token" not in lowered
    assert "discord_channel_id" not in lowered
    assert "https://discord.com" not in lowered
    assert "client.post" not in lowered
    assert "channel.send" not in lowered
    assert "curl " not in lowered
    assert "wget " not in lowered


def test_prod350_helper_has_no_protocol_write_or_capture_sqlite_access() -> None:
    lowered = HELPER.read_text("utf-8").lower()

    assert "sqlite3" not in lowered
    assert "lobby-capture-service.sqlite3" not in lowered
    assert "technocore_signing_key" not in lowered
    assert "oracle_signer" not in lowered
    assert "post-signed" not in lowered
    assert "publish-approved" not in lowered
    assert "execute_prepared(" not in lowered
    assert "stage_request(" not in lowered
    assert "_adapters[" not in lowered


def test_prod350_helper_guards_dormant_action_boundary() -> None:
    text = HELPER.read_text("utf-8")

    assert '[[ $requests == 0 ]]' in text
    assert '[[ $candidates == 0 ]]' in text
    assert '[[ $executions == 0 ]]' in text
    assert "_ADAPTERS: dict[str, ExecutionAdapter] = {}" in text
    assert 'state != "BLOCKED"' in text
    assert "readiness_blockers_missing_" in text
    assert "ADAPTER_REGISTRY=EMPTY" in text


def test_prod350_helper_preserves_all_long_running_pids_and_restarts() -> None:
    text = HELPER.read_text("utf-8")

    assert 'PID_PRE["$svc"]=$(svc_value "$svc" MainPID)' in text
    assert 'RESTART_PRE["$svc"]=$(svc_value "$svc" NRestarts)' in text
    assert 'unexpected_pid_change:$svc' in text
    assert 'unexpected_restart_change:$svc' in text
    assert "RESIDENT_PRESERVED=" in text
    assert "CAPTURE_PRESERVED=" in text
    assert "SIGNER_PRESERVED=" in text
    assert "DISCORD_PRESERVED=" in text
