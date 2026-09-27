from pathlib import Path
import re
import subprocess

HELPER = Path("packaging/oracle/issue523-discord-headroom-rollout-v1.sh")


def _source():
    return HELPER.read_text("utf-8")


def test_prod523_pins_exact_baseline_and_target():
    s=_source()
    assert "PRE=a4016accdef7b1df591d68d1bcdc54c7a9de7320" in s
    assert "TARGET=ebea19c35cd60aac930f43fe7eaaf69be68a250f" in s
    assert "RES_PID=2462149" in s
    assert "CAP_PID=2462148" in s
    assert "SIG_PID=2462068" in s
    assert "DIS_PID=2560998" in s
    assert "CORE_E=143" in s and "CORE_M=5652707" in s
    assert "BRIDGE_E=26" in s and "BRIDGE_M=569552" in s


def test_prod523_quiesces_only_discord_before_safe_window():
    s=_source()
    stop_discord="systemctl stop technocore-safe-agent-discord.service"
    restart_resident="systemctl restart technocore-safe-agent-resident.service"
    fetch='git_owner fetch --quiet --no-tags origin main'
    assert s.count(stop_discord)==1
    assert s.index(stop_discord) < s.index(fetch) < s.index(restart_resident)
    assert "systemctl stop technocore-safe-agent-resident.service" not in s
    assert "systemctl stop technocore-safe-agent-lobby-capture.service" not in s
    assert "systemctl stop technocore-safe-agent-signer.service" not in s


def test_prod523_requires_same_strict_safe_window_after_discord_quiesce():
    s=_source()
    assert "for _ in $(seq 1 40)" in s
    assert "SAFE_STREAK >= 5" in s
    assert "sleep 15" in s
    assert "mem < 256*1024*1024" in s
    assert "mpsi>5.0 or ipsi>10.0" in s
    assert "no_safe_window_after_discord_quiesce" in s


def test_prod523_restores_old_discord_without_source_update_if_no_window():
    s=_source()
    no_window=s.index("if (( SAFE_STREAK < 5 ))")
    fetch=s.index('git_owner fetch --quiet --no-tags origin main')
    assert no_window < fetch
    segment=s[no_window:fetch]
    assert "restore_discord" in segment
    assert "SOURCE_UPDATED=NO" in segment
    assert "git_owner merge" not in segment


def test_prod523_rechecks_pressure_immediately_before_resident_restart():
    s=_source()
    check="PRE_RESTART_SAFE=$(safe_sample 2>/dev/null) || finish_stop pressure_returned_before_resident_restart"
    restart="systemctl restart technocore-safe-agent-resident.service"
    assert check in s
    assert s.index(check) < s.index(restart)


def test_prod523_pins_exact_source_delta():
    s=_source()
    expected=(
        "src/flop_agent/close1_candidate_scanner.py|"
        "src/flop_agent/close1_discord_progress.py|"
        "src/flop_agent/close1_strategy.py|"
        "src/flop_agent/close_call.py|"
        "src/flop_agent/discord_control.py|"
        "src/flop_agent/observer_lobby_startup_hole_bridge.py|"
        "tests/test_close1_candidate_scanner.py|"
        "tests/test_close1_discord_progress.py|"
        "tests/test_close1_strategy.py|"
        "tests/test_close_call.py|"
        "tests/test_observer_lobby_startup_hole_bridge.py|"
    )
    assert f"EXPECTED='{expected}'" in s
    assert 'git_owner diff --name-only "$PRE" "$TARGET"' in s
    assert 'git_owner merge --quiet --ff-only "$TARGET"' in s


def test_prod523_restarts_resident_once_never_capture_or_signer():
    s=_source()
    assert s.count("systemctl restart technocore-safe-agent-resident.service")==1
    assert "systemctl restart technocore-safe-agent-lobby-capture.service" not in s
    assert "systemctl restart technocore-safe-agent-signer.service" not in s
    assert "CAPTURE_RESTART=NO SIGNER_RESTART=NO" in s


def test_prod523_starts_discord_once_on_success_and_can_restore_on_stop():
    s=_source()
    assert "systemctl start technocore-safe-agent-discord.service" in s
    assert "restore_discord()" in s
    assert "wait_discord_active" in s
    assert "DISCORD_RESTORED=" in s


def test_prod523_accepts_resident_only_on_fresh_ok_observer_and_exact_counters():
    s=_source()
    assert 'OBS_UPDATED_AFTER" != "$OBS_UPDATED_BEFORE"' in s
    assert '"$OBS_HEALTH_AFTER" == ok' in s
    assert '"$LOBBY_AFTER" -ge "$LOBBY_BEFORE"' in s
    assert "POST_HEALTH=$(health_sample" in s
    assert "protected_changed_after_resident_restart" in s


def test_prod523_requires_close1_worker_to_advance():
    s=_source()
    assert "PROGRESS_BEFORE=$(progress_fields)" in s
    assert 'if [[ "$ATTEMPT_AFTER" != "$ATTEMPT_BEFORE" ]]' in s
    assert "close1_worker_did_not_advance" in s
    assert "PROGRESS_ADVANCED=YES" in s


def test_prod523_smokes_bridge_and_discord_features():
    s=_source()
    assert "LOCAL_RECOVERY_GRACE_SECONDS == 8.5" in s
    assert "LOCAL_RECOVERY_POLL_SECONDS == 1.0" in s
    assert "callable(bridge._wait_for_local_resume)" in s
    assert "callable(scanner.fetch_candidate_scan)" in s
    assert "callable(discord_control._close1_progress_once)" in s
    assert "callable(discord_control.close1_progress_worker)" in s


def test_prod523_forbids_sensitive_or_unrelated_actions():
    s=_source()
    assert "TECHNOCORE_POST=NO TRADE=NO" in s
    assert "DO_NOT_RERUN=YES" in s
    for pattern in (
        r"\bsqlite3\b",
        r"\bjournalctl\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"SIGN_SEED",
        r"OCI_VAULT_SECRET_OCID",
        r"close1_registration_once",
        r"airdrop_monitor\.run_once",
        r"airdrop_notifier\.run_once",
    ):
        assert re.search(pattern,s) is None


def test_prod523_bash_syntax_valid():
    result=subprocess.run(
        ["bash","-n",str(HELPER)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode==0, result.stderr


def test_prod523_revalidates_discord_quiesce_at_critical_boundaries():
    s=_source()
    for token in (
        "discord_not_quiesced_before_fetch",
        "discord_not_quiesced_before_resident_restart",
        "discord_not_quiesced_before_start",
    ):
        assert token in s


def test_prod523_reports_already_restored_discord_on_later_stop():
    s=_source()
    assert 'if [[ -n "$RESTORED_DIS" ]]; then' in s
    assert 'restore="YES:$RESTORED_DIS"' in s
