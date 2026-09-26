from pathlib import Path
import re

HELPER = Path("packaging/oracle/issue519-prod-core143-close1-rollout-v1.sh")


def _source():
    return HELPER.read_text("utf-8")


def test_prod519_pins_source_target_services_and_new_protected_baseline():
    s = _source()
    assert "PRE=a4016accdef7b1df591d68d1bcdc54c7a9de7320" in s
    assert "TARGET=ebea19c35cd60aac930f43fe7eaaf69be68a250f" in s
    assert "RES_PID=2462149" in s
    assert "CAP_PID=2462148" in s
    assert "SIG_PID=2462068" in s
    assert "DIS_PID=2560998" in s
    assert "CORE_E=143" in s and "CORE_M=5652707" in s
    assert "BRIDGE_E=26" in s and "BRIDGE_M=569552" in s


def test_prod519_requires_sixty_second_safe_pressure_window_before_mutation():
    s = _source()
    assert "for _ in $(seq 1 40)" in s
    assert "SAFE_STREAK >= 5" in s
    assert "sleep 15" in s
    assert "mem < 256*1024*1024" in s
    assert "mpsi>5.0 or ipsi>10.0" in s
    wait_index = s.index("SAFE_STREAK=0")
    fetch_index = s.index("git_owner fetch --quiet --no-tags origin main")
    merge_index = s.index('git_owner merge --quiet --ff-only "$TARGET"')
    assert wait_index < fetch_index < merge_index
    assert "protected_changed_during_safe_wait" in s


def test_prod519_pins_exact_production_to_target_diff():
    s = _source()
    expected = (
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


def test_prod519_restarts_resident_then_discord_once_and_never_capture_or_signer():
    s = _source()
    resident = "systemctl restart technocore-safe-agent-resident.service"
    discord = "systemctl restart technocore-safe-agent-discord.service"
    assert s.count(resident) == 1
    assert s.count(discord) == 1
    assert s.index(resident) < s.index(discord)
    assert "systemctl restart technocore-safe-agent-lobby-capture.service" not in s
    assert "systemctl restart technocore-safe-agent-signer.service" not in s
    assert "CAPTURE_RESTART=NO SIGNER_RESTART=NO" in s


def test_prod519_preserves_capture_and_signer_across_resident_acceptance():
    s = _source()
    for token in (
        "capture_changed_before_resident_restart",
        "signer_changed_before_resident_restart",
        "capture_changed_after_resident_restart",
        "signer_changed_after_resident_restart",
        "capture_changed_during_discord_wait",
        "signer_changed_during_discord_wait",
        "capture_changed_post",
        "signer_changed_post",
    ):
        assert token in s
    assert "protected_changed_after_resident_restart" in s
    assert "protected_changed_during_discord_wait" in s


def test_prod519_accepts_resident_on_fresh_health_not_pressure_recheck():
    s = _source()
    assert "health_sample()" in s
    assert "safe_sample()" in s
    assert "POST_SAFE=$(health_sample" in s
    assert "POST_SAFE=$(safe_sample" not in s
    assert "OBS_UPDATED_AFTER" in s
    assert '"$LOBBY_AFTER" -ge "$LOBBY_BEFORE"' in s


def test_prod519_requires_close1_worker_to_advance_after_discord_restart():
    s = _source()
    assert "PROGRESS_BEFORE=$(progress_fields)" in s
    assert 'if [[ "$ATTEMPT_AFTER" != "$ATTEMPT_BEFORE" ]]' in s
    assert "close1_worker_did_not_advance" in s
    assert "PROGRESS_ADVANCED=YES" in s


def test_prod519_smokes_bridge_discord_and_self_healing_features():
    s = _source()
    assert "LOCAL_RECOVERY_GRACE_SECONDS == 8.5" in s
    assert "LOCAL_RECOVERY_POLL_SECONDS == 1.0" in s
    assert "callable(bridge._wait_for_local_resume)" in s
    assert "callable(scanner.fetch_candidate_scan)" in s
    assert "callable(discord_control._close1_progress_once)" in s
    assert "callable(discord_control.close1_progress_worker)" in s


def test_prod519_has_no_forbidden_observation_or_binding_actions():
    s = _source()
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
        assert re.search(pattern, s) is None


def test_prod519_operator_output_remains_compact():
    s = _source()
    assert s.count('echo "') <= 22
