
from pathlib import Path
import re
import subprocess

HELPER = Path("packaging/oracle/issue538-prod-tclk-idle-gate-v2.sh")


def _source():
    return HELPER.read_text("utf-8")


def test_prod538_pins_exact_production_and_target():
    s=_source()
    assert "PRE=a4016accdef7b1df591d68d1bcdc54c7a9de7320" in s
    assert "TARGET=58943a072eb0d752960e092970f06311344a8996" in s
    assert "RES_PID=2462149" in s
    assert "CAP_PID=2462148" in s
    assert "SIG_PID=2462068" in s
    assert "DIS_PID=2660066" in s
    assert "CORE_E=143" in s and "CORE_M=5652707" in s
    assert "BRIDGE_E=26" in s and "BRIDGE_M=569552" in s


def test_prod538_targets_only_five_tclk_service_units_and_timers():
    s=_source()
    for name in (
        "technocore-safe-agent-tclk-stager",
        "technocore-safe-agent-tclk-preparer",
        "technocore-safe-agent-tclk-lock-watcher",
        "technocore-safe-agent-tclk-work-watcher",
        "technocore-safe-agent-tclk-reveal-preparer",
    ):
        assert f"{name}.service" in s
        assert f"{name}.timer" in s
    assert "systemctl stop" in s and "TIMERS[@]" in s
    assert "systemctl start" in s and "TIMERS[@]" in s


def test_prod538_never_stops_or_restarts_long_running_services():
    s=_source()
    forbidden_units=(
        "technocore-safe-agent-resident.service",
        "technocore-safe-agent-lobby-capture.service",
        "technocore-safe-agent-signer.service",
        "technocore-safe-agent-discord.service",
    )
    for unit in forbidden_units:
        assert f"systemctl restart {unit}" not in s
        assert f"systemctl stop {unit}" not in s
        assert f"systemctl start {unit}" not in s
    assert "RUNTIME_RESTART=NONE" in s


def test_prod538_requires_installed_units_to_match_pre_before_mutation():
    s=_source()
    assert 'git_owner show "$PRE:packaging/oracle/$unit"' in s
    assert 'cmp -s "$TMPDIR/old-units/$unit" "$installed"' in s
    assert "installed_unit_not_pre_" in s


def test_prod538_requires_all_target_gates_idle_before_source_update():
    s=_source()
    gate_loop=s.index('for i in "$' + '{!MODES[@]}"; do')
    merge=s.index('git_owner merge --quiet --ff-only "$TARGET"')
    assert gate_loop < merge
    assert "target_gate_not_idle_" in s
    assert 'git_owner show "$TARGET:src/flop_agent/tclk_timer_gate.py"' in s


def test_prod538_waits_for_running_oneshots_to_quiesce_without_signals():
    s=_source()
    assert "for _ in $(seq 1 90)" in s
    assert "tclk_oneshots_did_not_quiesce" in s
    for pattern in (r"\bkill\b", r"\bpkill\b", r"systemctl kill"):
        assert re.search(pattern,s) is None


def test_prod538_pins_exact_prod_to_target_diff():
    s=_source()
    expected=(
        "packaging/oracle/technocore-safe-agent-tclk-lock-watcher.service|"
        "packaging/oracle/technocore-safe-agent-tclk-preparer.service|"
        "packaging/oracle/technocore-safe-agent-tclk-reveal-preparer.service|"
        "packaging/oracle/technocore-safe-agent-tclk-stager.service|"
        "packaging/oracle/technocore-safe-agent-tclk-work-watcher.service|"
        "src/flop_agent/close1_candidate_scanner.py|"
        "src/flop_agent/close1_discord_progress.py|"
        "src/flop_agent/close1_strategy.py|"
        "src/flop_agent/close_call.py|"
        "src/flop_agent/discord_control.py|"
        "src/flop_agent/observer_lobby_startup_hole_bridge.py|"
        "src/flop_agent/tclk_pilot.py|"
        "src/flop_agent/tclk_timer_gate.py|"
        "tests/test_close1_candidate_scanner.py|"
        "tests/test_close1_discord_progress.py|"
        "tests/test_close1_strategy.py|"
        "tests/test_close_call.py|"
        "tests/test_observer_lobby_startup_hole_bridge.py|"
        "tests/test_tclk_pilot_prepare.py|"
        "tests/test_tclk_timer_gate.py|"
    )
    assert ("EXPECTED='" + expected + "'") in s
    assert 'git_owner diff --name-only "$PRE" "$TARGET"' in s


def test_prod538_installs_only_target_service_units_then_daemon_reloads():
    s=_source()
    assert 'install -o root -g root -m 0644 "$TMPDIR/target-units/$unit" "/etc/systemd/system/$unit"' in s
    assert s.count("systemctl daemon-reload") == 1
    assert "systemctl enable" not in s
    assert "systemctl disable" not in s


def test_prod538_preserves_long_running_service_snapshots_and_counters():
    s=_source()
    for token in (
        "resident_changed_before_unit_stage",
        "capture_changed_before_unit_stage",
        "signer_changed_before_unit_stage",
        "discord_changed_before_unit_stage",
        "resident_changed_after_activation",
        "capture_changed_after_activation",
        "signer_changed_after_activation",
        "discord_changed_after_activation",
        "resident_changed_post",
        "capture_changed_post",
        "signer_changed_post",
        "discord_changed_post",
        "protected_changed_before_unit_stage",
        "protected_changed_after_activation",
        "protected_changed_post",
    ):
        assert token in s


def test_prod538_measures_post_activation_pressure_and_tclk_rss():
    s=_source()
    assert "for sample in range(76)" in s
    assert "PRESSURE=mem_mb:" in s
    assert "VMSTAT_DELTA=" in s
    assert "TCLK_GROUP=" in s
    assert "active_samples:" in s
    assert "peak_rss_mb:" in s
    assert "unique_pids:" in s
    assert "POST_GATE=" in s


def test_prod538_has_no_sensitive_or_binding_actions():
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


def test_prod538_bash_syntax_valid():
    result=subprocess.run(
        ["bash","-n",str(HELPER)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode==0, result.stderr


def test_prod538_temp_gate_is_traversable_by_service_users():
    s=_source()
    assert 'chmod 0755 "$TMPDIR"' in s
    assert 'chmod 0644 "$TMPDIR/tclk_timer_gate.py"' in s


def test_prod538_expected_idle_rc_is_captured_without_err_trap():
    s=_source()
    assert "set +e" not in s
    assert s.count('if runuser -u "$user" -- env') == 2
    assert '[[ "$rc" == 1 ]] || finish_stop "target_gate_not_idle_${mode}_rc_${rc}"' in s
    probe=subprocess.run(
        ["bash","-c","set -E; trap 'exit 99' ERR; if false; then rc=0; else rc=$?; fi; [[ $rc == 1 ]]"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stderr


def test_prod538_partial_unit_write_is_rollback_covered_before_first_install():
    s=_source()
    marker=s.index("UNIT_WRITES_STARTED=YES")
    install=s.index('install -o root -g root -m 0644 "$TMPDIR/target-units/$unit"')
    assert marker < install
    restore=s[s.index("restore_old_units() {"):s.index("restore_timers() {")]
    assert "systemctl daemon-reload" not in restore
    assert '[[ "$UNIT_WRITES_STARTED" == YES ]]' in restore


def test_prod538_reports_exact_unexpected_error_step():
    s=_source()
    assert "STEP=preflight" in s
    assert "STEP=pre_activation_gate" in s
    assert "STEP=install_target_units" in s
    assert "STEP=source_fast_forward" in s
    assert "STEP=daemon_reload" in s
    assert 'PROD538V1=ERROR:rc_$rc step:$STEP line:$failed_line' in s
    assert "ERROR_COMMAND=" in s


def test_prod538_revalidates_loaded_pre_unit_state():
    s=_source()
    assert "installed_unit_meta_changed_" in s
    assert "loaded_fragment_changed_" in s
    assert "loaded_gate_changed_" in s
    assert "ExecCondition" in s
    assert "FragmentPath" in s


def test_prod538_rolls_back_source_only_before_daemon_reload():
    s=_source()
    restore=s[s.index("restore_old_source() {"):s.index("restore_timers() {")]
    assert '[[ "$SOURCE_UPDATED" == YES ]]' in restore
    assert '[[ "$DAEMON_RELOADED" != YES ]]' in restore
    assert '[[ "$(git_owner rev-parse HEAD)" == "$TARGET" ]]' in restore
    assert '[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]]' in restore
    assert 'git_owner reset --hard "$PRE"' in restore
    assert "SOURCE_UPDATED=NO" in restore
    assert "SOURCE_RESTORE=" in s


def test_prod538_post_gate_rejects_unexpected_exit_codes():
    s=_source()
    assert '[[ "$rc" == 0 || "$rc" == 1 ]] || finish_stop "post_gate_unexpected_${mode}_rc_${rc}"' in s
