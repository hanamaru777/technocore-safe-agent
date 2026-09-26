from pathlib import Path
import re

HELPER = Path("packaging/oracle/issue511-prod-close1-resilient-rollout-v1.sh")


def _source():
    return HELPER.read_text("utf-8")


def test_prod511_pins_exact_source_target_and_baseline():
    s = _source()
    assert "PRE=a4016accdef7b1df591d68d1bcdc54c7a9de7320" in s
    assert "TARGET=b1b3837fd1bf3fd23111effc88c88a1458354372" in s
    assert "RES_PID=2462149" in s
    assert "CAP_PID=2462148" in s
    assert "SIG_PID=2462068" in s
    assert "DIS_PID=2560998" in s
    assert "CORE_E=124" in s and "CORE_M=5651120" in s
    assert "BRIDGE_E=7" in s and "BRIDGE_M=567965" in s


def test_prod511_pins_exact_expected_diff():
    s = _source()
    expected = (
        "src/flop_agent/close1_candidate_scanner.py|"
        "src/flop_agent/close1_discord_progress.py|"
        "src/flop_agent/close1_strategy.py|"
        "src/flop_agent/close_call.py|"
        "src/flop_agent/discord_control.py|"
        "tests/test_close1_candidate_scanner.py|"
        "tests/test_close1_discord_progress.py|"
        "tests/test_close1_strategy.py|"
        "tests/test_close_call.py|"
    )
    assert f"EXPECTED='{expected}'" in s
    assert 'git_owner diff --name-only "$PRE" "$TARGET"' in s
    assert 'git_owner merge --quiet --ff-only "$TARGET"' in s


def test_prod511_restarts_only_discord_once():
    s = _source()
    assert s.count("systemctl restart technocore-safe-agent-discord.service") == 1
    for unit in (
        "technocore-safe-agent-resident.service",
        "technocore-safe-agent-lobby-capture.service",
        "technocore-safe-agent-signer.service",
    ):
        assert f"systemctl restart {unit}" not in s
    assert "OTHER_RESTARTS=NO" in s


def test_prod511_preserves_progress_state_and_requires_real_advancement():
    s = _source()
    assert "PROGRESS_BEFORE=$(progress_fields)" in s
    assert "PROGRESS_AFTER=$(progress_fields)" in s
    assert 'rm -f "$PROGRESS"' not in s
    assert 'if [[ "$ATTEMPT_AFTER" != "$ATTEMPT_BEFORE" ]]' in s
    assert "seq 1 18" in s
    assert "sleep 10" in s
    assert "close1_worker_did_not_advance" in s
    assert "PROGRESS_ADVANCED=YES" in s


def test_prod511_import_smokes_candidate_and_self_healing_worker():
    s = _source()
    assert "from flop_agent import close1_candidate_scanner as scanner" in s
    assert "callable(discord_control._close1_progress_once)" in s
    assert "callable(discord_control._close1_worker_delay)" in s
    assert "callable(discord_control.close1_progress_worker)" in s
    assert "discord_control._close1_worker_delay(99) == 300" in s
    assert "SELF_HEALING_WORKER=LOADED" in s


def test_prod511_requires_fresh_safety_and_protected_counts():
    s = _source()
    assert "observer-safety.json" in s
    assert 'p.get("health") != "ok"' in s
    assert "age <= 300" in s
    assert '[[ "$(counts)" == "$BASE_COUNTS" ]]' in s
    assert "protected_counts_changed" in s


def test_prod511_does_not_require_public_fetch_success_for_rollout_pass():
    s = _source()
    assert "FAILURES_AFTER" in s
    assert "last_success" in s
    assert '[[ "$FAILURES_AFTER" == 0 ]]' not in s
    assert "PROGRESS_POST=" in s


def test_prod511_compact_and_forbids_sensitive_or_unrelated_actions():
    s = _source()
    assert s.count('echo "') <= 20
    assert "DO_NOT_RERUN=YES" in s
    assert "EXTERNAL_WRITE=NO" in s
    for pattern in (
        r"\bsqlite3\b",
        r"\bjournalctl\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"SIGN_SEED",
        r"OCI_VAULT_SECRET_OCID",
        r"airdrop_monitor\.run_once",
        r"airdrop_notifier\.run_once",
        r"close1_registration_once",
    ):
        assert re.search(pattern, s) is None
