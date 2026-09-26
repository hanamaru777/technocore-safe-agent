from pathlib import Path
import re

HELPER = Path("packaging/oracle/issue496-prod-close1-discord-progress-v1.sh")


def _source():
    return HELPER.read_text("utf-8")


def test_prod496_pins_exact_source_target_and_baseline():
    s = _source()
    assert "PRE=9baa91be7267b22143c33a06df3c67e1074dba0d" in s
    assert "TARGET=a4016accdef7b1df591d68d1bcdc54c7a9de7320" in s
    assert "RES_PID=2462149" in s
    assert "CAP_PID=2462148" in s
    assert "SIG_PID=2462068" in s
    assert "DIS_PID=2462020" in s
    assert "CORE_E=124" in s and "CORE_M=5651120" in s
    assert "BRIDGE_E=7" in s and "BRIDGE_M=567965" in s


def test_prod496_pins_exact_expected_diff():
    s = _source()
    expected = (
        "src/flop_agent/close1_discord_progress.py|"
        "src/flop_agent/close_call.py|"
        "src/flop_agent/discord_control.py|"
        "src/flop_agent/public_record.py|"
        "tests/test_close1_discord_progress.py|"
        "tests/test_close_call.py|"
    )
    assert f"EXPECTED='{expected}'" in s
    assert 'git_owner diff --name-only "$PRE" "$TARGET"' in s
    assert 'git_owner merge --quiet --ff-only "$TARGET"' in s


def test_prod496_restarts_only_discord():
    s = _source()
    assert "systemctl restart technocore-safe-agent-discord.service" in s
    for unit in (
        "technocore-safe-agent-resident.service",
        "technocore-safe-agent-lobby-capture.service",
        "technocore-safe-agent-signer.service",
    ):
        assert f"systemctl restart {unit}" not in s
    assert "OTHER_RESTARTS=NO" in s


def test_prod496_requires_fresh_observer_safety_and_protected_counts():
    s = _source()
    assert "observer-safety.json" in s
    assert 'p.get("health") != "ok"' in s
    assert "age <= 300" in s
    assert '[[ "$(counts)" == "$BASE_COUNTS" ]]' in s
    assert "protected_counts_changed" in s


def test_prod496_requires_close1_progress_worker_to_start():
    s = _source()
    assert "close1-discord-progress.json" in s
    assert "CLOSE1_DISCORD_PROGRESS=STARTED" in s
    assert "last_attempt_at" in s
    assert "close1_progress_worker" in s


def test_prod496_compact_and_forbids_sensitive_or_unrelated_actions():
    s = _source()
    assert s.count('echo "') <= 16
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
    ):
        assert re.search(pattern, s) is None
