from pathlib import Path
import re
import subprocess

HELPER = Path("packaging/oracle/issue535-prod533-reconcile-v1.sh")


def _source():
    return HELPER.read_text("utf-8")


def test_prod535_pins_pre_target_and_is_read_only():
    s=_source()
    assert "PRE=a4016accdef7b1df591d68d1bcdc54c7a9de7320" in s
    assert "TARGET=58943a072eb0d752960e092970f06311344a8996" in s
    assert "MUTATION=NONE" in s
    assert "DAEMON_RELOAD=NONE" in s
    assert "SERVICE_ACTION=NONE" in s
    assert "SOURCE_ACTION=NONE" in s
    assert "DO_NOT_RERUN=YES" in s


def test_prod535_classifies_all_five_units_against_pre_and_target():
    s=_source()
    for name in (
        "technocore-safe-agent-tclk-stager.service",
        "technocore-safe-agent-tclk-preparer.service",
        "technocore-safe-agent-tclk-lock-watcher.service",
        "technocore-safe-agent-tclk-work-watcher.service",
        "technocore-safe-agent-tclk-reveal-preparer.service",
    ):
        assert name in s
    assert 'git_owner show "$PRE:packaging/oracle/$unit"' in s
    assert 'git_owner show "$TARGET:packaging/oracle/$unit"' in s
    assert "disk=PRE" in s
    assert "disk=TARGET" in s
    assert "disk=OTHER" in s


def test_prod535_reports_loaded_gate_fragment_and_service_state():
    s=_source()
    assert "ExecCondition" in s
    assert "FragmentPath" in s
    assert "loaded_gate:" in s
    assert "state:$state" in s


def test_prod535_reports_all_five_timer_active_enabled_states():
    s=_source()
    for name in (
        "technocore-safe-agent-tclk-stager.timer",
        "technocore-safe-agent-tclk-preparer.timer",
        "technocore-safe-agent-tclk-lock-watcher.timer",
        "technocore-safe-agent-tclk-work-watcher.timer",
        "technocore-safe-agent-tclk-reveal-preparer.timer",
    ):
        assert name in s
    assert "systemctl is-active" in s
    assert "systemctl is-enabled" in s


def test_prod535_reports_long_running_and_protected_state():
    s=_source()
    for name in (
        "technocore-safe-agent-resident.service",
        "technocore-safe-agent-lobby-capture.service",
        "technocore-safe-agent-signer.service",
        "technocore-safe-agent-discord.service",
    ):
        assert name in s
    assert "PROTECTED=" in s
    assert "unrecoverable_core_gap_events" in s
    assert "lobby_startup_bridge_unrecoverable_events" in s


def test_prod535_has_no_mutating_or_sensitive_commands():
    s=_source()
    for pattern in (
        r"\bsystemctl\s+(restart|start|stop|enable|disable|reload|daemon-reload)\b",
        r"\bgit_owner\s+(fetch|merge|pull|checkout|reset|switch)\b",
        r"\binstall\b",
        r"\bcp\b",
        r"\bmv\b",
        r"\bsqlite3\b",
        r"\bjournalctl\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"\bkill\b",
        r"\bpkill\b",
        r"SIGN_SEED",
        r"OCI_VAULT_SECRET_OCID",
    ):
        assert re.search(pattern,s) is None


def test_prod535_bash_syntax_valid():
    result=subprocess.run(
        ["bash","-n",str(HELPER)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode==0, result.stderr
