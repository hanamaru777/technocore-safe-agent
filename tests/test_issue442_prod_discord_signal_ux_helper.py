from pathlib import Path
import re


HELPER = Path("packaging/oracle/issue442-prod-discord-signal-ux-v1.sh")


def _source() -> str:
    return HELPER.read_text("utf-8")


def test_issue442_rollout_pins_exact_source_transition_and_diff() -> None:
    source = _source()
    assert "PRE=d8a9c2a43e1ba85f57e057ebf06a2a20da51bb20" in source
    assert "TARGET=041b830d3b0ffd17ef95f8d889922f20d3ac6631" in source
    assert "EXPECTED_CORE_EVENTS=120" in source
    assert "EXPECTED_CORE_MESSAGES=5650166" in source
    assert 'git_owner merge --ff-only "$TARGET"' in source
    assert "target_diff_not_exact" in source

    for path in (
        "src/flop_agent/airdrop_notifier.py",
        "src/flop_agent/discord_control.py",
        "src/flop_agent/discord_tclk_review.py",
        "tests/test_airdrop_notifier.py",
        "tests/test_discord_gap_notice_coalescing.py",
        "tests/test_discord_signal_notifications.py",
        "tests/test_tclk_auto_review_evidence.py",
    ):
        assert path in source


def test_issue442_restarts_only_discord_once() -> None:
    source = _source()

    restart_lines = [
        line.strip()
        for line in source.splitlines()
        if re.search(r"\bsystemctl\s+restart\b", line)
    ]
    assert restart_lines == ['systemctl restart "$DISC" || stop_post discord_restart_command_failed']

    assert "verify_preserved_service RESIDENT" in source
    assert "verify_preserved_service CAPTURE" in source
    assert "verify_preserved_service SIGNER" in source
    assert "discord_pid_did_not_change" in source
    assert "discord_start_time_did_not_change" in source
    assert "discord_auto_restart_count_changed" in source
    assert "POST_DISCORD_STABILITY_SECONDS=15" in source


def test_issue442_has_no_forbidden_runtime_actions() -> None:
    source = _source()

    forbidden = [
        r"\bsqlite3\b",
        r"systemctl\s+(?:start|stop|enable|disable|daemon-reload)\b",
        r"airdrop_monitor\.run_once",
        r"airdrop_notifier\.run_once",
        r"\bpip\b",
        r"\buv\s+sync\b",
    ]
    for pattern in forbidden:
        assert re.search(pattern, source) is None

    for marker in (
        "AUTHORIZED_DISCORD_RESTARTS=1",
        "RESIDENT_RESTART=NO",
        "CAPTURE_RESTART=NO",
        "SIGNER_RESTART=NO",
        "METADATA_BLOCK_MUTATION=NO",
        "AIRDROP_TIMER_RESTART=NO",
        "PACKAGE_SYNC=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "SIGNER_ACTION=NO",
        "TECHNOCORE_WRITE=NO",
        "FLOP_WRITE=NO",
        "X_WRITE=NO",
        "SYNTHETIC_DISCORD_MESSAGE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert marker in source


def test_issue442_offline_smoke_checks_new_presentation_without_sending() -> None:
    source = _source()
    assert "airdrop_notifier.render_digest" in source
    assert "discord_tclk_review._auto_failure_notice" in source
    assert "GitHub重要repo更新" in source
    assert "操作不要" in source
    assert "full_spec_not_found" in source
    assert "SYNTHETIC_DISCORD_MESSAGE=NO" in source
