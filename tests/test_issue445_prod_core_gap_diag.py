from pathlib import Path
import re


HELPER = Path("packaging/oracle/issue445-prod-core-gap-diag-v1.sh")


def _source() -> str:
    return HELPER.read_text("utf-8")


def test_issue445_diag_is_strictly_read_only() -> None:
    source = _source()

    assert "EXPECTED_HEAD=041b830d3b0ffd17ef95f8d889922f20d3ac6631" in source
    assert "LAST_UNRECOVERABLE_GAP" in source
    assert "UNRECOVERABLE_CORE=" in source
    assert "RECENT_ERROR_HISTORY_BEGIN" in source
    assert "RECENT_GAP_EVENTS_BEGIN" in source
    assert "journalctl" in source

    forbidden = [
        r"git_owner\s+(?:fetch|merge|pull|checkout|reset)\b",
        r"systemctl\s+(?:restart|start|stop|enable|disable|daemon-reload)\b",
        r"\bsqlite3\b",
        r"observer_lobby_capture\.status",
        r"\bcurl\b",
        r"\bwget\b",
        r"airdrop_monitor\.run_once",
        r"airdrop_notifier\.run_once",
    ]
    for pattern in forbidden:
        assert re.search(pattern, source) is None

    for marker in (
        "GIT_MUTATION=NO",
        "NETWORK_PROBE=NO",
        "SYSTEMD_MUTATION=NO",
        "RUNNING_SERVICE_RESTART=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "SIGNER_ACTION=NO",
        "TECHNOCORE_WRITE=NO",
        "FLOP_WRITE=NO",
        "X_WRITE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert marker in source


def test_issue445_diag_reads_required_runtime_evidence() -> None:
    source = _source()
    for unit in (
        "technocore-safe-agent-resident.service",
        "technocore-safe-agent-lobby-capture.service",
        "technocore-safe-agent-signer.service",
        "technocore-safe-agent-discord.service",
        "technocore-safe-agent-airdrop-monitor.timer",
        "technocore-safe-agent-airdrop-notifier.timer",
    ):
        assert unit in source

    for token in (
        "unrecoverable_core_gap_events",
        "unrecoverable_core_gap_messages",
        "unrecoverable_optional_gap_events",
        "unrecoverable_optional_gap_messages",
        "gap_recovery_attempts",
        "gap_recovery_batches",
        "last_unrecoverable_gap",
        "error_history",
        "opportunities",
    ):
        assert token in source
