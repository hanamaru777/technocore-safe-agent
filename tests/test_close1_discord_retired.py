from pathlib import Path

from flop_agent import close1_discord_progress


ROOT = Path(__file__).resolve().parents[1]


def test_close1_periodic_notifications_are_retired():
    assert close1_discord_progress.periodic_notices() == []


def test_close1_status_is_compact_and_terminal():
    message = close1_discord_progress.status_message()

    assert "終了済み" in message
    assert "定期通知は停止" in message
    assert len(message.splitlines()) <= 3
    assert "sweep:" not in message
    assert "strategy scanner" not in message


def test_close1_standalone_notifier_files_are_retired():
    retired = (
        "src/flop_agent/close1_standalone_watch.py",
        "packaging/oracle/close1-standalone-pressure-gate.sh",
        "packaging/oracle/technocore-safe-agent-close1-standalone-watch.service",
        "packaging/oracle/technocore-safe-agent-close1-standalone-watch.timer",
    )

    for relative in retired:
        assert not (ROOT / relative).exists(), relative
