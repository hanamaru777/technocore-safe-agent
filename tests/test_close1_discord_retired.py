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


def test_close1_standalone_autostart_is_retired():
    assert not (
        ROOT / "packaging/oracle/close1-standalone-pressure-gate.sh"
    ).exists()
    assert not (
        ROOT / "packaging/oracle/technocore-safe-agent-close1-standalone-watch.timer"
    ).exists()

    service = (
        ROOT
        / "packaging/oracle/technocore-safe-agent-close1-standalone-watch.service"
    ).read_text("utf-8")
    assert "ExecCondition=/bin/false" in service
    assert "ExecStart=/bin/true" in service
    assert "-m flop_agent.close1_standalone_watch" not in service
