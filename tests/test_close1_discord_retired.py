import os
import subprocess
import sys
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


def test_retired_close1_status_import_is_lightweight(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    env["FLOP_STATE_DIR"] = str(tmp_path / "state")
    code = """
import sys
from flop_agent import close1_discord_progress
assert 'flop_agent.close1_account_reconciliation' not in sys.modules
assert 'flop_agent.close1_candidate_scanner' not in sys.modules
assert '終了済み' in close1_discord_progress.status_message()
print(
    'flop_agent.close1_account_reconciliation' in sys.modules,
    'flop_agent.close1_candidate_scanner' in sys.modules,
)
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout.strip() == "False False"


def test_discord_import_skips_retired_close1_and_command_lazy_loads(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    env["FLOP_STATE_DIR"] = str(tmp_path / "state")
    code = """
import sys
from flop_agent import discord_control
assert 'flop_agent.close1_discord_progress' not in sys.modules
assert 'flop_agent.close1_account_reconciliation' not in sys.modules
assert 'flop_agent.close1_candidate_scanner' not in sys.modules
control = discord_control.Control({'user'}, 'channel')
result = control.command('user', '/close1', 'channel')
assert result['ok'] is True
assert '終了済み' in result['message']
print(
    'flop_agent.close1_discord_progress' in sys.modules,
    'flop_agent.close1_account_reconciliation' in sys.modules,
    'flop_agent.close1_candidate_scanner' in sys.modules,
)
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout.strip() == "True False False"


def test_discord_source_has_no_retired_close1_background_worker():
    source = (ROOT / "src" / "flop_agent" / "discord_control.py").read_text("utf-8")
    assert "close1_progress_worker" not in source
    assert "_close1_progress_once" not in source
    assert "_close1_worker_delay" not in source
