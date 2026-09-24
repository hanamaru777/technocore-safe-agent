from pathlib import Path
import re

HELPER=Path("packaging/oracle/issue464-prod-discord-lanes-v1.sh")

def _source():
    return HELPER.read_text("utf-8")

def test_prod464_pins_exact_pre_target_and_continuity():
    s=_source()
    assert "PRE=b8c63f865856d5004f8d310eb8ff4c31dbd7ffb0" in s
    assert "TARGET=62fbd7c34c0671d10bcbb3cd3f86c54937040c7c" in s
    assert "CORE_E=121" in s and "CORE_M=5650187" in s
    assert "BRIDGE_E=4" in s and "BRIDGE_M=567032" in s
    for path in (
        "src/flop_agent/discord_control.py",
        "src/flop_agent/discord_outcome_scorecard.py",
        "tests/test_discord_gap_notice_coalescing.py",
        "tests/test_discord_outcome_scorecard.py",
    ):
        assert path in s

def test_prod464_restarts_only_discord():
    s=_source()
    assert "systemctl restart technocore-safe-agent-discord.service" in s
    for unit in (
        "technocore-safe-agent-resident.service",
        "technocore-safe-agent-lobby-capture.service",
        "technocore-safe-agent-signer.service",
    ):
        assert f"systemctl restart {unit}" not in s
    assert "OTHER_RESTARTS=NO" in s

def test_prod464_is_compact_and_has_no_dangerous_data_plane_actions():
    s=_source()
    assert s.count('echo "') <= 14
    assert "DISCORD_PENDING_GAP=0" in s
    assert "DO_NOT_RERUN=YES" in s
    for pattern in (
        r"\bsqlite3\b",
        r"\bjournalctl\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"airdrop_monitor\.run_once",
        r"airdrop_notifier\.run_once",
    ):
        assert re.search(pattern,s) is None
