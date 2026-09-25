from pathlib import Path
import re

HELPER=Path("packaging/oracle/issue476-prod-digest-severity-v1.sh")

def _source():
    return HELPER.read_text("utf-8")

def test_prod476_pins_exact_pre_target_and_baseline():
    s=_source()
    assert "PRE=d80a84aa04e1759e182e2cc16e6473d65b09eaef" in s
    assert "TARGET=9baa91be7267b22143c33a06df3c67e1074dba0d" in s
    assert "CORE_E=124" in s and "CORE_M=5651120" in s
    assert "BRIDGE_E=7" in s and "BRIDGE_M=567965" in s
    assert "src/flop_agent/discord_outcome_scorecard.py" in s
    assert "tests/test_discord_outcome_scorecard.py" in s

def test_prod476_restarts_only_discord():
    s=_source()
    assert "systemctl restart technocore-safe-agent-discord.service" in s
    for unit in (
        "technocore-safe-agent-resident.service",
        "technocore-safe-agent-lobby-capture.service",
        "technocore-safe-agent-signer.service",
    ):
        assert f"systemctl restart {unit}" not in s
    assert "OTHER_RESTARTS=NO" in s

def test_prod476_compact_and_safe():
    s=_source()
    assert s.count('echo "') <= 14
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
