from pathlib import Path
import re

HELPER=Path("packaging/oracle/issue471-prod-capture-partial-v1.sh")

def _source():
    return HELPER.read_text("utf-8")

def test_prod471_pins_exact_pre_target_and_fresh_baseline():
    s=_source()
    assert "PRE=62fbd7c34c0671d10bcbb3cd3f86c54937040c7c" in s
    assert "TARGET=d80a84aa04e1759e182e2cc16e6473d65b09eaef" in s
    assert "CORE_E=124" in s and "CORE_M=5651120" in s
    assert "BRIDGE_E=7" in s and "BRIDGE_M=567965" in s
    for path in (
        "src/flop_agent/observer_lobby_capture.py",
        "src/flop_agent/observer_lobby_capture_request_deadline.py",
        "tests/test_observer_lobby_capture.py",
        "tests/test_observer_lobby_capture_request_deadline.py",
    ):
        assert path in s

def test_prod471_restarts_only_capture():
    s=_source()
    assert "systemctl restart technocore-safe-agent-lobby-capture.service" in s
    for unit in (
        "technocore-safe-agent-resident.service",
        "technocore-safe-agent-signer.service",
        "technocore-safe-agent-discord.service",
    ):
        assert f"systemctl restart {unit}" not in s
    assert "OTHER_RESTARTS=NO" in s

def test_prod471_compact_and_safe():
    s=_source()
    assert s.count('echo "') <= 14
    assert "DO_NOT_RERUN=YES" in s
    assert "ACTIVE_CAPTURE_SQLITE" not in s
    for pattern in (
        r"\bsqlite3\b",
        r"\bjournalctl\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"airdrop_monitor\.run_once",
        r"airdrop_notifier\.run_once",
    ):
        assert re.search(pattern,s) is None

def test_prod471_watches_protected_continuity_for_180s():
    s=_source()
    assert "for phase in 0 60 120 180" in s
    assert "protected_core_changed_during_watch" in s
    assert "startup_bridge_changed_during_watch" in s
    assert "lobby_cursor_regressed" in s
