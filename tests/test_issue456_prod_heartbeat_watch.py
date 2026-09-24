from pathlib import Path
import re

HELPER = Path("packaging/oracle/issue456-prod-heartbeat-watch-v1.sh")

def _source() -> str:
    return HELPER.read_text("utf-8")

def test_issue456_pins_current_post452_runtime():
    source = _source()
    assert "EXPECTED_HEAD=b8c63f865856d5004f8d310eb8ff4c31dbd7ffb0" in source
    assert "EXPECTED_RESIDENT_PID=2256397" in source
    assert "EXPECTED_CAPTURE_PID=2349223" in source
    assert "EXPECTED_SIGNER_PID=2256324" in source
    assert "EXPECTED_DISCORD_PID=2349270" in source
    assert "EXPECTED_CORE_EVENTS=121" in source
    assert "EXPECTED_CORE_MESSAGES=5650187" in source
    assert "EXPECTED_BRIDGE_EVENTS=4" in source
    assert "EXPECTED_BRIDGE_MESSAGES=567032" in source

def test_issue456_samples_heartbeat_pressure_and_continuity():
    source = _source()
    for phase in ("T0","T30","T60","T90","T120","T150","T180"):
        assert phase in source
    assert "LIVENESS_SOURCE=resident-heartbeat.json:updated_at" in source
    assert "OBSERVER_STATE_UPDATED_AT_LIVENESS_GATE=NO" in source
    assert "MEM_AVAILABLE_KB" in source
    assert "MEM_PSI_FULL_AVG10" in source
    assert "IO_PSI_FULL_AVG10" in source
    assert "RESIDENT_CHILDREN" in source
    assert "HEARTBEAT_CLASSIFICATION=" in source
    assert "lobby_cursor_regressed" in source

def test_issue456_is_strictly_read_only():
    source = _source()
    forbidden = (
        r"git_owner\s+(?:fetch|merge|pull|checkout|reset)\b",
        r"systemctl\s+(?:restart|start|stop|enable|disable|daemon-reload)\b",
        r"\bsqlite3\b",
        r"\bjournalctl\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"\bstrace\b",
        r"\bgdb\b",
        r"\bkill\b",
    )
    for pattern in forbidden:
        assert re.search(pattern, source) is None

    for marker in (
        "GIT_MUTATION=NO",
        "NETWORK_PROBE=NO",
        "JOURNAL_READ=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "SYSTEMD_MUTATION=NO",
        "RUNNING_SERVICE_RESTART=NO",
        "PROCESS_SIGNAL=NO",
        "RAW_CMDLINE_ENV_READ=NO",
        "SIGNER_ACTION=NO",
        "SYNTHETIC_DISCORD_MESSAGE=NO",
        "TECHNOCORE_WRITE=NO",
        "FLOP_WRITE=NO",
        "X_WRITE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert marker in source
