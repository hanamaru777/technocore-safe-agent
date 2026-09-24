from pathlib import Path
import re

HELPER = Path("packaging/oracle/issue458-observer-degraded-diag-v1.sh")

def _source():
    return HELPER.read_text("utf-8")

def test_issue458_pins_runtime_and_protected_counters():
    source=_source()
    assert "EXPECTED_HEAD=b8c63f865856d5004f8d310eb8ff4c31dbd7ffb0" in source
    assert "EXPECTED_RESIDENT_PID=2256397" in source
    assert "EXPECTED_CAPTURE_PID=2349223" in source
    assert "EXPECTED_SIGNER_PID=2256324" in source
    assert "EXPECTED_DISCORD_PID=2349270" in source
    assert "EXPECTED_CORE_EVENTS=121" in source
    assert "EXPECTED_CORE_MESSAGES=5650187" in source
    assert "EXPECTED_BRIDGE_EVENTS=4" in source
    assert "EXPECTED_BRIDGE_MESSAGES=567032" in source

def test_issue458_reads_health_errors_pressure_and_bounded_journal():
    source=_source()
    for token in (
        "HEALTH_ROOMS_BEGIN",
        "RECENT_ERROR_HISTORY_BEGIN",
        "LAST_UNRECOVERABLE_GAP",
        "MEM_AVAILABLE_KB",
        "MEM_PSI_FULL_AVG10",
        "IO_PSI_FULL_AVG10",
        "BOUNDED RESIDENT JOURNAL",
        "BOUNDED CAPTURE JOURNAL",
    ):
        assert token in source
    for phase in ("T0","T30","T60","T90"):
        assert phase in source

def test_issue458_is_read_only():
    source=_source()
    forbidden=(
        r"git_owner\s+(?:fetch|merge|pull|checkout|reset)\b",
        r"systemctl\s+(?:restart|start|stop|enable|disable|daemon-reload)\b",
        r"\bsqlite3\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"(^|[;&|]\\s*)kill\\s+",
        r"\bstrace\b",
        r"\bgdb\b",
    )
    for pattern in forbidden:
        assert re.search(pattern,source) is None
    for marker in (
        "GIT_MUTATION=NO",
        "NETWORK_PROBE=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "SYSTEMD_MUTATION=NO",
        "RUNNING_SERVICE_RESTART=NO",
        "PROCESS_SIGNAL=NO",
        "SIGNER_ACTION=NO",
        "TECHNOCORE_WRITE=NO",
        "FLOP_WRITE=NO",
        "X_WRITE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert marker in source
