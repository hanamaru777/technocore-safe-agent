from pathlib import Path
import re

HELPER = Path("packaging/oracle/issue513-observer-safety-trace-v1.sh")


def _source():
    return HELPER.read_text("utf-8")


def test_prod513_is_read_only_and_pins_production_baseline():
    s = _source()
    assert "EXPECTED_HEAD=a4016accdef7b1df591d68d1bcdc54c7a9de7320" in s
    assert "RES_PID=2462149" in s
    assert "CAP_PID=2462148" in s
    assert "SIG_PID=2462068" in s
    assert "DIS_PID=2560998" in s
    assert "CORE_E=124" in s and "CORE_M=5651120" in s
    assert "BRIDGE_E=7" in s and "BRIDGE_M=567965" in s
    assert "MUTATION=NONE" in s
    assert "RESTART=NONE" in s
    assert "NETWORK_PROBE=NONE" in s
    assert "SQLITE=NONE" in s
    assert "JOURNAL=NONE" in s


def test_prod513_samples_t0_t30_t60_only():
    s = _source()
    assert "for PHASE in T0 T30 T60" in s
    assert '[[ "$PHASE" == T0 ]] || sleep 30' in s
    assert "SAMPLE=$PHASE" in s


def test_prod513_reads_safety_observer_heartbeats_and_pressure():
    s = _source()
    for token in (
        "observer-safety.json",
        "observer-heartbeat.json",
        "resident-heartbeat.json",
        "/proc/meminfo",
        "/proc/pressure/",
        "DEGRADED=",
        "MPSI=",
        "IPSI=",
    ):
        assert token in s


def test_prod513_guards_protected_counters_and_cursor():
    s = _source()
    assert "protected_core_changed" in s
    assert "startup_bridge_changed" in s
    assert "lobby_cursor_regressed" in s


def test_prod513_output_is_compact_and_no_sensitive_actions():
    s = _source()
    assert s.count('echo "') <= 12
    assert "DO_NOT_RERUN=YES" in s
    for pattern in (
        r"\bsqlite3\b",
        r"\bjournalctl\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"systemctl restart",
        r"systemctl stop",
        r"systemctl start",
        r"git_owner fetch",
        r"git_owner merge",
        r"SIGN_SEED",
        r"OCI_VAULT_SECRET_OCID",
    ):
        assert re.search(pattern, s) is None
