from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue364-resident-pressure-attribution.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue364_pressure_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue364_pressure_helper_pins_current_baseline() -> None:
    text = _text()

    for token in (
        "EXPECTED_APP_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe",
        "EXPECTED_CORE_EVENTS=117",
        "EXPECTED_CORE_MESSAGES=5083155",
        "EXPECTED_RES_PID=1868797",
        "EXPECTED_RES_RESTARTS=0",
    ):
        assert token in text


def test_issue364_pressure_helper_samples_required_pressure_signals() -> None:
    text = _text()

    for token in (
        "/proc/pressure",
        "/proc/vmstat",
        "/proc/meminfo",
        "/proc/{pid}/stat",
        "/proc/{pid}/io",
        "/proc/{pid}/status",
        "/proc/{pid}/wchan",
        "pgmajfault",
        "pswpin",
        "pswpout",
        "pgscan_direct",
        "pgsteal_direct",
        "MemAvailable",
        "SwapFree",
        "Dirty",
        "Writeback",
        "PROC_DELTA",
        "PSI_DELTA",
        "VMSTAT_DELTA",
    ):
        assert token in text


def test_issue364_pressure_helper_reads_only_resident_state_metadata_and_counts() -> None:
    text = _text()

    for token in (
        "resident-heartbeat.json",
        "resident-state.json",
        "resident-config.json",
        "observer-state.json",
        "observer_agents",
        "relationships",
        "candidates",
        "refresh_interval",
        "STATE_BYTES",
        "HEARTBEAT_UPDATED_DURING_WINDOW=",
        "RESIDENT_STATE_UPDATED_DURING_WINDOW=",
        "LAST_REFRESH_CHANGED_DURING_WINDOW=",
    ):
        assert token in text


def test_issue364_pressure_helper_is_bounded() -> None:
    text = _text()

    assert 'snap("T0")' in text
    assert "time.sleep(20)" in text
    assert 'snap("T20")' in text
    assert 'snap("T40")' in text
    assert text.count("time.sleep(20)") == 2


def test_issue364_pressure_helper_sanitizes_journal() -> None:
    text = _text()

    assert "journalctl -u" in text
    assert "JOURNAL_CLASS_" in text
    assert "RAW_JOURNAL_OUTPUT=NO" in text
    assert 'cat "$TMPDIR/resident.log"' not in text


def test_issue364_pressure_helper_is_read_only() -> None:
    text = _text().lower()

    for forbidden in (
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "kill -",
        "pkill ",
        "killall ",
        "strace ",
        "gdb ",
        "sqlite3.connect",
        "select ",
        "pragma ",
        "snap refresh",
        "snap revert",
        "snap install",
        "iptables ",
        "client.post(",
        "post_signed(",
        "write_note(",
        "git reset",
        "git checkout",
        "git pull",
        "git merge",
    ):
        assert forbidden not in text


def test_issue364_pressure_helper_safety_tail() -> None:
    text = _text()

    for token in (
        "MUTATION_COMMANDS=NONE",
        "SERVICE_RESTART=NO",
        "PROCESS_SIGNAL=NO",
        "STRACE_ATTACH=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "TECHNOCORE_WRITE=NO",
        "SNAP_MUTATION=NO",
        "RAW_JOURNAL_OUTPUT=NO",
    ):
        assert token in text
