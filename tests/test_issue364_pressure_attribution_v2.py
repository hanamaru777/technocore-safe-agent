from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue364-pressure-attribution-v2.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue364_pressure_v2_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue364_pressure_v2_pins_current_production_baseline() -> None:
    text = _text()

    for token in (
        "EXPECTED_APP_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe",
        "EXPECTED_CORE_EVENTS=119",
        "EXPECTED_CORE_MESSAGES=5497275",
        "EXPECTED_RES_PID=1868797",
        "EXPECTED_RES_RESTARTS=0",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_CAP_RESTARTS=0",
    ):
        assert token in text


def test_issue364_pressure_v2_samples_memory_psi_vmstat_and_process_trees() -> None:
    text = _text()

    for token in (
        'pathlib.Path("/proc").iterdir()',
        'read_text("/proc/meminfo")',
        'read_text(f"/proc/pressure/{kind}")',
        'read_text("/proc/vmstat")',
        "read_text('/proc/loadavg')",
        'read_text(f"/proc/{pid}/status")',
        'read_text(f"/proc/{pid}/io")',
        'read_text(entry/"wchan")',
        "RESIDENT_CHILD",
        "CAPTURE_CHILD",
        "TOP RSS+SWAP",
        "pgmajfault",
        "pswpin",
        "pswpout",
    ):
        assert token in text


def test_issue364_pressure_v2_uses_two_bounded_samples() -> None:
    text = _text()

    assert "sample T0" in text
    assert "sleep 10" in text
    assert "sample T10" in text
    assert "POST_STATE=CORE_STABLE" in text
    assert "POST_STATE=CORE_MOVED_DURING_SAMPLE" in text


def test_issue364_pressure_v2_does_not_read_sensitive_process_surfaces() -> None:
    text = _text().lower()

    assert "/cmdline" not in text
    assert "/environ" not in text
    assert "raw_cmdline_output=no" in text
    assert "process_env_output=no" in text


def test_issue364_pressure_v2_has_no_sqlite_network_or_mutation() -> None:
    text = _text().lower()

    for forbidden in (
        "sqlite3",
        "curl ",
        "wget ",
        "httpx",
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "kill -",
        "pkill ",
        "killall ",
        "strace ",
        "gdb ",
        "client.post(",
        "post_signed(",
        "write_note(",
        "git reset",
        "git checkout",
        "git pull",
        "git merge",
    ):
        assert forbidden not in text


def test_issue364_pressure_v2_safety_tail() -> None:
    text = _text()

    for token in (
        "MUTATION_COMMANDS=NONE",
        "SERVICE_RESTART=NO",
        "PROCESS_SIGNAL=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "NETWORK_PROBE=NO",
        "RAW_CMDLINE_OUTPUT=NO",
        "PROCESS_ENV_OUTPUT=NO",
        "TECHNOCORE_WRITE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert token in text
