from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue390-resident-crashloop-forensic-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue390_crashv1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue390_crashv1_pins_target_and_core() -> None:
    text = _text()
    for token in (
        "TARGET=473e4f73426069c682cfd716f611e0bfad7d4fe8",
        "EXPECTED_CORE_EVENTS=119",
        "EXPECTED_CORE_MESSAGES=5497275",
        "ISSUE390_CRASHV1=STOP:repo_not_exact_target",
    ):
        assert token in text


def test_issue390_crashv1_samples_restart_loop_without_pid_pin() -> None:
    text = _text()
    for token in (
        "sample_all T0",
        "sleep 5",
        "sample_all T5",
        "sample_all T10",
        "ExecMainCode",
        "ExecMainStatus",
        "NRestarts",
        "ExecMainStartTimestamp",
        "ExecMainExitTimestamp",
    ):
        assert token in text
    assert "EXPECTED_RES_PID=" not in text


def test_issue390_crashv1_sanitizes_journal() -> None:
    text = _text()
    for token in (
        'print(f"JOURNAL_CLASS_{label}=',
        "TRACEBACK",
        "MEMORY_ERROR",
        "MAINTENANCE_EXIT",
        "JOURNAL_FRAME idx=",
        "JOURNAL_SAFE_REASON idx=",
        "RAW_JOURNAL_OUTPUT=NO",
    ):
        assert token in text
    assert 'cat "$TMP"' not in text


def test_issue390_crashv1_reads_continuity_and_pressure() -> None:
    text = _text()
    for token in (
        "PROTECTED_CORE=",
        "PROTECTED_CORE_MATCH_EXPECTED=",
        "LOBBY_CURSOR=",
        "OBSERVER_HEARTBEAT_AGE=",
        "RESIDENT_HEARTBEAT_AGE=",
        'pathlib.Path("/proc/meminfo")',
        'pathlib.Path(f"/proc/pressure/{kind}")',
    ):
        assert token in text


def test_issue390_crashv1_is_read_only() -> None:
    text = _text().lower()
    for forbidden in (
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "git merge",
        "git reset",
        "git pull",
        "git checkout",
        "import sqlite3",
        "sqlite3.connect",
        "httpx",
        "curl ",
        "wget ",
        "kill -",
        "pkill ",
        "killall ",
        "strace ",
        "gdb ",
        "/cmdline",
        "/environ",
        "client.post(",
        "post_signed(",
        "write_note(",
    ):
        assert forbidden not in text


def test_issue390_crashv1_safety_tail() -> None:
    text = _text()
    for token in (
        "MUTATION_COMMANDS=NONE",
        "SERVICE_RESTART=NO",
        "PROCESS_SIGNAL=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "NETWORK_PROBE=NO",
        "RAW_JOURNAL_OUTPUT=NO",
        "RAW_CMDLINE_OUTPUT=NO",
        "PROCESS_ENV_OUTPUT=NO",
        "TECHNOCORE_WRITE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert token in text
