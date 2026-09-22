from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue390-post-repair-reconcile-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue390_postrepair_v1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue390_postrepair_v1_pins_target_core_and_repaired_files() -> None:
    text = _text()
    for token in (
        "TARGET=473e4f73426069c682cfd716f611e0bfad7d4fe8",
        "EXPECTED_CORE_EVENTS=119",
        "EXPECTED_CORE_MESSAGES=5497275",
        "F1=src/flop_agent/observer_lobby_capture.py",
        "F2=src/flop_agent/observer_lobby_startup_hole_bridge.py",
        "F3=src/flop_agent/observer_resident_isolation.py",
        "B1=285a95c539611c87768634cba1d45cdb442beb14",
        "B2=b96f315dd6bd5c2baa0f5db35acd85479e52e993",
        "B3=6ac40ac32108e141320c1d87d5ce0268e71e986b",
    ):
        assert token in text


def test_issue390_postrepair_v1_requires_permission_repair_persistence() -> None:
    text = _text()
    for token in (
        '[[ "$blob" != "$expected_blob" || "$mode" != 644 || "$owner" != root || "$group" != root || "$readable" != YES ]]',
        "ISSUE390_POSTREPAIR_V1=STOP:permission_repair_not_persistent:",
        "readable_as_technocore=",
    ):
        assert token in text


def test_issue390_postrepair_v1_samples_three_times() -> None:
    text = _text()
    for token in (
        "sample_all T0",
        "sleep 15",
        "sample_all T15",
        "sample_all T30",
        "PROTECTED_CORE=",
        "LOBBY_CURSOR=",
        "OBSERVER_HEARTBEAT_AGE=",
        "RESIDENT_HEARTBEAT_AGE=",
    ):
        assert token in text


def test_issue390_postrepair_v1_reads_only_resident_and_children() -> None:
    text = _text()
    for token in (
        "RESIDENT_MAIN",
        "RESIDENT_IMMEDIATE_CHILD_COUNT=",
        "RESIDENT_CHILD",
        "cpu_ticks=",
        "majflt=",
        "rss_bytes=",
        "swap_bytes=",
        "read_bytes=",
        "write_bytes=",
        "wchan=",
    ):
        assert token in text
    assert 'pathlib.Path("/proc").iterdir()' not in text


def test_issue390_postrepair_v1_classifies_only_post_repair_journal() -> None:
    text = _text()
    assert "--since '2026-09-22 11:31:00 UTC'" in text
    for token in (
        'print(f"POSTREPAIR_JOURNAL_CLASS_{label}=',
        "PERMISSION_ERROR",
        "MEMORY_ERROR",
        "RUNTIME_ERROR",
        "MAINTENANCE_EXIT",
        "POSTREPAIR_JOURNAL_FRAME idx=",
        "RAW_JOURNAL_OUTPUT=NO",
    ):
        assert token in text


def test_issue390_postrepair_v1_reads_pressure() -> None:
    text = _text()
    for token in (
        'pathlib.Path("/proc/meminfo")',
        'pathlib.Path(f"/proc/pressure/{kind}")',
        "MEMAVAILABLE",
        "SWAPFREE",
    ):
        assert token in text


def test_issue390_postrepair_v1_is_read_only() -> None:
    text = _text().lower()
    for forbidden in (
        "chmod ",
        "chown ",
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "systemctl try-restart",
        "systemctl reload",
        "git merge",
        "git reset",
        "git checkout",
        "git pull",
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


def test_issue390_postrepair_v1_safety_tail() -> None:
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
