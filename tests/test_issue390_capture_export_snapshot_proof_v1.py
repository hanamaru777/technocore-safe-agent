from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue390-capture-export-snapshot-proof-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue390_capsnap_v1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue390_capsnap_v1_pins_core_and_services_without_pinning_cursor() -> None:
    text = _text()

    for token in (
        "EXPECTED_CORE_EVENTS=119",
        "EXPECTED_CORE_MESSAGES=5497275",
        "EXPECTED_RES_PID=1868797",
        "EXPECTED_RES_RESTARTS=0",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_CAP_RESTARTS=0",
    ):
        assert token in text

    assert "EXPECTED_LOBBY_CURSOR=" not in text
    assert "ISSUE390_CAPSNAPV1=STOP:core_moved_again" in text


def test_issue390_capsnap_v1_uses_read_only_online_backup_before_sql_analysis() -> None:
    text = _text()

    assert 'sqlite3.connect(f"file:{source_path}?mode=ro",uri=True,timeout=2.0)' in text
    assert "source.backup(dest,pages=128,sleep=0.02)" in text
    assert "source.execute(" not in text
    assert "ACTIVE_CAPTURE_SQLITE_SELECT=NO" in text
    assert "ACTIVE_CAPTURE_SQLITE_BACKUP_MODE=READ_ONLY_ONLINE_BACKUP" in text

    backup_pos = text.index("source.backup(dest,pages=128,sleep=0.02)")
    snapshot_query_pos = text.index('conn.execute("PRAGMA quick_check")')
    assert backup_pos < snapshot_query_pos


def test_issue390_capsnap_v1_queries_only_snapshot_for_spool_metadata() -> None:
    text = _text()

    for token in (
        "SNAPSHOT_QUICK_CHECK=",
        "SNAPSHOT_ROW_COUNT=",
        "SNAPSHOT_FIRST_SEQ=",
        "SNAPSHOT_LAST_SEQ=",
        "SNAPSHOT_CAPTURE_CURSOR=",
        "SNAPSHOT_LAST_SUCCESS_AT=",
        "SNAPSHOT_LAST_ERROR=",
        "SNAPSHOT_LAST_CAPTURE_HOLE_FROM=",
        "SNAPSHOT_LAST_CAPTURE_HOLE_TO=",
        "SNAPSHOT_HAS_CURSOR_NEXT=",
        "SNAPSHOT_FIRST_AFTER_CURSOR=",
        "SNAPSHOT_LOCAL_CONTIGUOUS_END=",
    ):
        assert token in text


def test_issue390_capsnap_v1_measures_export_size_and_union_coverage() -> None:
    text = _text()

    for token in (
        'BASE_URL="https://technocore.chat"',
        'client.stream("GET",f"{BASE_URL}/r/lobby/export")',
        "SERVER_EXPORT_COMPLETE=",
        "SERVER_EXPORT_BYTES=",
        "SERVER_EXPORT_LIMIT_BYTES=",
        "SERVER_EXPORT_EXCEEDS_12MIB=",
        "SERVER_EXPORT_VALID_SEQ_COUNT=",
        "SERVER_EXPORT_FIRST_SEQ=",
        "SERVER_EXPORT_LAST_SEQ=",
        "SERVER_HAS_CURSOR_NEXT=",
        "UNION_HAS_CURSOR_NEXT=",
        "UNION_CONTIGUOUS_END=",
        "UNION_RECOVERABLE_MESSAGES=",
        "UNION_FIRST_MISSING_SEQ=",
    ):
        assert token in text

    assert "authoritative_server_seqs=server_seqs if server_complete else []" in text


def test_issue390_capsnap_v1_preserves_only_when_recommended() -> None:
    text = _text()

    assert "PRESERVE_RECOMMENDED=" in text
    assert 'if [[ "$PRESERVE" == YES ]]; then' in text
    assert 'install -d -m 700 -o root -g root "$FORENSICS_DIR"' in text
    assert 'install -m 600 -o root -g root "$SNAPSHOT" "$PERSISTED_PATH"' in text
    assert "FORENSIC_SNAPSHOT_PRESERVED=YES" in text
    assert "FORENSIC_SNAPSHOT_PRESERVED=NO" in text
    assert "PERSISTENT_MUTATION_SCOPE=ROOT_ONLY_FORENSIC_SNAPSHOT_IF_RECOMMENDED" in text


def test_issue390_capsnap_v1_samples_pressure_and_process_state() -> None:
    text = _text()

    for token in (
        'pathlib.Path(f"/proc/{pid}")',
        'pathlib.Path(f"/proc/pressure/{name}")',
        'pathlib.Path("/proc/meminfo")',
        "MEMAVAILABLE",
        "WRITEBACK",
        "LOADAVG=",
        "wchan=",
        "RESOURCE_PREFLIGHT=PASS",
        "MIN_MEM_AVAILABLE_BYTES",
    ):
        assert token.lower() in text.lower()


def test_issue390_capsnap_v1_has_no_service_or_technocore_write() -> None:
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
        "client.post(",
        "client.put(",
        "client.patch(",
        "client.delete(",
        "post_signed(",
        "write_note(",
        "git reset",
        "git checkout",
        "git pull",
        "git merge",
        "snap refresh",
        "snap revert",
        "snap install",
        "iptables ",
    ):
        assert forbidden not in text


def test_issue390_capsnap_v1_safety_tail() -> None:
    text = _text()

    for token in (
        "APPLICATION_STATE_MUTATION=NO",
        "SERVICE_MUTATION=NO",
        "SERVICE_RESTART=NO",
        "PROCESS_SIGNAL=NO",
        "ACTIVE_CAPTURE_SQLITE_SELECT=NO",
        "ACTIVE_CAPTURE_SQLITE_BACKUP_MODE=READ_ONLY_ONLINE_BACKUP",
        "SNAPSHOT_QUERY_ONLY=YES",
        "NETWORK_WRITE=NO",
        "NETWORK_READ=YES_GET_ONLY",
        "TECHNOCORE_WRITE=NO",
        "RAW_MESSAGE_OUTPUT=NO",
        "DID_OUTPUT=NO",
        "PERSISTENT_MUTATION_SCOPE=ROOT_ONLY_FORENSIC_SNAPSHOT_IF_RECOMMENDED",
        "DO_NOT_RERUN=YES",
    ):
        assert token in text
