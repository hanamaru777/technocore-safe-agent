from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue390-lobby-spool-snapshot-proof-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue390_spool_v1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue390_spool_v1_pins_current_production_baseline() -> None:
    text = _text()
    for token in (
        "EXPECTED_APP_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe",
        "EXPECTED_CORE_EVENTS=118",
        "EXPECTED_CORE_MESSAGES=5092411",
        "EXPECTED_LOBBY_CURSOR=59579961",
        "EXPECTED_RES_PID=1868797",
        "EXPECTED_CAP_PID=1868796",
    ):
        assert token in text


def test_issue390_spool_v1_guards_temporary_snapshot_disk_usage() -> None:
    text = _text()

    for token in (
        "SOURCE_DB_BYTES=",
        "TMP_FREE_BYTES=",
        "MIN_TMP_FREE_BYTES=",
        "TMP_SPACE_PREFLIGHT=PASS",
        "ISSUE390_SPOOLV1=STOP:insufficient_tmp_space",
        "SOURCE_DB_BYTES * 2 + 268435456",
    ):
        assert token in text


def test_issue390_spool_v1_uses_read_only_online_backup_before_snapshot_queries() -> None:
    text = _text()

    assert '?mode=ro' in text
    assert "source.backup(dest,pages=256,sleep=0.01)" in text
    assert "source.execute(" not in text
    assert "source.close()" in text
    assert "All SQL below runs only against the disposable clone." in text

    backup_at = text.index("source.backup(dest,pages=256,sleep=0.01)")
    close_at = text.index("source.close()", backup_at)
    first_snapshot_select = text.index('snap.execute("PRAGMA quick_check")', close_at)
    assert backup_at < close_at < first_snapshot_select


def test_issue390_spool_v1_proves_exact_missing_prefix_from_snapshot_only() -> None:
    text = _text()

    for token in (
        "SERVER_MISSING_PREFIX_START=",
        "SERVER_MISSING_PREFIX_END=",
        "SERVER_MISSING_PREFIX_EXPECTED_ROWS=",
        "SNAPSHOT_PREFIX_ROW_COUNT=",
        "SNAPSHOT_PREFIX_MIN_SEQ=",
        "SNAPSHOT_PREFIX_MAX_SEQ=",
        "SNAPSHOT_HAS_SERVER_MISSING_PREFIX=",
        "SNAPSHOT_PREFIX_MISSING_ROWS=",
    ):
        assert token in text

    assert (
        'snap.execute(\n'
        '            "SELECT COUNT(*),MIN(seq),MAX(seq) FROM messages WHERE seq BETWEEN ? AND ?",'
        in text
    )


def test_issue390_spool_v1_outputs_only_safe_capture_metadata() -> None:
    text = _text()

    for token in (
        "SNAPSHOT_CAPTURE_CURSOR=",
        "SNAPSHOT_LAST_SUCCESS_AT=",
        "SNAPSHOT_LAST_ERROR=",
        "SNAPSHOT_LAST_CAPTURE_HOLE_FROM=",
        "SNAPSHOT_LAST_CAPTURE_HOLE_TO=",
        "RAW_MESSAGE_OUTPUT=NO",
        "DID_OUTPUT=NO",
    ):
        assert token in text

    assert "print(payload)" not in text
    assert "print(item)" not in text
    assert "response.text" not in text


def test_issue390_spool_v1_samples_stall_and_capture_liveness() -> None:
    text = _text()

    for token in (
        "OBSERVER_HEARTBEAT_AGE=",
        "RESIDENT_HEARTBEAT_AGE=",
        "CAPTURE_PROC_T0=",
        "CAPTURE_PROC_T5=",
        "POST_LOBBY_CURSOR=",
        "ISSUE390_SPOOLV1_POST_STATE=STILL_STALLED",
        "sleep 5",
    ):
        assert token in text


def test_issue390_spool_v1_network_is_get_only() -> None:
    text = _text().lower()

    assert 'client.stream("get",base+"/r/lobby/export")' in text
    assert "network_probe_mode=get_only_seq_metadata" in text
    for forbidden in (
        "client.post(",
        "client.put(",
        "client.patch(",
        "client.delete(",
        "httpx.post(",
        "httpx.put(",
        "httpx.patch(",
        "httpx.delete(",
    ):
        assert forbidden not in text


def test_issue390_spool_v1_has_no_service_or_process_mutation() -> None:
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
        "snap refresh",
        "snap revert",
        "snap install",
        "iptables ",
        "post_signed(",
        "write_note(",
        "git reset",
        "git checkout",
        "git pull",
        "git merge",
    ):
        assert forbidden not in text


def test_issue390_spool_v1_safety_tail_is_explicit() -> None:
    text = _text()

    for token in (
        "APPLICATION_STATE_MUTATION=NO",
        "SERVICE_MUTATION=NO",
        "SERVICE_RESTART=NO",
        "PROCESS_SIGNAL=NO",
        "ACTIVE_CAPTURE_SQLITE_SELECT=NO",
        "ACTIVE_CAPTURE_SQLITE_BACKUP_MODE=READ_ONLY_ONLINE_BACKUP",
        "SNAPSHOT_QUERY_ONLY=YES",
        "TEMP_SNAPSHOT_REMOVED_ON_EXIT=YES",
        "NETWORK_WRITE=NO",
        "NETWORK_READ=YES_GET_ONLY",
        "TECHNOCORE_WRITE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert token in text
