from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue390-second-core-gap-forensic-v2.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue390_gapv2_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue390_gapv2_pins_new_baseline() -> None:
    text = _text()
    for token in (
        "EXPECTED_CORE_EVENTS=119",
        "EXPECTED_CORE_MESSAGES=5497275",
        "EXPECTED_LOBBY_CURSOR=59984825",
        "PRIOR_CORE_EVENTS=118",
        "PRIOR_CORE_MESSAGES=5092411",
        "PRIOR_LOBBY_CURSOR=59579961",
        "EXPECTED_RES_PID=1868797",
        "EXPECTED_CAP_PID=1868796",
    ):
        assert token in text


def test_issue390_gapv2_extracts_exact_last_gap_and_delta_relationships() -> None:
    text = _text()
    for token in (
        "LAST_GAP_ROOM_LABEL=",
        "LAST_GAP_LANE=",
        "LAST_GAP_OBSERVED_AT=",
        "LAST_GAP_MISSING_FROM=",
        "LAST_GAP_MISSING_TO=",
        "LAST_GAP_ESTIMATED_MISSING=",
        "LAST_GAP_RECOVERY_REASON=",
        "LAST_GAP_RANGE_LENGTH=",
        "LAST_GAP_STARTS_AT_PRIOR_CURSOR_NEXT=",
        "LAST_GAP_ENDS_AT_CURRENT_CURSOR=",
        "LAST_GAP_LENGTH_EQUALS_CORE_DELTA=",
        "CORE_MESSAGE_DELTA_EQUALS_LOBBY_CURSOR_DELTA=",
    ):
        assert token in text


def test_issue390_gapv2_emits_lobby_recovery_metrics() -> None:
    text = _text()
    for token in (
        "lobby_startup_bridge_unrecoverable_events",
        "lobby_startup_bridge_unrecoverable_messages",
        "lobby_startup_local_liveness_bridge_attempts",
        "lobby_startup_local_liveness_capture_stall_waits",
        "lobby_spool_recovered_messages",
        "lobby_spool_catchup_timeouts",
        "lobby_startup_spool_messages",
        "lobby_startup_capture_messages",
        "unrecoverable_not_in_retained_export_messages",
    ):
        assert token in text


def test_issue390_gapv2_sanitizes_gap_error_and_room_output() -> None:
    text = _text()
    assert 'return "LOBBY"' in text
    assert 'return "EVENTS"' in text
    assert "hashlib.sha256(room.encode" in text
    assert "text_excerpt" not in text
    assert "item.get('did'" not in text
    assert "RAW_UNTRUSTED_TEXT_OUTPUT=NO" in text
    assert "DID_OUTPUT=NO" in text
    assert "RAW_PRIVATE_ROOM_OUTPUT=NO" in text


def test_issue390_gapv2_samples_capture_without_sqlite_query() -> None:
    text = _text().lower()
    for token in (
        "/proc/{pid}/stat",
        "lobby-capture-service.sqlite3-wal",
        "lobby-capture-service.sqlite3-shm",
        "proc_snapshot t0",
        "proc_snapshot t5",
        "sleep 5",
        "active_capture_sqlite_query=no",
    ):
        assert token in text

    for forbidden in (
        "sqlite3.connect",
        "sqlite3 ",
        "pragma ",
        "select ",
    ):
        assert forbidden not in text


def test_issue390_gapv2_is_read_only() -> None:
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
        "client.post(",
        "post_signed(",
        "write_note(",
        "git reset",
        "git checkout",
        "git pull",
        "git merge",
        "curl ",
        "wget ",
    ):
        assert forbidden not in text


def test_issue390_gapv2_safety_tail() -> None:
    text = _text()
    for token in (
        "MUTATION_COMMANDS=NONE",
        "SERVICE_RESTART=NO",
        "PROCESS_SIGNAL=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "NETWORK_PROBE=NO",
        "TECHNOCORE_WRITE=NO",
        "RAW_JOURNAL_OUTPUT=NO",
        "RAW_UNTRUSTED_TEXT_OUTPUT=NO",
        "DID_OUTPUT=NO",
        "RAW_PRIVATE_ROOM_OUTPUT=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert token in text
