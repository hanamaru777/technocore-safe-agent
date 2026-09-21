from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue390-second-core-gap-forensic-v3.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue390_gapv3_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue390_gapv3_pins_core_but_not_exact_lobby_cursor() -> None:
    text = _text()

    for token in (
        "EXPECTED_CORE_EVENTS=119",
        "EXPECTED_CORE_MESSAGES=5497275",
        "PRIOR_LOBBY_CURSOR=59579961",
        "GAP_EVENT_CURSOR=59984825",
    ):
        assert token in text

    assert "EXPECTED_LOBBY_CURSOR=" not in text
    assert "lobby_cursor < GAP_EVENT_CURSOR" in text


def test_issue390_gapv3_extracts_exact_gap_metadata_and_relationships() -> None:
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
        "LAST_GAP_ENDS_AT_GAP_EVENT_CURSOR=",
        "LAST_GAP_LENGTH_EQUALS_CORE_DELTA=",
    ):
        assert token in text


def test_issue390_gapv3_emits_current_liveness_deltas() -> None:
    text = _text()

    for token in (
        "T0_LOBBY_CURSOR=",
        "T10_LOBBY_CURSOR=",
        "LOBBY_CURSOR_ADVANCE_AFTER_GAP_EVENT=",
        "sleep 10",
        "T0_STATE=PASS",
        "T10_STATE=PASS",
    ):
        assert token in text


def test_issue390_gapv3_emits_lobby_recovery_metrics() -> None:
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


def test_issue390_gapv3_sanitizes_output() -> None:
    text = _text()

    assert 'return "LOBBY"' in text
    assert 'return "EVENTS"' in text
    assert "hashlib.sha256(room.encode" in text
    assert "text_excerpt" not in text
    assert "item.get('did'" not in text
    assert "RAW_UNTRUSTED_TEXT_OUTPUT=NO" in text
    assert "DID_OUTPUT=NO" in text
    assert "RAW_PRIVATE_ROOM_OUTPUT=NO" in text


def test_issue390_gapv3_samples_capture_without_sqlite_query() -> None:
    text = _text().lower()

    for token in (
        "/proc/{pid}/stat",
        "lobby-capture-service.sqlite3-wal",
        "lobby-capture-service.sqlite3-shm",
        "proc_snapshot t0",
        "proc_snapshot t10",
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


def test_issue390_gapv3_is_read_only() -> None:
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


def test_issue390_gapv3_safety_tail() -> None:
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
