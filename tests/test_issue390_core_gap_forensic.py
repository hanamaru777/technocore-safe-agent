from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue390-core-gap-forensic.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue390_forensic_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue390_forensic_pins_new_core_baseline() -> None:
    text = _text()

    for token in (
        "EXPECTED_APP_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe",
        "EXPECTED_CORE_EVENTS=118",
        "EXPECTED_CORE_MESSAGES=5092411",
        "EXPECTED_RES_PID=1868797",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_SIG_PID=1539554",
        "EXPECTED_DIS_PID=1957840",
    ):
        assert token in text


def test_issue390_extracts_exact_gap_metadata_without_untrusted_text() -> None:
    text = _text()

    for token in (
        "last_unrecoverable_gap",
        "LAST_GAP_ROOM_LABEL=",
        "LAST_GAP_ROOM_HASH=",
        "LAST_GAP_LANE=",
        "LAST_GAP_OBSERVED_AT=",
        "LAST_GAP_MISSING_FROM=",
        "LAST_GAP_MISSING_TO=",
        "LAST_GAP_ESTIMATED_MISSING=",
        "LAST_GAP_RECOVERY_REASON=",
        "RECENT_UNRECOVERABLE_GAPS",
        "missing_from",
        "missing_to",
        "recovery_reason",
    ):
        assert token in text

    assert "text_excerpt" not in text
    assert "item.get('did'" not in text
    assert "RAW_UNTRUSTED_TEXT_OUTPUT=NO" in text
    assert "DID_OUTPUT=NO" in text
    assert "RAW_PRIVATE_ROOM_OUTPUT=NO" in text


def test_issue390_emits_relevant_continuity_metrics() -> None:
    text = _text()

    for token in (
        "unrecoverable_core_gap_events",
        "unrecoverable_core_gap_messages",
        "unrecoverable_retained_ring_start_events",
        "unrecoverable_retained_ring_start_messages",
        "unrecoverable_not_in_retained_export_events",
        "unrecoverable_not_in_retained_export_messages",
        "events_startup_snapshot_unrecoverable_events",
        "events_startup_snapshot_unrecoverable_messages",
        "startup_stream_export_attempts",
        "startup_stream_export_failures",
        "lobby_capture_pending_cycles",
        "lobby_startup_capture_messages",
    ):
        assert token in text


def test_issue390_uses_only_safe_room_labels_and_hashes() -> None:
    text = _text()

    assert 'return "EVENTS"' in text
    assert 'return "LOBBY"' in text
    assert 'return "MAILBOX"' in text
    assert 'return "WATCH"' in text
    assert 'return "OTHER"' in text
    assert "hashlib.sha256(room.encode" in text
    assert "print(room)" not in text


def test_issue390_samples_capture_without_opening_sqlite() -> None:
    text = _text().lower()

    assert "lobby-capture-service.sqlite3-wal" in text
    assert "lobby-capture-service.sqlite3-shm" in text
    assert "/proc/{pid}/stat" in text
    assert "sleep 10" in text
    assert "active_capture_sqlite_query=no" in text

    for forbidden in (
        "sqlite3.connect",
        "sqlite3 ",
        "pragma ",
        "select ",
    ):
        assert forbidden not in text


def test_issue390_sanitizes_journal() -> None:
    text = _text()

    assert "journalctl -u" in text
    assert "CAPTURE_JOURNAL_CLASS_" in text
    assert "RAW_JOURNAL_OUTPUT=NO" in text
    assert 'cat "$TMPDIR/capture.log"' not in text


def test_issue390_is_read_only() -> None:
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


def test_issue390_safety_tail() -> None:
    text = _text()

    for token in (
        "MUTATION_COMMANDS=NONE",
        "SERVICE_RESTART=NO",
        "PROCESS_SIGNAL=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "NETWORK_PROBE=NO",
        "TECHNOCORE_WRITE=NO",
        "SNAP_MUTATION=NO",
        "RAW_JOURNAL_OUTPUT=NO",
        "RAW_UNTRUSTED_TEXT_OUTPUT=NO",
        "DID_OUTPUT=NO",
        "RAW_PRIVATE_ROOM_OUTPUT=NO",
    ):
        assert token in text
