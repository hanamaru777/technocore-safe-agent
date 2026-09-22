from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue390-core120-attribution-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_core120_v1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_core120_v1_pins_exact_current_baseline() -> None:
    text = _text()
    for token in (
        "TARGET=473e4f73426069c682cfd716f611e0bfad7d4fe8",
        "EXPECTED_CORE_EVENTS=120",
        "EXPECTED_CORE_MESSAGES=5650166",
        "EXPECTED_RES_PID=2181484",
        "EXPECTED_RES_RESTARTS=1413",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_CAP_RESTARTS=0",
        "EXPECTED_SIGN_PID=1539554",
        "EXPECTED_SIGN_RESTARTS=1",
        "EXPECTED_DISC_PID=1957840",
        "EXPECTED_DISC_RESTARTS=0",
    ):
        assert token in text


def test_core120_v1_reads_only_persisted_observer_state_for_attribution() -> None:
    text = _text()
    for token in (
        'state=json.loads(state_path.read_text("utf-8"))',
        'gap=state.get("last_unrecoverable_gap")',
        'item.get("kind")!="message_gap"',
        'item.get("recovery")!="unrecoverable"',
        "RECENT_UNRECOVERABLE",
        "RECENT_CORE_ERROR",
    ):
        assert token in text


def test_core120_v1_exposes_exact_gap_fields_without_text() -> None:
    text = _text()
    for token in (
        '"room","lane","observed_at","missing_from","missing_to","estimated_missing","recovery_reason"',
        "LAST_GAP_",
        "missing_from=",
        "missing_to=",
        "estimated_missing=",
        "recovery_reason=",
    ):
        assert token in text
    assert "text_excerpt" not in text
    assert "item.get(\"text\"" not in text


def test_core120_v1_reads_recovery_metrics() -> None:
    text = _text()
    for token in (
        "lobby_startup_bridge_unrecoverable_events",
        "lobby_startup_bridge_unrecoverable_messages",
        "lobby_startup_bridge_local_suffix_handoffs",
        "lobby_startup_bridge_avoided_unrecoverable_messages",
        "lobby_startup_local_liveness_messages",
        "lobby_startup_spool_messages",
        "events_startup_snapshot_unrecoverable_events",
        "events_startup_snapshot_unrecoverable_messages",
        "unrecoverable_not_in_retained_export_events",
        "unrecoverable_not_in_retained_export_messages",
    ):
        assert token in text


def test_core120_v1_is_read_only_and_never_reads_capture_sqlite() -> None:
    text = _text().lower()
    for forbidden in (
        "sqlite3",
        "lobby-capture.sqlite3",
        "capture._connect",
        "capture.status",
        "read_range(",
        "chmod ",
        "chown ",
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "git merge",
        "git reset",
        "git checkout",
        "git pull",
        "curl ",
        "wget ",
        "httpx",
        "kill -",
        "pkill ",
        "killall ",
        "client.post(",
        "post_signed(",
        "write_note(",
    ):
        assert forbidden not in text


def test_core120_v1_no_raw_journal_or_untrusted_text() -> None:
    text = _text().lower()
    assert "journalctl" not in text
    assert "raw_journal_output=no" in text
    assert "text_excerpt" not in text


def test_core120_v1_pressure_and_heartbeat_are_read_only_context() -> None:
    text = _text()
    for token in (
        "/proc/meminfo",
        "/proc/pressure/",
        "OBSERVER_HEARTBEAT_AGE=",
        "RESIDENT_HEARTBEAT_AGE=",
        "STATE_HEALTH_CURRENT=",
        "CURSOR_LOBBY=",
        "CURSOR_EVENTS=",
    ):
        assert token in text


def test_core120_v1_safety_tail() -> None:
    text = _text()
    for token in (
        "SERVICE_MUTATION=NO",
        "SERVICE_RESTART=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "NETWORK_PROBE=NO",
        "RAW_JOURNAL_OUTPUT=NO",
        "TECHNOCORE_WRITE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert token in text
