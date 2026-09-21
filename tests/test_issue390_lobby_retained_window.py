from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue390-lobby-retained-window.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue390_lobby_lag_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue390_lobby_lag_pins_current_core_and_services() -> None:
    text = _text()

    for token in (
        "EXPECTED_APP_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe",
        "EXPECTED_CORE_EVENTS=118",
        "EXPECTED_CORE_MESSAGES=5092411",
        "EXPECTED_RES_PID=1868797",
        "EXPECTED_CAP_PID=1868796",
    ):
        assert token in text


def test_issue390_lobby_lag_reads_spool_metrics_from_observer_state() -> None:
    text = _text()

    for token in (
        "lobby_spool_recovery_events",
        "lobby_spool_recovered_messages",
        "lobby_spool_live_error_recoveries",
        "lobby_spool_partial_recovery_messages",
        "lobby_spool_catchup_waits",
        "lobby_spool_catchup_successes",
        "lobby_spool_catchup_timeouts",
        "lobby_startup_spool_attempts",
        "lobby_startup_spool_recoveries",
        "lobby_startup_spool_messages",
        "lobby_capture_health_proofs",
    ):
        assert token in text


def test_issue390_lobby_lag_uses_get_only_sanitized_network_probe() -> None:
    text = _text().lower()

    assert 'base="/'.lower() not in text  # no shell URL mishmash
    assert 'BASE="https://technocore.chat"' in _text()
    assert 'client.get(' in text
    assert 'client.stream("get"' in text
    assert 'params={"format":"json","since":cursor,"wait":0,"limit":200}' in text
    assert '"/r/lobby/export"' in text
    assert "raw_message_output=no" in text
    assert "did_output=no" in text
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


def test_issue390_lobby_lag_outputs_only_seq_metadata() -> None:
    text = _text()

    for token in (
        "LIVE_ROW_COUNT=",
        "LIVE_FIRST_SEQ=",
        "LIVE_LAST_SEQ=",
        "LIVE_FIRST_DISTANCE_FROM_CURSOR=",
        "EXPORT_VALID_ROW_COUNT=",
        "EXPORT_FIRST_SEQ=",
        "EXPORT_LAST_SEQ=",
        "EXPORT_FIRST_DISTANCE_FROM_CURSOR=",
        "SERVER_RETAINED_HAS_CURSOR_NEXT=",
        "SERVER_CURRENT_MISSING_PREFIX=",
    ):
        assert token in text

    assert "text_excerpt" not in text
    assert "print(item)" not in text
    assert "print(response.text)" not in text


def test_issue390_lobby_lag_never_opens_active_capture_sqlite() -> None:
    text = _text().lower()

    for forbidden in (
        "sqlite3.connect",
        "sqlite3 ",
        "lobby-capture-service.sqlite3",
        "pragma ",
        "select ",
    ):
        assert forbidden not in text


def test_issue390_lobby_lag_is_read_only() -> None:
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


def test_issue390_lobby_lag_safety_tail() -> None:
    text = _text()

    for token in (
        "MUTATION_COMMANDS=NONE",
        "SERVICE_RESTART=NO",
        "PROCESS_SIGNAL=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "NETWORK_WRITE=NO",
        "NETWORK_READ=YES_GET_ONLY",
        "TECHNOCORE_WRITE=NO",
        "RAW_MESSAGE_OUTPUT=NO",
        "DID_OUTPUT=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert token in text
