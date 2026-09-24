from pathlib import Path
import re


HELPER = Path("packaging/oracle/issue445-core121-path-attribution-v2.sh")


def _source() -> str:
    return HELPER.read_text("utf-8")


def test_issue445_v2_pins_known_baselines_and_exact_attribution() -> None:
    source = _source()
    assert "EXPECTED_PROD_HEAD=041b830d3b0ffd17ef95f8d889922f20d3ac6631" in source
    assert "BASE_CORE_EVENTS = 120" in source
    assert "BASE_CORE_MESSAGES = 5_650_166" in source
    assert "BASE_BRIDGE_EVENTS = 3" in source
    assert "BASE_BRIDGE_MESSAGES = 567_011" in source
    assert "STARTUP_BRIDGE_EXACTLY_EXPLAINS_POST_BASELINE_CORE=" in source

    for token in (
        "lobby_startup_bridge_unrecoverable_events",
        "lobby_startup_bridge_unrecoverable_messages",
        "lobby_startup_bridge_local_suffix_handoffs",
        "lobby_startup_bridge_avoided_unrecoverable_messages",
        "lobby_spool_catchup_waits",
        "lobby_spool_catchup_successes",
        "lobby_spool_catchup_timeouts",
        "last_unrecoverable_gap",
    ):
        assert token in source


def test_issue445_v2_is_strictly_persisted_state_read_only() -> None:
    source = _source()
    forbidden = (
        r"git_owner\s+(?:fetch|merge|pull|checkout|reset)\b",
        r"\bjournalctl\b",
        r"\bsqlite3\b",
        r"observer_lobby_capture\.status",
        r"\bcurl\b",
        r"\bwget\b",
        r"systemctl\s+(?:restart|start|stop|enable|disable|daemon-reload)\b",
    )
    for pattern in forbidden:
        assert re.search(pattern, source) is None

    for marker in (
        "GIT_MUTATION=NO",
        "NETWORK_PROBE=NO",
        "JOURNAL_READ=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "SYSTEMD_MUTATION=NO",
        "RUNNING_SERVICE_RESTART=NO",
        "SIGNER_ACTION=NO",
        "TECHNOCORE_WRITE=NO",
        "FLOP_WRITE=NO",
        "X_WRITE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert marker in source
