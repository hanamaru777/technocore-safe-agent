from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue419-prod-hysteresis-rollout-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_prod419_v1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod419_v1_pins_exact_pre_target_core_and_services() -> None:
    text = _text()
    for token in (
        "PRE=254c2328bcb2bffc27d1f123b93296ebe7b48661",
        "TARGET=077d1e478363751bf5b73d810326f95f3a36b7a3",
        "EXPECTED_CORE_EVENTS=120",
        "EXPECTED_CORE_MESSAGES=5650166",
        "EXPECTED_RES_PID=2232290",
        "EXPECTED_RES_RESTARTS=0",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_SIGN_PID=1539554",
        "EXPECTED_DISC_PID=1957840",
    ):
        assert token in text


def test_prod419_v1_pins_exact_hysteresis_blob_and_permissions() -> None:
    text = _text()
    for token in (
        "PRE_ISOLATION_BLOB=2de08f76a8bdcb9a1c5449230c8d6ea7940bd5c0",
        "TARGET_ISOLATION_BLOB=ce7193a5fe7e80dbb86cea2b0e3307c7124f30dc",
        "RESIDENT_BLOB=7e74f2f00a4e5caa251d28b4dacf51f867ba64cf",
        'assert observer_resident_isolation._PRESSURE_CLEAR_STABLE_SECONDS == 60.0',
        "chmod 0644",
    ):
        assert token in text
    assert "chmod -R" not in text


def test_prod419_v1_ff_only_and_restarts_only_resident() -> None:
    text = _text()
    for token in (
        'git -C "$APP" fetch --no-tags origin main',
        'git -C "$APP" merge-base --is-ancestor "$PRE" "$TARGET"',
        'git -C "$APP" merge --ff-only "$TARGET"',
        'timeout 120 systemctl restart "$RES"',
        "RESIDENT_RESTART=EXACTLY_ONCE",
        "CAPTURE_RESTART=NO",
        "SIGNER_RESTART=NO",
        "DISCORD_RESTART=NO",
    ):
        assert token in text
    for forbidden in (
        'systemctl restart "$CAP"',
        'systemctl restart "$SIGN"',
        'systemctl restart "$DISC"',
        "git reset --hard",
        "git checkout",
        "git rebase",
    ):
        assert forbidden not in text


def test_prod419_v1_proves_no_maintenance_before_sixty_second_window() -> None:
    text = _text()
    for token in (
        "sample T0 YES",
        "sample T20 YES",
        "sample T40 YES",
        "sample T80 NO",
        "sample T120 NO",
        "HYSTERESIS_EARLY_WINDOW=PASS",
        "hysteresis_early_admission_rc_",
        "MAINTENANCE_CHILD_COUNT=",
    ):
        assert token in text


def test_prod419_v1_checks_continuity_heartbeat_and_semantics() -> None:
    text = _text()
    for token in (
        "PROTECTED_CORE=",
        "LOBBY_CURSOR=",
        "OBSERVER_HEARTBEAT_AGE=",
        "RESIDENT_HEARTBEAT_AGE=",
        "RESIDENT_HEARTBEAT_SEMANTICS=",
        "FINAL_PROTECTED_CORE=",
        "FINAL_CURSOR_NONDECREASING=",
        "protected_core_changed",
        "heartbeat_not_fresh",
        "observer_not_progressing",
    ):
        assert token in text


def test_prod419_v1_no_capture_sqlite_or_technocore_write() -> None:
    text = _text().lower()
    for forbidden in (
        "sqlite3",
        "lobby-capture.sqlite3",
        "capture._connect",
        "read_range(",
        "httpx",
        "client.post(",
        "post_signed(",
        "write_note(",
        "strace ",
        "gdb ",
        "kill -",
        "pkill ",
        "killall ",
    ):
        assert forbidden not in text
    assert "ACTIVE_CAPTURE_SQLITE_QUERY=NO" in _text()
    assert "TECHNOCORE_WRITE=NO" in _text()


def test_prod419_v1_is_one_shot() -> None:
    assert "DO_NOT_RERUN=YES" in _text()
