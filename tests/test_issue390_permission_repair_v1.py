from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue390-permission-repair-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue390_permrepair_v1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue390_permrepair_v1_pins_exact_target_core_and_preserved_services() -> None:
    text = _text()
    for token in (
        "TARGET=473e4f73426069c682cfd716f611e0bfad7d4fe8",
        "EXPECTED_CORE_EVENTS=119",
        "EXPECTED_CORE_MESSAGES=5497275",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_CAP_RESTARTS=0",
        "EXPECTED_SIGN_PID=1539554",
        "EXPECTED_SIGN_RESTARTS=1",
        "EXPECTED_DISC_PID=1957840",
        "EXPECTED_DISC_RESTARTS=0",
    ):
        assert token in text


def test_issue390_permrepair_v1_pins_exact_three_files_and_blobs() -> None:
    text = _text()
    for token in (
        "F1=src/flop_agent/observer_lobby_capture.py",
        "F2=src/flop_agent/observer_lobby_startup_hole_bridge.py",
        "F3=src/flop_agent/observer_resident_isolation.py",
        "B1=285a95c539611c87768634cba1d45cdb442beb14",
        "B2=b96f315dd6bd5c2baa0f5db35acd85479e52e993",
        "B3=6ac40ac32108e141320c1d87d5ce0268e71e986b",
    ):
        assert token in text
    assert 'chmod 0644 "$APP/$F1" "$APP/$F2" "$APP/$F3"' in text
    assert "chmod -R" not in text


def test_issue390_permrepair_v1_requires_proven_0600_root_root_unreadable_baseline() -> None:
    text = _text()
    for token in (
        '[[ "$mode" != 600 || "$owner" != root || "$group" != root ]]',
        'runuser -u "$RES_USER" -- test -r "$path"',
        "PROD390_PERMREPAIR_V1=STOP:file_unexpectedly_readable:",
        "PROD390_PERMREPAIR_V1=STOP:permission_baseline_changed:",
    ):
        assert token in text


def test_issue390_permrepair_v1_preserves_content_and_git_cleanliness() -> None:
    text = _text()
    for token in (
        'actual_blob=$(git -C "$APP" hash-object "$path"',
        'index_blob=$(git -C "$APP" rev-parse "HEAD:$rel"',
        "POST_WORKTREE_CLEAN=YES",
        "FILE_CONTENT_CHANGED=NO",
    ):
        assert token in text


def test_issue390_permrepair_v1_import_smoke_runs_as_resident_without_bytecode() -> None:
    text = _text()
    for token in (
        'runuser -u "$RES_USER" -- env',
        'PYTHONDONTWRITEBYTECODE=1',
        'import flop_agent.observer_lobby_capture',
        'import flop_agent.observer_lobby_startup_hole_bridge',
        'import flop_agent.observer_resident_isolation',
        'import flop_agent.resident_daemon',
        'IMPORT_SMOKE=PASS',
    ):
        assert token in text


def test_issue390_permrepair_v1_never_manually_restarts_services() -> None:
    text = _text().lower()
    for forbidden in (
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "systemctl try-restart",
        "systemctl reload",
        "kill -",
        "pkill ",
        "killall ",
    ):
        assert forbidden not in text
    for token in (
        "MANUAL_SERVICE_RESTART=NO",
        "SYSTEMD_AUTO_RESTART_USED=YES",
        "CAPTURE_RESTART=NO",
        "SIGNER_RESTART=NO",
        "DISCORD_RESTART=NO",
        "METADATA_BLOCK_RESTART=NO",
    ):
        assert token in _text()


def test_issue390_permrepair_v1_requires_stable_auto_recovery_and_core() -> None:
    text = _text()
    for token in (
        "AUTO_RESTART_RECOVERY_STABLE=YES",
        "FINAL_RESIDENT ACTIVE=",
        "PROD390_PERMREPAIR_V1=STOP:resident_not_recovered_within_window",
        "PROD390_PERMREPAIR_V1=STOP:resident_not_stable_at_acceptance",
        "PROD390_PERMREPAIR_V1=STOP:protected_core_changed",
        "=== PROD390_PERMISSION_REPAIR_V1=PASS ===",
    ):
        assert token in text


def test_issue390_permrepair_v1_no_network_sqlite_or_technocore_write() -> None:
    text = _text().lower()
    for forbidden in (
        "sqlite3.connect",
        "httpx",
        "curl ",
        "wget ",
        "technocore.chat",
        "client.post(",
        "post_signed(",
        "write_note(",
        "strace ",
        "gdb ",
    ):
        assert forbidden not in text
    assert "ACTIVE_CAPTURE_SQLITE_QUERY=NO" in _text()
    assert "NETWORK_PROBE=NO" in _text()
    assert "TECHNOCORE_WRITE=NO" in _text()


def test_issue390_permrepair_v1_never_restores_bad_permissions_after_mutation() -> None:
    text = _text()
    repair_pos = text.index('chmod 0644 "$APP/$F1" "$APP/$F2" "$APP/$F3"')
    assert "chmod 0600" not in text[repair_pos:]
    assert "PERMISSIONS_REMAIN_REPAIRED=YES" in text[repair_pos:]


def test_issue390_permrepair_v1_do_not_rerun_marker() -> None:
    assert "DO_NOT_RERUN=YES" in _text()
