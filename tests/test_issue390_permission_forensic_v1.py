from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue390-permission-forensic-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue390_perm_v1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue390_perm_v1_pins_target() -> None:
    text = _text()
    assert "TARGET=473e4f73426069c682cfd716f611e0bfad7d4fe8" in text
    assert "ISSUE390_PERMV1=STOP:repo_not_exact_target" in text


def test_issue390_perm_v1_reads_exact_runtime_modes_and_readability() -> None:
    text = _text()
    for token in (
        "resident_daemon.py",
        "observer_core_local_continuity.py",
        "observer_lobby_capture.py",
        "observer_lobby_startup_hole_bridge.py",
        "observer_resident_isolation.py",
        "stat -c '%a'",
        "stat -c '%U'",
        "stat -c '%G'",
        "READABLE_AS_RESIDENT",
        "runuser -u",
    ):
        assert token in text


def test_issue390_perm_v1_outputs_service_identity() -> None:
    text = _text()
    for token in (
        "RESIDENT_USER=",
        "RESIDENT_GROUP=",
        "RESIDENT_DYNAMIC_USER=",
        "systemctl show",
        "-p User",
        "-p Group",
        "-p DynamicUser",
    ):
        assert token in text


def test_issue390_perm_v1_sanitizes_permission_target_paths() -> None:
    text = _text()
    assert "PermissionError:" in text
    assert 'label="repo/"+str(path.relative_to(app))' in text
    assert 'label="state/"+str(path.relative_to(state))' in text
    assert "PERMISSION_TARGET idx=" in text
    assert "PERMISSION_TARGET_COUNT=" in text
    assert 'cat "$TMP"' not in text


def test_issue390_perm_v1_is_read_only() -> None:
    text = _text().lower()
    for forbidden in (
        "chmod ",
        "chown ",
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "git merge",
        "git reset",
        "git checkout",
        "git pull",
        "sqlite3.connect",
        "httpx",
        "curl ",
        "wget ",
        "kill -",
        "pkill ",
        "killall ",
        "strace ",
        "gdb ",
        "client.post(",
        "post_signed(",
        "write_note(",
    ):
        assert forbidden not in text


def test_issue390_perm_v1_safety_tail() -> None:
    text = _text()
    for token in (
        "MUTATION_COMMANDS=NONE",
        "SERVICE_RESTART=NO",
        "PROCESS_SIGNAL=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "NETWORK_PROBE=NO",
        "RAW_JOURNAL_OUTPUT=NO",
        "TECHNOCORE_WRITE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert token in text
