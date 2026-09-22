from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue390-post-permission-recovery-acceptance-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_postperm_v1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_postperm_v1_pins_recovered_resident_and_preserved_services() -> None:
    text = _text()
    for token in (
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


def test_postperm_v1_pins_repaired_files_and_modes() -> None:
    text = _text()
    for token in (
        "observer_lobby_capture.py",
        "observer_lobby_startup_hole_bridge.py",
        "observer_resident_isolation.py",
        '"$mode" != 644',
        "FILE_PERMISSION_REPAIR_PRESERVED=YES",
    ):
        assert token in text


def test_postperm_v1_samples_over_seventy_seconds() -> None:
    text = _text()
    for token in (
        "sample T0",
        "sleep 35",
        "sample T35",
        "sample T70",
        "OBSERVER_HEARTBEAT_FRESH=",
        "OBSERVER_HEARTBEAT_RECOVERED=YES",
    ):
        assert token in text


def test_postperm_v1_observes_pressure_guard_and_resident_children() -> None:
    text = _text()
    for token in (
        "PRESSURE_GUARD_CURRENT=",
        "256*1024*1024",
        'psi.get("memory",0.0) > 5.0',
        'psi.get("io",0.0) > 10.0',
        "RESIDENT_CHILD_COUNT=",
        "RESIDENT_PROC state=",
    ):
        assert token in text


def test_postperm_v1_requires_core_and_observer_heartbeat() -> None:
    text = _text()
    for token in (
        "EXPECTED_CORE_EVENTS=119",
        "EXPECTED_CORE_MESSAGES=5497275",
        "ISSUE390_POSTPERM_V1=STOP:protected_core_changed",
        "ISSUE390_POSTPERM_V1=STOP:observer_heartbeat_not_fresh",
        "PROTECTED_CORE_STABLE=YES",
    ):
        assert token in text


def test_postperm_v1_is_read_only() -> None:
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
        "client.post(",
        "post_signed(",
        "write_note(",
    ):
        assert forbidden not in text


def test_postperm_v1_safety_tail() -> None:
    text = _text()
    for token in (
        "SERVICE_MUTATION=NO",
        "SERVICE_RESTART=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "NETWORK_PROBE=NO",
        "TECHNOCORE_WRITE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert token in text
