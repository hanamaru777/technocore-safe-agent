from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue423-steady-pressure-attribution-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue423_pressure_v1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue423_pressure_v1_pins_exact_target_core_and_services() -> None:
    text = _text()
    for token in (
        "TARGET=077d1e478363751bf5b73d810326f95f3a36b7a3",
        "EXPECTED_CORE_EVENTS=120",
        "EXPECTED_CORE_MESSAGES=5650166",
        "EXPECTED_RES_PID=2243415",
        "EXPECTED_RES_RESTARTS=0",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_SIGN_PID=1539554",
        "EXPECTED_DISC_PID=1957840",
    ):
        assert token in text


def test_issue423_pressure_v1_is_read_only() -> None:
    text = _text().lower()
    for forbidden in (
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "git fetch",
        "git merge",
        "git pull",
        "git reset",
        "git checkout",
        "chmod ",
        "chown ",
        "kill -",
        "pkill ",
        "killall ",
        "sqlite3",
        "lobby-capture.sqlite3",
        "httpx",
        "curl ",
        "wget ",
        "client.post(",
        "post_signed(",
        "write_note(",
    ):
        assert forbidden not in text


def test_issue423_pressure_v1_samples_known_services_and_cgroups_only() -> None:
    text = _text()
    for token in (
        'names=["RESIDENT","CAPTURE","SIGNER","DISCORD","OCA_AGENT","OCA_UPDATER"]',
        "ControlGroup",
        "memory.current",
        "memory.swap.current",
        "io.stat",
        "RSS_BYTES=",
        "SWAP_BYTES=",
        "MAJFLT=",
        "CG_MEMORY_BYTES=",
        "CG_SWAP_BYTES=",
        "CG_RBYTES=",
        "CG_WBYTES=",
    ):
        assert token in text
    assert "/proc/*" not in text
    assert "ps aux" not in text
    assert "top -" not in text


def test_issue423_pressure_v1_samples_system_pressure_and_vmstat() -> None:
    text = _text()
    for token in (
        "/proc/meminfo",
        "/proc/pressure/",
        "/proc/vmstat",
        "pgmajfault",
        "pswpin",
        "pswpout",
        "sample T0",
        "sample T30",
        "sample T60",
    ):
        assert token in text


def test_issue423_pressure_v1_keeps_continuity_gate() -> None:
    text = _text()
    for token in (
        "FINAL_PROTECTED_CORE=",
        "FINAL_LOBBY_CURSOR=",
        "FINAL_OBSERVER_HEARTBEAT_AGE=",
        "protected_core_changed_during_watch",
        "observer_not_progressing",
        "observer_heartbeat_not_fresh",
    ):
        assert token in text


def test_issue423_pressure_v1_no_raw_cmdline_or_env_output() -> None:
    text = _text()
    assert "RAW_CMDLINE_OUTPUT=NO" in text
    assert "PROCESS_ENV_OUTPUT=NO" in text
    assert "cmdline" not in text.lower()
    assert "environ" not in text.lower()


def test_issue423_pressure_v1_safety_tail() -> None:
    text = _text()
    for token in (
        "SERVICE_MUTATION=NO",
        "SERVICE_RESTART=NO",
        "SOURCE_MUTATION=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "NETWORK_PROBE=NO",
        "TECHNOCORE_WRITE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert token in text
