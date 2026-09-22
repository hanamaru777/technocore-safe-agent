from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue364-prod-pressure-heartbeat-rollout-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_prod364_hbv1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod364_hbv1_pins_exact_pre_target_core_and_services() -> None:
    text = _text()
    for token in (
        "PRE=9d635be14de715d61e680136dd688bd8598e9403",
        "TARGET=254c2328bcb2bffc27d1f123b93296ebe7b48661",
        "EXPECTED_CORE_EVENTS=120",
        "EXPECTED_CORE_MESSAGES=5650166",
        "EXPECTED_RES_PID=2195965",
        "EXPECTED_RES_RESTARTS=0",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_SIGN_PID=1539554",
        "EXPECTED_DISC_PID=1957840",
    ):
        assert token in text


def test_prod364_hbv1_pins_runtime_blobs_and_permissions() -> None:
    text = _text()
    for token in (
        "PRE_ISOLATION_BLOB=6ea86a3f7350162727763e58f95116970eb43f35",
        "PRE_RESIDENT_BLOB=a614a0569abbffa86eb32ce99372ff4757009241",
        "TARGET_ISOLATION_BLOB=2de08f76a8bdcb9a1c5449230c8d6ea7940bd5c0",
        "TARGET_RESIDENT_BLOB=7e74f2f00a4e5caa251d28b4dacf51f867ba64cf",
        "chmod 0644",
    ):
        assert token in text
    assert "chmod -R" not in text


def test_prod364_hbv1_ff_only_and_restarts_resident_only() -> None:
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


def test_prod364_hbv1_accepts_pressure_paused_semantics_without_faking_maintenance() -> None:
    text = _text()
    for token in (
        "PRESSURE_PAUSED_HEARTBEAT_STATUS",
        "RAW_MAINTENANCE_LAST_REFRESH",
        "OPERATIONAL_LAST_REFRESH",
        "OPERATIONAL_MAINTENANCE_STATUS",
        "OPERATIONAL_MAINTENANCE_LAST_REFRESH",
        "RESIDENT_HEARTBEAT_SEMANTICS=",
        "FINAL_RESIDENT_HEARTBEAT_SEMANTICS=",
        "heartbeat_semantics_invalid",
    ):
        assert token in text


def test_prod364_hbv1_samples_continuity_pressure_and_children() -> None:
    text = _text()
    for token in (
        "sample T0",
        "sample T60",
        "sample T120",
        "PROTECTED_CORE=",
        "OBSERVER_HEARTBEAT_AGE=",
        "RESIDENT_HEARTBEAT_AGE=",
        "PRESSURE_GUARD_CURRENT=",
        "MAINTENANCE_CHILD_COUNT=",
        "MAINTENANCE_CHILD_STATES=",
        "FINAL_CURSOR_NONDECREASING=",
    ):
        assert token in text


def test_prod364_hbv1_has_no_capture_sqlite_or_technocore_write() -> None:
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
        "kill -",
        "pkill ",
        "killall ",
        "strace ",
        "gdb ",
    ):
        assert forbidden not in text
    assert "ACTIVE_CAPTURE_SQLITE_QUERY=NO" in _text()
    assert "TECHNOCORE_WRITE=NO" in _text()


def test_prod364_hbv1_is_one_shot() -> None:
    assert "DO_NOT_RERUN=YES" in _text()
