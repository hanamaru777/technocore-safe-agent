from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue364-prod-pressure-preemption-rollout-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_prod364_v1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod364_v1_pins_exact_pre_target_and_core() -> None:
    text = _text()
    for token in (
        "PRE=473e4f73426069c682cfd716f611e0bfad7d4fe8",
        "TARGET=9d635be14de715d61e680136dd688bd8598e9403",
        "EXPECTED_CORE_EVENTS=120",
        "EXPECTED_CORE_MESSAGES=5650166",
        "EXPECTED_RES_PID=2181484",
        "EXPECTED_RES_RESTARTS=1413",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_SIGN_PID=1539554",
        "EXPECTED_DISC_PID=1957840",
    ):
        assert token in text


def test_prod364_v1_pins_runtime_blobs_and_repairs_permissions() -> None:
    text = _text()
    for token in (
        "CAPTURE_BLOB=285a95c539611c87768634cba1d45cdb442beb14",
        "BRIDGE_BLOB=b96f315dd6bd5c2baa0f5db35acd85479e52e993",
        "PRE_ISOLATION_BLOB=6ac40ac32108e141320c1d87d5ce0268e71e986b",
        "TARGET_ISOLATION_BLOB=6ea86a3f7350162727763e58f95116970eb43f35",
        'chmod 0644 "$APP/$CAPTURE_FILE" "$APP/$BRIDGE_FILE" "$APP/$ISOLATION_FILE"',
    ):
        assert token in text
    assert "chmod -R" not in text


def test_prod364_v1_is_ff_only_and_exact_remote() -> None:
    text = _text()
    for token in (
        'git -C "$APP" fetch --no-tags origin main',
        '[[ "$REMOTE_MAIN" == "$TARGET" ]]',
        'git -C "$APP" merge-base --is-ancestor "$PRE" "$TARGET"',
        'git -C "$APP" merge --ff-only "$TARGET"',
    ):
        assert token in text
    for forbidden in ("git reset --hard", "git checkout", "git rebase", "git cherry-pick"):
        assert forbidden not in text


def test_prod364_v1_restarts_only_resident() -> None:
    text = _text()
    assert 'timeout 120 systemctl restart "$RES"' in text
    for forbidden in (
        'systemctl restart "$CAP"',
        'systemctl restart "$SIGN"',
        'systemctl restart "$DISC"',
        'systemctl stop "$CAP"',
        'systemctl stop "$SIGN"',
        'systemctl stop "$DISC"',
    ):
        assert forbidden not in text
    for token in (
        "RESIDENT_RESTART=EXACTLY_ONCE",
        "CAPTURE_RESTART=NO",
        "SIGNER_RESTART=NO",
        "DISCORD_RESTART=NO",
    ):
        assert token in text


def test_prod364_v1_acceptance_checks_continuity_and_pressure_children() -> None:
    text = _text()
    for token in (
        "sample T0",
        "sample T45",
        "sample T90",
        "PRESSURE_GUARD_CURRENT=",
        "MAINTENANCE_CHILD_COUNT=",
        "MAINTENANCE_CHILD_STATES=",
        "FINAL_PROTECTED_CORE=",
        "FINAL_OBSERVER_HEARTBEAT_AGE=",
        "FINAL_OBSERVER_UPDATED_MOVED=",
        "FINAL_CURSOR_NONDECREASING=",
        "PROD364V1=STOP:protected_core_changed",
        "PROD364V1=STOP:observer_not_progressing",
        "PROD364V1=STOP:observer_heartbeat_not_fresh",
    ):
        assert token in text


def test_prod364_v1_import_smoke_uses_service_identity_without_bytecode() -> None:
    text = _text()
    for token in (
        "runuser -u technocore -- env",
        "PYTHONDONTWRITEBYTECODE=1",
        "import flop_agent.observer_resident_isolation",
        "import flop_agent.resident_daemon",
        "IMPORT_SMOKE=PASS",
    ):
        assert token in text


def test_prod364_v1_never_queries_capture_sqlite_or_writes_technocore() -> None:
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


def test_prod364_v1_marks_one_shot() -> None:
    assert "DO_NOT_RERUN=YES" in _text()
