from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue390-production-recovery-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_prod390v1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod390v1_pins_exact_pre_target_core_and_service_baselines() -> None:
    text = _text()

    for token in (
        "PRE=b7bf27dbaa605971d340aa926fdffc17489c3afe",
        "TARGET=473e4f73426069c682cfd716f611e0bfad7d4fe8",
        "EXPECTED_CORE_EVENTS=119",
        "EXPECTED_CORE_MESSAGES=5497275",
        "EXPECTED_RES_PID=1868797",
        "EXPECTED_RES_RESTARTS=0",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_CAP_RESTARTS=0",
        "EXPECTED_SIGN_PID=1539554",
        "EXPECTED_SIGN_RESTARTS=1",
        "EXPECTED_DISC_PID=1957840",
        "EXPECTED_DISC_RESTARTS=0",
    ):
        assert token in text


def test_prod390v1_pins_runtime_file_blobs() -> None:
    text = _text()

    for token in (
        "EXPECTED_PRE_CAPTURE_BLOB=56e2d142d1df78fe0b26577ab9abca24f111bbf0",
        "EXPECTED_PRE_BRIDGE_BLOB=55d4c17b1b2a07d3f7740836d4d149c727ef0bcd",
        "EXPECTED_PRE_ISOLATION_BLOB=12d7a7b139cb631203b11b7e6b20c1887ec9a3cc",
        "EXPECTED_TARGET_CAPTURE_BLOB=285a95c539611c87768634cba1d45cdb442beb14",
        "EXPECTED_TARGET_BRIDGE_BLOB=b96f315dd6bd5c2baa0f5db35acd85479e52e993",
        "EXPECTED_TARGET_ISOLATION_BLOB=6ac40ac32108e141320c1d87d5ce0268e71e986b",
    ):
        assert token in text


def test_prod390v1_pins_exact_pre_to_target_diff() -> None:
    text = _text()

    expected = {
        "packaging/oracle/README.md",
        "packaging/oracle/block-technocore-metadata.sh",
        "packaging/oracle/oci-cloud-agent-diagnostic.sh",
        "src/flop_agent/observer_lobby_capture.py",
        "src/flop_agent/observer_lobby_startup_hole_bridge.py",
        "src/flop_agent/observer_resident_isolation.py",
        "tests/test_metadata_imds_isolation.py",
        "tests/test_observer_lobby_capture.py",
        "tests/test_observer_lobby_startup_hole_bridge.py",
        "tests/test_observer_resident_isolation.py",
        "tests/test_oci_cloud_agent_diagnostic.py",
    }
    for path in expected:
        assert path in text
    assert "PROD390V1=STOP:unexpected_target_diff" in text
    assert 'git -C "$APP" merge-base --is-ancestor "$PRE" "$TARGET"' in text


def test_prod390v1_pre_restart_smoke_and_rollback_are_before_restart() -> None:
    text = _text()

    restart_pos = text.index('systemctl restart "$RES"')
    for token in (
        "TARGET_LOCAL_SMOKE=PASS",
        "py_compile",
        "JUST_BEFORE_CORE=",
        'git -C "$APP" reset --hard "$PRE"',
    ):
        assert text.index(token) < restart_pos


def test_prod390v1_restarts_only_resident() -> None:
    text = _text()

    assert text.count('systemctl restart "$RES"') == 1
    for forbidden in (
        'systemctl restart "$CAP"',
        'systemctl restart "$SIGN"',
        'systemctl restart "$DISC"',
        'systemctl restart "$META"',
        "systemctl restart technocore-safe-agent-lobby-capture",
        "systemctl restart technocore-safe-agent-signer",
        "systemctl restart technocore-safe-agent-discord",
        "systemctl restart technocore-safe-agent-metadata-block",
    ):
        assert forbidden not in text

    for token in (
        "CAPTURE_RESTART=NO",
        "SIGNER_RESTART=NO",
        "DISCORD_RESTART=NO",
        "METADATA_BLOCK_RESTART=NO",
    ):
        assert token in text


def test_prod390v1_never_rolls_repo_back_after_resident_restart() -> None:
    text = _text()

    restart_pos = text.index('systemctl restart "$RES"')
    assert 'git -C "$APP" reset --hard "$PRE"' not in text[restart_pos:]
    assert "REPO_REMAINS_TARGET=YES" in text[restart_pos:]


def test_prod390v1_monitors_core_and_preserves_capture_signer_discord() -> None:
    text = _text()

    for token in (
        "PROD390V1=STOP:core_moved_after_restart",
        "PROD390V1=STOP:capture_changed_after_restart",
        "PROD390V1=STOP:resident_unstable_after_restart",
        "PROD390V1=STOP:final_capture_changed",
        "PROD390V1=STOP:final_signer_changed",
        "PROD390V1=STOP:final_discord_changed",
        "PROD390V1=STOP:final_metadata_block_changed",
        "PROD390V1=STOP:no_observer_progress_after_restart",
        "POST_PROGRESS=",
    ):
        assert token in text


def test_prod390v1_has_no_capture_sqlite_or_technocore_write() -> None:
    text = _text().lower()

    for forbidden in (
        "sqlite3",
        "httpx",
        "client.post(",
        "post_signed(",
        "write_note(",
        "technocore.chat",
        "curl ",
        "wget ",
        "kill -",
        "pkill ",
        "killall ",
        "strace ",
        "gdb ",
    ):
        assert forbidden not in text

    assert "ACTIVE_CAPTURE_SQLITE_QUERY=NO" in _text()
    assert "TECHNOCORE_WRITE=NO" in _text()
    assert "SYNTHETIC_ACTIVITY=NO" in _text()


def test_prod390v1_avoids_full_process_tree_scan_during_recovery() -> None:
    text = _text()

    assert "process_tree()" not in text
    assert 'pathlib.Path("/proc").iterdir()' not in text
    assert "TOP RSS+SWAP" not in text


def test_prod390v1_requires_minimum_memory_before_restart() -> None:
    text = _text()

    assert "MIN_MEM_AVAILABLE_BYTES=$((96 * 1024 * 1024))" in text
    assert "PROD390V1=STOP:mem_too_low_for_restart" in text
    assert "PRESSURE_GUARD_CURRENT=" in text


def test_prod390v1_final_pass_markers() -> None:
    text = _text()

    for token in (
        "APPLICATION_REPO_FAST_FORWARD=YES",
        "RESIDENT_RESTART=YES_EXACTLY_ONCE",
        "=== PROD390V1=PASS ===",
        "DO_NOT_RERUN=YES",
    ):
        assert token in text
