from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue423-prod-discord-cache-rollout-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_prod423_cache_v1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod423_cache_v1_pins_exact_pre_target_core_and_services() -> None:
    text = _text()
    for token in (
        "PRE=077d1e478363751bf5b73d810326f95f3a36b7a3",
        "TARGET=576d06dae3550ca7f32b3857d17ff79e911be0d0",
        "EXPECTED_CORE_EVENTS=120",
        "EXPECTED_CORE_MESSAGES=5650166",
        "EXPECTED_RES_PID=2243415",
        "EXPECTED_RES_RESTARTS=0",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_CAP_RESTARTS=0",
        "EXPECTED_SIGN_PID=1539554",
        "EXPECTED_SIGN_RESTARTS=1",
        "EXPECTED_DISC_PID=1957840",
        "EXPECTED_DISC_RESTARTS=0",
    ):
        assert token in text


def test_prod423_cache_v1_pins_exact_changed_source_blobs() -> None:
    text = _text()
    for token in (
        "PRE_DK=840f3bb30427b358ad7a56ba6738becb7b872e9c",
        "PRE_DR=5e8cb7fc701bdab779431eebc422f6a5159293eb",
        "PRE_OW=bb9f19a0bdbb1cd24bac77360f3b63aae56a2ada",
        "PRE_TW=bc4c2629edd95af73ae7c3d481826a12c1a7163a",
        "TARGET_DK=5e5cf8f72931c351740add75aa1719fd436fa288",
        "TARGET_DR=fcf2a5bb8bedbdef6dc922e9e805e741ee6e9d0f",
        "TARGET_OW=18d70de61c84d0e8b59d0de296d7b65d6d747f32",
        "TARGET_TW=734b60aff2bf2a4e46a025c9e6a9a4aad9e1b714",
    ):
        assert token in text
    assert "chmod 0644" in text
    assert "chmod -R" not in text


def test_prod423_cache_v1_is_exact_ff_only() -> None:
    text = _text()
    for token in (
        'git -C "$APP" fetch --no-tags origin main',
        '[[ "$REMOTE_MAIN" == "$TARGET" ]]',
        'git -C "$APP" merge-base --is-ancestor "$PRE" "$TARGET"',
        'git -C "$APP" merge --ff-only "$TARGET"',
    ):
        assert token in text
    for forbidden in (
        "git reset --hard",
        "git checkout",
        "git rebase",
        "git cherry-pick",
    ):
        assert forbidden not in text


def test_prod423_cache_v1_restarts_only_resident_then_discord() -> None:
    text = _text()
    assert text.index('systemctl restart "$RES"') < text.index('systemctl restart "$DISC"')
    assert 'timeout 120 systemctl restart "$RES"' in text
    assert 'timeout 120 systemctl restart "$DISC"' in text
    for forbidden in (
        'systemctl restart "$CAP"',
        'systemctl restart "$SIGN"',
        'systemctl stop "$RES"',
        'systemctl stop "$DISC"',
        'systemctl stop "$CAP"',
        'systemctl stop "$SIGN"',
        'systemctl start "$CAP"',
        'systemctl start "$SIGN"',
    ):
        assert forbidden not in text
    for token in (
        "RESIDENT_RESTART=EXACTLY_ONCE",
        "DISCORD_RESTART=EXACTLY_ONCE",
        "CAPTURE_RESTART=NO",
        "SIGNER_RESTART=NO",
    ):
        assert token in text


def test_prod423_cache_v1_requires_revision_before_discord_restart() -> None:
    text = _text()
    for token in (
        "--- WAIT FOR NEW OBSERVER HEARTBEAT REVISION ---",
        "OBSERVER_TCLK_REVISION=",
        "tclk_revision_not_emitted",
        '--- RESTART DISCORD ONLY ---',
    ):
        assert token in text
    assert text.index("--- WAIT FOR NEW OBSERVER HEARTBEAT REVISION ---") < text.index("--- RESTART DISCORD ONLY ---")


def test_prod423_cache_v1_warms_up_then_measures_same_baseline_window() -> None:
    text = _text()
    for token in (
        "--- WARMUP 60S ---",
        "sample B0",
        "sample B30",
        "sample B60",
        "MAJFLT=",
        "READ_BYTES=",
        "WRITE_BYTES=",
        "RSS_BYTES=",
        "SWAP_BYTES=",
        "pgmajfault",
        "pswpin",
        "pswpout",
        "TCLK_REVISION=",
        "PSI_IO_",
        "PSI_MEMORY_",
    ):
        assert token in text
    assert text.index("--- WARMUP 60S ---") < text.index("sample B0")
    assert text.index("sample B0") < text.index("sample B30") < text.index("sample B60")


def test_prod423_cache_v1_keeps_continuity_acceptance_strict() -> None:
    text = _text()
    for token in (
        "FINAL_PROTECTED_CORE=",
        "FINAL_LOBBY_CURSOR=",
        "FINAL_OBSERVER_HEARTBEAT_AGE=",
        "FINAL_RESIDENT_HEARTBEAT_AGE=",
        "FINAL_TCLK_REVISION=",
        "FINAL_OBSERVER_UPDATED_MOVED=",
        "FINAL_CURSOR_NONDECREASING=",
        "protected_core_changed",
        "continuity_or_revision_invalid",
        "heartbeat_not_fresh",
        "capture_changed",
        "signer_changed",
    ):
        assert token in text


def test_prod423_cache_v1_import_smoke_checks_new_cache_symbols() -> None:
    text = _text()
    for token in (
        "runuser -u technocore -- env",
        "PYTHONDONTWRITEBYTECODE=1",
        "discord_knowledge._periodic_tclk_state",
        "tclk_watch.tclk_revision",
        "IMPORT_SMOKE=PASS",
    ):
        assert token in text


def test_prod423_cache_v1_has_no_capture_sqlite_or_external_write_surface() -> None:
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


def test_prod423_cache_v1_is_one_shot() -> None:
    assert "DO_NOT_RERUN=YES" in _text()
