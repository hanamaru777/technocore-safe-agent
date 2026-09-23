from pathlib import Path
import re


HELPER = Path("packaging/oracle/issue431-prod-campaign-readiness-v1.sh")


def _source() -> str:
    return HELPER.read_text("utf-8")


def test_issue431_helper_is_exact_head_no_restart_and_read_only_for_runtime() -> None:
    source = _source()

    assert "PRE=576d06dae3550ca7f32b3857d17ff79e911be0d0" in source
    assert "TARGET=d8a9c2a43e1ba85f57e057ebf06a2a20da51bb20" in source
    assert "EXPECTED_CORE_EVENTS=120" in source
    assert "EXPECTED_CORE_MESSAGES=5650166" in source

    for path in (
        "docs/FIELD_REPORT_2026-09-23.md",
        "src/flop_agent/airdrop_challenge.py",
        "tests/test_airdrop_campaign_replay.py",
    ):
        assert path in source

    assert 'git_owner merge --ff-only "$TARGET"' in source
    assert "target_diff_not_exact" in source
    assert "repo_baseline_changed" in source
    assert "remote_main_moved" in source

    assert "technocore-safe-agent-airdrop-monitor.timer" in source
    assert "technocore-safe-agent-airdrop-notifier.timer" in source
    assert "airdrop_monitor.monitor_status()" in source
    assert "airdrop_notifier.status()" in source
    assert "ledger_integrity_valid" in source
    assert "heartbeat_stale" in source

    forbidden_systemctl_mutations = re.compile(
        r"systemctl\s+(?:restart|start|stop|enable|disable|daemon-reload)\b"
    )
    assert forbidden_systemctl_mutations.search(source) is None

    assert "lobby-capture-service.sqlite3" not in source
    assert "sqlite3" not in source
    assert "airdrop_monitor.run_once" not in source
    assert "airdrop_notifier.run_once" not in source

    assert "RUNNING_SERVICE_RESTART=NO" in source
    assert "SYSTEMD_MUTATION=NO" in source
    assert "ACTIVE_CAPTURE_SQLITE_QUERY=NO" in source
    assert "TECHNOCORE_WRITE=NO" in source
    assert "FLOP_WRITE=NO" in source
    assert "X_WRITE=NO" in source
    assert "DO_NOT_RERUN=YES" in source


def test_issue431_helper_preserves_exact_running_service_baselines() -> None:
    source = _source()
    expected = {
        "EXPECTED_RES_PID=2251452",
        "EXPECTED_RES_NR=0",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_CAP_NR=0",
        "EXPECTED_SIGN_PID=1539554",
        "EXPECTED_SIGN_NR=1",
        "EXPECTED_DISC_PID=2251589",
        "EXPECTED_DISC_NR=0",
    }
    for value in expected:
        assert value in source

    assert 'service_exact RESIDENT "$RES"' in source
    assert 'service_exact CAPTURE "$CAP"' in source
    assert 'service_exact SIGNER "$SIGN"' in source
    assert 'service_exact DISCORD "$DISC"' in source
