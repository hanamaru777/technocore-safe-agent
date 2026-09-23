from pathlib import Path
import re


HELPER = Path("packaging/oracle/issue438-prod-campaign-readiness-rollout-v2.sh")


def _source() -> str:
    return HELPER.read_text("utf-8")


def test_issue438_rollout_uses_dynamic_stable_service_baseline() -> None:
    source = _source()

    assert "PRE=576d06dae3550ca7f32b3857d17ff79e911be0d0" in source
    assert "TARGET=d8a9c2a43e1ba85f57e057ebf06a2a20da51bb20" in source
    assert "EXPECTED_CORE_EVENTS=120" in source
    assert "EXPECTED_CORE_MESSAGES=5650166" in source
    assert "MIN_SERVICE_AGE_SECONDS=300" in source

    assert "service_snapshot()" in source
    assert "ExecMainStartTimestampMonotonic" in source
    assert "age_s=$(( UPTIME_SECONDS - (start_us / 1000000) ))" in source
    assert "(( age_s >= MIN_SERVICE_AGE_SECONDS ))" in source

    # The post-check must compare immutable service identity only. The moving
    # service age is an entry gate, not part of the equality snapshot.
    assert "printf '%s|%s|%s|%s|%s|%s\\n'" in source
    assert "verify_same_service RESIDENT" in source
    assert "verify_same_service CAPTURE" in source
    assert "verify_same_service SIGNER" in source
    assert "verify_same_service DISCORD" in source


def test_issue438_rollout_is_no_restart_source_only() -> None:
    source = _source()

    expected_paths = (
        "docs/FIELD_REPORT_2026-09-23.md",
        "src/flop_agent/airdrop_challenge.py",
        "tests/test_airdrop_campaign_replay.py",
    )
    for path in expected_paths:
        assert path in source

    assert 'git_owner merge --ff-only "$TARGET"' in source
    assert "target_diff_not_exact" in source
    assert "DEFAULT_ARTIFACT_ATTEMPTS == 3" in source

    forbidden = [
        r"systemctl\s+(?:restart|start|stop|enable|disable|daemon-reload)\b",
        r"\bsqlite3\b",
        r"airdrop_monitor\.run_once",
        r"airdrop_notifier\.run_once",
        r"\bpip\b",
        r"\buv\s+sync\b",
    ]
    for pattern in forbidden:
        assert re.search(pattern, source) is None

    for marker in (
        "PACKAGE_SYNC=NO",
        "SYSTEMD_MUTATION=NO",
        "RUNNING_SERVICE_RESTART=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "SIGNER_ACTION=NO",
        "TECHNOCORE_WRITE=NO",
        "FLOP_WRITE=NO",
        "X_WRITE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert marker in source


def test_issue438_rollout_rechecks_campaign_monitoring_health() -> None:
    source = _source()

    for unit in (
        "technocore-safe-agent-airdrop-monitor.timer",
        "technocore-safe-agent-airdrop-monitor.service",
        "technocore-safe-agent-airdrop-notifier.timer",
        "technocore-safe-agent-airdrop-notifier.service",
    ):
        assert unit in source

    assert "airdrop_monitor.monitor_status()" in source
    assert "airdrop_notifier.status()" in source
    assert "heartbeat_stale" in source
    assert "ledger_integrity_valid" in source
    assert "failure_count" in source
    assert "backoff_active" in source
