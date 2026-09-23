from pathlib import Path
import re


HELPER = Path("packaging/oracle/issue436-prod-resident-pid-drift-diag-v1.sh")


def _source() -> str:
    return HELPER.read_text("utf-8")


def test_issue436_diag_is_strictly_read_only() -> None:
    source = _source()

    assert "EXPECTED_HEAD=576d06dae3550ca7f32b3857d17ff79e911be0d0" in source
    assert "EXPECTED_CORE_EVENTS=120" in source
    assert "EXPECTED_CORE_MESSAGES=5650166" in source

    assert "journalctl" in source
    assert "ExecMainStartTimestamp" in source
    assert "ActiveEnterTimestamp" in source
    assert "StateChangeTimestamp" in source
    assert "airdrop_monitor.monitor_status()" in source
    assert "airdrop_notifier.status()" in source
    assert "PROTECTED_CORE_MATCH" in source
    assert "LOBBY_CURSOR" in source

    forbidden = [
        r"git_owner\s+fetch\b",
        r"git_owner\s+merge\b",
        r"git_owner\s+pull\b",
        r"git_owner\s+checkout\b",
        r"systemctl\s+(?:restart|start|stop|enable|disable|daemon-reload)\b",
        r"\bsqlite3\b",
        r"airdrop_monitor\.run_once",
        r"airdrop_notifier\.run_once",
    ]
    for pattern in forbidden:
        assert re.search(pattern, source) is None

    for marker in (
        "GIT_FETCH_INSIDE_DIAG=NO",
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


def test_issue436_diag_reads_all_runtime_components() -> None:
    source = _source()
    for unit in (
        "technocore-safe-agent-resident.service",
        "technocore-safe-agent-lobby-capture.service",
        "technocore-safe-agent-signer.service",
        "technocore-safe-agent-discord.service",
        "technocore-safe-agent-metadata-block.service",
        "technocore-safe-agent-airdrop-monitor.timer",
        "technocore-safe-agent-airdrop-monitor.service",
        "technocore-safe-agent-airdrop-notifier.timer",
        "technocore-safe-agent-airdrop-notifier.service",
    ):
        assert unit in source
