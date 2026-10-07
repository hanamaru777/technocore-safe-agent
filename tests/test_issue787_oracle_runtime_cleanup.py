from __future__ import annotations

from pathlib import Path
import subprocess


SCRIPT = Path("packaging/oracle/prune-expired-campaign-runtime.sh")
TEXT = SCRIPT.read_text(encoding="utf-8")


def test_cleanup_has_exact_expired_campaign_allowlist() -> None:
    expected = {
        "technocore-safe-agent-sonnet-invites.service",
        "technocore-safe-agent-sonnet-murphy-invite.service",
        "technocore-safe-agent-sonnet-priority-invites.service",
        "technocore-safe-agent-sonnet-registration.service",
        "technocore-safe-agent-sonnet-team-request.service",
    }
    for unit in expected:
        assert unit in TEXT

    assert "technocore-safe-agent-close1-auto-resident.service" in TEXT


def test_cleanup_protects_current_runtime_and_avoids_evidence_deletion() -> None:
    for unit in (
        "technocore-safe-agent-resident.service",
        "technocore-safe-agent-lobby-capture.service",
        "technocore-safe-agent-signer.service",
        "technocore-safe-agent-discord.service",
    ):
        assert unit in TEXT

    forbidden = (
        "journalctl --vacuum",
        "/var/lib/technocore-safe-agent/observer",
        "lobby-capture-service.sqlite3",
        "technocore-safe-agent-airdrop-monitor",
        "technocore-safe-agent-airdrop-notifier",
        "technocore-safe-agent-tclk-",
        "technocore-safe-agent-precontest-supervisor.timer",
    )
    for token in forbidden:
        assert token not in TEXT


def test_cleanup_has_no_wildcard_systemd_removal() -> None:
    for line in TEXT.splitlines():
        stripped = line.strip()
        if "rm " not in stripped:
            continue
        assert "/etc/systemd/system/technocore-safe-agent-*" not in stripped
        assert "/etc/systemd/system/*" not in stripped


def test_cleanup_requires_apply_and_checks_protected_pid_restart_invariants() -> None:
    assert '"--apply"' in TEXT
    assert "STOP_PROTECTED_BASELINE_INVALID" in TEXT
    assert "STOP_PROTECTED_DRIFT" in TEXT
    assert "PRE_PID" in TEXT
    assert "PRE_RESTARTS" in TEXT
    assert "ORACLE_EXPIRED_CAMPAIGN_CLEANUP=PASS" in TEXT


def test_cleanup_script_is_valid_bash() -> None:
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
