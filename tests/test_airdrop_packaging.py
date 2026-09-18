from __future__ import annotations

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / "packaging" / "oracle"


def _read(name: str) -> str:
    return (ORACLE / name).read_text("utf-8")


def test_airdrop_monitor_unit_is_read_only_network_plus_local_state() -> None:
    unit = _read("airdrop-monitor.service")
    assert "Type=oneshot" in unit
    assert "User=technocore" in unit
    assert "airdrop-monitor-once" in unit
    assert "FLOP_STATE_DIR=/var/lib/technocore-safe-agent" in unit
    assert "ReadWritePaths=/var/lib/technocore-safe-agent" in unit
    assert "EnvironmentFile=" not in unit
    assert "NoNewPrivileges=true" in unit
    assert "CapabilityBoundingSet=" in unit
    assert "ProtectSystem=strict" in unit
    assert "ProtectHome=true" in unit
    assert "IPAddressDeny=169.254.169.254" in unit
    assert "technocore-safe-agent-metadata-block.service" in unit
    assert "signer" not in unit.lower()
    assert "autopilot" not in unit.lower()


def test_airdrop_notifier_unit_reuses_only_public_discord_env() -> None:
    unit = _read("airdrop-notifier.service")
    assert "Type=oneshot" in unit
    assert "User=technocore" in unit
    assert "EnvironmentFile=/etc/technocore-safe-agent/airdrop-notifier.env" in unit
    assert "airdrop-notifier-once" in unit
    assert "ReadWritePaths=/var/lib/technocore-safe-agent" in unit
    assert "NoNewPrivileges=true" in unit
    assert "CapabilityBoundingSet=" in unit
    assert "ProtectSystem=strict" in unit
    assert "ProtectHome=true" in unit
    assert "IPAddressDeny=169.254.169.254" in unit
    assert "signer.env" not in unit
    assert "technocore-safe-agent-signer.service" not in unit
    assert "TECHNOCORE_SIGNING_KEY" not in unit
    assert "DID" not in unit


def test_airdrop_timers_are_bounded_and_separate() -> None:
    monitor = _read("airdrop-monitor.timer")
    notifier = _read("airdrop-notifier.timer")

    assert "OnUnitInactiveSec=15min" in monitor
    assert "RandomizedDelaySec=15s" in monitor
    assert "Unit=technocore-safe-agent-airdrop-monitor.service" in monitor
    assert "WantedBy=timers.target" in monitor

    assert "OnUnitInactiveSec=1min" in notifier
    assert "RandomizedDelaySec=5s" in notifier
    assert "Unit=technocore-safe-agent-airdrop-notifier.service" in notifier
    assert "WantedBy=timers.target" in notifier


def test_airdrop_units_do_not_restart_or_bind_existing_services() -> None:
    combined = "\n".join(
        _read(name)
        for name in (
            "airdrop-monitor.service",
            "airdrop-monitor.timer",
            "airdrop-notifier.service",
            "airdrop-notifier.timer",
        )
    )
    assert "Restart=" not in combined
    assert "ExecStartPre=systemctl" not in combined
    assert "ExecStartPost=systemctl" not in combined
    assert "resident.service" not in combined
    assert "discord.service" not in combined
    assert "signer.service" not in combined
    assert "lobby-capture.service" not in combined


def test_airdrop_production_deploy_helper_shell_syntax() -> None:
    helper = ORACLE / "deploy-airdrop-production-v1.sh"
    subprocess.run(
        ["bash", "-n", str(helper)],
        check=True,
        capture_output=True,
        text=True,
    )


def test_airdrop_production_deploy_is_exact_head_and_core_guarded() -> None:
    helper = _read("deploy-airdrop-production-v1.sh")
    assert "PRE_EXPECTED=b8dc6ef0b1ac689f1c45a0fb1451800c75dd5c1f" in helper
    assert "CORE_EVENTS_EXPECTED=117" in helper
    assert "CORE_MESSAGES_EXPECTED=5083155" in helper
    assert '[[ $REMOTE == "$TARGET" ]]' in helper
    assert 'git merge-base --is-ancestor "$PRE" "$TARGET"' in helper
    assert "changed_file_allowlist_mismatch" in helper
    assert "P0_core_changed_before" in helper
    assert "P0_core_changed_after" in helper
    assert "DO_NOT_RERUN=YES" in helper


def test_airdrop_production_deploy_never_restarts_existing_core_services() -> None:
    helper = _read("deploy-airdrop-production-v1.sh")
    forbidden = (
        "systemctl restart technocore-safe-agent-resident",
        "systemctl restart technocore-safe-agent-lobby-capture",
        "systemctl restart technocore-safe-agent-signer",
        "systemctl restart technocore-safe-agent-discord",
        'systemctl restart "$RESIDENT',
        'systemctl restart "$SIGNER',
        'systemctl restart "$DISCORD',
    )
    for value in forbidden:
        assert value not in helper
    assert "EXISTING_SERVICES_UNCHANGED=YES" in helper
    assert "existing_service_pid_changed" in helper
    assert "existing_service_restarts_changed" in helper


def test_airdrop_production_deploy_uses_dedicated_minimal_discord_env() -> None:
    helper = _read("deploy-airdrop-production-v1.sh")
    assert "NOTIFIER_ENV=/etc/technocore-safe-agent/airdrop-notifier.env" in helper
    assert '{"DISCORD_BOT_TOKEN", "DISCORD_CHANNEL_ID"}' in helper
    assert "DISCORD_ALLOWED_USER_IDS" not in helper
    assert 'install -o root -g root -m 0600 "$ENV_TMP" "$NOTIFIER_ENV"' in helper
    assert "signer.env" not in helper
    assert "TECHNOCORE_SIGNING_KEY" not in helper
    assert "SIGN_SEED" not in helper


def test_airdrop_production_deploy_only_enables_new_timers() -> None:
    helper = _read("deploy-airdrop-production-v1.sh")
    assert 'systemctl enable --now "$MONITOR_TIMER" "$NOTIFIER_TIMER"' in helper
    assert 'systemctl is-active --quiet "$MONITOR_TIMER"' in helper
    assert 'systemctl is-active --quiet "$NOTIFIER_TIMER"' in helper
    assert "airdrop_state_already_exists_review_required" in helper
    assert "airdrop_install_artifact_already_exists" in helper


def test_airdrop_production_deploy_smoke_is_discord_only() -> None:
    helper = _read("deploy-airdrop-production-v1.sh")
    assert '"type": "PRODUCTION_SMOKE_TEST"' in helper
    assert '"source": "local_deploy_helper"' in helper
    assert '"authority": "local_smoke_test"' in helper
    assert "FLOP_EXTERNAL_WRITE=NO" in helper
    assert "DISCORD_SMOKE=DELIVERED" in helper
    assert "technocore.chat" not in helper
    assert "sign.py" not in helper
