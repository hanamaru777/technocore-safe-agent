from __future__ import annotations

from pathlib import Path


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
    assert "EnvironmentFile=/etc/technocore-safe-agent/env" in unit
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
