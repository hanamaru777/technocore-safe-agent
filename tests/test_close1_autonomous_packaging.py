from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "packaging" / "oracle"


def text(name: str) -> str:
    return (PKG / name).read_text("utf-8")


def test_single_resident_service_is_unprivileged_and_bounded():
    unit = text("technocore-safe-agent-close1-auto-resident.service")
    assert "Type=simple\n" in unit
    assert "User=technocore\n" in unit
    assert "Group=technocore-autopilot\n" in unit
    assert "signer.env" not in unit
    assert "technocore-signer" not in unit
    assert "close1_autonomous_resident" in unit
    assert "ReadWritePaths=/var/lib/technocore-safe-agent/close1" in unit
    assert "MemoryMax=128M\n" in unit
    assert "TasksMax=32\n" in unit
    assert "Restart=on-failure\n" in unit
    assert "RestartSec=30s\n" in unit


def test_short_interval_spawn_units_are_not_packaged():
    retired = (
        "technocore-safe-agent-close1-auto-stage.service",
        "technocore-safe-agent-close1-auto-stage.timer",
        "technocore-safe-agent-close1-auto-rehearsal.service",
        "technocore-safe-agent-close1-auto-rehearsal.path",
    )
    assert all(not (PKG / name).exists() for name in retired)
