from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "packaging" / "oracle"


def text(name: str) -> str:
    return (PKG / name).read_text("utf-8")


def test_stage_unit_is_unprivileged_and_has_no_signer_environment():
    unit = text("technocore-safe-agent-close1-auto-stage.service")
    assert "User=technocore\n" in unit
    assert "Group=technocore-autopilot\n" in unit
    assert "signer.env" not in unit
    assert "technocore-signer" not in unit
    assert "ReadWritePaths=/var/lib/technocore-safe-agent/close1" in unit
    assert "close1_autonomous_stage" in unit


def test_rehearsal_unit_is_unprivileged_and_non_binding():
    unit = text("technocore-safe-agent-close1-auto-rehearsal.service")
    assert "User=technocore\n" in unit
    assert "Group=technocore-autopilot\n" in unit
    assert "signer.env" not in unit
    assert "technocore-signer" not in unit
    assert "close1_autonomous_rehearsal" in unit


def test_stage_timer_targets_two_second_rehearsal_cadence():
    timer = text("technocore-safe-agent-close1-auto-stage.timer")
    assert "OnUnitActiveSec=2s" in timer
    assert "AccuracySec=100ms" in timer
    assert "Persistent=false" in timer


def test_stage_file_is_the_only_path_trigger():
    path = text("technocore-safe-agent-close1-auto-rehearsal.path")
    assert (
        "PathExists=/var/lib/technocore-safe-agent/close1/close1-autonomous-stage.json"
        in path
    )
    assert "technocore-safe-agent-close1-auto-rehearsal.service" in path
