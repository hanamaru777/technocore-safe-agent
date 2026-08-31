from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_isolated_launcher_disables_legacy_autopilot_migration():
    text = (ROOT / "scripts" / "publish_field_report_v1_isolated.py").read_text("utf-8")
    assert "autopilot.load(allow_legacy=False)" in text
    assert "observer/autopilot-outbox.json" not in text


def test_contribution_oneshot_has_no_observer_write_access():
    unit = (ROOT / "packaging" / "oracle" / "technocore-safe-agent-contribution2.service").read_text("utf-8")
    assert "User=technocore-signer" in unit
    assert "EnvironmentFile=/etc/technocore-safe-agent/signer.env" in unit
    assert "/var/lib/technocore-safe-agent/observer" not in unit
    assert "ReadWritePaths=/var/lib/technocore-safe-agent/contributions" in unit


def test_v2_wrapper_restores_production_services():
    text = (ROOT / "packaging" / "oracle" / "publish-field-report-v1-v2.sh").read_text("utf-8")
    assert "autopilot-pause" in text
    assert "autopilot-resume" in text
    assert 'systemctl start "$signer_service"' in text
    assert 'systemctl stop "$signer_service"' in text
