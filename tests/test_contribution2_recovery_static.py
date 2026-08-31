from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "recover_field_report_v1_evidence.py"
WRAPPER = ROOT / "packaging" / "oracle" / "recover-field-report-v1-evidence.sh"
UNIT = ROOT / "packaging" / "oracle" / "technocore-safe-agent-contribution2-recovery.service"


def test_recovery_script_has_no_network_write_or_arbitrary_input():
    text = SCRIPT.read_text("utf-8")
    assert "post_signed(" not in text
    assert "httpx.post" not in text
    assert "requests.post" not in text
    assert "fixed-function recovery helper accepts no arguments" in text
    assert "state\") != \"acknowledged\"" in text
    assert "signature_verified" in text
    assert "limitations" in text


def test_recovery_wrapper_freezes_autopilot_and_restores_signer():
    text = WRAPPER.read_text("utf-8")
    assert "autopilot-pause" in text
    assert 's["queued"] == 0' in text
    assert 'systemctl stop "$signer_service"' in text
    assert 'systemctl start "$signer_service"' in text
    assert "autopilot-resume" in text
    assert "publish-field-report" not in text


def test_recovery_unit_keeps_isolated_signer_boundary():
    text = UNIT.read_text("utf-8")
    assert "User=technocore-signer" in text
    assert "SupplementaryGroups=technocore-autopilot" in text
    assert "ProtectSystem=strict" in text
    assert "NoNewPrivileges=true" in text
    assert "recover_field_report_v1_evidence.py" in text
    assert "ReadWritePaths=/var/lib/technocore-safe-agent/contributions /var/lib/technocore-safe-agent/signer/uv-cache" in text
