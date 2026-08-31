from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = (ROOT / "scripts" / "publish_field_report_v1.py").read_text("utf-8")
WRAPPER = (ROOT / "packaging" / "oracle" / "publish-field-report-v1.sh").read_text("utf-8")


def test_publisher_is_fixed_function_and_non_interactive():
    assert "FIELD_REPORT_TEXT" in PUBLISHER
    assert "https://github.com/hanamaru777/technocore-safe-agent" in PUBLISHER
    assert "argparse" not in PUBLISHER
    assert "input(" not in PUBLISHER
    assert "--text" not in PUBLISHER
    assert "eval(" not in PUBLISHER
    assert "exec(" not in PUBLISHER
    assert "len(sys.argv) != 1" in PUBLISHER


def test_ambiguous_write_is_terminal_and_evidence_is_read_only():
    assert 'receipt["state"] = "ambiguous"' in PUBLISHER
    assert "no retry permitted" in PUBLISHER
    assert '"capture"' in PUBLISHER
    assert '"verify"' in PUBLISHER
    assert "FIELD_REPORT_TEXT" not in WRAPPER
    assert "SIGN_SEED" not in WRAPPER


def test_oracle_wrapper_freezes_queue_before_stopping_signer_and_restores_services():
    pause = WRAPPER.index("autopilot-pause")
    queue_check = WRAPPER.index('s["queued"] == 0')
    stop = WRAPPER.index('systemctl stop "$signer_service"')
    assert pause < queue_check < stop
    assert "trap cleanup EXIT" in WRAPPER
    assert 'systemctl start "$signer_service"' in WRAPPER
    assert "autopilot-resume" in WRAPPER
    assert '. "$signer_env"' in WRAPPER
    assert "echo $OCI_VAULT_SECRET_OCID" not in WRAPPER
