"""R1113: public STOP-code contract; offline static regression only."""
from pathlib import Path

SOURCE=Path(__file__).resolve().parents[1]/"packaging/windows/r1112_original_identity_readonly.ps1"


def test_distinct_local_prompt_stop_codes():
    script=SOURCE.read_text("utf-8")
    assert script.count("$stage='R987_INPUT_HOST_STOP'")==2
    assert script.count("$stage='R987_INPUT_EMPTY_STOP'")==2
    assert "R987_CODE_PROMPT" in script
    assert "R987_INPUT_HOST_STOP','" in script
    assert "'R987_INPUT_EMPTY_STOP'" in script


def test_prompt_error_is_classified_before_remote_stage():
    script=SOURCE.read_text("utf-8")
    assert script.index("$stage='R987_CODE_PROMPT'") < script.index("$stage='LOCAL_ESCROW_DECRYPT'")
    assert script.index("$stage='LOCAL_ESCROW_DECRYPT'") < script.index("$stage='SSH_AND_ORACLE'")
    assert "Remove-R1027Custody" in script
    assert "STRICT_NO_GO" in script
