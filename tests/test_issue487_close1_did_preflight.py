from pathlib import Path
import re

HELPER=Path("packaging/oracle/issue487-close1-did-preflight-v1.sh")

def _source():
    return HELPER.read_text("utf-8")

def test_pre487_pins_accepted_production_baseline():
    s=_source()
    assert "EXPECTED_HEAD=9baa91be7267b22143c33a06df3c67e1074dba0d" in s
    assert "RES_PID=2462149" in s
    assert "CAP_PID=2462148" in s
    assert "SIG_PID=2462068" in s
    assert "DIS_PID=2462020" in s
    assert "CORE_E=124" in s and "CORE_M=5651120" in s
    assert "BRIDGE_E=7" in s and "BRIDGE_M=567965" in s

def test_pre487_only_reads_public_verified_did_and_renders_registration():
    s=_source()
    assert "verified-did.json" in s
    assert "REGISTRATION_ROOM=close1" in s
    assert "REGISTRATION_TEXT=" in s
    assert "BINDING_ACTION_EXECUTED=NO" in s
    assert "SECRET_OR_VAULT_ACCESS=NO" in s
    assert "season" in s and "close-1" in s and "owner" in s

def test_pre487_is_strictly_read_only_and_compact():
    s=_source()
    assert s.count('echo "') <= 12
    for pattern in (
        r"systemctl\s+(?:restart|start|stop|enable|disable|daemon-reload)\b",
        r"git_owner\s+(?:fetch|merge|pull|checkout|reset)\b",
        r"\bsqlite3\b",
        r"\bjournalctl\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"vault_seed",
        r"with_vault_seed",
        r"post_signed",
        r"invoke_signer",
    ):
        assert re.search(pattern,s) is None
