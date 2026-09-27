from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue556-prod-capture-close1-runtime-v1.sh")

def s():
    return H.read_text("utf-8")

def test_pins_exact_current_production_and_target():
    x=s()
    assert "PRE=81bba50432cdd7d6025787bd4b882d30bb139c4b" in x
    assert "TARGET=498d332ff70cc6e5487982e27711097793a16c86" in x
    for token in ("RES_PID=2462149","CAP_PID=2462148","SIG_PID=2462068","DIS_PID=2660066","CORE_E=143","CORE_M=5652707","BRIDGE_E=26","BRIDGE_M=569552"):
        assert token in x

def test_bootstrap_cursor_is_written_before_capture_restart():
    x=s()
    assert "observer-lobby-prune-cursor-bootstrap.json" in x
    assert "BOOT_CURSOR=$STATE_CURSOR" in x
    assert "bootstrap_fallback_mismatch" in x
    assert x.index("BOOT_CURSOR=$STATE_CURSOR") < x.index('systemctl restart "$CAP"')
    assert x.index("bootstrap_fallback_mismatch") < x.index('systemctl restart "$CAP"')

def test_capture_restart_is_first_and_discord_restart_is_strictly_gated():
    x=s()
    assert x.count('systemctl restart "$CAP"') == 1
    assert x.count('systemctl restart "$DIS"') == 1
    assert x.index('systemctl restart "$CAP"') < x.index('if [[ "$GATE" != PASS ]]')
    assert x.index('if [[ "$GATE" != PASS ]]') < x.index('systemctl restart "$DIS"')
    assert "PASS_CAPTURE_ONLY" in x
    assert "PASS_FULL" in x

def test_discord_gate_keeps_original_strict_thresholds_for_60s():
    x=s()
    assert "for i in range(7):" in x
    assert "time.sleep(10)" in x
    assert 'r["mem"] >= 256*1024*1024' in x
    assert 'r["mpsi"] <= 5' in x
    assert 'r["ipsi"] <= 10' in x
    assert 'r["hstatus"]=="ok"' in x
    assert 'r["shealth"]=="ok"' in x
    assert "STRICT_GATE=PASS:60s" in x

def test_resident_and_signer_are_never_restarted():
    x=s()
    assert re.search(r'systemctl restart "\$(RES|SIG)"',x) is None
    assert "RESIDENT_RESTART=NO SIGNER_RESTART=NO" in x

def test_expected_source_diff_is_narrow():
    x=s()
    assert "src/flop_agent/close1_discord_progress.py" in x
    assert "src/flop_agent/observer_lobby_capture.py" in x
    assert "tests/test_close1_discord_progress.py" in x
    assert "tests/test_observer_lobby_capture.py" in x
    assert "target_diff_unexpected" in x

def test_forbidden_surfaces_absent():
    x=s()
    for pat in (
        r"\bsqlite3\b",r"journalctl",r"curl ",r"wget ",r"/cmdline",r"/environ",
        r"SIGN_SEED",r"OCI_VAULT_SECRET_OCID",r"say-signed",r"post_message",
    ):
        assert re.search(pat,x,re.I) is None
    assert "TECHNOCORE_WRITE=NO FLOP_WRITE=NO TRADE=NO" in x

def test_bash_syntax():
    r=subprocess.run(["bash","-n",str(H)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
