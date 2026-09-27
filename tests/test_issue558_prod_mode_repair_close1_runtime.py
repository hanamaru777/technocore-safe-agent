from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue558-prod-mode-repair-close1-runtime-v1.sh")

def s():
    return H.read_text("utf-8")

def test_pins_current_production_and_uses_safe_umask():
    x=s()
    assert "umask 022" in x
    assert "HEAD_EXPECTED=498d332ff70cc6e5487982e27711097793a16c86" in x
    for token in ("RES_PID=2462149","CAP_PID=2462148","SIG_PID=2462068","DIS_PID=2660066"):
        assert token in x

def test_repairs_only_two_proven_source_modes():
    x=s()
    assert 'chmod 0644 "$CAP_FILE" "$DIS_FILE"' in x
    assert 'capture_mode_not_600' in x
    assert 'discord_mode_not_600' in x
    assert 'observer_mode_changed' in x
    assert 'scanner_mode_changed' in x
    assert x.count("chmod 0644") == 1

def test_root_checks_protected_before_mutation():
    x=s()
    assert "require_protected PRE" in x
    assert x.index("require_protected PRE") < x.index('chmod 0644 "$CAP_FILE" "$DIS_FILE"')
    assert "CORE_E=143" in x and "CORE_M=5652707" in x
    assert "BRIDGE_E=26" in x and "BRIDGE_M=569552" in x

def test_bootstrap_and_technocore_import_precede_capture_restart():
    x=s()
    assert "observer-lobby-prune-cursor-bootstrap.json" in x
    assert "technocore_import_failed" in x
    assert "bootstrap_fallback_mismatch" in x
    assert x.index("technocore_import_failed") < x.index('systemctl restart "$CAP"')
    assert x.index("bootstrap_fallback_mismatch") < x.index('systemctl restart "$CAP"')

def test_restart_order_capture_then_strict_gate_then_discord_only():
    x=s()
    assert x.count('systemctl restart "$CAP"') == 1
    assert x.count('systemctl restart "$DIS"') == 1
    assert re.search(r'systemctl restart "\$(RES|SIG)"',x) is None
    assert x.index('systemctl restart "$CAP"') < x.index('if [[ "$GATE" != PASS ]]')
    assert x.index('if [[ "$GATE" != PASS ]]') < x.index('systemctl restart "$DIS"')
    assert "PASS_CAPTURE_ONLY" in x
    assert "PASS_FULL" in x

def test_strict_gate_is_original_519_threshold():
    x=s()
    assert "for i in range(7):" in x
    assert "time.sleep(10)" in x
    assert 'r["mem"]>=256*1024*1024' in x
    assert 'r["mp"]<=5' in x
    assert 'r["ip"]<=10' in x
    assert 'r["hs"]=="ok"' in x
    assert 'r["ss"]=="ok"' in x

def test_forbidden_surfaces_absent():
    x=s()
    for pat in (
        r"\bsqlite3\b",r"journalctl",r"curl ",r"wget ",r"/cmdline",r"/environ",
        r"SIGN_SEED",r"OCI_VAULT_SECRET_OCID",r"say-signed",r"post_message",
        r"git_owner\s+(fetch|merge|pull|checkout|reset|switch)",
    ):
        assert re.search(pat,x,re.I) is None
    assert "TECHNOCORE_WRITE=NO FLOP_WRITE=NO TRADE=NO" in x

def test_bash_syntax():
    r=subprocess.run(["bash","-n",str(H)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
