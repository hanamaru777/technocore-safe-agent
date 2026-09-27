from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue547-prod-capture-tiny-cursor-rollout-v1.sh")

def s():
    return H.read_text("utf-8")

def test_pins_exact_pre_target_and_runtime():
    x=s()
    assert "PRE=58943a072eb0d752960e092970f06311344a8996" in x
    assert "TARGET=81bba50432cdd7d6025787bd4b882d30bb139c4b" in x
    for token in ("RES_PID=2462149","CAP_PID=2462148","SIG_PID=2462068","DIS_PID=2660066","CORE_E=143","BRIDGE_E=26"):
        assert token in x

def test_only_capture_restart_is_authorized():
    x=s()
    assert 'systemctl restart "$CAP"' in x
    assert 'RESTARTS=capture:1 resident:0 signer:0 discord:0' in x
    assert re.search(r'systemctl restart "\$(RES|SIG|DIS)"',x) is None

def test_checks_rolling_upgrade_fallback_before_restart():
    x=s()
    assert "FALLBACK_CURSOR=" in x
    assert "rolling_fallback_cursor_mismatch" in x
    assert "OBSERVER_CURSOR_PREFIX_BYTES == 64 * 1024" in x

def test_warmup_then_60s_measurement():
    x=s()
    assert "sleep 60" in x
    assert "a=sample();time.sleep(30);b=sample();time.sleep(30);c=sample()" in x
    assert "BASELINE_PROD542=capture_majflt:2929 capture_read_mb:109.7" in x

def test_protects_continuity_and_other_services():
    x=s()
    for token in ("resident_changed_post","signer_changed_post","discord_changed_post","capture_changed_post","lobby_cursor_not_advancing"):
        assert token in x
    assert "core:143/5652707 bridge:26/569552" in x

def test_no_forbidden_surfaces():
    x=s()
    for pat in (r"sqlite3",r"journalctl",r"curl ",r"wget ",r"/cmdline",r"/environ",r"SIGN_SEED",r"OCI_VAULT_SECRET_OCID"):
        assert re.search(pat,x,re.I) is None
    assert "ACTIVE_CAPTURE_SQLITE_QUERY=NO" in x
    assert "TECHNOCORE_WRITE=NO FLOP_WRITE=NO TRADE=NO" in x

def test_bash_syntax():
    r=subprocess.run(["bash","-n",str(H)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
