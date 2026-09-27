from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue551-prod-capture-safe-window-rollout-v1.sh")

def s():
    return H.read_text("utf-8")

def test_pins_pre_target_and_exact_runtime():
    x=s()
    assert "PRE=58943a072eb0d752960e092970f06311344a8996" in x
    assert "TARGET=81bba50432cdd7d6025787bd4b882d30bb139c4b" in x
    for token in ("RES_PID=2462149","CAP_PID=2462148","SIG_PID=2462068","DIS_PID=2660066","CORE_E=143","CORE_M=5652707","BRIDGE_E=26","BRIDGE_M=569552"):
        assert token in x

def test_waits_for_three_consecutive_safe_samples_before_any_mutation():
    x=s()
    assert "for i in range(13):" in x
    assert "time.sleep(10)" in x
    assert "streak >= 3" in x
    assert 'status=="ok"' in x
    assert "mem >= 128*1024*1024" in x
    assert "mpsi <= 30" in x
    assert "ipsi <= 50" in x
    assert x.index("SAFE_WINDOW=") < x.index("git_owner fetch --no-tags origin main")
    assert x.index("SAFE_WINDOW=") < x.index('git_owner merge --ff-only "$TARGET"')
    assert x.index("SAFE_WINDOW=") < x.index('systemctl restart "$CAP"')

def test_no_safe_window_stops_before_mutation():
    x=s()
    assert '[[ "$WINDOW_RESULT" == PASS ]] || stop_now no_safe_capture_window' in x
    assert x.index("no_safe_capture_window") < x.index("git_owner fetch --no-tags origin main")

def test_rechecks_exact_state_and_floor_before_capture_restart():
    x=s()
    assert "require_state PRE_SAFE" in x
    assert "require_state PRE_RESTART" in x
    assert "host_floor_unsafe" in x
    assert x.index("require_state PRE_RESTART") < x.index('systemctl restart "$CAP"')
    assert x.index("host_floor_unsafe") < x.index('systemctl restart "$CAP"')

def test_only_capture_restart_is_authorized():
    x=s()
    assert 'systemctl restart "$CAP"' in x
    assert 'RESTARTS=capture:1 resident:0 signer:0 discord:0' in x
    assert re.search(r'systemctl restart "\$(RES|SIG|DIS)"',x) is None

def test_rolling_fallback_and_measurement_remain():
    x=s()
    assert "rolling_fallback_cursor_mismatch" in x
    assert "OBSERVER_CURSOR_PREFIX_BYTES == 64 * 1024" in x
    assert "sleep 60" in x
    assert "a=sample();time.sleep(30);b=sample();time.sleep(30);c=sample()" in x
    assert "BASELINE_PROD542=capture_majflt:2929 capture_read_mb:109.7" in x

def test_forbidden_surfaces_absent():
    x=s()
    for pat in (
        r"\bsqlite3\b",r"journalctl",r"curl ",r"wget ",r"/cmdline",r"/environ",
        r"SIGN_SEED",r"OCI_VAULT_SECRET_OCID",r"systemctl\s+restart\s+technocore-safe-agent-(resident|signer|discord)",
    ):
        assert re.search(pat,x,re.I) is None
    assert "ACTIVE_CAPTURE_SQLITE_QUERY=NO" in x
    assert "TECHNOCORE_WRITE=NO FLOP_WRITE=NO TRADE=NO" in x

def test_bash_syntax():
    r=subprocess.run(["bash","-n",str(H)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
