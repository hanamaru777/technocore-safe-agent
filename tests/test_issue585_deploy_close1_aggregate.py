from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue585-deploy-close1-aggregate-v1.sh")

def s():
    return H.read_text("utf-8")

def test_exact_transition():
    x=s()
    assert "OLD=346e6bb3a01bc6554b01fa5e45006b4246678f3f" in x
    assert "TARGET=de4c5ca70798b0b85496b300daff4e813421df58" in x
    assert 'git_owner merge --ff-only "$TARGET"' in x

def test_trade_amount_bound_is_explicitly_preserved():
    x=s()
    assert 'AMOUNT_RE.pattern == r"[0-9]{1,7}' in x
    assert 'AGGREGATE_AMOUNT_RE.pattern == r"[0-9]{1,12}' in x
    assert 'close_call._amount("22388090.22", label="price")' in x

def test_only_watcher_timer_is_stopped():
    x=s()
    assert 'systemctl stop "$WATCH_TIMER"' in x
    assert re.search(r'systemctl\s+(restart|stop|start)\s+"?\$(RES|CAP|SIG|DIS)"?',x) is None

def test_legacy_probe_and_watcher_probe_are_read_only():
    x=s()
    assert "fetch_live_snapshot" in x
    assert 'systemctl start "$WATCH_SERVICE"' in x
    for pat in (r"say-signed",r"post_message",r"SIGN_SEED",r"OCI_VAULT_SECRET_OCID"):
        assert re.search(pat,x,re.I) is None

def test_long_running_services_and_protected_counters_stay_pinned():
    x=s()
    for token in ("RES_PRE","CAP_PRE","SIG_PRE","DIS_PRE"):
        assert x.count(token) >= 3
    assert "CORE_E=143" in x and "CORE_M=5652707" in x
    assert "BRIDGE_E=26" in x and "BRIDGE_M=569552" in x

def test_timer_is_restored_and_old_activation_timer_stays_off():
    x=s()
    assert "restore_timer" in x
    assert 'systemctl start "$WATCH_TIMER"' in x
    assert "old_activation_timer_enabled" in x
    assert "old_activation_timer_active" in x

def test_rollback_restores_source():
    x=s()
    assert 'git_owner reset --hard "$OLD"' in x

def test_forbidden_surfaces_absent():
    x=s()
    for pat in (r"sqlite3",r"journalctl",r"/cmdline",r"/environ",r"curl ",r"wget "):
        assert re.search(pat,x,re.I) is None

def test_bash_syntax():
    r=subprocess.run(["bash","-n",str(H)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
