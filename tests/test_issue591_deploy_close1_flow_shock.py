from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue591-deploy-close1-flow-shock-v1.sh")

def s():
    return H.read_text("utf-8")

def test_exact_transition_is_pinned():
    x=s()
    assert "OLD=de4c5ca70798b0b85496b300daff4e813421df58" in x
    assert "TARGET=8f747f8f58de09f29d70bcc25d63b7f882a4ccaa" in x
    assert 'git_owner merge --ff-only "$TARGET"' in x
    assert "umask 022" in x

def test_only_standalone_timer_is_stopped():
    x=s()
    assert 'systemctl stop "$WATCH_TIMER"' in x
    assert re.search(r'systemctl\s+(restart|stop|start)\s+"?\$(RES|CAP|SIG|DIS)"?',x) is None

def test_flow_feature_is_verified():
    x=s()
    assert '"recent_flows" in scan_fields' in x
    assert "FLOW_SHOCK_QTY == 40" in x
    assert "FLOW_SHOCK_IMPROVEMENT == 20" in x
    assert "_recent_flow_views" in x
    assert "_flow_signal" in x
    assert "last_flow_qty" in x

def test_probe_is_read_only():
    x=s()
    assert "fetch_candidate_scan" in x
    assert "FLOW_SCAN=" in x
    for pat in (r"say-signed",r"post_message",r"SIGN_SEED",r"OCI_VAULT_SECRET_OCID"):
        assert re.search(pat,x,re.I) is None

def test_runs_watcher_and_resumes_timer():
    x=s()
    assert 'systemctl start "$WATCH_SERVICE"' in x
    assert 'systemctl start "$WATCH_TIMER"' in x
    assert "ACTIVE_FLOW_SHOCK" in x

def test_long_running_services_and_protected_counters_are_pinned():
    x=s()
    for token in ("RES_PRE","CAP_PRE","SIG_PRE","DIS_PRE"):
        assert x.count(token) >= 3
    assert "CORE_E=143" in x and "CORE_M=5652707" in x
    assert "BRIDGE_E=26" in x and "BRIDGE_M=569552" in x
    assert x.count("protected_ok") >= 3

def test_rollback_restores_source_and_timer():
    x=s()
    assert 'git_owner reset --hard "$OLD"' in x
    assert "restore_timer" in x

def test_old_activation_timer_stays_off():
    x=s()
    assert "old_activation_timer_enabled" in x
    assert "old_activation_timer_active" in x

def test_forbidden_surfaces_absent():
    x=s()
    for pat in (
        r"sqlite3",r"journalctl",r"/cmdline",r"/environ",
        r"curl ",r"wget ",
    ):
        assert re.search(pat,x,re.I) is None

def test_bash_syntax():
    r=subprocess.run(["bash","-n",str(H)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
