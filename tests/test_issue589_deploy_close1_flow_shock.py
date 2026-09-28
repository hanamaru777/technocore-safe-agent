from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue589-deploy-close1-flow-shock-v1.sh")

def s():
    return H.read_text("utf-8")

def test_exact_transition():
    x=s()
    assert "OLD=de4c5ca70798b0b85496b300daff4e813421df58" in x
    assert "TARGET=8f747f8f58de09f29d70bcc25d63b7f882a4ccaa" in x
    assert 'git_owner merge --ff-only "$TARGET"' in x
    assert "umask 022" in x

def test_only_standalone_timer_is_stopped():
    x=s()
    assert 'systemctl stop "$WATCH_TIMER"' in x
    assert re.search(r'systemctl\s+(restart|stop|start)\s+"?\$(RES|CAP|SIG|DIS)"?',x) is None

def test_flow_code_and_thresholds_are_verified():
    x=s()
    assert "RecentFlowView" in x
    assert 'FLOW_SHOCK_QTY == Decimal("40")' in x
    assert 'FLOW_SHOCK_IMPROVEMENT == Decimal("20")' in x
    assert "_verified_trade_details" in x
    assert "_recent_flow_views" in x
    assert "_flow_signal" in x

def test_read_only_flow_probe_is_present():
    x=s()
    assert "FLOW_PROBE=" in x
    assert "fetch_candidate_scan" in x
    assert "top_qty=" in x
    assert "trades=" in x

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
    for pat in (
        r"sqlite3",r"journalctl",r"/cmdline",r"/environ",
        r"SIGN_SEED",r"OCI_VAULT_SECRET_OCID",r"say-signed",
        r"post_message",r"curl ",r"wget ",
    ):
        assert re.search(pat,x,re.I) is None

def test_bash_syntax():
    r=subprocess.run(["bash","-n",str(H)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
