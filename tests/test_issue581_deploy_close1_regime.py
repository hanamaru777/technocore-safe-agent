from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue581-deploy-close1-regime-v1.sh")

def s():
    return H.read_text("utf-8")

def test_exact_transition_is_pinned():
    x=s()
    assert "OLD=5951d069eb022c25a302363b26494be70ce09f25" in x
    assert "TARGET=346e6bb3a01bc6554b01fa5e45006b4246678f3f" in x
    assert 'git_owner merge --ff-only "$TARGET"' in x
    assert "umask 022" in x

def test_only_standalone_timer_is_stopped():
    x=s()
    assert 'systemctl stop "$WATCH_TIMER"' in x
    assert re.search(r'systemctl\s+(restart|stop|start)\s+"?\$(RES|CAP|SIG|DIS)"?',x) is None

def test_waits_for_active_watcher_oneshot():
    x=s()
    assert 'systemctl is-active "$WATCH_SERVICE"' in x
    assert "watcher_oneshot_still_active" in x

def test_new_read_only_logic_is_verified():
    x=s()
    assert "_latest_common_referee_sweep" in x
    assert "stable_recent_regime" in x
    assert "unstable_recent_score_mark_slope" in x
    assert "close1_snapshot_no_common_sweep" in x

def test_read_only_probes_are_nonfatal_and_no_binding_action():
    x=s()
    assert "LEGACY_PROBE=" in x
    assert "REGIME_PROBE=" in x
    assert "fetch_live_snapshot" in x
    assert "fetch_candidate_scan" in x
    for pat in (r"say-signed",r"post_message",r"maker_signature",r"taker_signature",r"SIGN_SEED"):
        assert re.search(pat,x,re.I) is None

def test_long_running_services_are_pinned():
    x=s()
    for token in ("RES_PRE","CAP_PRE","SIG_PRE","DIS_PRE"):
        assert x.count(token) >= 3
    assert "LONG_RUNNING_SERVICES=UNCHANGED" in x
    assert "LEGACY_DISCORD_PROCESS_RESTARTED=NO" in x

def test_protected_counters_are_pinned():
    x=s()
    assert "CORE_E=143" in x and "CORE_M=5652707" in x
    assert "BRIDGE_E=26" in x and "BRIDGE_M=569552" in x
    assert x.count("protected_ok") >= 3

def test_timer_is_restored_on_success_stop_and_error():
    x=s()
    assert "restore_timer" in x
    assert 'systemctl start "$WATCH_TIMER"' in x
    assert 'git_owner reset --hard "$OLD"' in x

def test_old_activation_timer_stays_off():
    x=s()
    assert "old_activation_timer_enabled" in x
    assert "old_activation_timer_active" in x

def test_forbidden_surfaces_absent():
    x=s()
    for pat in (
        r"sqlite3",r"journalctl",r"/cmdline",r"/environ",
        r"OCI_VAULT_SECRET_OCID",r"curl ",r"wget ",
    ):
        assert re.search(pat,x,re.I) is None

def test_bash_syntax():
    r=subprocess.run(["bash","-n",str(H)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
