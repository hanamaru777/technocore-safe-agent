from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue577-deploy-close1-strategy-v1.sh")

def s():
    return H.read_text("utf-8")

def test_pins_exact_transition():
    x=s()
    assert "OLD=2be06f6aa74f7e1b65032cfa4bfe99c3583e9562" in x
    assert "TARGET=5951d069eb022c25a302363b26494be70ce09f25" in x
    assert 'git_owner merge --ff-only "$TARGET"' in x
    assert "umask 022" in x

def test_only_standalone_timer_is_stopped():
    x=s()
    assert 'systemctl stop "$WATCH_TIMER"' in x
    assert re.search(r'systemctl\s+(restart|stop|start)\s+"?\$(RES|CAP|SIG|DIS)"?',x) is None

def test_waits_for_existing_watcher_oneshot():
    x=s()
    assert 'systemctl is-active "$WATCH_SERVICE"' in x
    assert "watcher_oneshot_still_active" in x

def test_strategy_import_proof_is_explicit():
    x=s()
    assert "base_fee_roundtrip_exit_price" in x
    assert "seen_makers" in x
    assert "one leg per maker" in x
    assert "flat_target_score" in x

def test_runs_one_watcher_and_restores_timer():
    x=s()
    assert 'systemctl start "$WATCH_SERVICE"' in x
    assert 'systemctl start "$WATCH_TIMER"' in x
    assert "ACTIVE_NEW_STRATEGY" in x
    assert "PRESSURE_SKIP_OR_NO_NEW_SWEEP" in x
    assert "RETRYING" in x

def test_old_activation_timer_must_remain_off():
    x=s()
    assert 'systemctl is-enabled "$OLD_TIMER"' in x
    assert 'systemctl is-active "$OLD_TIMER"' in x
    assert "old_activation_timer_enabled" in x
    assert "old_activation_timer_active" in x

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
