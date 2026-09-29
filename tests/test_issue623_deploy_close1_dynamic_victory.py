from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue623-deploy-close1-dynamic-victory-v1.sh")

def s():
    return H.read_text("utf-8")

def test_exact_transition_is_pinned():
    x=s()
    assert "OLD=5ca7e65f2401926be82f8eddbcd9e5610fa1e4e4" in x
    assert "TARGET=bf2be7d8de2dbc6b063d780642f764121deb60a4" in x
    assert 'git_owner merge --ff-only "$TARGET"' in x
    assert "umask 022" in x

def test_semantic_dynamic_victory_verification():
    x=s()
    for token in (
        '"dynamic_victory_price" in names',
        '"dynamic_victory_condition" in names',
        '"dynamic_victory_move_percent" in names',
        'Decimal("106.5")',
        'Decimal("110")',
        'is None',
        '"dynamic_victory"',
        '"shadow leaders"',
        '"future trades"',
        '"clawback"',
        "DYNAMIC_SCAN=",
    ):
        assert token in x

def test_only_standalone_timer_is_stopped():
    x=s()
    assert 'systemctl stop "$WATCH_TIMER"' in x
    assert re.search(r'systemctl\s+(restart|stop|start)\s+"?\$(RES|CAP|SIG|DIS)"?',x) is None

def test_read_only_probe_and_no_sensitive_surface():
    x=s()
    assert "fetch_candidate_scan" in x
    for pat in (r"say-signed",r"post_message",r"SIGN_SEED",r"OCI_VAULT_SECRET_OCID"):
        assert re.search(pat,x,re.I) is None

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

def test_forbidden_diagnostics_absent():
    x=s()
    for pat in (r"sqlite3",r"journalctl",r"/cmdline",r"/environ",r"curl ",r"wget "):
        assert re.search(pat,x,re.I) is None

def test_one_shot_markers():
    x=s()
    assert "PROD623V1=PASS_DYNAMIC_VICTORY_DEPLOYED" in x
    assert "TRADE=NO" in x
    assert "DO_NOT_RERUN=YES" in x

def test_bash_syntax():
    r=subprocess.run(["bash","-n",str(H)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
