from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue609-deploy-close1-fallback-compression-v1.sh")

def s():
    return H.read_text("utf-8")

def test_exact_transition_is_pinned():
    x=s()
    assert "OLD=f1a36446e8df82a6c2da6759edafcecf8c6389e8" in x
    assert "TARGET=bfb39f3b6c32600afa2a02f9613bf81b74293f1a" in x
    assert 'git_owner merge --ff-only "$TARGET"' in x
    assert "umask 022" in x

def test_semantic_compression_verification():
    x=s()
    assert 'FALLBACK_COMPRESSION_RATIO == Decimal("0.75")' in x
    assert 'FALLBACK_WORSEN_RATIO == Decimal("1.25")' in x
    assert '"last_fallback_watch_move" in w._default_state()' in x
    assert 'scan("0.131")' in x
    assert 'scan("0.132")' in x

def test_candidate_binding_gate_is_not_mutated_by_carrier():
    x=s()
    assert "CANDIDATE_NEAR" not in x
    assert "CANDIDATE_IMPROVEMENT" not in x
    assert "_candidate_signal" not in x

def test_only_standalone_timer_is_stopped():
    x=s()
    assert 'systemctl stop "$WATCH_TIMER"' in x
    assert re.search(r'systemctl\s+(restart|stop|start)\s+"?\$(RES|CAP|SIG|DIS)"?',x) is None

def test_read_only_probe_and_no_binding_surface():
    x=s()
    assert "fetch_candidate_scan" in x
    assert "COMPRESSION_SCAN=" in x
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

def test_forbidden_surfaces_absent():
    x=s()
    for pat in (r"sqlite3",r"journalctl",r"/cmdline",r"/environ",r"curl ",r"wget "):
        assert re.search(pat,x,re.I) is None

def test_bash_syntax():
    r=subprocess.run(["bash","-n",str(H)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
