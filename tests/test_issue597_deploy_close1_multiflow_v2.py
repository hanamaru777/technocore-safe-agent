from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue597-deploy-close1-multiflow-v2.sh")

def s():
    return H.read_text("utf-8")

def test_exact_transition_is_pinned():
    x=s()
    assert "OLD=8f747f8f58de09f29d70bcc25d63b7f882a4ccaa" in x
    assert "TARGET=2bd368a3a114bf9b0906370150159062ddbe3ace" in x
    assert 'git_owner merge --ff-only "$TARGET"' in x
    assert "umask 022" in x

def test_semantic_verification_replaces_brittle_comment_assertion():
    x=s()
    assert "_flow_alerted_qty" in x
    assert 'migrated == {"did:key:legacy:buy": Decimal("43.21")}' in x
    assert "len(rows) == 3" in x
    assert 'assert [row.qty for row in rows] == [Decimal("40"),Decimal("41"),Decimal("42")]' in x
    assert "leave the active ten-minute window" not in x

def test_only_standalone_timer_is_stopped():
    x=s()
    assert 'systemctl stop "$WATCH_TIMER"' in x
    assert re.search(r'systemctl\s+(restart|stop|start)\s+"?\$(RES|CAP|SIG|DIS)"?',x) is None

def test_read_only_probe_and_no_binding_surface():
    x=s()
    assert "fetch_candidate_scan" in x
    assert "FLOW_SCAN=" in x
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

def test_terminal_results_are_new_carrier_ids():
    x=s()
    assert "PROD597V1=PASS_MULTI_FLOW_DEPLOYED" in x
    assert "PROD597V1=STOP:" in x
    assert "PROD597V1=ERROR:" in x
    assert "PROD595V1" not in x

def test_forbidden_surfaces_absent():
    x=s()
    for pat in (r"sqlite3",r"journalctl",r"/cmdline",r"/environ",r"curl ",r"wget "):
        assert re.search(pat,x,re.I) is None

def test_bash_syntax():
    r=subprocess.run(["bash","-n",str(H)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
