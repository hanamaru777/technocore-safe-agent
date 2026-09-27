from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue569-activate-close1-standalone-watch-v1.sh")

def s():
    return H.read_text("utf-8")

def test_pins_exact_source_transition():
    x=s()
    assert "OLD=8a6053326fbd9986a1845ae7e2c0f0deb896af41" in x
    assert "TARGET=2be06f6aa74f7e1b65032cfa4bfe99c3583e9562" in x
    assert "umask 022" in x
    assert 'git_owner merge --ff-only "$TARGET"' in x

def test_old_activation_timer_is_disabled_before_service_snapshot():
    x=s()
    assert 'systemctl disable --now "$OLD_TIMER"' in x
    assert x.index('systemctl disable --now "$OLD_TIMER"') < x.index('RES_PRE=$(require_running resident "$RES")')

def test_installs_only_standalone_units_and_runs_oneshot():
    x=s()
    assert 'install -o root -g root -m 0644 "$SRC_SERVICE" "$DST_SERVICE"' in x
    assert 'install -o root -g root -m 0644 "$SRC_TIMER" "$DST_TIMER"' in x
    assert 'systemctl start "$NEW_SERVICE"' in x
    assert 'systemctl start "$NEW_TIMER"' in x
    assert 'systemctl enable "$NEW_TIMER"' in x

def test_long_running_services_are_never_restarted_or_stopped():
    x=s()
    assert re.search(r'systemctl\s+(restart|stop|start)\s+"?\$(RES|CAP|SIG|DIS)"?',x) is None
    assert '[[ "$(snap "$RES")" == "$RES_PRE" ]]' in x
    assert '[[ "$(snap "$CAP")" == "$CAP_PRE" ]]' in x
    assert '[[ "$(snap "$SIG")" == "$SIG_PRE" ]]' in x
    assert '[[ "$(snap "$DIS")" == "$DIS_PRE" ]]' in x

def test_protected_counters_are_required_before_and_after():
    x=s()
    assert "CORE_E=143" in x and "CORE_M=5652707" in x
    assert "BRIDGE_E=26" in x and "BRIDGE_M=569552" in x
    assert x.count("protected_ok") >= 4

def test_first_run_classifies_active_retrying_or_pressure_skip():
    x=s()
    assert "CLASSIFICATION=ACTIVE" in x
    assert "CLASSIFICATION=INSTALLED_RETRYING" in x
    assert "CLASSIFICATION=PRESSURE_SKIP_OR_NO_STATE" in x
    assert "FIRST_RUN=$CLASSIFICATION" in x

def test_rollback_restores_old_source_and_timer_before_activation():
    x=s()
    assert 'git_owner reset --hard "$OLD"' in x
    assert 'systemctl enable --now "$OLD_TIMER"' in x
    assert 'systemctl disable --now "$NEW_TIMER"' in x

def test_forbidden_surfaces_absent():
    x=s()
    for pat in (
        r"sqlite3",r"journalctl",r"/cmdline",r"/environ",
        r"SIGN_SEED",r"OCI_VAULT_SECRET_OCID",r"say-signed",r"post_message",
        r"curl ",r"wget ",
    ):
        assert re.search(pat,x,re.I) is None

def test_bash_syntax():
    r=subprocess.run(["bash","-n",str(H)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
