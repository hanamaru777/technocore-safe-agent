from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue564-repin-close1-autostart-shadow-main-v1.sh")

def s():
    return H.read_text("utf-8")

def test_pins_old_and_target_heads():
    x=s()
    assert "OLD=498d332ff70cc6e5487982e27711097793a16c86" in x
    assert "TARGET=8a6053326fbd9986a1845ae7e2c0f0deb896af41" in x

def test_stops_if_old_runtime_already_activated_or_blocked():
    x=s()
    assert "old_runtime_already_activated" in x
    assert "activation_already_blocked" in x
    assert x.index("old_runtime_already_activated") < x.index('systemctl disable --now "$TIMER"')
    assert x.index("activation_already_blocked") < x.index('systemctl disable --now "$TIMER"')

def test_only_activation_timer_is_touched():
    x=s()
    assert 'systemctl disable --now "$TIMER"' in x
    assert 'systemctl enable --now "$TIMER"' in x
    assert re.search(r"systemctl\s+(restart|start|stop)\s+\"\$(RES|CAP|SIG|DIS)\"",x) is None

def test_source_update_is_ff_only_and_under_safe_umask():
    x=s()
    assert "umask 022" in x
    assert 'git_owner merge --ff-only "$TARGET"' in x
    assert 'git_owner reset --hard "$OLD"' in x
    assert 'close1_candidate_scanner.py")" == 644' in x

def test_activator_pin_is_exactly_replaced():
    x=s()
    assert 'OLD_LINE="EXPECTED_HEAD=$OLD"' in x
    assert 'TARGET_LINE="EXPECTED_HEAD=$TARGET"' in x
    assert "text.count(old)!=1" in x
    assert "text.replace(old,new,1)" in x

def test_rollback_restores_all_changed_surfaces():
    x=s()
    assert 'cp "$BACKUP" "$ACTIVATOR"' in x
    assert 'git_owner reset --hard "$OLD"' in x
    assert 'systemctl enable --now "$TIMER"' in x
    assert "ROLLBACK=activator:" in x

def test_requires_shadow_scanner_before_reenabling_timer():
    x=s()
    assert '"stable_shadow_leader" in open(scanner.__file__' in x
    assert x.index('"stable_shadow_leader" in open(scanner.__file__') < x.rindex('systemctl enable --now "$TIMER"')

def test_forbidden_surfaces_absent():
    x=s()
    for pat in (
        r"sqlite3",r"journalctl",r"/cmdline",r"/environ",
        r"DISCORD_BOT_TOKEN",r"SIGN_SEED",r"OCI_VAULT_SECRET_OCID",
        r"say-signed",r"post_message",r"curl ",r"wget ",
    ):
        assert re.search(pat,x,re.I) is None

def test_bash_syntax():
    r=subprocess.run(["bash","-n",str(H)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
