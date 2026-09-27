from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue560-close1-discord-safe-autostart-v1.sh")

def s():
    return H.read_text("utf-8")

def test_pins_exact_current_production():
    x=s()
    assert "EXPECTED_HEAD=498d332ff70cc6e5487982e27711097793a16c86" in x
    for token in ("RES_PID=2462149","CAP_PID=2708820","SIG_PID=2462068","DIS_PID=2660066"):
        assert token in x

def test_installer_never_restarts_long_running_services():
    x=s()
    outer=x.split("cat >\"$ACTIVATOR\"",1)[0]
    assert re.search(r"systemctl restart",outer) is None

def test_activator_restarts_discord_only_once():
    x=s()
    assert x.count('systemctl restart "$DIS"') == 1
    assert re.search(r'systemctl restart "\$(RES|CAP|SIG)"',x) is None

def test_uses_original_strict_restart_gate():
    x=s()
    assert 'm >= 262144 && mp <= 5 && ip <= 10' in x
    assert 'for i in range(7):' in x
    assert 'time.sleep(10)' in x
    assert 'mem()>=256*1024*1024' in x
    assert 'psi("memory")<=5' in x
    assert 'psi("io")<=10' in x

def test_wait_is_zero_mutation_to_services():
    x=s()
    assert 'CLOSE1_ACTIVATION=WAIT:pressure' in x
    assert 'CLOSE1_ACTIVATION=WAIT:strict_gate' in x
    assert x.index('CLOSE1_ACTIVATION=WAIT:strict_gate') < x.index('systemctl restart "$DIS"')

def test_success_and_block_markers_prevent_repeat():
    x=s()
    assert "close1-discord-runtime-activated.json" in x
    assert "close1-discord-runtime-blocked.json" in x
    assert '[[ ! -e "$MARKER" && ! -e "$BLOCKED" ]] || exit 0' in x

def test_timer_is_five_minutes():
    x=s()
    assert "OnUnitActiveSec=5min" in x
    assert "systemctl enable --now technocore-safe-agent-close1-discord-activation.timer" in x

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
