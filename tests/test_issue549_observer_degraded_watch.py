from pathlib import Path
import re
import subprocess

H=Path("packaging/oracle/issue549-observer-degraded-watch-v1.sh")

def s():
    return H.read_text("utf-8")

def test_pins_pre547_no_mutation_state():
    x=s()
    assert "EXPECTED_HEAD=58943a072eb0d752960e092970f06311344a8996" in x
    for token in ("RES_PID=2462149","CAP_PID=2462148","SIG_PID=2462068","DIS_PID=2660066"):
        assert token in x

def test_samples_tiny_heartbeat_for_90_seconds():
    x=s()
    assert "for i in range(7):" in x
    assert "time.sleep(15)" in x
    assert "HEALTH_SEQUENCE=" in x
    assert "heartbeat_age_max_s:" in x

def test_reads_rich_state_only_at_start_and_end():
    x=s()
    assert x.count("state_summary()") == 3
    assert "start=state_summary()" in x
    assert "end=state_summary()" in x
    assert "START_BAD_ROOMS=" in x
    assert "END_BAD_ROOMS=" in x

def test_protected_counts_and_services_are_exact():
    x=s()
    assert "expected=(143,5652707,26,569552)" in x
    for token in ("resident_changed_post","capture_changed_post","signer_changed_post","discord_changed_post"):
        assert token in x

def test_strictly_read_only():
    x=s()
    for pat in (
        r"systemctl\s+(restart|start|stop|enable|disable|reload|daemon-reload)",
        r"git_owner\s+(fetch|merge|pull|checkout|reset|switch)",
        r"\bsqlite3\b",r"journalctl",r"curl ",r"wget ",
        r"/cmdline",r"/environ",r"SIGN_SEED",r"OCI_VAULT_SECRET_OCID",
        r"\bkill\b",r"\bpkill\b",
    ):
        assert re.search(pat,x,re.I) is None
    assert "MUTATION=NONE" in x

def test_bash_syntax():
    r=subprocess.run(["bash","-n",str(H)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
