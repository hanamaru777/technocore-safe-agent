from pathlib import Path
import re
import subprocess

HELPER=Path("packaging/oracle/issue542-steady-paging-reattribution-v1.sh")

def src():
    return HELPER.read_text("utf-8")

def test_prod542_pins_current_post538_runtime():
    s=src()
    assert "EXPECTED_HEAD=58943a072eb0d752960e092970f06311344a8996" in s
    assert "RES_PID=2462149" in s
    assert "CAP_PID=2462148" in s
    assert "SIG_PID=2462068" in s
    assert "DIS_PID=2660066" in s
    assert "CORE_E=143" in s and "CORE_M=5652707" in s
    assert "BRIDGE_E=26" in s and "BRIDGE_M=569552" in s

def test_prod542_samples_t0_t30_t60():
    s=src()
    assert "a=sample()" in s
    assert "time.sleep(30)" in s
    assert "b=sample()" in s
    assert "c=sample()" in s

def test_prod542_collects_comparable_process_and_cgroup_metrics():
    s=src()
    for token in (
        "VmRSS:","VmSwap:","/proc/{pid}/stat","/proc/{pid}/io",
        "read_bytes:","write_bytes:","memory.current","memory.swap.current",
        "io.stat","pgmajfault","pswpin","pswpout",
    ):
        assert token in s

def test_prod542_outputs_compact_deltas():
    s=src()
    for token in (
        "SERVICE={name}","majflt_delta:","read_mb:","write_mb:",
        "rss_mb:","swap_mb:","cg_mem_mb:","cg_swap_mb:",
        "HOST=","VMSTAT_DELTA=","CONTINUITY=",
    ):
        assert token in s

def test_prod542_preserves_runtime_and_protected_state():
    s=src()
    for token in (
        "repo_changed_post","resident_changed_post","capture_changed_post",
        "signer_changed_post","discord_changed_post","protected_changed_post",
    ):
        assert token in s

def test_prod542_is_strictly_read_only():
    s=src()
    assert "MUTATION=NONE" in s
    assert "DO_NOT_RERUN=YES" in s
    for pattern in (
        r"\bsystemctl\s+(restart|start|stop|enable|disable|reload|daemon-reload)\b",
        r"\bgit_owner\s+(fetch|merge|pull|checkout|reset|switch)\b",
        r"\bsqlite3\b",r"\bjournalctl\b",r"\bcurl\b",r"\bwget\b",
        r"/cmdline",r"/environ",r"SIGN_SEED",r"OCI_VAULT_SECRET_OCID",
        r"\bkill\b",r"\bpkill\b",
    ):
        assert re.search(pattern,s) is None

def test_prod542_bash_syntax():
    r=subprocess.run(["bash","-n",str(HELPER)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
