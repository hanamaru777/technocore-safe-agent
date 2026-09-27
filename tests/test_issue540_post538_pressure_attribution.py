from pathlib import Path
import re
import subprocess

HELPER=Path("packaging/oracle/issue540-post538-pressure-attribution-v1.sh")
PROBE=Path("packaging/oracle/issue540_pressure_probe.py")

def _helper():
    return HELPER.read_text("utf-8")

def _probe():
    return PROBE.read_text("utf-8")

def test_prod540_pins_post538_baseline():
    s=_helper()
    assert "EXPECTED_HEAD=58943a072eb0d752960e092970f06311344a8996" in s
    assert "RES_PID=2462149" in s and "CAP_PID=2462148" in s
    assert "SIG_PID=2462068" in s and "DIS_PID=2660066" in s
    assert "CORE_E=143" in s and "CORE_M=5652707" in s
    assert "BRIDGE_E=26" in s and "BRIDGE_M=569552" in s

def test_prod540_requires_target_units_loaded_gates_and_timers():
    s=_helper()
    assert 'cmp -s "$APP/packaging/oracle/$unit" "$installed"' in s
    assert "ExecCondition" in s and "tclk_timer_gate" in s
    assert "FragmentPath" in s
    assert "root:root:644" in s
    assert "systemctl is-active --quiet" in s
    assert "systemctl is-enabled" in s

def test_prod540_samples_two_minutes_at_low_frequency():
    s=_probe()
    assert "SAMPLES=61" in s
    assert "INTERVAL=2.0" in s
    assert "time.sleep(INTERVAL)" in s

def test_prod540_measures_restart_gate_and_pressure():
    s=_probe()
    for token in (
        "gate_pass:","max_safe_window_s:","BLOCKERS=",
        "MEM_AVAILABLE_MB=","MEMORY_PSI_FULL=","IO_PSI_FULL=",
        "OBSERVER=","OBSERVER_SAFETY=","VMSTAT_DELTA=",
        "pswpin","pswpout","pgmajfault","pgscan_kswapd","pgsteal_kswapd",
    ):
        assert token in s
    assert 'checks["mem"].append(mem>=256)' in s
    assert 'checks["memory_psi"].append(0 <= mp <= 5.0)' in s
    assert 'checks["io_psi"].append(0 <= ip <= 10.0)' in s

def test_prod540_attributes_tclk_and_residual_runtime_groups():
    s=_probe()
    assert '{"python","python3","node"}' in s
    assert "/proc/{pid}/cgroup" in s
    assert "TRANSIENT_RUNTIME_PEAK_RSS_MB=" in s
    assert "TCLK=" in s
    assert "RESIDUAL_" in s
    assert ".service" in s and ".scope" in s
    assert "/cmdline" not in s and "/environ" not in s

def test_prod540_reports_long_running_cgroups():
    s=_probe()
    assert "/sys/fs/cgroup" in s
    assert "memory.current" in s
    assert "memory.peak" in s
    assert "pids.current" in s
    assert "CGROUP_" in s

def test_prod540_revalidates_postconditions():
    s=_helper()
    for token in (
        "repo_changed_post","resident_changed_post","capture_changed_post",
        "signer_changed_post","discord_changed_post","protected_changed_post",
        "unit_changed_post","loaded_gate_changed_post","timer_changed_post",
        "timer_enablement_changed_post",
    ):
        assert token in s

def test_prod540_is_strictly_read_only():
    s=_helper()+"\n"+_probe()
    assert "MUTATION=NONE" in s and "DO_NOT_RERUN=YES" in s
    for pattern in (
        r"\bsystemctl\s+(restart|start|stop|enable|disable|reload|daemon-reload)\b",
        r"\bgit_owner\s+(fetch|merge|pull|checkout|reset|switch)\b",
        r"\bsqlite3\b",r"\bjournalctl\b",r"\bcurl\b",r"\bwget\b",
        r"SIGN_SEED",r"OCI_VAULT_SECRET_OCID",r"technocore\.chat",
        r"\bkill\b",r"\bpkill\b",
    ):
        assert re.search(pattern,s) is None

def test_prod540_bash_syntax_valid():
    r=subprocess.run(["bash","-n",str(HELPER)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr

def test_prod540_probe_compiles():
    r=subprocess.run(["python","-m","py_compile",str(PROBE)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
