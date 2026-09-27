from pathlib import Path
import re
import subprocess

HELPER = Path("packaging/oracle/issue525-cgroup-memory-attribution-v1.sh")


def _source():
    return HELPER.read_text("utf-8")


def test_prod525_pins_fresh_production_baseline():
    s=_source()
    assert "EXPECTED_HEAD=a4016accdef7b1df591d68d1bcdc54c7a9de7320" in s
    assert "RES_PID=2462149" in s
    assert "CAP_PID=2462148" in s
    assert "SIG_PID=2462068" in s
    assert "DIS_PID=2660066" in s
    assert "CORE_E=143" in s and "CORE_M=5652707" in s
    assert "BRIDGE_E=26" in s and "BRIDGE_M=569552" in s


def test_prod525_samples_t0_and_t60_only():
    s=_source()
    assert 'sample "$TMPDIR/t0.json"' in s
    assert 'sleep 60' in s
    assert 'sample "$TMPDIR/t60.json"' in s
    assert s.index('sample "$TMPDIR/t0.json"') < s.index('sleep 60') < s.index('sample "$TMPDIR/t60.json"')


def test_prod525_reports_cgroup_memory_and_child_processes():
    s=_source()
    for token in (
        "/proc/{pid}/cgroup",
        "/sys/fs/cgroup",
        "memory.current",
        "memory.peak",
        "pids.current",
        "cgroup.procs",
        "CGROUP_{name.upper()}=",
        "for name in (\"resident\",\"capture\",\"signer\",\"discord\")",
        "rss_sum",
    ):
        assert token in s


def test_prod525_reports_host_memory_pressure_and_swap_activity():
    s=_source()
    for token in (
        "MemAvailable",
        "Cached",
        "SReclaimable",
        "AnonPages",
        "Slab",
        "PageTables",
        "SwapTotal",
        "SwapFree",
        "/proc/pressure/{kind}",
        'psi("memory")',
        'psi("io")',
        "pswpin",
        "pswpout",
        "pgmajfault",
        "pgscan_kswapd",
        "pgsteal_kswapd",
        "VMSTAT_DELTA=",
    ):
        assert token in s


def test_prod525_never_reads_process_cmdline_or_environment():
    s=_source()
    assert "/cmdline" not in s
    assert "/environ" not in s
    assert "/proc/{pid}/comm" in s
    assert "TOP_RSS=" in s
    assert "FLOP_NAMED_PROCS=" in s


def test_prod525_revalidates_services_and_protected_counters():
    s=_source()
    for token in (
        "repo_changed_during_sample",
        "resident_changed_during_sample",
        "capture_changed_during_sample",
        "signer_changed_during_sample",
        "discord_changed_during_sample",
        "protected_changed_during_sample",
    ):
        assert token in s
    assert '[[ "$(counts)" == "$BASE_COUNTS" ]]' in s


def test_prod525_is_strictly_read_only():
    s=_source()
    assert "MUTATION=NONE" in s
    assert "DO_NOT_RERUN=YES" in s
    for pattern in (
        r"\bsystemctl\s+(restart|start|stop|enable|disable|reload|daemon-reload)\b",
        r"\bgit_owner\s+(fetch|merge|pull|checkout|reset|switch)\b",
        r"\bsqlite3\b",
        r"\bjournalctl\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"SIGN_SEED",
        r"OCI_VAULT_SECRET_OCID",
        r"technocore\.chat",
        r"close1_registration_once",
        r"airdrop_monitor\.run_once",
        r"airdrop_notifier\.run_once",
        r"\bkill\b",
        r"\bpkill\b",
    ):
        assert re.search(pattern,s) is None


def test_prod525_bash_syntax_valid():
    result=subprocess.run(
        ["bash","-n",str(HELPER)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode==0, result.stderr
