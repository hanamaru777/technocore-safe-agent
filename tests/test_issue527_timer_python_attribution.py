from pathlib import Path
import re
import subprocess

HELPER = Path("packaging/oracle/issue527-timer-python-attribution-v1.sh")


def _source():
    return HELPER.read_text("utf-8")


def test_prod527_pins_current_production_baseline():
    s=_source()
    assert "EXPECTED_HEAD=a4016accdef7b1df591d68d1bcdc54c7a9de7320" in s
    assert "RES_PID=2462149" in s
    assert "CAP_PID=2462148" in s
    assert "SIG_PID=2462068" in s
    assert "DIS_PID=2660066" in s
    assert "CORE_E=143" in s and "CORE_M=5652707" in s
    assert "BRIDGE_E=26" in s and "BRIDGE_M=569552" in s


def test_prod527_samples_python_processes_for_sixty_seconds():
    s=_source()
    assert "SAMPLES=61" in s
    assert "INTERVAL=1.0" in s
    assert 'for idx in range(SAMPLES):' in s
    assert 'time.sleep(INTERVAL)' in s
    assert '{"python","python3","node"}' in s


def test_prod527_maps_processes_by_cgroup_without_cmdline_or_env():
    s=_source()
    assert "/proc/{pid}/cgroup" in s
    assert ".service" in s
    assert ".scope" in s
    assert "/proc/{pid}/comm" in s
    assert "/cmdline" not in s
    assert "/environ" not in s
    assert "ppid" in s
    assert "uid" in s


def test_prod527_reports_transient_peak_and_group_activity():
    s=_source()
    for token in (
        "TRANSIENT_PYTHON_PEAK=",
        "active_samples:",
        "peak_rss_mb:",
        "max_concurrent:",
        "unique_pids:",
        "GROUP_",
        "VMSTAT_DELTA=",
        "PSI=",
    ):
        assert token in s


def test_prod527_excludes_long_running_main_pids_from_transient_peak():
    s=_source()
    assert "LONG_RUNNING=set(map(int,sys.argv[1:5]))" in s
    assert "if pid not in LONG_RUNNING:" in s


def test_prod527_revalidates_services_and_protected_counters():
    s=_source()
    for token in (
        "repo_changed_post",
        "resident_changed_post",
        "capture_changed_post",
        "signer_changed_post",
        "discord_changed_post",
        "protected_changed_post",
    ):
        assert token in s
    assert '[[ "$(counts)" == "$BASE_COUNTS" ]]' in s


def test_prod527_is_strictly_read_only():
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
        r"\bkill\b",
        r"\bpkill\b",
    ):
        assert re.search(pattern,s) is None


def test_prod527_bash_syntax_valid():
    result=subprocess.run(
        ["bash","-n",str(HELPER)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode==0, result.stderr
