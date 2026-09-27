from pathlib import Path
import re
import subprocess

HELPER = Path("packaging/oracle/issue521-safe-window-attribution-v1.sh")


def _source():
    return HELPER.read_text("utf-8")


def test_prod521_is_read_only_and_pins_consumed_prod519_baseline():
    s = _source()
    assert "EXPECTED_HEAD=a4016accdef7b1df591d68d1bcdc54c7a9de7320" in s
    assert "RES_PID=2462149" in s
    assert "CAP_PID=2462148" in s
    assert "SIG_PID=2462068" in s
    assert "DIS_PID=2560998" in s
    assert "CORE_E=143" in s and "CORE_M=5652707" in s
    assert "BRIDGE_E=26" in s and "BRIDGE_M=569552" in s
    assert "MUTATION=NONE" in s
    assert "DO_NOT_RERUN=YES" in s


def test_prod521_samples_same_safe_window_gates_for_two_minutes():
    s = _source()
    assert "SAMPLES=9" in s
    assert "INTERVAL=15" in s
    assert 'mem < 256' not in s
    assert 'r["mem"]>=256' in s
    assert 'r["mpsi"]<=5.0' in s
    assert 'r["ipsi"]<=10.0' in s
    assert 'r["obs_health"]=="ok"' in s
    assert 'r["safe_health"]=="ok"' in s
    assert 'r["obs_age"] <= 300' in s
    assert 'r["safe_age"] <= 300' in s


def test_prod521_reports_blockers_and_safe_streak():
    s = _source()
    assert 'BLOCKERS=' in s
    assert 'max_safe_streak=' in s
    assert 'max_safe_window_s=' in s
    assert 'MEM_AVAILABLE_MB=' in s
    assert 'MEMORY_PSI_FULL_AVG10=' in s
    assert 'IO_PSI_FULL_AVG10=' in s
    assert 'OBSERVER=' in s
    assert 'OBSERVER_SAFETY=' in s
    assert 'RSS_MB=' in s


def test_prod521_revalidates_source_services_and_protected_counters():
    s = _source()
    for token in (
        "repo_changed_during_sampling",
        "resident_changed_during_sampling",
        "capture_changed_during_sampling",
        "signer_changed_during_sampling",
        "discord_changed_during_sampling",
        "protected_changed_during_sampling",
        "repo_changed_post_sampling",
        "protected_changed_post_sampling",
    ):
        assert token in s
    assert '[[ "$(counts)" == "$BASE_COUNTS" ]]' in s


def test_prod521_has_no_mutation_or_forbidden_observation_surface():
    s = _source()
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
    ):
        assert re.search(pattern, s) is None


def test_prod521_output_is_compact():
    s = _source()
    assert s.count('print("') + s.count("print(f") <= 20


def test_prod521_bash_syntax_is_valid():
    result = subprocess.run(
        ["bash", "-n", str(HELPER)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
