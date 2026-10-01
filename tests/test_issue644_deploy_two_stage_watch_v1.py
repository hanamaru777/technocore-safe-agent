from pathlib import Path
import re
import subprocess

H = Path("packaging/oracle/issue644-deploy-two-stage-watch-v1.sh")


def s():
    return H.read_text("utf-8")


def test_exact_transition_is_pinned():
    x = s()
    assert "OLD=facf67e8b8565dd311fabcea1920dc14dd2088f0" in x
    assert "TARGET=d6b9d4198f37b66722d42d6f951b35f652e1dfec" in x
    assert "SOURCE_MODE=old_needs_update" in x
    assert "SOURCE_MODE=target_already_present" in x
    assert 'git_owner merge --ff-only "$TARGET"' in x
    assert "umask 022" in x


def test_two_stage_semantic_probe_is_pinned():
    x = s()
    for token in (
        "TWO_STAGE_MAX_EVALS == 16",
        'TWO_STAGE_ALERT == Decimal("0.15")',
        'TWO_STAGE_CRITICAL == Decimal("0.10")',
        'TWO_STAGE_IMPROVEMENT == Decimal("0.02")',
        'TWO_STAGE_CRITICAL_IMPROVEMENT == Decimal("0.005")',
        'assert len(selected) == 16',
        'assert "single:c29" in keys',
        'assert "single:c0" in keys',
        'assert w._two_stage_signal(path("0.15"), w._default_state()) is True',
        'assert w._two_stage_signal(path("0.151"), w._default_state()) is False',
        'current_position="1"',
        'starting_cash="9999"',
    ):
        assert token in x


def test_reconciler_and_fast_planner_guards_remain():
    x = s()
    for token in (
        "SCHEMA_VERSION == 2",
        'scanner_account(flat) == ("10000", "0")',
        "close1_pending_binding_inflight",
        "def tighten(",
        "assert solve(leaders[:1]) is None",
        'result[0] == Decimal("113.50")',
        "ACCOUNT_STATE=",
        "unexpected_account_state_present",
        "reconcile_pending(owner_did=w.OWNER_DID)",
    ):
        assert token in x


def test_only_standalone_timer_is_stopped():
    x = s()
    assert 'systemctl stop "$WATCH_TIMER"' in x
    assert re.search(r'systemctl\s+(restart|stop|start)\s+"?\$(RES|CAP|SIG|DIS)"?', x) is None


def test_read_only_scan_and_no_sensitive_surface():
    x = s()
    assert "fetch_candidate_scan" in x
    assert "_best_two_stage_path" in x
    for pat in (r"say-signed", r"post_message", r"SIGN_SEED", r"OCI_VAULT_SECRET_OCID"):
        assert re.search(pat, x, re.I) is None


def test_long_running_services_and_protected_counters_are_pinned():
    x = s()
    for token in ("RES_PRE", "CAP_PRE", "SIG_PRE", "DIS_PRE"):
        assert x.count(token) >= 3
    assert "CORE_E=143" in x and "CORE_M=5652707" in x
    assert "BRIDGE_E=26" in x and "BRIDGE_M=569552" in x
    assert x.count("protected_ok") >= 3


def test_rollback_restores_old_source_and_timer():
    x = s()
    assert 'git_owner reset --hard "$OLD"' in x
    assert "restore_timer" in x


def test_old_activation_timer_stays_off():
    x = s()
    assert "old_activation_timer_enabled" in x
    assert "old_activation_timer_active" in x


def test_forbidden_diagnostics_absent():
    x = s()
    for pat in (r"sqlite3", r"journalctl", r"/cmdline", r"/environ", r"curl ", r"wget "):
        assert re.search(pat, x, re.I) is None


def test_one_shot_markers_and_state_telemetry():
    x = s()
    assert "PROD644V1=PASS_TWO_STAGE_WATCH_DEPLOYED" in x
    assert "two_stage_key=" in x
    assert "two_stage_move=" in x
    assert "stage1_close=" in x
    assert "stage2_side=" in x
    assert "victory_price=" in x
    assert "TRADE=NO" in x
    assert "DO_NOT_RERUN=YES" in x


def test_bash_syntax():
    r = subprocess.run(["bash", "-n", str(H)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
