"""Synthetic no-host R1016 original writer inventory scope and fail-closed tests."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "packaging/oracle/r1016_writer_inventory_readonly.py"
SPEC = importlib.util.spec_from_file_location("r1016_writer_inventory", SCRIPT)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def test_exact_static_original_19_services_8_timers():
    assert len(m.EXPECTED) == 27
    assert sum(x.endswith(".service") for x in m.EXPECTED) == 19
    assert sum(x.endswith(".timer") for x in m.EXPECTED) == 8
    assert "technocore-safe-agent-lobby-capture.service" in m.EXPECTED
    assert "technocore-safe-agent-resident.service" in m.EXPECTED
    assert "technocore-safe-agent-signer.service" in m.EXPECTED


def test_template_instances_remain_classified_but_unknown_units_do_not():
    assert m.classify("technocore-safe-agent-tclk-accept@stage1.service") == (
        "technocore-safe-agent-tclk-accept@.service")
    assert m.classify("technocore-safe-agent-tclk-reveal@phase-0.service") == (
        "technocore-safe-agent-tclk-reveal@.service")
    assert m.classify("technocore-safe-agent-tclk-accept@bad space.service") is None
    assert m.classify("technocore-safe-agent-shadow-writer.service") is None


def test_live_writer_and_timer_categories_never_claim_quiescence():
    enabled = {"technocore-safe-agent-signer.service": ("enabled",),
               "technocore-safe-agent-precontest-supervisor.timer": ("enabled",),
               "technocore-safe-agent-tclk-accept@.service": ("static",),
               "technocore-safe-agent-shadow-writer.service": ("enabled",)}
    running = {"technocore-safe-agent-signer.service": (
        "loaded", "active", "running"),
        "technocore-safe-agent-tclk-accept@stage1.service": (
            "loaded", "active", "exited")}
    r = m.analyze_units(enabled, running)
    assert r["active_signer_candidate_rows"] == 2
    assert r["active_known_rows"] == 2
    assert r["enabled_timer_rows"] == 1
    assert r["unknown_flop_unit_rows"] == 1
    assert r["missing_static_templates"] > 0


def test_parse_systemd_visible_state_and_fail_closed_on_duplicates():
    units = m.metadata_names(
        "technocore-safe-agent-signer.service loaded active running text\n"
        "● technocore-safe-agent-lobby-capture.service loaded inactive dead text\n",
        active=True)
    assert units["technocore-safe-agent-signer.service"] == (
        "loaded", "active", "running")
    assert units["technocore-safe-agent-lobby-capture.service"][1] == "inactive"
    with pytest.raises(m.Stop, match="DUPLICATE_UNIT_ROW_STOP"):
        m.metadata_names("x.service enabled\nx.service disabled\n")


def test_guest_pin_mismatch_fails_before_scanning(monkeypatch, tmp_path):
    source = tmp_path / "source"
    state = tmp_path / "state"
    source.mkdir()
    state.mkdir()
    monkeypatch.setattr(m, "ROOT", source)
    monkeypatch.setattr(m, "STATE", state)
    monkeypatch.setattr(m.sys, "platform", "linux")
    monkeypatch.setattr(m.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(m, "read_command", lambda args, stage: "changed-head")
    with pytest.raises(m.Stop, match="ORIGINAL_HEAD_MISMATCH_STOP"):
        m.guest_preflight()


@pytest.mark.parametrize(("stage", "cause", "expected"), (
    ("HEAD", "timeout", "READONLY_HEAD_TIMEOUT_STOP"),
    ("HEAD", "nonzero", "READONLY_HEAD_EXIT_STOP"),
    ("UNIT_FILES", "os_error", "READONLY_UNIT_FILES_EXEC_STOP"),
    ("UNIT_FILES", "too_big", "READONLY_UNIT_FILES_OUTPUT_BOUND_STOP"),
    ("LIVE_UNITS", "timeout", "READONLY_LIVE_UNITS_TIMEOUT_STOP"),
    ("LIVE_UNITS", "nonzero", "READONLY_LIVE_UNITS_EXIT_STOP"),
))
def test_readonly_guest_command_failure_has_safe_stage_code(
        monkeypatch, stage, cause, expected):
    def simulated_run(args, **kwargs):
        if cause == "timeout":
            raise m.subprocess.TimeoutExpired(cmd=args, timeout=10)
        if cause == "os_error":
            raise OSError("sensitive-data-must-not-be-output")
        if cause == "nonzero":
            return SimpleNamespace(returncode=1, stdout="sensitive-result")
        return SimpleNamespace(returncode=0, stdout="x" * 512001)
    monkeypatch.setattr(m.subprocess, "run", simulated_run)
    with pytest.raises(m.Stop, match=expected) as error:
        m.read_command(("synthetic-readonly-only",), stage=stage)
    assert "sensitive" not in str(error.value)


def test_invalid_readonly_stage_rejected_without_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected execution")
    monkeypatch.setattr(m.subprocess, "run", forbidden)
    with pytest.raises(m.Stop, match="READONLY_STAGE_INVALID_STOP"):
        m.read_command(("ignored",), stage="UNTRUSTED")


def test_proc_metadata_counts_manual_processes_without_printing_arguments(tmp_path):
    proc = tmp_path / "proc"
    proc.mkdir()
    for n, cmd, cg in [
        ("10", b"python\x00-m\x00flop_agent.oracle_signer", b"0::/system.slice/technocore-safe-agent-signer.service"),
        ("20", b"python\x00-m\x00flop_agent.other", b"0::/user.slice/user-1.scope"),
        ("30", b"python\x00-m\x00unrelated", b"0::/user.slice"),
    ]:
        p = proc / n
        p.mkdir()
        (p / "cmdline").write_bytes(cmd)
        (p / "cgroup").write_bytes(cg)
    r = m.process_witness(proc)
    assert r["candidate_flop_processes"] == 2
    assert r["unscoped_or_raced_processes"] == 1
    assert r["oversized_cmdline_processes"] == 0
    assert r["oversized_cgroup_processes"] == 0
    assert r["process_scan_racy"] is True
    assert "flop_agent" not in str(r)


def test_oversized_process_metadata_is_unclassified_without_raw_output(tmp_path):
    proc = tmp_path / "proc"
    proc.mkdir()
    oversized_cmd = proc / "40"
    oversized_cmd.mkdir()
    (oversized_cmd / "cmdline").write_bytes(b"x" * (m.MAX_CMDLINE + 1))
    (oversized_cmd / "cgroup").write_bytes(b"unused")
    oversized_cgroup = proc / "50"
    oversized_cgroup.mkdir()
    (oversized_cgroup / "cmdline").write_bytes(
        b"python\x00-m\x00flop_agent.oracle_signer"
    )
    (oversized_cgroup / "cgroup").write_bytes(b"y" * (m.MAX_CGROUP + 1))

    result = m.process_witness(proc)

    assert result == {
        "candidate_flop_processes": 1,
        "unscoped_or_raced_processes": 2,
        "oversized_cmdline_processes": 1,
        "oversized_cgroup_processes": 1,
        "process_scan_racy": True,
    }
    assert "40" not in str(result)
    assert "50" not in str(result)
    assert "flop_agent" not in str(result)


def test_readonly_no_host_side_effect_primitive_and_no_approval():
    raw = SCRIPT.read_text(encoding="utf-8")
    compile(raw, str(SCRIPT), "exec")
    for denied in ("systemctl stop", "systemctl disable", "systemctl mask",
                   "os.unlink(", "os.remove(", ".write_text(", ".write_bytes(",
                   "SIGN_SEED", "vault_seed(", "sqlite3.connect(", "ssh "):
        assert denied not in raw
    assert "ALL_WRITERS_FENCED=NO" in raw
    assert "SIGNER_INFLIGHT_POST_RESOLVED=NO" in raw
    assert "OCI_RETIREMENT=STRICT_NO_GO" in raw
