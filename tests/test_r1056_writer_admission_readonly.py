"""R1056 only synthetic, no execution on original OCI or K137."""
import ast
import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging/oracle/r1056_writer_admission_readonly.py"
spec = importlib.util.spec_from_file_location("r1056", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def test_unit_file_and_live_unit_names_parse_without_descriptions():
    data = ("technocore-safe-agent-signer.service loaded active running description\n"
            "technocore-safe-agent-tclk-accept@e2e.service loaded active running private\n"
            "technocore-safe-agent-tclk-reveal@.service enabled enabled\n"
            "technocore-safe-agent-tclk-work-watcher.timer enabled enabled\n"
            "sshd.service loaded active running other\n")
    expected = {
        "technocore-safe-agent-signer.service",
        "technocore-safe-agent-tclk-accept@e2e.service",
        "technocore-safe-agent-tclk-reveal@.service",
        "technocore-safe-agent-tclk-work-watcher.timer",
        "sshd.service",
    }
    assert m.unit_tokens(data) == expected


def test_unit_lists_redacted_and_no_global_fence_claim(monkeypatch):
    def read(argv, label):
        if label == "UNITS":
            return ("technocore-safe-agent-tclk-accept@99.service loaded active running\n"
                    "technocore-safe-agent-signer.service loaded active running\n")
        if label == "UNITFILES":
            return ("technocore-safe-agent-tclk-accept@.service enabled enabled\n"
                    "technocore-safe-agent-postreboot-check.service enabled enabled\n")
        pytest.fail("unexpected command")
    monkeypatch.setattr(m, "checked_read", read)
    response = m.unit_census()
    assert response["flop_prefixed_total"] == 4
    assert response["flop_dynamic_instance_or_template_names"] == 2
    assert response["dynamic_or_manual_instance_proven_absent"] == "NO"
    assert response["unit_restart_or_reboot_fence"] == "NOT_PROVEN"


def test_malicious_or_oversized_unit_summary_fail_closed():
    with pytest.raises(m.Stop, match="UNIT_LIST_SIZE_STOP"):
        m.unit_tokens("x" * (m.MAX_UNIT_BYTES + 1))
    assert "surreptitious.service" not in m.unit_tokens("UNTRUSTED BAD INPUT")


def test_cron_matches_only_bytes_without_disclosure():
    data = (b"MAILTO=private@address.test\n"
            b"# /opt/technocore-safe-agent/comment\n"
            b"*/5 * * * * root /opt/technocore-safe-agent/bin/private.sh\n"
            b"@reboot root python -m flop_agent.hidden\n")
    assert m.cron_data(data) == 2
    with pytest.raises(m.Stop, match="CRON_CONTENT_BOUND_STOP"):
        m.cron_data(b"x" * 65537)


@pytest.mark.parametrize(("flags", "expected"), (
    (b"pos:\t0\nflags:\t0100000\n", False),
    (b"pos:\t0\nflags:\t0100001\n", True),
    (b"pos:\t0\nflags:\t0100002\n", True),
    (b"flags:\tnot-octal\n", None),
    (b"irrelevant:\t1\n", None),
))
def test_proc_fdinfo_write_access(flags, expected):
    assert m.write_fd_flags(flags) is expected


def test_proc_census_matching_writer_fd_and_unknown_file(tmp_path):
    proc = tmp_path / "proc"
    proc.mkdir()
    p = proc / "123"
    (p / "fd").mkdir(parents=True)
    (p / "fdinfo").mkdir()
    (p / "cmdline").write_bytes(b"python\0-m\0flop_agent.resident_daemon\0")
    (p / "fd" / "7").symlink_to("/var/lib/technocore-safe-agent/observer/data")
    (p / "fdinfo" / "7").write_bytes(b"flags:\t0100002\n")
    report = m.proc_census(proc)
    assert report["scanned_pids"] == 1
    assert report["flop_commandline_matches"] == 1
    assert report["open_flop_state_write_file_descriptors"] == 1
    assert report["fd_snapshot_is_durable_fence"] == "NO"


def test_readonly_surface_no_mutating_calls():
    tree = ast.parse(SOURCE.read_text(encoding="utf8"))
    prohibited = {"remove", "unlink", "rmtree", "rename", "replace", "mkdir",
                  "write_text", "write_bytes", "chmod", "chown", "kill", "system"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in prohibited
    assert "oci_retirement" in SOURCE.read_text(encoding="utf8")
    assert "STRICT_NO_GO" in SOURCE.read_text(encoding="utf8")
