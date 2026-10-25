"""R1061 synthetic-only test: partial OCI witness remains explicitly UNKNOWN."""
import ast
import hashlib
import importlib.util
import json
import re
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging/oracle/r1061_partial_writer_witness_readonly.py"
WIN = ROOT / "packaging/windows/r1061_partial_writer_witness_one_shot_readonly.ps1"
spec = importlib.util.spec_from_file_location("flop_r1061", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def test_git_blob_of_python_guest_matches_immutable_windows_guest_pin():
    data = SOURCE.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
    ps = WIN.read_text(encoding="utf8")
    assert f'public const string GuestBlob = "{blob}"' in ps
    assert "8f69c578bd6a8e2de04a9b55cd4d22b05981b8b9/packaging/oracle/r1061_partial_writer_witness_readonly.py" in ps
    assert "r1059_writer_stage_readonly.py" not in ps
    assert "GUEST_UNRECOGNIZED_STOP" in ps


def test_systemctl_nonzero_not_considered_missing_real_units(monkeypatch):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 1, stdout=b"", stderr=b"UNTRUSTED")
    monkeypatch.setattr(m.subprocess, "run", fake_run)
    units, live, files = m.unit_census()
    assert (live, files) == ("NONZERO", "NONZERO")
    assert units["flop_prefixed_total"] == 0
    assert units["unprefixed_unit_exec_targets_proven_exhaustive"] == "NO"
    assert units["unit_restart_or_reboot_fence"] == "NOT_PROVEN"


def test_systemctl_timeout_on_one_command_and_success_on_other(monkeypatch):
    calls = []
    def fake_run(argv, **kwargs):
        calls.append(argv[1])
        if argv[1] == "list-units":
            raise subprocess.TimeoutExpired(argv, 10)
        return subprocess.CompletedProcess(argv, 0,
            stdout=b"technocore-safe-agent-signer.service enabled enabled\n",
            stderr=b"")
    monkeypatch.setattr(m.subprocess, "run", fake_run)
    units, live, files = m.unit_census()
    assert calls == ["list-units", "list-unit-files"]
    assert (live, files) == ("TIMEOUT", "OK")
    assert units["flop_prefixed_total"] == 0  # explicitly UNVERIFIED in carrier


def test_unknown_encoding_and_source_bound_are_safe(monkeypatch):
    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=b"\xff\xfe", stderr=b"")
    monkeypatch.setattr(m.subprocess, "run", fake_run)
    _, live, files = m.unit_census()
    assert (live, files) == ("PARSE", "PARSE")


def test_both_lists_clean_compute_dynamic_templates(monkeypatch):
    def fake_run(argv, **kwargs):
        if argv[1] == "list-units":
            payload = (b"technocore-safe-agent-tclk-accept@case1.service loaded active running\n"
                       b"technocore-safe-agent-signer.service loaded active running\n")
        else:
            payload = (b"technocore-safe-agent-tclk-accept@.service enabled enabled\n"
                       b"technocore-safe-agent-signer.service enabled enabled\n")
        return subprocess.CompletedProcess(argv, 0, stdout=payload, stderr=b"")
    monkeypatch.setattr(m.subprocess, "run", fake_run)
    units, live, files = m.unit_census()
    assert (live, files) == ("OK", "OK")
    assert units["flop_prefixed_total"] == 3
    assert units["flop_dynamic_instance_or_template_names"] == 2


def test_one_failed_census_does_not_hide_other_readonly_evidence(monkeypatch, capsys):
    monkeypatch.setattr(m, "preflight", lambda: None)
    monkeypatch.setattr(m, "unit_census",
        lambda: ({
            "loaded_unit_names": 0, "unitfile_names": 0,
            "flop_prefixed_total": 0,
            "flop_dynamic_instance_or_template_names": 0,
            "dynamic_or_manual_instance_proven_absent": "NO",
            "unprefixed_unit_exec_targets_proven_exhaustive": "NO",
            "unit_restart_or_reboot_fence": "NOT_PROVEN",
        }, "TIMEOUT", "OK"))
    monkeypatch.setattr(m, "cron_census", lambda: {
        "cron_regular_read": 4, "cron_unverified_entries": 1,
        "cron_direct_flop_line_matches": 1,
        "cron_indirect_launch_exhaustively_proven": "NO"})
    def broken_proc():
        raise m.Stop("PRIVATE_UNSAFE_ERROR")
    monkeypatch.setattr(m, "proc_census", broken_proc)
    m.run()
    report = json.loads(capsys.readouterr().out)
    assert report["systemd_loaded_status"] == "TIMEOUT"
    assert report["systemd_unitfiles_status"] == "OK"
    assert report["cron_collection_status"] == "OK"
    assert report["cron"]["cron_direct_flop_line_matches"] == 1
    assert report["proc_collection_status"] == "UNVERIFIED"
    assert report["processes"]["unknown_or_raced_process_fd_objects"] >= 1
    assert report["external_signer_post_resolved"] == "NO"
    assert report["all_writers_fenced"] == "NO"
    assert report["oci_retirement"] == "STRICT_NO_GO"
    assert "PRIVATE_UNSAFE" not in json.dumps(report)


def test_preflight_cannot_be_swallowed(monkeypatch):
    def bad_preflight():
        raise m.Stop("SCOPE_PRIVATE_STOP")
    monkeypatch.setattr(m, "preflight", bad_preflight)
    with pytest.raises(m.Stop):
        m.run()
    assert m.redacted_stop("PREFLIGHT", "SCOPE_PRIVATE_STOP") == "PREFLIGHT_SCOPE_STOP"


def test_no_mutating_original_host_methods_or_new_ssh_paths():
    tree = ast.parse(SOURCE.read_text("utf8"))
    forbidden = {"unlink", "remove", "rename", "replace", "rmtree", "chmod",
                 "chown", "mkdir", "write_text", "write_bytes", "kill", "system"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            assert n.func.attr not in forbidden
    ps = WIN.read_text("utf8")
    for forbidden_cmd in ("systemctl stop", "systemctl start", "systemctl restart",
                          "reboot", "rm -rf", "FLOP_R1061_OCI_RETIREMENT=GO"):
        assert re.search(r"(?<![A-Za-z0-9_])" + re.escape(forbidden_cmd) + r"(?![A-Za-z0-9_])", ps) is None
