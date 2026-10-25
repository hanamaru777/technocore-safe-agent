"""R1062 only OFFLINE synthetic proof of exact writer buckets and NO_GO."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import os
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[1]
GUEST = ROOT / "packaging/oracle/r1062_writer_attribution_readonly.py"
WIN = ROOT / "packaging/windows/r1062_writer_attribution_one_shot_readonly.ps1"
spec = importlib.util.spec_from_file_location("flop_r1062", GUEST)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def test_github_guest_blob_pinned_and_original_oci_identity():
    raw = GUEST.read_bytes()
    expected = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    source = WIN.read_text("utf8")
    assert f'public const string GuestBlob = "{expected}"' in source
    assert "3901f267d5342263b5215764c077978c32244821/packaging/oracle/r1062_writer_attribution_readonly.py" in source
    assert m.HEAD == "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
    assert str(m.STATE) == "/var/lib/technocore-safe-agent"


def test_all_27_sources_four_prior_extra_and_five_signer_routes():
    assert len(m.EXPECTED_UNITS) == 27
    assert len(m.EXTRA_UNITS) == 4
    assert len(m.SIGNER_TEMPLATES) == 5
    assert not (m.EXTRA_UNITS & m.EXPECTED_UNITS)
    names = m.EXPECTED_UNITS | m.EXTRA_UNITS
    r = m.unit_roles(set(names))
    assert r == {
        "expected_template_present": 27,
        "expected_template_missing": 0,
        "historical_extra_present": 4,
        "new_or_unknown_unit_names": 0,
        "dynamic_actual_instances": 0,
        "signer_route_template_present": 5,
    }


def test_actual_template_instance_or_unknown_never_marked_known():
    names = {
        "technocore-safe-agent-signer.service",
        "technocore-safe-agent-tclk-accept@ABC.service",
        "technocore-safe-agent-something-unexpected.timer",
    }
    r = m.unit_roles(names)
    assert r["expected_template_present"] == 1
    assert r["expected_template_missing"] == 26
    assert r["dynamic_actual_instances"] == 1
    assert r["new_or_unknown_unit_names"] == 1


@pytest.mark.parametrize(("path","want"), (
    ("/var/lib/technocore-safe-agent/signer/receipts.json", "SIGNER"),
    ("/var/lib/technocore-safe-agent/autopilot/outbox.json", "SIGNER"),
    ("/var/lib/technocore-safe-agent/nonces.json", "SIGNER"),
    ("/var/lib/technocore-safe-agent/lobby-capture.sqlite3", "CAPTURE"),
    ("/var/lib/technocore-safe-agent/observer/state.json", "CAPTURE"),
    ("/var/lib/technocore-safe-agent/tclk-pilot-stage.json", "TCLK"),
    ("/var/lib/technocore-safe-agent/close1-approved-batch.json", "CLOSE1"),
    ("/var/lib/technocore-safe-agent/random", "OTHER"),
    ("/var/lib/technocore-safe-agent-other/signer/secret", "OTHER"),
))
def test_strict_state_fd_origin_categories(path,want):
    assert m.classify_state_fd_target(path) == want


def test_one_cron_symlink_or_dir_unknown_not_silently_accepted(tmp_path, monkeypatch):
    cron = tmp_path / "cron"
    cron.mkdir()
    real = cron / "task"
    real.write_text("* * * * * root /usr/bin/true\n", encoding="utf8")
    link = cron / "linked"
    link.symlink_to(real)
    (cron / "nested").mkdir()
    monkeypatch.setattr(m, "CRON", (cron,))
    out = m.cron_census()
    assert out["cron_regular_read"] == 1
    assert out["cron_unverified_entries"] == 2
    assert out["cron_unverified_links"] == 1
    assert out["cron_unverified_specials"] == 1
    assert out["cron_unverified_regulars"] == 0
    assert out["cron_direct_flop_line_matches"] == 0
    assert out["cron_indirect_launch_exhaustively_proven"] == "NO"


def test_proc_writable_path_categories_and_fd_race(tmp_path):
    root = tmp_path / "proc"
    (root / "99" / "fd").mkdir(parents=True)
    (root / "99" / "fdinfo").mkdir()
    (root / "99" / "cmdline").write_bytes(b"python\0-m\0flop_agent.oracle_signer\0")
    for leaf, target in (
        ("3", "/var/lib/technocore-safe-agent/signer/receipts.json"),
        ("4", "/var/lib/technocore-safe-agent/lobby-capture.sqlite3"),
        ("5", "/var/lib/technocore-safe-agent/close1-approved-trade.json"),
    ):
        (root / "99" / "fd" / leaf).symlink_to(target)
        if leaf != "5":
            (root / "99" / "fdinfo" / leaf).write_bytes(b"flags:\t0100002\n")
    result = m.proc_census(root)
    assert result["flop_commandline_matches"] == 1
    assert result["open_flop_state_write_file_descriptors"] == 2
    assert result["writable_fd_signer"] == 1
    assert result["writable_fd_capture"] == 1
    assert result["writable_fd_other"] == 0
    assert result["unknown_or_raced_process_fd_objects"] == 1
    assert result["proc_unknown_race"] == 1
    assert result["proc_unknown_permission"] == 0


def test_guest_never_prints_sensitive_did_command_or_writer_path():
    source = GUEST.read_text("utf8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {
                "unlink", "remove", "rename", "replace", "rmtree",
                "chmod", "chown", "mkdir", "write_text", "write_bytes", "kill",
                "system",
            }
    ps = WIN.read_text("utf8")
    assert "OCI_RETIREMENT=GO" not in ps
    assert "FLOP_R1062_ALL_WRITERS_FENCED=NO" in ps
    assert "FLOP_R1062_SIGNER_EXTERNAL_POST_RESOLVED=NO" in ps
    assert "FLOP_R1062_NEW_UNKNOWN_UNITS=" in ps
    assert "FLOP_R1062_CRON_UNKNOWN_SPECIALS=" in ps
    assert "FLOP_R1062_WRITABLE_FD_CAPTURE=" in ps
