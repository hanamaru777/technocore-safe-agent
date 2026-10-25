"""R1059: static + synthetic redacted one-shot diagnosis, no SSH/cloud."""
import ast
import hashlib
import importlib.util
import re
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
GUEST = ROOT / "packaging/oracle/r1059_writer_stage_readonly.py"
WIN = ROOT / "packaging/windows/r1059_oci_writer_stage_one_shot_readonly.ps1"
spec = importlib.util.spec_from_file_location("flop_r1059_guest", GUEST)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def test_guest_pin_blob_matches_windows_pinned_blob_and_commit():
    raw = GUEST.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    ps = WIN.read_text(encoding="utf8")
    assert f'public const string GuestBlob = "{blob}"' in ps
    assert ("742b81367ff31c20791f89b7b85c5c925a9e24f7/packaging/oracle/"
            "r1059_writer_stage_readonly.py") in ps
    assert "r1056_writer_admission_readonly.py" not in ps
    assert "r1041_signer_unit_cron_readonly.py" not in ps


@pytest.mark.parametrize(("stage","reason","expected"),(
    ("PREFLIGHT", "ORIGINAL_GUEST_PATH_STOP", "PREFLIGHT_SCOPE_STOP"),
    ("PREFLIGHT", "SHARED_K137_HOST_STOP", "PREFLIGHT_SCOPE_STOP"),
    ("PREFLIGHT", "EXACT_ORIGINAL_APP_HEAD_DRIFT_STOP", "PREFLIGHT_HEAD_STOP"),
    ("PREFLIGHT", "HEAD_OUTPUT_STOP", "PREFLIGHT_HEAD_STOP"),
    ("PREFLIGHT", "anything untrusted", "PREFLIGHT_SCOPE_STOP"),
    ("UNITS", "private data", "UNITS_STOP"),
    ("CRON", "private data", "CRON_STOP"),
    ("PROCESS", "private data", "PROCESS_STOP"),
    ("REPORT", "private data", "REPORT_STOP"),
    ("UNKNOWN", "private data", "GUARD_STOP"),
))
def test_fixed_stop_group_never_uses_error_text(stage, reason, expected):
    result = m.redacted_stop(stage, reason)
    assert result == expected
    assert "private" not in result
    assert len(result) < 32


def test_original_scope_and_source_identity_constant_protected():
    assert str(m.APP) == "/opt/technocore-safe-agent"
    assert str(m.STATE) == "/var/lib/technocore-safe-agent"
    assert m.HEAD == "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
    assert m.MAX_SECONDS == 30.0


def test_no_new_migrator_code_or_service_mutations():
    raw = GUEST.read_text("utf8")
    ps = WIN.read_text("utf8")
    tree = ast.parse(raw)
    forbidden = {"unlink", "remove", "rename", "replace", "rmtree", "chmod",
                 "chown", "mkdir", "write_text", "write_bytes", "kill", "system"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            assert n.func.attr not in forbidden
    for phrase in ("systemctl stop", "systemctl start", "systemctl restart",
                   "FLOP_R1059_ALL_WRITERS_FENCED=YES",
                   "FLOP_R1059_OCI_RETIREMENT=GO"):
        assert phrase not in ps
    assert 'return "GUEST_"' not in ps
    assert "FLOP_R1059_STOP=" in ps
    assert "GUEST_UNRECOGNIZED_STOP" in ps
    assert "Get-R1059GuestStop $result.Output" in ps


def test_remote_errors_are_not_leaked_from_exception_handler():
    raw = GUEST.read_text("utf8")
    assert 'redacted_stop(STAGE, str(error))' in raw
    assert 'print("FLOP_R1059_STOP=" + redacted_stop' in raw
    assert "print(str(error))" not in raw
    assert "traceback.print" not in raw
