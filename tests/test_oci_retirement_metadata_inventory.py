"""Offline regression for one-time OCI metadata-only Flop retirement inventory."""
import importlib.util
from pathlib import Path
import os
import stat
from types import SimpleNamespace

import pytest

PATH = Path(__file__).resolve().parents[1] / "packaging/oracle/retirement-metadata-inventory.py"

def module():
    spec = importlib.util.spec_from_file_location("flop_oci_retirement_metadata", PATH)
    out = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(out)
    return out

def test_code_compiles_and_explicit_allowlist():
    compile(PATH.read_text(), str(PATH), "exec")
    m = module()
    assert len(m.UNITS) == 4
    assert all(x.startswith("technocore-safe-agent-") for x in m.UNITS)
    assert len(m.STATE_LEAVES) < 30
    assert len(m.STATE_DIRECTORIES) < 10
    assert m.MAX_RUNTIME_SEC <= 16
    assert len(set(m.STATE_LEAVES)) == len(m.STATE_LEAVES)

def test_only_size_mtime_and_file_category_not_file_content(tmp_path):
    m = module()
    p = tmp_path / "observer"
    p.mkdir()
    leaf = p / "lobby-capture-service.sqlite3"
    leaf.write_bytes(b"very_private_data_should_never_appear")
    meta = m.safe_meta(tmp_path, "observer/lobby-capture-service.sqlite3")
    assert meta.startswith("FILE size=")
    assert "mtime_ns=" in meta
    assert "very_private_data" not in meta
    assert m.safe_meta(tmp_path, "observer/absent.sqlite3") == "ABSENT"
    assert m.safe_meta(tmp_path, "observer") == "DIRECTORY"

def test_symlink_rejected_even_if_it_points_to_real_file(tmp_path):
    m = module()
    (tmp_path / "allowed").symlink_to(tmp_path / "not-present")
    with pytest.raises(m.Stop, match="SYMLINK_PATH_STOP"):
        m.safe_meta(tmp_path, "allowed")
    (tmp_path / "parent").symlink_to("/etc")
    with pytest.raises(m.Stop, match="SYMLINK_PATH_STOP"):
        m.safe_meta(tmp_path, "parent/passwd")

def test_path_traversal_is_rejected(tmp_path):
    m = module()
    for bad in ("../../etc/shadow", "/root/.ssh/id_rsa", "a/../b"):
        with pytest.raises(m.Stop, match="UNSAFE_PATH"):
            m.safe_meta(tmp_path, bad)

def test_systemd_scrubs_arbitrary_unit_output(monkeypatch):
    m = module()
    class P:
        returncode = 0
        stdout = ("LoadState=loaded\nActiveState=active\nSubState=running\n"
                  "UnitFileState=enabled\nMainPID=1234\nNRestarts=0\n")
    monkeypatch.setattr(m.subprocess, "run", lambda *args, **kwargs: P())
    safe = m.systemd(m.UNITS[0])
    assert "MainPID=1234" in safe
    assert "Environment" not in safe
    assert "credentials" not in safe

def test_systemd_rejects_unexpected_untrusted_data(monkeypatch):
    m = module()
    class P:
        returncode = 0
        stdout = ("LoadState=loaded\nActiveState=active;rm\nSubState=running\n"
                  "UnitFileState=enabled\nMainPID=1234\nNRestarts=0\n")
    monkeypatch.setattr(m.subprocess, "run", lambda *args, **kwargs: P())
    with pytest.raises(m.Stop, match="UNIT_VALUE_STOP"):
        m.systemd(m.UNITS[0])

def test_script_never_opens_secret_state_or_network():
    s = PATH.read_text()
    for forbidden in (
        "open(", ".read_bytes(", "sqlite3.connect", "urlopen(",
        "requests.get", "httpx.", "socket.connect", "os.walk", "rglob(",
        "os.scandir", "systemctl start", "systemctl stop", "systemctl restart",
        "systemctl enable", "service restart", "kill(", "unlink(", "rmtree(",
        "copyfile(", "shutil.copy", "chmod(", "chown(", "SIGN_SEED",
        "OCI_VAULT_SECRET_OCID", "EnvironmentFile", ".env", "cat ",
    ):
        assert forbidden not in s
    assert "FLOP_OCI_STATE_CONTENT_NOT_READ_NO_MUTATION_PASS" in s
    assert "FLOP_OCI_RETIREMENT_METADATA_INVENTORY_PASS" in s
