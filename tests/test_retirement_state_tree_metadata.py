"""R862 synthetic filesystem metadata-only collector tests, no Production access."""
import importlib.util
import os
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "packaging/oracle/retirement_state_tree_metadata.py"

def module():
    spec = importlib.util.spec_from_file_location("flop_r862", SCRIPT)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

def fixture(tmp_path):
    (tmp_path / "observer").mkdir()
    (tmp_path / "signer").mkdir()
    (tmp_path / "autopilot").mkdir()
    (tmp_path / "close1").mkdir()
    (tmp_path / "observer" / "lobby-capture.sqlite3").write_bytes(b"x" * 25)
    (tmp_path / "signer" / "oracle-signer-receipts.json").write_bytes(b"secret")
    (tmp_path / "close1" / "close1-own-account.json").write_bytes(b"money")
    (tmp_path / "autopilot" / "autopilot-audit.jsonl.1").write_bytes(b"audit")
    return tmp_path

def test_collect_complete_bounded_tree_without_opening_contents(tmp_path, monkeypatch):
    m = module()
    root = fixture(tmp_path)
    original = os.open
    def check_open(path, flags, *args, **kw):
        assert flags & os.O_DIRECTORY, "a regular data file must never open"
        return original(path, flags, *args, **kw)
    monkeypatch.setattr(m.os, "open", check_open)
    files, dirs, total = m.inventory(root)
    assert len(files) == 4 and dirs == 5 and total == 25+6+5+5
    rows = {x["path"]:x for x in files}
    assert "autopilot/autopilot-audit.jsonl.1" in rows
    assert rows["observer/lobby-capture.sqlite3"]["size"] == 25

def test_summary_has_no_filename_or_state_value(tmp_path):
    m = module()
    files, dirs, total = m.inventory(fixture(tmp_path))
    info = m.summary(files, dirs, total)
    assert info["groups"]["signer"] == 1
    assert info["groups"]["close1"] == 1
    assert "money" not in str(info) and "oracle-signer" not in str(info)
    assert len(info["path_size_digest"]) == 64

def test_symlinked_file_and_directory_are_rejected(tmp_path):
    m = module()
    fixture(tmp_path)
    (tmp_path/"signer"/"outside").symlink_to("/etc/passwd")
    with pytest.raises(m.Stop, match="SYMLINK_STOP"):
        m.inventory(tmp_path)
    (tmp_path/"signer"/"outside").unlink()
    (tmp_path/"close1"/"linkdir").symlink_to("/etc")
    with pytest.raises(m.Stop, match="SYMLINK_STOP"):
        m.inventory(tmp_path)

def test_unknown_directory_rejected(tmp_path):
    m = module()
    fixture(tmp_path)
    (tmp_path/"secrets").mkdir()
    with pytest.raises(m.Stop, match="UNEXPECTED_DIRECTORY_STOP"):
        m.inventory(tmp_path)

def test_non_regular_fifo_rejected(tmp_path):
    m = module()
    fixture(tmp_path)
    if not hasattr(os, "mkfifo"):
        pytest.skip("POSIX only")
    os.mkfifo(tmp_path/"observer"/"fifo")
    with pytest.raises(m.Stop, match="NONREGULAR_FILE_STOP"):
        m.inventory(tmp_path)

def test_hardlinks_rejected(tmp_path):
    m = module()
    fixture(tmp_path)
    (tmp_path/"observer"/"lobby-capture.sqlite3-extra").hardlink_to(
        tmp_path/"observer"/"lobby-capture.sqlite3")
    with pytest.raises(m.Stop, match="HARDLINK_STOP"):
        m.inventory(tmp_path)

def test_too_many_files_and_timeout(tmp_path, monkeypatch):
    m = module()
    fixture(tmp_path)
    monkeypatch.setattr(m, "MAX_ITEMS", 1)
    with pytest.raises(m.Stop, match="FILE_COUNT_STOP"):
        m.inventory(tmp_path)
    monkeypatch.setattr(m, "MAX_ITEMS", 512)
    with pytest.raises(m.Stop, match="TIME_BUDGET_STOP"):
        m.inventory(tmp_path, max_seconds=0)

def test_paths_or_file_contents_are_never_echoed_by_public_summary(tmp_path):
    m = module()
    f, d, n = m.inventory(fixture(tmp_path))
    printed = " ".join(str(value) for value in m.summary(f,d,n).values())
    assert "close1-own-account" not in printed
    assert "lobby-capture" not in printed
    assert "secret" not in printed

def test_source_only_directory_descriptors_no_deployment_capability():
    s = SCRIPT.read_text()
    compile(s, str(SCRIPT), "exec")
    assert "os.scandir(fd)" in s
    assert "follow_symlinks=False" in s
    assert "fstat(child)" in s and "O_NOFOLLOW" in s
    for bad in ("read_bytes(", "read_text(", "sqlite3.connect",
                "os.walk(", "glob(", "rglob(", "systemctl", "subprocess",
                "requests", "urlopen(", "os.system(", "write_bytes(",
                "write_text(", "unlink(", "chmod(", "chown(",
                "SIGN_SEED", "OCI_VAULT_SECRET_OCID"):
        assert bad not in s
    assert "FLOP_R862_NO_ARCHIVE_OR_WRITER_EPOCH_PROOF" in s
