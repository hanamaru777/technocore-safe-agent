"""Pure local source metadata tests; no OCI/SSH/account/DB involved."""
from pathlib import Path
import importlib.util
import os
import stat

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "packaging/archive/oci-source-metadata-stream.py"
spec = importlib.util.spec_from_file_location("r1002", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_traverses_all_regulars_and_symlinks_without_dereference(tmp_path):
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    for name in ("observer", "unknown-a", "unknown-b", "unknown-c", "unknown-d"):
        (root / name).mkdir()
    (root / "observer" / ".resident-heartbeat.json.a.tmp").write_bytes(b"some secret")
    (root / "observer" / "lobby-capture.sqlite3").write_bytes(b"sqlite fake")
    (root / "unknown-a" / "data").write_bytes(b"other private")
    (root / "inside").symlink_to("observer/lobby-capture.sqlite3")
    (root / "outside").symlink_to("/etc/passwd")
    witness = module.scan(root)
    paths = {e["path"] for e in witness["entries"]}
    assert paths >= {"observer/.resident-heartbeat.json.a.tmp", "unknown-a/data",
                     "inside", "outside", "unknown-b", "unknown-c", "unknown-d"}
    assert witness["files"] == 3
    assert witness["symlinks"] == 2
    assert witness["writer_epoch_proven"] is False
    assert witness["sqlite_coherent_backup_proven"] is False
    assert witness["walk_complete"] is True
    assert {e["target"] for e in witness["entries"] if e["type"] == "symlink"} == {
        "observer/lobby-capture.sqlite3", "/etc/passwd"
    }


def test_special_fifo_refused(tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    os.mkfifo(root / "pipe")
    with pytest.raises(module.Stop, match="SPECIAL_FILE_STOP"):
        module.scan(root)


def test_entry_limit_refused_before_silent_omission(tmp_path, monkeypatch):
    root = tmp_path / "state"
    root.mkdir()
    (root / "a").touch()
    (root / "b").touch()
    monkeypatch.setattr(module, "MAX_ITEMS", 1)
    with pytest.raises(module.Stop, match="ENTRY_LIMIT_STOP"):
        module.scan(root)


def test_depth_limit_refused(tmp_path, monkeypatch):
    root = tmp_path / "state"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "c").touch()
    monkeypatch.setattr(module, "MAX_DEPTH", 0)
    with pytest.raises(module.Stop, match="DEPTH_LIMIT_STOP"):
        module.scan(root)


def test_non_dir_root_refused(tmp_path):
    plain = tmp_path / "plain"
    plain.touch()
    with pytest.raises((OSError, module.Stop)):
        module.scan(plain)


def test_no_original_contents_printed_and_no_data_writes():
    raw = SCRIPT.read_text()
    assert "sys.stdout.buffer.write(raw)" in raw
    assert "read_bytes" not in raw
    assert "unlink(" not in raw and "os.remove" not in raw
    assert "GIT_CONFIG_GLOBAL" in raw
    assert "FLOP_STATE_DIR" in raw
    assert "writer_epoch_proven" in raw
    assert "json.dumps" in raw
