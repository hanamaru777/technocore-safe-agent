"""R932 fully synthetic read-only metadata tests: never execute on source VM."""
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / (
    "packaging/oracle/r932_readonly_source_metadata_triage.py"
)


def module():
    spec = importlib.util.spec_from_file_location("r932", SCRIPT)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def test_regular_state_metadata_only(tmp_path):
    m = module()
    (tmp_path / "observer").mkdir()
    (tmp_path / "signer").mkdir()
    (tmp_path / "observer" / "synthetic.sqlite3").write_bytes(b"sample" * 2)
    result = m.inspect(tmp_path)
    assert not result["incomplete"]
    assert result["files"] == 1
    assert result["bytes"] == 12
    assert result["groups"]["observer"]["bytes"] == 12
    assert result["stop_reason"] == "none"


def test_symlink_skipped_and_incomplete(tmp_path):
    m = module()
    (tmp_path / "signer").mkdir()
    (tmp_path / "signer" / "testlink").symlink_to("/etc/passwd")
    result = m.inspect(tmp_path)
    assert result["symlinks"] == 1
    assert result["incomplete"]
    assert result["stop_reason"] == "UNCLASSIFIED_ENTRY"


def test_bounded_count_returns_reason_without_crashing(tmp_path):
    m = module()
    (tmp_path / "observer").mkdir()
    for name in ("a", "b"):
        (tmp_path / "observer" / name).write_bytes(b"X")
    result = m.inspect(tmp_path, file_cap=1)
    assert result["incomplete"]
    assert result["stop_reason"] == "FILE_COUNT_LIMIT"


def test_unknown_root_subtree_is_not_scanned(tmp_path):
    m = module()
    (tmp_path / "untrusted").mkdir()
    (tmp_path / "untrusted" / "contents").write_bytes(b"secret")
    result = m.inspect(tmp_path)
    assert result["unknown_top_dirs"] == 1
    assert result["bytes"] == 0
    assert result["incomplete"]


def test_hardlinked_file_skipped(tmp_path):
    import os
    m = module()
    (tmp_path / "autopilot").mkdir()
    first = tmp_path / "autopilot" / "original"
    second = tmp_path / "autopilot" / "link"
    first.write_bytes(b"content")
    os.link(first, second)
    report = m.inspect(tmp_path)
    assert report["incomplete"]
    assert report["bytes"] == 0
    assert report["hardlinks"] >= 1


def test_no_snapshot_backup_sign_or_secret_read_functions():
    source = SCRIPT.read_text(encoding="utf-8")
    compile(source, str(SCRIPT), "exec")
    for marker in (
        "subprocess.Popen", "import requests", "import oci",
        "import sqlite3", "Path.read_bytes", "Path.read_text",
        "systemctl stop", "systemctl start", "os.unlink(",
        "shutil.copy", "open(\"wb\")", "get_secret_bundle",
    ):
        assert marker not in source
    assert "R932_NO_DATA_VALUES_NO_WRITES_NO_SIGN_NO_RETIRE" in source


def test_live_gate_fails_closed_in_unit_test(monkeypatch, capsys):
    m = module()
    monkeypatch.setattr(m.sys, "platform", "linux")
    monkeypatch.setattr(m.os, "geteuid", lambda: 1000)
    with pytest.raises(m.Stop, match="ROOT_REQUIRED"):
        m.main()
