"""Safety admission and isolation regression tests for the offline capture archiver."""
import importlib.util
from pathlib import Path

import pytest


def _module():
    f = Path(__file__).resolve().parents[1] / "packaging/oracle/retirement-low-io-capture-snapshot.py"
    spec = importlib.util.spec_from_file_location("oci_preliminary_capture", f)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_active_capture_fails_closed(monkeypatch):
    m = _module()
    def snapshot(name):
        if "lobby-capture" in name:
            return {"ActiveState": "active", "SubState": "running", "MainPID": "42"}
        return {"ActiveState": "active", "SubState": "running", "MainPID": "43"}
    monkeypatch.setattr(m, "unit_state", snapshot)
    with pytest.raises(m.Stop, match="CAPTURE_MUST_REMAIN_STOPPED"):
        m.units()


def test_normal_stopped_capture_with_active_other_units_is_observable(monkeypatch):
    m = _module()
    def snapshot(name):
        if "lobby-capture" in name:
            return {"ActiveState": "inactive", "SubState": "dead", "MainPID": "0"}
        return {"ActiveState": "active", "SubState": "running", "MainPID": "43"}
    monkeypatch.setattr(m, "unit_state", snapshot)
    observed = m.units()
    assert observed[0]["ActiveState"] == "inactive"


def test_backup_inputs_are_strictly_limited(tmp_path, monkeypatch):
    m = _module()
    observer = tmp_path / "observer"
    observer.mkdir()
    data = observer / "lobby-capture.sqlite3"
    data.write_bytes(b"x")
    monkeypatch.setattr(m, "ROOT", tmp_path)
    assert m.safe_input("observer/lobby-capture.sqlite3")[1] == 1
    with pytest.raises(m.Stop, match="NOT_A_CAPTURE_DB_STOP"):
        m.safe_input("observer/other.sqlite3")


def test_separate_archive_root_never_uses_live_state_root():
    m = _module()
    assert m.ARCHIVE_ROOT != m.ROOT
    assert m.TEMP.parent == m.ARCHIVE_ROOT
    assert m.DEST.parent == m.ARCHIVE_ROOT
    assert m.BATCH_PAGES < 100
