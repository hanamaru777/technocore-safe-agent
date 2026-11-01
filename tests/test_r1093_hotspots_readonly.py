"""R1093 bounded metadata hot spot scanner offline test."""
from pathlib import Path
import importlib.util
import os
import time
import pytest

FILE=Path(__file__).resolve().parents[1]/"packaging/oracle/r1093_hotspots_readonly.py"
spec=importlib.util.spec_from_file_location("r1093_hotspots",FILE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def test_two_folder_hotspots_no_content_or_symlinks(tmp_path):
    obs=tmp_path/"observer"
    obs.mkdir()
    (obs/"lobby-capture.sqlite3").write_bytes(b"x"*12000)
    (obs/"autopilot-outbox.json").write_text('{"foo":1}')
    outside=tmp_path/"secret"
    outside.write_bytes(b"must not open")
    (obs/"link").symlink_to(outside)
    out=m.scan(obs,time.monotonic(),time.time())
    assert out["regular_files"]==2
    assert out["symlinks"]==1
    assert out["objects"]==4
    assert out["largest"][0]["kind"]=="CAPTURE_DB"
    assert all("path" not in item and "name" not in item for item in out["largest"])
    assert outside.read_bytes()==b"must not open"

def test_known_but_not_disposable_types():
    assert m.kind("lobby-capture-service.sqlite3-wal") == "SERVICE_WAL"
    assert m.kind("autopilot-outbox.json") == "AUTOPILOT_OUTBOX"
    assert m.kind("garbage.bak") == "BACKUP_CANDIDATE_UNVERIFIED"
    assert m.kind("random") == "OTHER"

def test_count_bound_and_root_guard(tmp_path):
    q=tmp_path/"observer";q.mkdir()
    (q/"somefile").write_text("a")
    with pytest.raises(m.Stop,match="COUNT_BOUND_STOP"):
        m.scan(q,time.monotonic(),time.time(),limit=1)
    assert "/var/lib/technocore-safe-agent/observer" == str(m.ROOTS["observer"])
    assert "/var/lib/technocore-safe-agent/autopilot" == str(m.ROOTS["autopilot"])
