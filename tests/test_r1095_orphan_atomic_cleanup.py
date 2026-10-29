"""R1095 actual atomic tempfile shape vs protected live and unrecognized tmp."""
from pathlib import Path
import importlib.util
import os
import time
import pytest
SOURCE=Path(__file__).resolve().parents[1]/"packaging/oracle/r1095_orphan_atomic_cleanup.py"
spec=importlib.util.spec_from_file_location("r1095",SOURCE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def test_strict_7day_and_newer_canonical(tmp_path):
    obs=tmp_path/"observer";obs.mkdir()
    canonical=obs/"resident-state.json"
    canonical.write_bytes(b"current")
    before=time.time()
    old=obs/".resident-state.json.abcdefgh.tmp"
    old.write_bytes(b"orphan" * 400)
    oldtime=before-9*86400
    os.utime(old,(oldtime,oldtime))
    # ctime is new on fixture, so FAIL CLOSED even if mtime is old
    stats,eligible=m.candidates(obs,before)
    assert stats["eligible"]==0
    assert stats["matching_tmp"]==1
    assert stats["skipped_tmp"]==1
    assert old.exists()

def test_other_names_never_delete(tmp_path):
    obs=tmp_path/"observer";obs.mkdir()
    (obs/"observer-state.json").write_bytes(b"current")
    unknown=obs/".nonces.json.abcdefgh.tmp"
    unknown.write_bytes(b"protected")
    strange=obs/".observer-state.json.abcdefgh.tmp.backup"
    strange.write_bytes(b"protected")
    stats,eligible=m.candidates(obs,time.time())
    assert not eligible
    assert unknown.read_bytes()==b"protected"
    assert strange.read_bytes()==b"protected"

def test_whitelist_and_no_general_backup_delete():
    assert "resident-state.json" in m.BASES
    assert "observer-state.json" in m.BASES
    assert "autopilot-outbox.json" not in m.BASES
    assert m.TEMP.fullmatch(".observer-state.json.abcdefgh.tmp")
    assert not m.TEMP.fullmatch("observer-state.json.abcdefgh.tmp")
    assert not m.TEMP.fullmatch(".observer-state.json.abcdefgh.tmp/other")

def test_actual_deletion_only_of_stale_exact_atomic_orphan(tmp_path,monkeypatch):
    obs=tmp_path/"observer";obs.mkdir()
    old=obs/".resident-state.json.abcdefgh.tmp"
    old.write_bytes(b"orphan" * 5000)
    time.sleep(0.02)
    canonical=obs/"resident-state.json"
    canonical.write_bytes(b"current" * 100)
    unknown=obs/".untrusted-nonce.json.abcdefgh.tmp"
    unknown.write_bytes(b"protect")
    # Simulate the passage of 8 days without changing real files or root ctime.
    now=time.time()+8*86400
    stats,eligible=m.candidates(obs,now)
    assert stats["eligible"]==1
    assert eligible[0][0]==old.name
    monkeypatch.setattr(m,"no_candidate_handles",lambda _:None)
    deleted,freed=m.apply(obs,eligible,now)
    assert deleted==1 and freed>=0
    assert not old.exists()
    assert canonical.read_bytes()==b"current" * 100
    assert unknown.read_bytes()==b"protect"
