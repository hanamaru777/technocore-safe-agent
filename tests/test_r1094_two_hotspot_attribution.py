"""R1094 read-only 2 known dirs attribution and no mutation test."""
import importlib.util
from pathlib import Path
import time
import pytest
ROOT=Path(__file__).resolve().parents[1]
P=ROOT/"packaging/oracle/r1094_two_hotspot_attribution.py"
spec=importlib.util.spec_from_file_location("r1094",P)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def test_bounded_grouping_real_orphan_shape(tmp_path):
    p=tmp_path/"observer";p.mkdir()
    (p/".observer-state.json.abcdef.tmp").write_bytes(b"x"*11000)
    (p/"lobby-capture-service.sqlite3").write_bytes(b"x"*25000)
    (p/"observer-state.json").write_bytes(b"x"*600)
    outsider=tmp_path/"secret"
    outsider.write_bytes(b"private")
    (p/"link").symlink_to(outsider)
    z=m.scan(p,"observer",time.monotonic(),time.time())
    assert z["objects"]==5 and z["regular_files"]==3
    assert z["categories"]["OBSERVER_ATOMIC_TMP"]["files"]==1
    assert z["categories"]["LIVE_SQLITE"]["files"]==1
    assert z["top"][0]["class"]=="LIVE_SQLITE"
    assert all("path" not in item for item in z["top"])
    assert outsider.read_bytes()==b"private"

def test_5gb_jsonl_must_not_be_assumed_disposable():
    assert m.label("strange-history.jsonl","autopilot")=="OTHER_JSONL"
    assert m.label("autopilot-audit.jsonl","autopilot")=="AUTOPILOT_AUDIT_FAMILY"
    assert m.label("autopilot-audit.jsonl.1","autopilot")=="AUTOPILOT_AUDIT_FAMILY"
    assert m.label("abc.tmp","observer")=="UNCLASSIFIED_TEMP"
    assert m.label(".observer-state.json.random.tmp","observer")=="OBSERVER_ATOMIC_TMP"

def test_bound_and_filename_privacy(tmp_path):
    p=tmp_path/"autopilot";p.mkdir()
    (p/"wallet-private-key.jsonl").write_bytes(b"public")
    f=p/"wallet-private-key.jsonl"
    b=m.file_brief(f,Path(f.name),f.lstat(),"autopilot",time.time())
    assert b["basename"]=="REDACTED"
    assert m.NAME.fullmatch("safe-history.jsonl")
    assert m.PRIVATE.search("wallet-private-key.jsonl")
