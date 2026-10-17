"""R963: OFFHOST-only synthetic census vs manifest metadata test cases."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = (Path(__file__).resolve().parents[1] /
          "packaging/archive/verify-flop-source-coverage.py")

def module():
    spec = importlib.util.spec_from_file_location("r963", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def docs(m):
    files = {}
    for name in sorted(m.REQUIRED_STATE | m.DBS):
        files[name] = (102, hashlib.sha256(name.encode()).hexdigest())
    files["airdrop-radar/events.jsonl"] = (
        21, hashlib.sha256(b"nonexistent-synthetic-hash").hexdigest())
    source = {
        "kind": m.SOURCE_KIND, "source_commit": m.SOURCE,
        "scope": "FLOP_STATE_DIR", "walk_complete": True,
        "unknown_roots": [], "symlinks": 0, "special": 0, "hardlinks": 0,
        "file_count": len(files),
        "logical_bytes": sum(size for size, _digest in files.values()),
        "files": [{"path":name,"type":"regular","size":size,"sha256":digest}
                  for name,(size,digest) in sorted(files.items())],
    }
    kept = {name:pair for name,pair in files.items() if name not in m.DBS}
    archive = {
        "kind": m.ARCHIVE_KIND, "schema": 1, "source_commit": m.SOURCE,
        "files": [
            {"path":"state/"+name,"size":size,"sha256":digest}
            for name,(size,digest) in sorted(kept.items())
        ] + [
            {"path":name,"size":333,"sha256":"a"*64}
            for name in sorted(m.CAPTURE_IMAGES)
        ],
    }
    return source,archive

def test_r963_synthetic_pair_consistency_is_only_metadata_not_production():
    m = module()
    s,a = docs(m)
    assert m.check(s,a) == (len(s["files"])-len(m.DBS),2)

@pytest.mark.parametrize("change,stop",(
    ("missing_archive","ORIGINAL_SOURCE_PATH_UNARCHIVED_STOP"),
    ("extra_archive","ARCHIVE_PATH_ABSENT_FROM_SOURCE_STOP"),
    ("wrong_source_bytes","SOURCE_CENSUS_SUMMARY_MISMATCH"),
    ("changed_digest","SOURCE_ARCHIVE_FILE_MISMATCH_STOP"),
    ("no_source_digest","SOURCE_CONTENT_DIGEST_MISSING_STOP"),
    ("unknown_roots","SOURCE_CENSUS_NOT_EXHAUSTIVE_STOP"),
    ("symlink","SOURCE_CENSUS_NOT_EXHAUSTIVE_STOP"),
    ("incomplete","SOURCE_CENSUS_NOT_EXHAUSTIVE_STOP"),
    ("source_missing_db","ORIGINAL_REQUIRED_SOURCE_MISSING_STOP"),
    ("source_duplicate","SOURCE_ENTRY_DUPLICATE_OR_TYPE_STOP"),
    ("archive_sidecar","LIVE_SQLITE_COPY_FORBIDDEN_STOP"),
    ("capture_missing","CAPTURE_IMAGES_MISSING_STOP"),
    ("source_commit","SOURCE_WITNESS_SCHEMA_STOP"),
))
def test_r963_coverage_fail_closed_on_omissions_and_unreviewed_names(change,stop):
    m=module()
    s,a=docs(m)
    if change=="missing_archive":
        a["files"]=[r for r in a["files"]
                    if r["path"]!="state/airdrop-radar/events.jsonl"]
    elif change=="extra_archive":
        a["files"].append({"path":"state/airdrop-radar/phantom.json",
                           "size":1,"sha256":"f"*64})
    elif change=="wrong_source_bytes":
        s["logical_bytes"]+=1
    elif change=="changed_digest":
        next(r for r in a["files"] if r["path"].startswith("state/"))["sha256"]="e"*64
    elif change=="no_source_digest":
        next(r for r in s["files"] if r["path"]=="nonces.json")["sha256"]=None
    elif change=="unknown_roots":
        s["unknown_roots"]=["unreviewed-root"]
    elif change=="symlink":
        s["symlinks"]=19
    elif change=="incomplete":
        s["walk_complete"]=False
    elif change=="source_missing_db":
        s["files"]=[r for r in s["files"]
                    if r["path"]!="observer/lobby-capture.sqlite3"]
        s["file_count"]-=1
        s["logical_bytes"]-=102
    elif change=="source_duplicate":
        s["files"].append(dict(s["files"][0]))
        s["file_count"]+=1
        s["logical_bytes"]+=102
    elif change=="archive_sidecar":
        a["files"].append({"path":"state/observer/lobby-capture.sqlite3-wal",
                           "size":1,"sha256":"b"*64})
    elif change=="capture_missing":
        a["files"]=[r for r in a["files"]
                    if r["path"]!="capture/lobby-capture.sqlite3"]
    elif change=="source_commit":
        s["source_commit"]="0"*40
    with pytest.raises(m.Stop,match=stop):
        m.check(s,a)

def test_r963_source_extra_tmp_does_not_become_auto_disposable():
    m=module()
    s,a=docs(m)
    # An old-looking temporary pathname is STILL a source file.
    s["files"].append({"path":"observer/.snapshot.012345.tmp","type":"regular",
                       "size":999,"sha256":"e"*64})
    s["file_count"]+=1
    s["logical_bytes"]+=999
    with pytest.raises(m.Stop,match="ORIGINAL_SOURCE_PATH_UNARCHIVED_STOP"):
        m.check(s,a)

def test_r963_external_hashes_required_and_wrong_digest_rejected(tmp_path):
    m=module()
    s,a=docs(m)
    a_path=tmp_path/"archive.json"
    s_path=tmp_path/"source.json"
    for path,data in ((a_path,a),(s_path,s)):
        path.write_text(json.dumps(data))
    sha=lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    proc=subprocess.run([sys.executable,"-I",str(SCRIPT),
        "--source-census",str(s_path), "--source-census-sha256",sha(s_path),
        "--archive-manifest",str(a_path),
        "--archive-manifest-sha256",sha(a_path)],
        text=True,capture_output=True,timeout=20)
    assert proc.returncode==0,proc.stdout+proc.stderr
    assert "FLOP_SOURCE_AUTHENTICITY_NOT_PROVEN" in proc.stdout
    assert "FLOP_OCI_DELETION_NEVER_AUTHORIZED_BY_THIS_TOOL" in proc.stdout
    assert "airdrop-radar" not in proc.stdout
    fail=subprocess.run([sys.executable,"-I",str(SCRIPT),
        "--source-census",str(s_path), "--source-census-sha256","0"*64,
        "--archive-manifest",str(a_path),
        "--archive-manifest-sha256",sha(a_path)],
        text=True,capture_output=True,timeout=20)
    assert fail.returncode==42
    assert "EXTERNAL_SHA256_PIN_MISMATCH" in fail.stdout
    assert "airdrop-radar" not in fail.stdout

def test_r963_size_count_hard_caps_and_signer_secret_names_not_echoed():
    m=module()
    s,a=docs(m)
    s["files"].append({"path":"signer/private-do-not-print.json",
                       "type":"regular","size":1,"sha256":"c"*64})
    s["file_count"]+=1
    s["logical_bytes"]+=1
    try:
        m.check(s,a)
    except m.Stop as error:
        assert str(error)=="ORIGINAL_SOURCE_PATH_UNARCHIVED_STOP"
        assert "private-do-not-print" not in str(error)
    else:
        pytest.fail("must STOP on missing private source record")
    s,a=docs(m)
    a["files"]*=35
    with pytest.raises(m.Stop,match="ARCHIVE_FILE_COUNT_STOP"):
        m.check(s,a)
