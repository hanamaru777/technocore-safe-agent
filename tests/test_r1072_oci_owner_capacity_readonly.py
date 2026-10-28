"""R1072 synthetic validation only. No live hosts used in tests."""
import importlib.util
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

ROOT=Path(__file__).resolve().parents[1]
GUEST=ROOT/"packaging/oracle/r1072_original_readonly_capacity.py"
OWNER=ROOT/"packaging/migration/r1072_oci_owner_capacity_readonly.ps1"
spec=importlib.util.spec_from_file_location("r1072_guest",GUEST)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@pytest.fixture
def roots(tmp_path,monkeypatch):
    app=tmp_path/"app"; app.mkdir()
    state=tmp_path/"state"; state.mkdir()
    (app/"a").write_bytes(b"a"*13)
    (state/"lobby-capture.sqlite3").write_bytes(b"b"*100)
    (state/"lobby-capture-service.sqlite3").write_bytes(b"c"*200)
    (state/"lobby-capture.sqlite3-wal").write_bytes(b"d"*9)
    monkeypatch.setattr(mod,"APP",app)
    monkeypatch.setattr(mod,"STATE",state)
    return app,state


def test_inventory_metadata_only(roots):
    app,state=roots
    (state/"hardlink").hardlink_to(app/"a")
    (state/"symbolic").symlink_to(app/"a")
    before=(app/"a").stat().st_mtime_ns
    report=mod.inventory()
    assert report["sqlite_bases"]==2
    assert report["sqlite_wals"]==1
    assert report["regular_bytes"]==13+100+200+9
    assert report["hardlink_repeated"]==1
    assert report["symlinks"]==1
    assert (app/"a").stat().st_mtime_ns==before


def test_missing_second_db_stops(roots):
    _,state=roots
    (state/"lobby-capture-service.sqlite3").unlink()
    with pytest.raises(mod.Stop):
        mod.inventory()


def test_original_sha_drifts_stops(monkeypatch,roots):
    monkeypatch.setattr(mod.os,"geteuid",lambda:0)
    monkeypatch.setattr(mod.os.path,"lexists",lambda _p:False)
    monkeypatch.setattr(mod.subprocess,"run",lambda *a,**k:
        SimpleNamespace(returncode=0,stdout=b"f"*40+b"\n"))
    with pytest.raises(mod.Stop):
        mod.assert_original()


def test_windows_wrapper_pins_existing_r1066_and_new_guest():
    src=OWNER.read_text()
    assert "r1066_owner_workflow.ps1" in src
    assert "7a7d9790ccd9bb464c254188096d85fb315ee550" in src
    assert "cb05b793e0b8e04a99af4e7edc2b9a2206d54b1c" in src
    assert "StrictHostKeyChecking=yes" in src
    assert "Remove-R1027Custody" in src
    assert "NOT_PROVEN" in src
    assert "Function:script:" in src
    guest=GUEST.read_text()
    assert "os.scandir(" in guest
    assert "lstat()" in guest
    assert "SOURCE_UNVERIFIED" in guest


@pytest.mark.skipif(os.name!="nt",reason="Windows PS5.1 required")
def test_windows_ps51_parse_and_extra_argument_refusal():
    ps="powershell.exe"
    path=str(OWNER).replace("'","''")
    parsed=subprocess.run([ps,"-NoProfile","-NonInteractive","-Command",
         "$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('"
         +path+"',[ref]$t,[ref]$e);if($e.Count -ne 0){exit 42};exit 0"],
         capture_output=True,timeout=30)
    assert parsed.returncode==0,parsed.stderr.decode(errors="replace")
    guard=subprocess.run([ps,"-NoProfile","-NonInteractive",
        "-File",str(OWNER),"unexpected"],capture_output=True,timeout=30)
    assert guard.returncode==0
    assert b"ARGS_STOP" in guard.stdout
