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
    assert "0ee105633366abe9e92d72eacc86e7be789aa851" in src
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



def test_r1072_receipt_schema_includes_numeric_field_name(roots, monkeypatch, capsys):
    import json
    monkeypatch.setattr(mod, "assert_original", lambda: None)
    assert mod.main() == 0
    captured = capsys.readouterr().out
    row = json.loads(captured)
    assert row["result"] == "INVENTORY_ONLY"
    assert row["writer_admission"] == "NOT_PROVEN"
    assert row["k137_restore"] == "NOT_PERFORMED"
    assert row["oci_retirement"] == "STRICT_NO_GO"
    pattern = __import__("re").compile(r'"[a-z0-9_]+"[ ]*:')
    assert len(pattern.findall(captured)) == 22
    assert len(__import__("re").compile(r'"[a-z_]+"[ ]*:').findall(captured)) == 21


@pytest.mark.skipif(os.name != "nt", reason="Windows PS5.1 required")
def test_r1072_ps51_actual_schema_validator_happy_and_rejection(tmp_path):
    import json
    row = {
        "phase": "R1072_ORIGINAL_READONLY_CAPACITY",
        "result": "INVENTORY_ONLY",
        "original_git": "MATCH",
        "tree": {"entries": 3017, "regular": 2950, "directories": 41,
                 "symlinks": 19, "hardlink_repeated": 1, "special_objects": 4,
                 "regular_bytes": 20900000000, "sqlite_bases": 2,
                 "sqlite_wals": 2, "sqlite_shms": 1},
        "free_bytes": 4000000000,
        "writer_admission": "NOT_PROVEN",
        "common_sqlite_epoch": "NOT_PROVEN",
        "original_archive": "NOT_CREATED",
        "offhost_backup": "NOT_CREATED",
        "k137_restore": "NOT_PERFORMED",
        "cutover": "NO_GO",
        "oci_retirement": "STRICT_NO_GO",
    }
    sample = tmp_path/"ok.json"
    sample.write_text(json.dumps(row, sort_keys=True), encoding="ascii")
    invalid = tmp_path/"bad.json"
    wrong = dict(row, cutover="GO")
    invalid.write_text(json.dumps(wrong, sort_keys=True), encoding="ascii")
    controller_path = str(OWNER).replace("'", "''")
    good_path = str(sample).replace("'", "''")
    bad_path = str(invalid).replace("'", "''")
    code = (
        "$ErrorActionPreference='Stop';$tokens=$null;$errors=$null;"
        "$ast=[Management.Automation.Language.Parser]::ParseFile('"
        + controller_path + "',[ref]$tokens,[ref]$errors);"
        "if($errors.Count -ne 0){exit 40};"
        "$defs=@($ast.FindAll({param($n)"
        "$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)"
        "|Where-Object {$_.Name -eq 'Check-R1072Result'});"
        "if($defs.Count -ne 1){exit 41};"
        "Invoke-Expression $defs[0].Extent.Text;"
        "$good=[Text.Encoding]::ASCII.GetBytes("
        "[IO.File]::ReadAllText('" + good_path + "'));"
        "$out=Check-R1072Result $good;"
        "if(($out|ConvertFrom-Json).result -ne 'INVENTORY_ONLY'){exit 42};"
        "$bad=[Text.Encoding]::ASCII.GetBytes("
        "[IO.File]::ReadAllText('" + bad_path + "'));"
        "try {$null=Check-R1072Result $bad;exit 43}"
        "catch {Write-Output 'R1072_SCHEMA_POSITIVE_AND_DENY=PASS';exit 0}"
    )
    done = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", code],
        capture_output=True, timeout=30)
    assert done.returncode == 0, (done.stdout,done.stderr)
    assert b"R1072_SCHEMA_POSITIVE_AND_DENY=PASS" in done.stdout



def test_original_source_classifies_guard_without_disclosing_path(monkeypatch, capsys):
    import json
    monkeypatch.setattr(mod, "assert_original", lambda: None)
    def guard():
        raise mod.Stop("ORIGINAL_HEAD_STOP")
    monkeypatch.setattr(mod, "inventory", guard)
    assert mod.main() == 42
    msg=json.loads(capsys.readouterr().out)
    assert msg == {
        "phase":"R1072_ORIGINAL_READONLY_CAPACITY",
        "result":"STOP","code":"ORIGINAL_HEAD_STOP",
        "cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}


def test_unexpected_exception_is_redacted_without_echo(monkeypatch, capsys):
    import json
    monkeypatch.setattr(mod, "assert_original", lambda: None)
    def fail():
        raise RuntimeError("/var/lib/technocore-safe-agent/PRIVATE-do-not-print")
    monkeypatch.setattr(mod, "inventory", fail)
    assert mod.main() == 42
    msg=capsys.readouterr().out
    assert "PRIVATE-do-not-print" not in msg
    assert json.loads(msg)["code"]=="SOURCE_UNVERIFIED"



def test_r1072_integrity_and_decryption_are_distinct_redacted_stages():
    source = OWNER.read_text()
    assert source.count("$stage='LOCAL_ESCROW_INTEGRITY'") == 1
    assert source.count("$stage='LOCAL_DECRYPT'") == 1
    assert "'LOCAL_ESCROW_INTEGRITY','LOCAL_CODE_ENTRY','LOCAL_CODE_EMPTY'" in source
    assert "'LOCAL_DECRYPT','LOCAL_CUSTODY'" in source
    assert source.index("$stage='LOCAL_ESCROW_INTEGRITY'") < source.index(
        "$stage='LOCAL_DECRYPT'") < source.index("$stage='LOCAL_CUSTODY'")



def test_empty_local_secret_is_rejected_before_decrypt_and_redacted():
    source = OWNER.read_text()
    assert "if ($null -eq $code -or $code.Length -eq 0)" in source
    assert "$stage='LOCAL_CODE_EMPTY'" in source
    assert "'LOCAL_CODE_ENTRY','LOCAL_CODE_EMPTY'" in source
    assert source.index("$stage='LOCAL_CODE_EMPTY'") < source.index(
        "$plain=Unprotect-R1027 $encrypted $code")
    assert "Write-Output $code" not in source



def test_r1079_bootstrap_all_source_pins_match_immutable_git_blobs():
    """Prevent an R1079 carrier refresh with a stale owner-internal pin.

    Strict checks are intentionally not weakened to fix a mismatched source.
    """
    import hashlib
    import re

    root = ROOT
    bootstrap = (root/"packaging/windows/r1072_owner_public_bootstrap.ps1").read_text()
    owner = OWNER.read_text()
    rows = re.findall(
        r"@\{path='([^']+)';blob='([0-9a-f]{40})'\}",
        bootstrap)
    assert len(rows) == 6
    assert len(set(path for path, _ in rows)) == 6

    pinned = {}
    for path, advertised in rows:
        content = (root/path).read_bytes()
        assert 10 <= len(content) <= 65536
        check = hashlib.sha1(
            b"blob " + str(len(content)).encode("ascii") + b"\0" + content
        ).hexdigest()
        assert advertised == check, path
        pinned[path] = advertised

    controller = "packaging/migration/r1072_oci_owner_capacity_readonly.ps1"
    carrier = "packaging/migration/r1079_profile_ssh_transport.cs"
    assert controller in pinned and carrier in pinned
    assert pinned[carrier] in owner
    assert re.search(
        r"r1079_profile_ssh_transport\.cs'\s*\)\s*'"+pinned[carrier]+r"'",
        owner)
    assert "Read-R1066PinnedSource" in owner
    assert "Initialize-R1066" in owner
    assert "FlopR1079.Transport" in owner
    assert "FlopR1075.Transport]::Run" not in owner
