"""R1086 synthetic only, no network, no production path mutations."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/"packaging/migration/r1086_k137_disarmed_stream_restore.py"
spec=importlib.util.spec_from_file_location("r1086_tests",FILE)
m=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=m
spec.loader.exec_module(m)
LINUX=pytest.mark.skipif(sys.platform!="linux" or os.geteuid()==0,
                         reason="requires unprivileged Linux POSIX owner")

@pytest.fixture
def offline(tmp_path,monkeypatch):
    os.chmod(tmp_path,0o700)
    source=tmp_path/"source"
    app=source/"app";state=source/"state"
    source.mkdir(mode=0o700);app.mkdir(mode=0o700);state.mkdir(mode=0o700)
    (app/"file").write_bytes(bytes(range(256))*1500)
    (app/"link").symlink_to("file")
    for db in m.T.G.DATABASES:
        with sqlite3.connect(state/db) as con:
            con.execute("CREATE TABLE messages(seq INTEGER PRIMARY KEY, text TEXT)")
            con.execute("INSERT INTO messages VALUES (1,'fixture')")
    (state/"history").write_bytes(b"synthetic-record")
    arc=tmp_path/"archive"
    m.T.seal(app,state,arc,os.urandom(48),source_head=m.T.HEAD)
    # Source bytes are from a synthetic committed test archive. In production,
    # they would be reassembled over independently authenticated SSH.
    key_file=next(iter((tmp_path/"unused").parent.glob("nonexistent*")),None)
    # Recreate a deterministic archive so this fixture retains its private key.
    import shutil
    shutil.rmtree(arc)
    material=os.urandom(48)
    m.T.seal(app,state,arc,material,source_head=m.T.HEAD)
    plaintext=b"".join(m.T.decrypt(arc,material))
    landing=tmp_path/"disarmed";landing.mkdir(mode=0o700)
    monkeypatch.setattr(m,"ROOT",landing)
    monkeypatch.setattr(m,"machine_digest",lambda:"a"*64)
    monkeypatch.setattr(m.shutil,"disk_usage",lambda _:type("Disk",(),{"free":64*1024**3})())
    return tmp_path,landing,plaintext

@LINUX
def test_disarmed_stream_restore_exact_bytes_and_sqlite(offline):
    root,landing,plain=offline
    receipt=m.restore_stream(io.BytesIO(plain),"c"*32,"a"*64,os.geteuid(),
                             quota_bytes=4*1024**2)
    assert receipt["operation"]=="K137_DISARMED_STREAM_RESTORE_ONLY"
    assert receipt["cutover"]=="NO_GO"
    target=landing/("c"*32)
    assert (target/"app/file").read_bytes()==bytes(range(256))*1500
    assert (target/"app/link").readlink()==Path("file")
    j=json.loads((target/"DISARMED-STREAM-RECEIPT.json").read_bytes())
    assert j["runtime_started"] is False and j["source_epoch"]=="PROVISIONAL_UNFENCED"

@LINUX
@pytest.mark.parametrize("failure",["wrong_host","wrong_uid","no_space","truncated","existing","wrong_root"])
def test_disarmed_stream_restore_protected_failures(offline,monkeypatch,failure):
    root,landing,plain=offline
    name="c"*32
    identity="a"*64
    uid=os.geteuid()
    if failure=="wrong_host":identity="f"*64
    if failure=="wrong_uid":uid=uid+1
    if failure=="no_space":
        monkeypatch.setattr(m.shutil,"disk_usage",
            lambda _:type("Disk",(),{"free":m.RESERVE})())
    if failure=="truncated":plain=plain[:-70]
    if failure=="existing":(landing/name).mkdir(mode=0o700)
    if failure=="wrong_root":monkeypatch.setattr(m,"ROOT",root)
    with pytest.raises((m.Stop,m.T.Stop,m.T.G.Deny,ValueError,sqlite3.Error,OSError)):
        m.restore_stream(io.BytesIO(plain),name,identity,uid,quota_bytes=4*1024**2)
    if failure in ("wrong_host","wrong_uid","no_space","wrong_root"):
        assert not (landing/name/"DISARMED-STREAM-RECEIPT.json").exists()

def test_no_production_ssh_wallet_or_start():
    code=FILE.read_text()
    assert "subprocess.Popen" not in code
    assert "systemctl" not in code
    assert "LIVE_RESTORER_AUTHORITY_NOT_ENROLLED" in (FILE.parent/"r1066_transfer.py").read_text()
    assert str(m.ROOT)=="/var/lib/flop-migration-r1066/disarmed"
