"""R1086 isolated DISARMED plaintext-stream restore, never K137 runtime start.

Only for an independently authenticated two-pass R1001 offhost archive over an
owner-enrolled encrypted SSH channel. The source side must FIRST fully AEAD
verify, then stream plaintext exactly as R1066's pack format. No SSH, key
handling, signer, service, Oracle, TradeBot or source-writer authority here.

A missing exact independent K137 identity/UID enrollment stops before writing.
The fixed landing is separate from /opt/flop-shadow and TradeBot. Source epoch
remains PROVISIONAL_UNFENCED, not an authorized production migration.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys

def load():
    p=Path(__file__).with_name("r1066_transfer.py")
    spec=importlib.util.spec_from_file_location("r1086_transfer",p)
    m=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=m
    spec.loader.exec_module(m)
    return m

T=load()
ROOT=Path("/var/lib/flop-migration-r1066/disarmed")
RESERVE=20*1024**3
SQLITE_ALLOWANCE=1024**3

class Stop(ValueError):
    pass

def need(ok,code):
    if not ok: raise Stop(code)

def machine_digest():
    raw=Path("/etc/machine-id").read_bytes()
    need(1<=len(raw)<=128,"MACHINE_ID_STOP")
    return hashlib.sha256(raw.strip()).hexdigest()

def private_parent(path):
    need(path==ROOT,"K137_DISARMED_ROOT_STOP")
    need(path.is_absolute() and ".." not in path.parts,"PATH_STOP")
    for p in (path,*path.parents):
        need(not p.is_symlink(),"PATH_LINK_STOP")
    s=path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid()
         and stat.S_IMODE(s.st_mode)==0o700,"OWNER_CUSTODY_STOP")

def evidence_gate(parent,expected_machine_sha256,expected_uid):
    need(sys.platform=="linux" and type(expected_uid) is int and
         expected_uid>0 and os.geteuid()==expected_uid,
         "DEDICATED_USER_STOP")
    need(type(expected_machine_sha256) is str and
         T.G.HEX.fullmatch(expected_machine_sha256) is not None and
         machine_digest()==expected_machine_sha256,"HOST_IDENTITY_STOP")
    private_parent(parent)

def input_blocks(source):
    while True:
        data=source.read(T.CHUNK)
        need(type(data) is bytes,"BINARY_STREAM_STOP")
        if not data: break
        yield data

def restore_stream(source,target_name,expected_machine_sha256,expected_uid, *,
                   quota_bytes, reserve_bytes=RESERVE):
    """Caller holds a separate signed owner approval and a pinned SSH channel.

    This function only asserts destination custody; it CANNOT assert original
    source epoch or signer. No ability to activate or mutate protected roots.
    """
    evidence_gate(ROOT,expected_machine_sha256,expected_uid)
    need(type(target_name) is str and len(target_name)==32 and
         all(c in "0123456789abcdef" for c in target_name),"TARGET_ID_STOP")
    need(type(quota_bytes) is int and 0<quota_bytes<=T.C.MAX_SOURCE_BYTES,
         "QUOTA_STOP")
    need(reserve_bytes>=RESERVE,"TRADEBOT_RESERVE_STOP")
    target=ROOT/target_name
    need(not target.exists() and not target.is_symlink(),"TARGET_EXISTS_STOP")
    reader=T.Reader(input_blocks(source))
    length=int.from_bytes(reader.read(8),"big")
    need(0<length<=T.MAX_MANIFEST,"MANIFEST_BOUND")
    manifest=json.loads(reader.read(length),object_pairs_hook=T.G._pairs)
    T.G.shape(manifest,"version source_head epoch entries")
    need(manifest["version"]==1 and manifest["source_head"]==T.HEAD and
         manifest["epoch"]=="PROVISIONAL_UNFENCED","EPOCH_STOP")
    entries=manifest["entries"]
    need(type(entries) is list and 2<=len(entries)<=T.MAX_ARCHIVE_ENTRIES,
         "COUNT_STOP")
    rows={};total=0;database_names=set()
    for row in entries:
        T.G.shape(row,"path mode uid gid mtime_ns kind size sha256 target")
        name=row["path"];p=T.relative(name)
        need(len(p.parts)<=T.MAX_ARCHIVE_DEPTH+1 and name not in rows,
             "PATH_COUNT_STOP")
        need(row["kind"] in ("directory","file","hardlink","symlink"),
             "KIND_STOP")
        T.G.integer(row["mode"],0,0o7777)
        T.G.integer(row["uid"]);T.G.integer(row["gid"])
        T.G.integer(row["mtime_ns"])
        T.G.integer(row["size"],0,T.C.MAX_SOURCE_BYTES)
        if len(p.parts)>1:
            parent=str(p.parent).replace("\\","/")
            need(parent in rows and rows[parent]["kind"]=="directory",
                 "PARENT_STOP")
        if row["kind"]=="file":
            T.G.digest(row["sha256"]);total+=row["size"]
            if p.name in T.G.DATABASES: database_names.add(p.name)
        elif row["kind"]=="hardlink":
            need(row["target"] in rows and
                 rows[row["target"]]["kind"]=="file","HARDLINK_STOP")
        elif row["kind"]=="symlink":
            link=row["target"]
            need(type(link) is str and link and not Path(link).is_absolute()
                 and "\\" not in link and
                 all(s not in ("","..") for s in link.split("/")),
                 "SYMLINK_REVIEW_STOP")
        rows[name]=row
    need(database_names==set(T.G.DATABASES),"TWO_SQLITE_STOP")
    need(total<=quota_bytes and total<=T.C.MAX_SOURCE_BYTES,"QUOTA_STOP")
    need(shutil.disk_usage(ROOT).free>=total+SQLITE_ALLOWANCE+reserve_bytes,
         "TRADEBOT_SPACE_STOP")
    # The manifest is validated and full space budget confirmed BEFORE mkdir.
    target.mkdir(mode=0o700)
    digests={}
    dbs=[]
    for name,row in rows.items():
        destination=target/T.relative(name)
        kind=row["kind"]
        if kind=="directory":
            destination.mkdir(mode=0o700)
        elif kind=="file":
            sha=hashlib.sha256()
            remaining=row["size"]
            with destination.open("xb") as f:
                os.chmod(destination,0o600)
                while remaining:
                    data=reader.read(min(T.CHUNK,remaining))
                    need(data,"SOURCE_STREAM_STOP")
                    f.write(data);sha.update(data);remaining-=len(data)
                f.flush();os.fsync(f.fileno())
            need(sha.hexdigest()==row["sha256"],"FILE_DIGEST_STOP")
            digests[name]=sha.hexdigest()
            if destination.name in database_names: dbs.append(destination)
        elif kind=="hardlink":
            os.link(target/T.relative(row["target"]),destination)
        else:
            destination.symlink_to(row["target"])
    reader.finish()
    need(len(dbs)==2,"TWO_SQLITE_STOP")
    cursors=[]
    for db in dbs:
        with sqlite3.connect(db.as_uri()+"?mode=ro",uri=True) as c:
            c.execute("PRAGMA trusted_schema=OFF")
            need(c.execute("PRAGMA integrity_check").fetchall()==[("ok",)],
                 "SQLITE_INTEGRITY_STOP")
            cursors.append(c.execute(
                "SELECT count(*),coalesce(max(seq),0) FROM messages").fetchone())
    # The receipt is the only completion marker. No auto-service operations.
    T.C.write_new_file(target,"DISARMED-STREAM-RECEIPT.json",T.G.canonical({
        "schema_version":1,"manifest_sha256":hashlib.sha256(
            T.G.canonical(manifest)).hexdigest(),
        "files":len(rows),"bytes":total,"sqlite_cursors":cursors,
        "source_epoch":"PROVISIONAL_UNFENCED","runtime_started":False,
        "signer_continuity":"NOT_PROVEN","cutover":"NO_GO",
        "oci_retirement":"STRICT_NO_GO"}))
    return {"operation":"K137_DISARMED_STREAM_RESTORE_ONLY",
            "files":len(rows),"bytes":total,"sqlite_integrity":"PASS",
            "common_sqlite_epoch":"NOT_PROVEN","signer":"NOT_PROVEN",
            "tradebot_impact":"NOT_PROVEN","cutover":"NO_GO",
            "oci_retirement":"STRICT_NO_GO"}
