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
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import re
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
                   quota_bytes, reserve_bytes=RESERVE, expected_epoch=None,
                   expected_manifest_sha256=None, preserve_inert_links=False,
                   resume=False, expected_cursors=None):
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
    existed=target.exists()
    need(not target.is_symlink() and (not existed or resume),"TARGET_EXISTS_STOP")
    reader=T.Reader(input_blocks(source))
    length=int.from_bytes(reader.read(8),"big")
    need(0<length<=T.MAX_MANIFEST,"MANIFEST_BOUND")
    manifest=json.loads(reader.read(length),object_pairs_hook=T.G._pairs)
    T.G.shape(manifest,"version source_head epoch entries")
    need(manifest["version"]==1 and manifest["source_head"]==T.HEAD,"EPOCH_STOP")
    actual_manifest_sha=hashlib.sha256(T.G.canonical(manifest)).hexdigest()
    if expected_epoch is None:
        need(manifest["epoch"]=="PROVISIONAL_UNFENCED","EPOCH_STOP")
    else:
        need(type(expected_epoch) is str and
             re.fullmatch(r"FROZEN:[0-9a-f]{64}",expected_epoch) and
             manifest["epoch"]==expected_epoch and
             expected_manifest_sha256==actual_manifest_sha,"EPOCH_BINDING_STOP")
    rows,total,database_names=validate_manifest(manifest,preserve_inert_links=preserve_inert_links)
    need(total<=quota_bytes and total<=T.C.MAX_SOURCE_BYTES,"QUOTA_STOP")
    # No optimistic compression or shrinking the protected TradeBot reserve.
    remaining=total
    marker=target/"DISARMED-STREAM-INCOMPLETE.json"
    receipt_path=target/"DISARMED-STREAM-RECEIPT.json"
    if existed:
        s=target.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and
             stat.S_IMODE(s.st_mode)==0o700,"RESUME_CUSTODY_STOP")
        proof=receipt_path if receipt_path.exists() else marker
        ps=proof.lstat()
        need(stat.S_ISREG(ps.st_mode) and ps.st_uid==os.geteuid() and ps.st_nlink==1
             and stat.S_IMODE(ps.st_mode)==0o600 and ps.st_size<=8192,"RESUME_PROOF_STOP")
        known=json.loads(proof.read_bytes(),object_pairs_hook=T.G._pairs)
        need(known.get("manifest_sha256")==actual_manifest_sha,"RESUME_BINDING_STOP")
        allowed=set(rows)|{marker.name,receipt_path.name}
        present=0
        for p in target.rglob("*"):
            relative=p.relative_to(target).as_posix()
            need(relative in allowed,"RESUME_EXTRA_OBJECT_STOP")
            if relative in rows and rows[relative]["kind"]=="file" and not p.is_symlink():
                need(p.stat().st_size<=rows[relative]["size"],"RESUME_SIZE_STOP")
                present+=p.stat().st_size
        remaining=max(0,total-present)
    need(shutil.disk_usage(ROOT).free>=remaining+SQLITE_ALLOWANCE+reserve_bytes,
         "TRADEBOT_SPACE_STOP")
    if not existed:
        target.mkdir(mode=0o700)
        T.C.write_new_file(target,marker.name,T.G.canonical({"manifest_sha256":actual_manifest_sha}))
    dbs=[];hardlinks={}
    for name,row in rows.items():
        if row["kind"]=="hardlink": hardlinks.setdefault(row["target"],[]).append(name)
    for name,row in rows.items():
        destination=target/T.relative(name)
        kind=row["kind"]
        present=destination.exists() or destination.is_symlink()
        if kind=="directory":
            if present:
                s=destination.lstat()
                need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and
                     stat.S_IMODE(s.st_mode)==0o700,"RESUME_CUSTODY_STOP")
            else:
                destination.mkdir(mode=0o700)
        elif kind=="file":
            old=0
            if present:
                s=destination.lstat()
                need(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and
                     stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=row["size"],"RESUME_CUSTODY_STOP")
                aliases=0
                for other in hardlinks.get(name,[]):
                    alias=target/T.relative(other)
                    if alias.exists() and not alias.is_symlink():
                        a=alias.stat()
                        if (a.st_dev,a.st_ino)==(s.st_dev,s.st_ino): aliases+=1
                need(s.st_nlink==1+aliases,"RESUME_EXTERNAL_HARDLINK_STOP")
                old=s.st_size
            flags=os.O_RDWR|os.O_NOFOLLOW
            if not present: flags|=os.O_CREAT|os.O_EXCL
            fd=os.open(destination,flags,0o600)
            sha=hashlib.sha256();remaining=row["size"];at=0
            with os.fdopen(fd,"r+b") as f:
                while remaining:
                    data=reader.read(min(T.CHUNK,remaining))
                    compare=min(len(data),max(0,old-at))
                    if compare:
                        need(f.read(compare)==data[:compare],"RESUME_PREFIX_STOP")
                    if compare<len(data):
                        need(not receipt_path.exists(),"COMPLETED_RESTORE_DRIFT_STOP")
                        f.write(data[compare:])
                    sha.update(data);remaining-=len(data);at+=len(data)
                f.flush();os.fsync(f.fileno())
            need(sha.hexdigest()==row["sha256"],"FILE_DIGEST_STOP")
            if destination.name in database_names: dbs.append(destination)
        elif kind=="hardlink":
            original=target/T.relative(row["target"])
            if present:
                need(not destination.is_symlink() and
                     (destination.stat().st_dev,destination.stat().st_ino)==
                     (original.stat().st_dev,original.stat().st_ino),
                     "RESUME_HARDLINK_STOP")
            else:
                os.link(original,destination)
        else:
            if present:
                need(destination.is_symlink() and os.readlink(destination)==row["target"],"RESUME_SYMLINK_STOP")
            else:
                destination.symlink_to(row["target"])
    reader.finish()
    need(len(dbs)==2,"TWO_SQLITE_STOP")
    cursors=[]
    for db in dbs:
        # Validation must not rewrite copied WAL/SHM evidence or create a new
        # sidecar. This is an inert private copy, never an active database.
        protected=[p for p in (db,Path(str(db)+"-wal"),Path(str(db)+"-shm")) if p.exists()]
        try:
            for p in protected: os.chmod(p,0o400)
            os.chmod(db.parent,0o500)
            with contextlib.closing(sqlite3.connect(db.as_uri()+"?mode=ro",uri=True)) as c:
                c.execute("PRAGMA trusted_schema=OFF")
                c.execute("PRAGMA query_only=ON")
                need(c.execute("PRAGMA integrity_check").fetchall()==[("ok",)],"SQLITE_INTEGRITY_STOP")
                cursors.append(c.execute("SELECT count(*),coalesce(max(seq),0) FROM messages").fetchone())
        finally:
            os.chmod(db.parent,0o700)
            for p in protected: os.chmod(p,0o600)
        for p in protected:
            row=rows[p.relative_to(target).as_posix()]
            with p.open("rb") as f:
                sha=hashlib.sha256()
                while data:=f.read(T.CHUNK): sha.update(data)
            need(sha.hexdigest()==row["sha256"],"SQLITE_EVIDENCE_DRIFT_STOP")
    if expected_cursors is not None:
        need([list(v) for v in cursors]==expected_cursors,"SQLITE_CURSOR_BINDING_STOP")
    receipt={"schema_version":1,"manifest_sha256":actual_manifest_sha,
        "files":len(rows),"bytes":total,"sqlite_cursors":cursors,
        "source_epoch":manifest["epoch"],"runtime_started":False,
        "original_metadata":"PRESERVED_IN_ENCRYPTED_MANIFEST_NOT_ACTIVATED",
        "symlinks":sum(r["kind"]=="symlink" for r in rows.values()),
        "links_require_activation_review":preserve_inert_links,
        "signer_continuity":"NOT_PROVEN","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}
    if receipt_path.exists():
        need(T.G.canonical(json.loads(receipt_path.read_bytes(),object_pairs_hook=T.G._pairs))==T.G.canonical(receipt),
             "COMPLETED_RESTORE_DRIFT_STOP")
    else:
        T.C.write_new_file(target,receipt_path.name,T.G.canonical(receipt))
    if marker.exists(): marker.unlink()  # only this invocation's generated checkpoint
    return {"operation":"K137_DISARMED_STREAM_RESTORE_ONLY",
            "files":len(rows),"bytes":total,"sqlite_integrity":"PASS",
            "manifest_sha256":actual_manifest_sha,"sqlite_cursors":cursors,
            "symlinks":sum(r["kind"]=="symlink" for r in rows.values()),
            "common_sqlite_epoch":"NOT_PROVEN","signer":"NOT_PROVEN",
            "tradebot_impact":"NOT_PROVEN","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}


def validate_manifest(manifest, *, preserve_inert_links=False):
    """Read-only shared validation for independent offhost authentication."""
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
            need(type(link) is str and link and "\0" not in link and
                 len(os.fsencode(link))<=4096,"SYMLINK_REVIEW_STOP")
            if not preserve_inert_links:
                need(not Path(link).is_absolute() and "\\" not in link and
                     all(s not in ("","..") for s in link.split("/")),
                     "SYMLINK_REVIEW_STOP")
        rows[name]=row
    need(database_names==set(T.G.DATABASES),"TWO_SQLITE_STOP")
    return rows,total,database_names
