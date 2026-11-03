"""Bounded private SQLite/WAL verification. NEVER opens original DB in SQLite."""
import hashlib
import shutil
import sqlite3
import tempfile
import struct
from pathlib import Path
import importlib.util
import sys

sp=importlib.util.spec_from_file_location("r1155_hold",Path(__file__).with_name("r1154_app_hold.py"))
H=importlib.util.module_from_spec(sp);sys.modules[sp.name]=H;sp.loader.exec_module(H)
C=H.C
MAX_STAGE=2*1024**3


def strict_wal(path):
    """SQLite fileformat2 WAL checksum algorithm; bounded to one page in RAM.

    Conservatively reject incomplete/uncommitted/reset tails instead of letting
    SQLite silently fall back to an earlier commit after power loss.
    """
    if not path.exists() or path.stat().st_size==0:return
    with path.open("rb") as f:
        header=f.read(32);H.need(len(header)==32,"WAL_TRUNCATED_STOP")
        magic,version,page,seq,salt1,salt2,check1,check2=struct.unpack(">8I",header)
        H.need(magic in (0x377f0682,0x377f0683) and version==3007000 and
               512<=page<=65536 and page&(page-1)==0,"WAL_HEADER_STOP")
        endian="<" if magic==0x377f0682 else ">"
        def checksum(raw,state):
            a,b=state
            for x,y in struct.iter_unpack(endian+"II",raw):a=(a+x+b)&0xffffffff;b=(b+y+a)&0xffffffff
            return a,b
        state=checksum(header[:24],(0,0));H.need(state==(check1,check2),"WAL_CHECKSUM_STOP")
        committed=False;frames=0
        while raw:=f.read(24):
            H.need(len(raw)==24,"WAL_TRUNCATED_STOP")
            pgno,dbsize,s1,s2,c1,c2=struct.unpack(">6I",raw);data=f.read(page)
            H.need(len(data)==page and pgno>0 and (s1,s2)==(salt1,salt2),"WAL_FRAME_STOP")
            state=checksum(data,checksum(raw[:8],state))
            H.need(state==(c1,c2),"WAL_CHECKSUM_STOP")
            committed=dbsize>0;frames+=1
        H.need(frames>0 and committed,"WAL_UNCOMMITTED_TAIL_STOP")


def validate(roots,manifest,identities,guard,*,parent=None):
    """Single held epoch; immutable=1 would ignore WAL and is forbidden here.

    The staged SHM may be updated by SQLite; the original DB/WAL/SHM are only
    opened through R1066's identity-pinned read_blocks. Hashes rechecked after
    validation, and again by the original full-stream recensus/packer.
    """
    rows={r["path"]:r for r in manifest["entries"] if r["kind"]=="file"}
    allrows={r["path"]:r for r in manifest["entries"]}
    dbs=sorted(p for p in rows if p.rsplit("/",1)[-1] in C.G.DATABASES)
    H.need(len(dbs)==2,"WAL_TWO_DATABASES_STOP")
    total=sum(rows[p+s]["size"] for p in dbs for s in ("","-wal","-shm") if p+s in rows)
    H.need(total<=MAX_STAGE,"WAL_STAGE_BOUND_STOP")
    base=H.private_dir(parent or H.WORK/"sqlite-validation")
    H.need(shutil.disk_usage(base).free>=total+256*1024**2,"WAL_STAGE_SPACE_STOP")
    cursors=[]
    for index,name in enumerate(dbs):
        guard(True)
        for suffix in ("-wal","-shm","-journal"):
            row=allrows.get(name+suffix)
            H.need(row is None or row["kind"]=="file","WAL_SIDECAR_TYPE_STOP")
        H.need(name+"-journal" not in rows or rows[name+"-journal"]["size"]==0,"WAL_HOT_JOURNAL_STOP")
        wal=rows.get(name+"-wal")
        if wal and wal["size"]:
            H.need(name+"-shm" in rows and 32768<=rows[name+"-shm"]["size"]<=16*1024**2,
                   "WAL_SHM_MISSING_STOP")
        source={}
        with tempfile.TemporaryDirectory(prefix="check-",dir=base) as temporary:
            dst=Path(temporary)/"db.sqlite3"
            for suffix in ("","-wal","-shm"):
                key=name+suffix
                if key not in rows:continue
                path=C.R.T.resolve_source(roots,key);sha=hashlib.sha256()
                with (Path(str(dst)+suffix)).open("xb") as out:
                    for block in C.R.T.read_blocks(path,identities[key]):
                        guard();sha.update(block);out.write(block)
                H.need(sha.hexdigest()==rows[key]["sha256"],"WAL_SOURCE_DRIFT_STOP")
                source[key]=path
            try:
                strict_wal(Path(str(dst)+"-wal"))
                # Private disposable copy, read-only connection, WAL-aware.
                con=sqlite3.connect(dst.as_uri()+"?mode=ro",uri=True,timeout=1)
                try:
                    con.execute("PRAGMA trusted_schema=OFF");con.execute("PRAGMA query_only=ON")
                    H.need(con.execute("PRAGMA integrity_check").fetchall()==[("ok",)],"WAL_INTEGRITY_STOP")
                    cursors.append(con.execute("SELECT count(*),coalesce(max(seq),0) FROM messages").fetchone())
                finally:con.close()
            except sqlite3.Error:raise H.Stop("WAL_INTEGRITY_STOP") from None
            for key,path in source.items():
                sha=hashlib.sha256()
                for block in C.R.T.read_blocks(path,identities[key]):guard();sha.update(block)
                H.need(sha.hexdigest()==rows[key]["sha256"],"WAL_SOURCE_DRIFT_STOP")
            guard(True)
    return cursors
