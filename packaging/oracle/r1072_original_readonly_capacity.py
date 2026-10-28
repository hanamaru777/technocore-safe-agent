"""R1072 read-only ORIGINAL source backup feasibility (no content read).

Only size/type metadata: never open state payload, SQLite DB, WAL, wallet,
signer, credentials, environment, systemd or cron; no writer change.
Cannot prove a coherent checkpoint or authorize any backup/cutover.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

APP=Path("/opt/technocore-safe-agent")
STATE=Path("/var/lib/technocore-safe-agent")
EXPECTED_SHA="ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
DB_FILES=frozenset(("lobby-capture.sqlite3","lobby-capture-service.sqlite3"))
MAX_OBJECTS=25000
MAX_TOTAL=64*1024**3
TIME_LIMIT=35

class Stop(ValueError):
    pass

def require(v, code="SOURCE_UNVERIFIED"):
    if not v:
        raise Stop(code)

def assert_original():
    require(sys.platform=="linux" and os.geteuid()==0, "ORIGINAL_PRIVILEGE_STOP")
    for forbidden in ("/opt/flop-shadow","/opt/tradebot-k137",
                      "/opt/tradebot-k137-private"):
        require(not os.path.lexists(forbidden), "WRONG_HOST_STOP")
    for root in (APP,STATE):
        for part in (root,*root.parents):
            s=part.lstat()
            require(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode), "ORIGINAL_ROOT_STOP")
    p=subprocess.run(["/usr/bin/git","-c","safe.directory="+str(APP),
        "-C",str(APP),"rev-parse","--verify","HEAD"],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,check=False,timeout=6,
        env={"PATH":"/usr/bin:/bin","HOME":"/nonexistent",
             "GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null",
             "GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0"})
    require(p.returncode==0 and p.stdout.strip()==EXPECTED_SHA.encode(), "ORIGINAL_HEAD_STOP")

def inventory():
    start=time.monotonic()
    totals={"entries":0,"regular":0,"directories":0,"symlinks":0,
            "hardlink_repeated":0,"special_objects":0,"regular_bytes":0,
            "sqlite_bases":0,"sqlite_wals":0,"sqlite_shms":0}
    found=set()
    seen=set()
    todo=[(APP,0),(STATE,0)]
    while todo:
        require(time.monotonic()-start<=TIME_LIMIT, "INVENTORY_TIME_STOP")
        path,depth=todo.pop()
        require(depth<=48 and len(os.fsencode(path))<=4096, "INVENTORY_PATH_STOP")
        info=path.lstat()
        totals["entries"]+=1
        require(totals["entries"]<=MAX_OBJECTS, "INVENTORY_ENTRY_STOP")
        if stat.S_ISDIR(info.st_mode):
            totals["directories"]+=1
            with os.scandir(path) as directory:
                children=[Path(row.path) for row in directory]
            require(len(children)<=MAX_OBJECTS, "INVENTORY_CHILD_STOP")
            todo.extend((item,depth+1) for item in children)
        elif stat.S_ISLNK(info.st_mode):
            totals["symlinks"]+=1
        elif stat.S_ISREG(info.st_mode):
            inode=(info.st_dev,info.st_ino)
            if info.st_nlink>1 and inode in seen:
                totals["hardlink_repeated"]+=1
            else:
                seen.add(inode)
                totals["regular"]+=1
                totals["regular_bytes"]+=info.st_size
            require(totals["regular_bytes"]<=MAX_TOTAL, "INVENTORY_BYTES_STOP")
            for name in DB_FILES:
                if path.name==name:
                    found.add(name)
                    totals["sqlite_bases"]+=1
                elif path.name==name+"-wal":
                    totals["sqlite_wals"]+=1
                elif path.name==name+"-shm":
                    totals["sqlite_shms"]+=1
        else:
            totals["special_objects"]+=1
    require(found==DB_FILES, "TWO_SQLITE_STOP")
    return totals

def main():
    try:
        assert_original()
        totals=inventory()
        fs=os.statvfs(STATE)
        free=fs.f_bavail*fs.f_frsize
        require(free>=0, "DISK_STATUS_STOP")
        print(json.dumps({"phase":"R1072_ORIGINAL_READONLY_CAPACITY",
            "result":"INVENTORY_ONLY","original_git":"MATCH",
            "tree":totals,"free_bytes":free,
            "writer_admission":"NOT_PROVEN","common_sqlite_epoch":"NOT_PROVEN",
            "original_archive":"NOT_CREATED","offhost_backup":"NOT_CREATED",
            "k137_restore":"NOT_PERFORMED","cutover":"NO_GO",
            "oci_retirement":"STRICT_NO_GO"},
            sort_keys=True,separators=(",",":")))
        return 0
    except Exception as exc:
        allowed = {"SOURCE_UNVERIFIED", "ORIGINAL_PRIVILEGE_STOP", "WRONG_HOST_STOP",
                   "ORIGINAL_ROOT_STOP", "ORIGINAL_HEAD_STOP", "INVENTORY_TIME_STOP",
                   "INVENTORY_PATH_STOP", "INVENTORY_ENTRY_STOP",
                   "INVENTORY_CHILD_STOP", "INVENTORY_BYTES_STOP",
                   "TWO_SQLITE_STOP", "DISK_STATUS_STOP"}
        code = str(exc) if type(exc) is Stop and str(exc) in allowed else "SOURCE_UNVERIFIED"
        print(json.dumps({"phase":"R1072_ORIGINAL_READONLY_CAPACITY",
            "result":"STOP","code":code,"cutover":"NO_GO",
            "oci_retirement":"STRICT_NO_GO"},separators=(",",":"),sort_keys=True))
        return 42

if __name__=="__main__":
    raise SystemExit(main())
