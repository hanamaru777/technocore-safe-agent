"""R1093: single bounded READ-ONLY attribution of two known OCI FLOP hot directories.

Never reads file contents or SQLite, opens sockets, stops a service, writes, or
deletes. Returns only bounded anonymized metadata: allocated size, known file
type, age, and a nonreversible path token. Does NOT replace consumed R1072
full-root census or prove source coherency.
"""
import hashlib
import heapq
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

APP = Path("/opt/technocore-safe-agent")
STATE = Path("/var/lib/technocore-safe-agent")
ROOTS = {"observer": STATE / "observer", "autopilot": STATE / "autopilot"}
EXPECTED_HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
MAX_ENTRIES = 100000
MAX_DEPTH = 48
TOP_N = 12
MAX_TIME = 42

class Stop(Exception):
    pass

def need(ok, code):
    if not ok:
        raise Stop(code)

def check_host():
    need(sys.platform == "linux" and os.geteuid() == 0, "ORIGINAL_ROOT_STOP")
    for root in (APP, STATE, *ROOTS.values()):
        need(root.is_absolute(), "ROOT_PATH_STOP")
        for node in (root, *root.parents):
            need(not node.is_symlink(), "ROOT_SYMLINK_STOP")
        need(stat.S_ISDIR(root.lstat().st_mode), "ROOT_TYPE_STOP")
    done = subprocess.run(
        ["/usr/bin/git", "-c", "safe.directory=" + str(APP), "-C", str(APP),
         "rev-parse", "--verify", "HEAD"],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
             "GIT_OPTIONAL_LOCKS": "0"})
    need(done.returncode == 0 and done.stdout == (EXPECTED_HEAD + "\n").encode(), "ORIGINAL_HEAD_STOP")

def kind(name):
    fixed = {
        "lobby-capture.sqlite3": "CAPTURE_DB",
        "lobby-capture-service.sqlite3": "SERVICE_DB",
        "lobby-capture.sqlite3-wal": "CAPTURE_WAL",
        "lobby-capture-service.sqlite3-wal": "SERVICE_WAL",
        "lobby-capture.sqlite3-shm": "CAPTURE_SHM",
        "lobby-capture-service.sqlite3-shm": "SERVICE_SHM",
        "observer-state.json": "OBSERVER_STATE",
        "autopilot-outbox.json": "AUTOPILOT_OUTBOX",
        "autopilot-audit.jsonl": "AUTOPILOT_AUDIT"
    }
    if name in fixed:
        return fixed[name]
    if name.endswith((".sqlite", ".sqlite3", ".db")): return "OTHER_DB"
    if name.endswith("-wal"): return "OTHER_WAL"
    if name.endswith("-shm"): return "OTHER_SHM"
    if name.endswith(".jsonl"): return "JSONL"
    if name.endswith(".json"): return "JSON"
    if name.endswith(".log"): return "LOG"
    if name.endswith((".bak", ".backup", ".old")): return "BACKUP_CANDIDATE_UNVERIFIED"
    if name.endswith((".tmp", ".temp")): return "TEMP_CANDIDATE_UNVERIFIED"
    return "OTHER"

def scan(root, start, now, limit=MAX_ENTRIES):
    root_device = root.lstat().st_dev
    used=0
    count=0
    regular=0
    links=0
    top=[]
    # No file payload read, no link following. All symlinks are metadata-only.
    todo=[(root, Path(), 0)]
    while todo:
        need(time.monotonic()-start <= MAX_TIME, "TIME_BOUND_STOP")
        path, rel, depth = todo.pop()
        count+=1
        need(count <= limit and depth <= MAX_DEPTH, "COUNT_BOUND_STOP")
        s=path.lstat()
        need(s.st_dev == root_device, "CROSS_MOUNT_STOP")
        used+=s.st_blocks*512
        if stat.S_ISLNK(s.st_mode):
            links+=1
            continue
        if stat.S_ISDIR(s.st_mode):
            with os.scandir(path) as entries:
                for e in entries:
                    todo.append((Path(e.path), rel/e.name, depth+1))
            continue
        need(stat.S_ISREG(s.st_mode), "SPECIAL_OBJECT_STOP")
        regular+=1
        rel_bytes=rel.as_posix().encode("utf-8",errors="surrogateescape")
        token=hashlib.sha256(rel_bytes).hexdigest()[:12]
        age=max(0,min(36500,int((now-s.st_mtime)//86400)))
        row={"token":token,"kind":kind(path.name),"allocated_bytes":s.st_blocks*512,
             "logical_bytes":s.st_size,"age_days":age}
        rec=(row["allocated_bytes"],token,row)
        if len(top)<TOP_N: heapq.heappush(top,rec)
        elif rec[:2]>top[0][:2]: heapq.heapreplace(top,rec)
    return {"allocated_bytes":used,"objects":count,"regular_files":regular,
            "symlinks":links,"largest":[row for _,_,row in sorted(top,reverse=True)]}

def main():
    try:
        check_host()
        now=time.time()
        start=time.monotonic()
        stats={name:scan(root,start,now) for name,root in ROOTS.items()}
        payload={"schema_version":1,"phase":"R1093","result":"HOTSPOTS_ONLY",
                 "head":"MATCH","roots":stats,
                 "disk_free_bytes":shutil.disk_usage(STATE).free,
                 "action":"READ_ONLY","cutover":"NO_GO",
                 "oci_retirement":"STRICT_NO_GO"}
        print(json.dumps(payload,separators=(",",":"),sort_keys=True))
        return 0
    except (Stop,OSError,subprocess.SubprocessError) as exc:
        code = str(exc) if isinstance(exc, Stop) else "HOST_STOP"
        print("R1093_STOP="+code,file=sys.stderr)
        return 42

if __name__ == "__main__":
    sys.exit(main())
