"""R1094: read-only exact hotspots, no content reads, no state mutations."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

APP=Path("/opt/technocore-safe-agent")
STATE=Path("/var/lib/technocore-safe-agent")
ROOTS={"observer":STATE/"observer","autopilot":STATE/"autopilot"}
HEAD="ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
MAX_OBJECTS=100000
MAX_SECONDS=42
MAX_DEPTH=48
NAME=re.compile(r"[A-Za-z0-9._-]{1,100}\Z")
PRIVATE=re.compile(r"secret|credential|password|private|seed|token|key",re.I)

class Stop(Exception): pass
def need(ok, code):
    if not ok: raise Stop(code)

def preflight():
    need(sys.platform=="linux" and os.geteuid()==0,"ROOT_STOP")
    for path in (APP,STATE,*ROOTS.values()):
        for ancestor in (path,*path.parents):
            need(not ancestor.is_symlink(),"ROOT_LINK_STOP")
        need(stat.S_ISDIR(path.lstat().st_mode),"ROOT_TYPE_STOP")
    out=subprocess.run(["/usr/bin/git","-c","safe.directory="+str(APP),
        "-C",str(APP),"rev-parse","--verify","HEAD"],
        stdin=subprocess.DEVNULL,capture_output=True,timeout=10,
        env={"PATH":"/usr/bin:/bin","HOME":"/nonexistent",
             "GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null",
             "GIT_OPTIONAL_LOCKS":"0"})
    need(out.returncode==0 and out.stdout==(HEAD+"\n").encode(),"HEAD_STOP")

def label(name,root):
    if name in ("lobby-capture.sqlite3","lobby-capture-service.sqlite3"):
        return "LIVE_SQLITE"
    if name.endswith(("-wal","-shm")): return "SQLITE_SIDECAR"
    if root=="observer" and (
        name.startswith(".observer-state.json.") and name.endswith(".tmp")
        or name.startswith(".compact-estimate.") and name.endswith(".tmp")
        or name.startswith(".observer-heartbeat.json.") and name.endswith(".tmp")
        or name.startswith(".observer-config.json.") and name.endswith(".tmp")):
        return "OBSERVER_ATOMIC_TMP"
    if name.endswith((".tmp",".temp")): return "UNCLASSIFIED_TEMP"
    if root=="observer" and name=="observer-state.json":return "OBSERVER_STATE"
    if root=="autopilot" and name=="autopilot-outbox.json":return "AUTOPILOT_OUTBOX"
    if root=="autopilot" and name.startswith("autopilot-audit.jsonl"):
        return "AUTOPILOT_AUDIT_FAMILY"
    if name.endswith(".jsonl"):return "OTHER_JSONL"
    if name.endswith(".json"):return "OTHER_JSON"
    if name.endswith((".bak",".old",".backup",".gz",".zip",".zst")):
        return "BACKUP_OR_ARCHIVE_UNVERIFIED"
    if name.endswith(".log"):return "LOG"
    return "OTHER"

def file_brief(path, rel, meta,root,now):
    name=path.name
    safe=name if NAME.fullmatch(name) and not PRIVATE.search(name) else "REDACTED"
    return {"token":hashlib.sha256(rel.as_posix().encode("utf-8",errors="surrogateescape")).hexdigest()[:12],
      "basename":safe,"class":label(name,root),"allocated_bytes":meta.st_blocks*512,
      "logical_bytes":meta.st_size,"age_days":max(0,min(36500,int((now-meta.st_mtime)//86400))),
      "hardlinks":meta.st_nlink}

def scan(root,kind,start,now):
    device=root.lstat().st_dev
    count=0
    totals={}
    items=[]
    stack=[(root,Path(),0)]
    while stack:
        need(time.monotonic()-start<=MAX_SECONDS,"TIME_STOP")
        path,rel,depth=stack.pop()
        count+=1
        need(count<=MAX_OBJECTS and depth<=MAX_DEPTH,"COUNT_STOP")
        st=path.lstat()
        need(st.st_dev==device,"MOUNT_STOP")
        if stat.S_ISLNK(st.st_mode):continue
        if stat.S_ISDIR(st.st_mode):
            with os.scandir(path) as it:
                stack.extend((Path(e.path),rel/e.name,depth+1) for e in it)
            continue
        need(stat.S_ISREG(st.st_mode),"TYPE_STOP")
        b=file_brief(path,rel,st,kind,now)
        cat=b["class"]; group=totals.setdefault(cat,{"files":0,"allocated_bytes":0,
            "over_7d_files":0,"over_7d_bytes":0,"over_30d_files":0,"over_30d_bytes":0})
        group["files"]+=1
        group["allocated_bytes"]+=b["allocated_bytes"]
        if b["age_days"]>=7:
            group["over_7d_files"]+=1;group["over_7d_bytes"]+=b["allocated_bytes"]
        if b["age_days"]>=30:
            group["over_30d_files"]+=1;group["over_30d_bytes"]+=b["allocated_bytes"]
        items.append(b)
    items.sort(key=lambda x:(x["allocated_bytes"],x["token"]),reverse=True)
    top=items[:8]
    return {"objects":count,"regular_files":len(items),
        "allocated_bytes":sum(x["allocated_bytes"] for x in items),
        "categories":totals,"top":top}

def main():
    try:
        preflight()
        start=time.monotonic();now=time.time()
        roots={name:scan(root,name,start,now) for name,root in ROOTS.items()}
        result={"schema":1,"phase":"R1094","result":"ATTRIBUTION_READONLY",
            "roots":roots,"action":"READ_ONLY","cutover":"NO_GO",
            "oci_retirement":"STRICT_NO_GO"}
        print(json.dumps(result,separators=(",",":"),sort_keys=True,ensure_ascii=True))
        return 0
    except (Stop,OSError,subprocess.SubprocessError) as exc:
        code=str(exc) if isinstance(exc,Stop) else "HOST_STOP"
        print("R1094_STOP="+code,file=sys.stderr)
        return 42

if __name__=="__main__":raise SystemExit(main())
