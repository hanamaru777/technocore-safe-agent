"""R1095: one-shot original OCI proven orphan atomic-temp cleanup only.

DESTRUCTIVE only with --apply-obsolete-atomic-temp. No write to SQLite,
signer, autopilot, active state, records, logs, backup, or unknown files.
Exact original source, single fixed observer dir, strict two-phase validation,
FD inode exclusion. No generic shell or user-supplied paths.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

APP=Path("/opt/technocore-safe-agent")
STATE=Path("/var/lib/technocore-safe-agent")
OBS=STATE/"observer"
HEAD="ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
AGE_SECONDS=7*86400
MAX_ENTRIES=10000
MAX_FDS=65536
MAX_SECS=43
# Exactly the atomic temp prefix and suffix produced by original observer.py.
BASES=frozenset(("observer-state.json","resident-state.json",
  "observer-heartbeat.json","resident-heartbeat.json","observer-config.json",
  "resident-config.json","resident-control.json"))
TEMP=re.compile(r"\A\.([a-z0-9-]+\.json)\.([a-z0-9_]{8})\.tmp\Z")
class Refuse(Exception):pass
def need(ok,reason):
    if not ok:raise Refuse(reason)

def verify_host():
    need(sys.platform=="linux" and os.geteuid()==0,"OWNER_ROOT_REQUIRED")
    for path in (APP,STATE,OBS):
        for d in (path,*path.parents):
            need(not d.is_symlink(),"PARENT_SYMLINK_STOP")
        need(stat.S_ISDIR(path.lstat().st_mode),"ROOT_TYPE_STOP")
    p=subprocess.run(["/usr/bin/git","-c","safe.directory="+str(APP),
        "-C",str(APP),"rev-parse","--verify","HEAD"],
        stdin=subprocess.DEVNULL,capture_output=True,timeout=10,
        env={"PATH":"/usr/bin:/bin","HOME":"/nonexistent",
             "GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null",
             "GIT_OPTIONAL_LOCKS":"0"})
    need(p.returncode==0 and p.stdout==(HEAD+"\n").encode(),"ORIGINAL_HEAD_STOP")

def candidates(obs,now):
    # Read only directory metadata; never look into SQLite, archives or state JSON.
    root=obs.lstat()
    need(stat.S_ISDIR(root.st_mode),"ROOT_TYPE_STOP")
    cutoff=now-AGE_SECONDS
    eligible=[]
    counted=0;old_unknown=0;matched=0;skipped=0;bytes_eligible=0
    with os.scandir(obs) as entries:
        for entry in entries:
            counted+=1
            need(counted<=MAX_ENTRIES,"ENTRY_BUDGET_STOP")
            path=obs/entry.name
            s=path.lstat()
            if s.st_mtime > cutoff and s.st_ctime > cutoff:
                continue
            m=TEMP.fullmatch(entry.name)
            if not m or m.group(1) not in BASES:
                if stat.S_ISREG(s.st_mode) and entry.name.endswith(".tmp"):
                    old_unknown+=1
                continue
            matched+=1
            if (not stat.S_ISREG(s.st_mode) or s.st_dev!=root.st_dev or
                s.st_nlink!=1 or s.st_mtime > cutoff or s.st_ctime > cutoff):
                skipped+=1
                continue
            target=obs/m.group(1)
            try: c=target.lstat()
            except FileNotFoundError:
                skipped+=1;continue
            if (not stat.S_ISREG(c.st_mode) or c.st_dev!=root.st_dev or
                c.st_nlink!=1 or c.st_size<1 or c.st_mtime_ns<=s.st_mtime_ns):
                skipped+=1;continue
            eligible.append((entry.name,m.group(1),
                  (s.st_dev,s.st_ino,s.st_mtime_ns,s.st_ctime_ns,s.st_size),
                  (c.st_dev,c.st_ino,c.st_mtime_ns),s.st_blocks*512))
            bytes_eligible+=s.st_blocks*512
    return {"entries":counted,"matching_tmp":matched,"skipped_tmp":skipped,
            "unknown_tmp":old_unknown,"eligible":len(eligible),
            "eligible_bytes":bytes_eligible},eligible

def no_candidate_handles(eligible):
    inodes=frozenset((x[2][0],x[2][1]) for x in eligible)
    if not inodes:return
    count=0
    with os.scandir("/proc") as entries:
        pids=[str(p.name) for p in entries if p.name.isdecimal()]
    need(len(pids)<=4096,"PID_BUDGET_STOP")
    for pid in pids:
        try:
            with os.scandir("/proc/"+pid+"/fd") as entries:
                fds=[x.name for x in entries]
        except FileNotFoundError:continue
        except PermissionError as exc:raise Refuse("FD_VISIBILITY_STOP") from exc
        for fd in fds:
            count+=1
            need(count<=MAX_FDS,"FD_BUDGET_STOP")
            try:
                f=os.stat("/proc/"+pid+"/fd/"+fd)
            except FileNotFoundError:continue
            except PermissionError as exc:raise Refuse("FD_VISIBILITY_STOP") from exc
            if (f.st_dev,f.st_ino) in inodes:
                raise Refuse("CANDIDATE_OPEN_FD_STOP")

def apply(obs,entries,now):
    # All candidates validated first, no active FD to any candidate.
    no_candidate_handles(entries)
    root=obs.lstat()
    fd=os.open(obs,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    deleted=0;bytes_unlinked=0
    try:
        d=os.fstat(fd)
        need((d.st_dev,d.st_ino)==(root.st_dev,root.st_ino),"ROOT_REPLACED_STOP")
        cutoff=now-AGE_SECONDS
        for name,canonical,expected,canonicalExpected,allocated in entries:
            st=os.stat(name,dir_fd=fd,follow_symlinks=False)
            need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
                 (st.st_dev,st.st_ino,st.st_mtime_ns,st.st_ctime_ns,st.st_size)==expected
                 and st.st_mtime<=cutoff and st.st_ctime<=cutoff,"CANDIDATE_CHANGED_STOP")
            c=os.stat(canonical,dir_fd=fd,follow_symlinks=False)
            need(stat.S_ISREG(c.st_mode) and c.st_nlink==1 and c.st_size>0 and
                 (c.st_dev,c.st_ino,c.st_mtime_ns)==canonicalExpected and
                 c.st_mtime_ns>st.st_mtime_ns,"CANONICAL_CHANGED_STOP")
            os.unlink(name,dir_fd=fd)
            deleted+=1;bytes_unlinked+=allocated
    finally:os.close(fd)
    return deleted,bytes_unlinked

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--apply-obsolete-atomic-temp",action="store_true")
    args=parser.parse_args()
    try:
        verify_host()
        now=time.time()
        before=shutil.disk_usage(OBS).free
        stats,eligible=candidates(OBS,now)
        count=freed=0
        if args.apply_obsolete_atomic_temp:
            count,freed=apply(OBS,eligible,now)
        after=shutil.disk_usage(OBS).free
        payload={"phase":"R1095","result":"APPLIED" if args.apply_obsolete_atomic_temp
                 else "INVENTORY_ONLY","dry_run":not args.apply_obsolete_atomic_temp,
                 **stats,"deleted":count,"deleted_allocated_bytes":freed,
                 "disk_free_before":before,"disk_free_after":after,
                 "source":"ORIGINAL_PINNED","protected_data":"UNTOUCHED",
                 "historical_autopilot_archive":"PRESERVED",
                 "cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}
        print(json.dumps(payload,separators=(",",":"),sort_keys=True))
        return 0
    except (Refuse,OSError,subprocess.SubprocessError) as exc:
        print("R1095_STOP="+(str(exc) if isinstance(exc,Refuse) else "HOST_STOP"),file=sys.stderr)
        return 42

if __name__=="__main__":raise SystemExit(main())
