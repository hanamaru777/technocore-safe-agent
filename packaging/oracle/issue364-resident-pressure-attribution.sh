#!/usr/bin/env bash
# Issue #364: bounded read-only Resident pressure attribution.
set -u
umask 077

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
RESHB=$STATE/observer/resident-heartbeat.json
RESSTATE=$STATE/observer/resident-state.json
RESCFG=$STATE/observer/resident-config.json
RES=technocore-safe-agent-resident.service

EXPECTED_APP_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe
EXPECTED_CORE_EVENTS=117
EXPECTED_CORE_MESSAGES=5083155
EXPECTED_RES_PID=1868797
EXPECTED_RES_RESTARTS=0

TMPDIR=$(mktemp -d /tmp/issue364.XXXXXX)
cleanup() { rm -rf -- "$TMPDIR"; }
trap cleanup EXIT

echo '=== ISSUE364 RESIDENT PRESSURE ATTRIBUTION READ-ONLY ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'ISSUE364=STOP:not_root'
  exit 0
fi

for path in "$APP/.git" "$OBS" "$RESHB" "$RESSTATE" "$RESCFG"; do
  if [[ ! -e "$path" ]]; then
    echo 'ISSUE364=STOP:required_path_missing'
    exit 0
  fi
done

APP_HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
RES_PID=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
RES_RESTARTS=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
RES_ACTIVE=$(systemctl is-active "$RES" 2>/dev/null || true)
RES_RESULT=$(systemctl show "$RES" -p Result --value 2>/dev/null || true)

echo "APP_HEAD=$APP_HEAD"
if [[ -z "$WORKTREE" ]]; then echo 'WORKTREE_CLEAN=YES'; else echo 'WORKTREE_CLEAN=NO'; fi
echo "SERVICE=RESIDENT ACTIVE=$RES_ACTIVE PID=$RES_PID NRESTARTS=$RES_RESTARTS RESULT=$RES_RESULT"

if [[ "$APP_HEAD" != "$EXPECTED_APP_HEAD" ]]; then
  echo 'ISSUE364=STOP:app_head_changed'
  exit 0
fi
if [[ -n "$WORKTREE" ]]; then
  echo 'ISSUE364=STOP:worktree_not_clean'
  exit 0
fi
if [[ "$RES_ACTIVE" != active || "$RES_RESULT" != success ]]; then
  echo 'ISSUE364=STOP:resident_service_not_healthy'
  exit 0
fi
if [[ "$RES_PID" != "$EXPECTED_RES_PID" || "$RES_RESTARTS" != "$EXPECTED_RES_RESTARTS" ]]; then
  echo 'ISSUE364=STOP:resident_baseline_changed'
  exit 0
fi

python3 - "$OBS" "$RESHB" "$RESSTATE" "$RESCFG" "$RES_PID" "$EXPECTED_CORE_EVENTS" "$EXPECTED_CORE_MESSAGES" <<'PY'
import json
import os
import pathlib
import sys
import time
from datetime import UTC, datetime

OBS=pathlib.Path(sys.argv[1])
HB=pathlib.Path(sys.argv[2])
RS=pathlib.Path(sys.argv[3])
CFG=pathlib.Path(sys.argv[4])
MAIN_PID=int(sys.argv[5])
EXPECTED_EVENTS=str(sys.argv[6])
EXPECTED_MESSAGES=str(sys.argv[7])
PAGE_KIB=os.sysconf("SC_PAGE_SIZE") // 1024
TICKS=os.sysconf("SC_CLK_TCK")

def load_json(path):
    return json.loads(path.read_text("utf-8"))

def age(value):
    if not isinstance(value,str) or not value:
        return -1
    try:
        dt=datetime.fromisoformat(value)
    except Exception:
        return -1
    if dt.tzinfo is None:
        dt=dt.replace(tzinfo=UTC)
    return max(0.0,(datetime.now(UTC)-dt).total_seconds())

def stat_fields(pid):
    p=pathlib.Path(f"/proc/{pid}/stat")
    raw=p.read_text("utf-8",errors="replace")
    right=raw.rfind(")")
    if right < 0:
        raise RuntimeError("bad_proc_stat")
    comm=raw[raw.find("(")+1:right]
    rest=raw[right+2:].split()
    return {
        "pid": pid,
        "comm": comm[:64],
        "state": rest[0],
        "ppid": int(rest[1]),
        "minflt": int(rest[7]),
        "majflt": int(rest[9]),
        "utime": int(rest[11]),
        "stime": int(rest[12]),
        "rss_kib": int(rest[21]) * PAGE_KIB,
    }

def proc_status(pid):
    out={}
    try:
        lines=pathlib.Path(f"/proc/{pid}/status").read_text("utf-8",errors="replace").splitlines()
    except Exception:
        return out
    wanted={"Threads","VmRSS","RssAnon","RssFile","VmSwap","voluntary_ctxt_switches","nonvoluntary_ctxt_switches"}
    for line in lines:
        if ":" not in line: continue
        k,v=line.split(":",1)
        if k in wanted:
            out[k]=v.strip().split()[0]
    return out

def proc_io(pid):
    out={}
    try:
        lines=pathlib.Path(f"/proc/{pid}/io").read_text("utf-8",errors="replace").splitlines()
    except Exception:
        return out
    for line in lines:
        if ":" not in line: continue
        k,v=line.split(":",1)
        if k in {"rchar","wchar","syscr","syscw","read_bytes","write_bytes","cancelled_write_bytes"}:
            try: out[k]=int(v.strip())
            except Exception: pass
    return out

def wchan(pid):
    try:
        return pathlib.Path(f"/proc/{pid}/wchan").read_text("utf-8",errors="replace").strip()[:80]
    except Exception:
        return "unavailable"

def all_processes():
    rows={}
    for p in pathlib.Path("/proc").iterdir():
        if not p.name.isdigit(): continue
        try:
            s=stat_fields(int(p.name))
        except Exception:
            continue
        rows[s["pid"]]=s
    return rows

def descendants(main_pid, rows):
    found=[]
    frontier=[main_pid]
    seen={main_pid}
    while frontier:
        parent=frontier.pop()
        for pid,row in rows.items():
            if pid in seen: continue
            if row["ppid"]==parent:
                seen.add(pid); found.append(pid); frontier.append(pid)
    return sorted(found)

def psi(kind):
    out={}
    p=pathlib.Path("/proc/pressure")/kind
    if not p.exists(): return out
    for line in p.read_text("utf-8",errors="replace").splitlines():
        parts=line.split()
        if not parts: continue
        level=parts[0]
        vals={}
        for item in parts[1:]:
            if "=" not in item: continue
            k,v=item.split("=",1)
            try: vals[k]=float(v) if k.startswith("avg") else int(v)
            except Exception: pass
        out[level]=vals
    return out

def vmstat():
    keys={"pgfault","pgmajfault","pswpin","pswpout","pgscan_kswapd","pgsteal_kswapd","pgscan_direct","pgsteal_direct","oom_kill"}
    out={}
    for line in pathlib.Path("/proc/vmstat").read_text("utf-8",errors="replace").splitlines():
        parts=line.split()
        if len(parts)==2 and parts[0] in keys:
            out[parts[0]]=int(parts[1])
    return out

def meminfo():
    keys={"MemTotal","MemAvailable","SwapTotal","SwapFree","Dirty","Writeback"}
    out={}
    for line in pathlib.Path("/proc/meminfo").read_text("utf-8",errors="replace").splitlines():
        if ":" not in line: continue
        k,v=line.split(":",1)
        if k in keys:
            out[k]=int(v.strip().split()[0])
    return out

def heartbeat_state():
    hb=load_json(HB)
    rs=load_json(RS)
    obs=load_json(OBS)
    cfg=load_json(CFG)
    metrics=obs.get("metrics") or {}
    core=(str(metrics.get("unrecoverable_core_gap_events","missing")),str(metrics.get("unrecoverable_core_gap_messages","missing")))
    if core != (EXPECTED_EVENTS,EXPECTED_MESSAGES):
        print("PROTECTED_CORE=CHANGED:"+"/".join(core))
        raise SystemExit(20)
    resident_status=hb.get("resident_status") if isinstance(hb,dict) else {}
    if not isinstance(resident_status,dict): resident_status={}
    daemon=rs.get("daemon") if isinstance(rs,dict) else {}
    if not isinstance(daemon,dict): daemon={}
    return {
        "hb_updated": hb.get("updated_at") if isinstance(hb,dict) else None,
        "hb_age": age(hb.get("updated_at") if isinstance(hb,dict) else None),
        "hb_refresh": resident_status.get("last_refresh_at"),
        "hb_refresh_age": age(resident_status.get("last_refresh_at")),
        "state_updated": rs.get("updated_at") if isinstance(rs,dict) else None,
        "state_age": age(rs.get("updated_at") if isinstance(rs,dict) else None),
        "state_refresh": daemon.get("last_refresh_at"),
        "state_refresh_age": age(daemon.get("last_refresh_at")),
        "observer_agents": len(obs.get("agents") or {}),
        "observer_rooms": len(obs.get("rooms") or {}),
        "relationships": len(rs.get("relationships") or {}),
        "candidates": len(rs.get("candidates") or {}),
        "feedback": len(rs.get("feedback") or []),
        "published": len(rs.get("published") or []),
        "refresh_interval": cfg.get("refresh_interval_seconds"),
        "core": core,
    }

def file_meta(path):
    st=path.stat()
    return {"size":st.st_size,"mtime":st.st_mtime}

def snap(tag):
    rows=all_processes()
    if MAIN_PID not in rows:
        print(f"SNAPSHOT_{tag}=STOP:main_pid_missing")
        raise SystemExit(21)
    ds=descendants(MAIN_PID,rows)
    selected=[MAIN_PID]+ds
    procs={}
    for pid in selected:
        row=rows.get(pid)
        if not row: continue
        row=dict(row)
        row["io"]=proc_io(pid)
        row["status"]=proc_status(pid)
        row["wchan"]=wchan(pid)
        procs[pid]=row

    hs=heartbeat_state()
    loadavg=pathlib.Path("/proc/loadavg").read_text("utf-8").split()[:3]
    snap={
        "tag":tag,
        "epoch":time.time(),
        "descendants":ds,
        "procs":procs,
        "psi":{k:psi(k) for k in ("cpu","memory","io")},
        "vmstat":vmstat(),
        "meminfo":meminfo(),
        "heartbeat":hs,
        "files":{"heartbeat":file_meta(HB),"resident_state":file_meta(RS),"observer_state":file_meta(OBS)},
        "loadavg":loadavg,
    }

    print(f"SNAPSHOT={tag} DESCENDANTS={len(ds)} LOADAVG={'/'.join(loadavg)}")
    print(f"CORE={hs['core'][0]}/{hs['core'][1]} REFRESH_INTERVAL={hs['refresh_interval']}")
    print(f"RESIDENT_HEARTBEAT_AGE={hs['hb_age']:.1f} RESIDENT_REFRESH_AGE={hs['hb_refresh_age']:.1f} RESIDENT_STATE_AGE={hs['state_age']:.1f}")
    print(f"STATE_COUNTS observer_agents={hs['observer_agents']} observer_rooms={hs['observer_rooms']} relationships={hs['relationships']} candidates={hs['candidates']} feedback={hs['feedback']} published={hs['published']}")
    print(f"STATE_BYTES heartbeat={snap['files']['heartbeat']['size']} resident={snap['files']['resident_state']['size']} observer={snap['files']['observer_state']['size']}")
    mi=snap["meminfo"]
    print("MEM_KIB "+ " ".join(f"{k}={mi.get(k,'NA')}" for k in ("MemAvailable","SwapFree","SwapTotal","Dirty","Writeback")))
    for kind in ("cpu","memory","io"):
        p=snap["psi"].get(kind,{})
        some=p.get("some",{})
        full=p.get("full",{})
        print(f"PSI_{kind.upper()} some_total={some.get('total','NA')} full_total={full.get('total','NA')}")
    for pid in selected:
        row=procs.get(pid)
        if not row: continue
        io=row["io"]; st=row["status"]
        role="MAIN" if pid==MAIN_PID else "DESC"
        print(
            f"PROC {tag} role={role} pid={pid} ppid={row['ppid']} comm={row['comm']} state={row['state']} "
            f"cpu_ticks={row['utime']+row['stime']} minflt={row['minflt']} majflt={row['majflt']} rss_kib={row['rss_kib']} "
            f"wchan={row['wchan']} read_bytes={io.get('read_bytes','NA')} write_bytes={io.get('write_bytes','NA')} "
            f"rchar={io.get('rchar','NA')} wchar={io.get('wchar','NA')} threads={st.get('Threads','NA')} "
            f"rss_anon_kib={st.get('RssAnon','NA')} rss_file_kib={st.get('RssFile','NA')} vm_swap_kib={st.get('VmSwap','NA')}"
        )
    return snap

def delta(a,b):
    print("--- DELTA T0_TO_T40 ---")
    for pid,row0 in a["procs"].items():
        row1=b["procs"].get(pid)
        if not row1: 
            print(f"PROC_DELTA pid={pid} status=EXITED_OR_REPLACED")
            continue
        io0=row0["io"]; io1=row1["io"]
        print(
            f"PROC_DELTA pid={pid} comm={row1['comm']} "
            f"cpu_ticks={row1['utime']+row1['stime']-(row0['utime']+row0['stime'])} "
            f"minflt={row1['minflt']-row0['minflt']} majflt={row1['majflt']-row0['majflt']} "
            f"rss_kib={row1['rss_kib']-row0['rss_kib']} "
            f"read_bytes={io1.get('read_bytes',0)-io0.get('read_bytes',0)} "
            f"write_bytes={io1.get('write_bytes',0)-io0.get('write_bytes',0)} "
            f"rchar={io1.get('rchar',0)-io0.get('rchar',0)} wchar={io1.get('wchar',0)-io0.get('wchar',0)}"
        )
    for kind in ("cpu","memory","io"):
        for level in ("some","full"):
            x=a["psi"].get(kind,{}).get(level,{}).get("total")
            y=b["psi"].get(kind,{}).get(level,{}).get("total")
            if isinstance(x,int) and isinstance(y,int):
                print(f"PSI_DELTA kind={kind} level={level} total_us={y-x}")
    for key in sorted(set(a["vmstat"])|set(b["vmstat"])):
        print(f"VMSTAT_DELTA {key}={b['vmstat'].get(key,0)-a['vmstat'].get(key,0)}")
    h0=a["heartbeat"]; h1=b["heartbeat"]
    print("HEARTBEAT_UPDATED_DURING_WINDOW="+("YES" if h0["hb_updated"]!=h1["hb_updated"] else "NO"))
    print("RESIDENT_STATE_UPDATED_DURING_WINDOW="+("YES" if h0["state_updated"]!=h1["state_updated"] else "NO"))
    print("LAST_REFRESH_CHANGED_DURING_WINDOW="+("YES" if h0["hb_refresh"]!=h1["hb_refresh"] else "NO"))

a=snap("T0")
time.sleep(20)
m=snap("T20")
time.sleep(20)
b=snap("T40")
delta(a,b)
print("ISSUE364_PYTHON_PROBE=PASS")
PY
PY_RC=$?
echo "ISSUE364_PYTHON_RC=$PY_RC"

RES_PID_POST=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
RES_RESTARTS_POST=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
RES_ACTIVE_POST=$(systemctl is-active "$RES" 2>/dev/null || true)
echo "POST_SERVICE=RESIDENT ACTIVE=$RES_ACTIVE_POST PID=$RES_PID_POST NRESTARTS=$RES_RESTARTS_POST"

journalctl -u "$RES" --since '45 minutes ago' --no-pager --output=cat >"$TMPDIR/resident.log" 2>/dev/null || true
python3 - "$TMPDIR/resident.log" <<'PY'
import pathlib,sys
text=pathlib.Path(sys.argv[1]).read_text("utf-8",errors="replace").lower()
patterns={
    "TRACEBACK":("traceback",),
    "MAINTENANCE_EXIT":("resident maintenance process exited unexpectedly",),
    "OOM":("out of memory","oom-kill","oom kill"),
    "MEMORY_ERROR":("memoryerror",),
    "KILLED":("killed process",),
    "RUNTIME_ERROR":("runtimeerror",),
}
for label,needles in patterns.items():
    print("JOURNAL_CLASS_"+label+"="+str(sum(text.count(n) for n in needles)))
PY

echo '--- SAFETY TAIL ---'
echo 'MUTATION_COMMANDS=NONE'
echo 'SERVICE_RESTART=NO'
echo 'PROCESS_SIGNAL=NO'
echo 'STRACE_ATTACH=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'TECHNOCORE_WRITE=NO'
echo 'SNAP_MUTATION=NO'
echo 'RAW_JOURNAL_OUTPUT=NO'
echo '=== ISSUE364_PRESSURE_ATTRIBUTION=COMPLETE_READ_ONLY ==='
exit 0
