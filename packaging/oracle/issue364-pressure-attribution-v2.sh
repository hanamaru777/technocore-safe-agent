#!/usr/bin/env bash
# Issue #364 / #390: lightweight read-only pressure attribution.
set -u
umask 077

APP=/opt/technocore-safe-agent
APP_PY=$APP/.venv/bin/python
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
OBHB=$STATE/observer/observer-heartbeat.json
RESHB=$STATE/observer/resident-heartbeat.json

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service

EXPECTED_APP_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe
EXPECTED_CORE_EVENTS=119
EXPECTED_CORE_MESSAGES=5497275
EXPECTED_RES_PID=1868797
EXPECTED_RES_RESTARTS=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0

echo '=== ISSUE364 PRESSURE ATTRIBUTION V2 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'ISSUE364_PRESSUREV2=STOP:not_root'
  exit 0
fi

for path in "$APP/.git" "$APP_PY" "$OBS" "$OBHB" "$RESHB"; do
  if [[ ! -e "$path" ]]; then
    echo 'ISSUE364_PRESSUREV2=STOP:required_path_missing'
    exit 0
  fi
done

APP_HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "APP_HEAD=$APP_HEAD"
if [[ -z "$WORKTREE" ]]; then echo 'WORKTREE_CLEAN=YES'; else echo 'WORKTREE_CLEAN=NO'; fi
if [[ "$APP_HEAD" != "$EXPECTED_APP_HEAD" || -n "$WORKTREE" ]]; then
  echo 'ISSUE364_PRESSUREV2=STOP:repo_baseline_changed'
  exit 0
fi

svc() {
  local label=$1 unit=$2 expected_pid=$3 expected_restarts=$4
  local active pid nr result mem peak cpu tasks
  active=$(systemctl is-active "$unit" 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  mem=$(systemctl show "$unit" -p MemoryCurrent --value 2>/dev/null || true)
  peak=$(systemctl show "$unit" -p MemoryPeak --value 2>/dev/null || true)
  cpu=$(systemctl show "$unit" -p CPUUsageNSec --value 2>/dev/null || true)
  tasks=$(systemctl show "$unit" -p TasksCurrent --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active PID=$pid NRESTARTS=$nr RESULT=$result MEMORY_CURRENT=$mem MEMORY_PEAK=$peak CPU_NSEC=$cpu TASKS=$tasks"
  if [[ "$active" != active || "$pid" != "$expected_pid" || "$nr" != "$expected_restarts" || "$result" != success ]]; then
    echo "ISSUE364_PRESSUREV2=STOP:service_baseline_changed:$label"
    exit 0
  fi
}

state_gate() {
  "$APP_PY" - "$OBS" "$OBHB" "$RESHB" "$EXPECTED_CORE_EVENTS" "$EXPECTED_CORE_MESSAGES" <<'PY'
import json
import pathlib
import sys
from datetime import UTC, datetime

state=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
obhb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
reshb=json.loads(pathlib.Path(sys.argv[3]).read_text("utf-8"))
expected_events=int(sys.argv[4])
expected_messages=int(sys.argv[5])
metrics=state.get("metrics") or {}
cursors=state.get("cursors") or {}
events=int(metrics.get("unrecoverable_core_gap_events",0) or 0)
messages=int(metrics.get("unrecoverable_core_gap_messages",0) or 0)

def age(v):
    if not isinstance(v,str) or not v:
        return -1.0
    try:
        dt=datetime.fromisoformat(v)
    except Exception:
        return -1.0
    if dt.tzinfo is None:
        dt=dt.replace(tzinfo=UTC)
    return max(0.0,(datetime.now(UTC)-dt.astimezone(UTC)).total_seconds())

print(f"PROTECTED_CORE={events}/{messages}")
print(f"LOBBY_CURSOR={int(cursors.get('lobby',0) or 0)}")
print(f"OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
print(f"OBSERVER_HEALTH={(state.get('health') or {}).get('current','missing')}")
print(f"OBSERVER_HEARTBEAT_STATUS={obhb.get('status','missing')}")
print(f"OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")
if events != expected_events or messages != expected_messages:
    print("STATE_GATE=STOP:core_moved_again")
    raise SystemExit(20)
print("STATE_GATE=PASS")
PY
}

svc RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS"
svc CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"

PRE=$(state_gate)
RC=$?
printf '%s\n' "$PRE"
if [[ "$RC" -eq 20 ]]; then
  echo 'ISSUE364_PRESSUREV2=STOP:core_moved_again'
  exit 0
fi
if [[ "$RC" -ne 0 ]]; then
  echo 'ISSUE364_PRESSUREV2=STOP:state_gate_failed'
  exit 0
fi

sample() {
  local tag=$1
  "$APP_PY" - "$tag" "$EXPECTED_RES_PID" "$EXPECTED_CAP_PID" <<'PY'
import os
import pathlib
import re
import sys

tag=sys.argv[1]
resident=int(sys.argv[2])
capture=int(sys.argv[3])
page=os.sysconf("SC_PAGE_SIZE")

def clean(v):
    return re.sub(r"[^A-Za-z0-9_.:/=-]", "", str(v))[:100] or "unknown"

def read_text(path):
    try:
        return pathlib.Path(path).read_text("utf-8",errors="replace")
    except Exception:
        return ""

def status_kib(pid,key):
    for line in read_text(f"/proc/{pid}/status").splitlines():
        if line.startswith(key+":"):
            parts=line.split()
            try:
                return int(parts[1])
            except Exception:
                return 0
    return 0

def io_value(pid,key):
    for line in read_text(f"/proc/{pid}/io").splitlines():
        if line.startswith(key+":"):
            try:
                return int(line.split(":",1)[1].strip())
            except Exception:
                return 0
    return 0

procs={}
for entry in pathlib.Path("/proc").iterdir():
    if not entry.name.isdigit():
        continue
    pid=int(entry.name)
    raw=read_text(entry/"stat")
    if not raw:
        continue
    right=raw.rfind(")")
    if right < 0:
        continue
    comm=clean(raw[raw.find("(")+1:right])
    rest=raw[right+2:].split()
    if len(rest) < 22:
        continue
    try:
        state=rest[0]
        ppid=int(rest[1])
        minflt=int(rest[7])
        majflt=int(rest[9])
        ticks=int(rest[11])+int(rest[12])
        rss_pages=int(rest[21])
    except Exception:
        continue
    procs[pid]={
        "pid":pid,
        "ppid":ppid,
        "comm":comm,
        "state":state,
        "ticks":ticks,
        "rss":rss_pages*page,
        "swap":status_kib(pid,"VmSwap")*1024,
        "majflt":majflt,
        "minflt":minflt,
        "read_bytes":io_value(pid,"read_bytes"),
        "write_bytes":io_value(pid,"write_bytes"),
        "wchan":clean(read_text(entry/"wchan").strip()),
    }

children={}
for pid,p in procs.items():
    children.setdefault(p["ppid"],[]).append(pid)

def descendants(root):
    seen=set()
    stack=[root]
    while stack:
        parent=stack.pop()
        for child in children.get(parent,[]):
            if child not in seen:
                seen.add(child)
                stack.append(child)
    return seen

res_tree={resident}|descendants(resident)
cap_tree={capture}|descendants(capture)
for p in procs.values():
    if p["pid"] == resident:
        p["role"]="RESIDENT_MAIN"
    elif p["pid"] in res_tree:
        p["role"]="RESIDENT_CHILD"
    elif p["pid"] == capture:
        p["role"]="CAPTURE_MAIN"
    elif p["pid"] in cap_tree:
        p["role"]="CAPTURE_CHILD"
    else:
        p["role"]="OTHER"

print(f"--- {tag} MEMORY ---")
wanted={
    "MemTotal","MemAvailable","MemFree","Buffers","Cached","SwapCached",
    "Active","Inactive","AnonPages","Mapped","Shmem","Slab",
    "SReclaimable","SUnreclaim","PageTables","KernelStack",
    "SwapTotal","SwapFree","Dirty","Writeback"
}
for line in read_text("/proc/meminfo").splitlines():
    if ":" not in line:
        continue
    key,val=line.split(":",1)
    if key in wanted:
        parts=val.strip().split()
        amount=int(parts[0])*1024 if parts else 0
        print(f"{tag}_MEM_{key.upper()}_BYTES={amount}")

print(f"--- {tag} PSI ---")
for kind in ("cpu","io","memory"):
    for idx,line in enumerate(read_text(f"/proc/pressure/{kind}").splitlines()[:2],1):
        print(f"{tag}_PSI_{kind.upper()}_{idx}={clean(line)}")

print(f"--- {tag} VMSTAT ---")
vmwanted={
    "pgfault","pgmajfault","pswpin","pswpout",
    "pgscan_kswapd","pgscan_direct","pgsteal_kswapd","pgsteal_direct"
}
for line in read_text("/proc/vmstat").splitlines():
    parts=line.split()
    if len(parts)==2 and parts[0] in vmwanted:
        print(f"{tag}_VMSTAT_{parts[0].upper()}={parts[1]}")
print(f"{tag}_LOADAVG={clean(read_text('/proc/loadavg').strip())}")

def emit(prefix,p):
    print(
        f"{prefix} pid={p['pid']} ppid={p['ppid']} role={p['role']} comm={p['comm']} "
        f"state={p['state']} rss_bytes={p['rss']} swap_bytes={p['swap']} "
        f"cpu_ticks={p['ticks']} majflt={p['majflt']} minflt={p['minflt']} "
        f"read_bytes={p['read_bytes']} write_bytes={p['write_bytes']} wchan={p['wchan']}"
    )

print(f"--- {tag} RESIDENT/CAPTURE TREES ---")
for p in sorted((p for p in procs.values() if p["role"]!="OTHER"),key=lambda x:(x["role"],x["pid"])):
    emit(f"{tag}_TREE",p)

print(f"--- {tag} TOP RSS+SWAP ---")
for p in sorted(procs.values(),key=lambda x:(x["rss"]+x["swap"],x["rss"]),reverse=True)[:15]:
    emit(f"{tag}_TOP",p)
PY
}

sample T0
sleep 10
sample T10

POST=$(state_gate)
POST_RC=$?
printf '%s\n' "$POST" | sed 's/^/POST_/'
if [[ "$POST_RC" -eq 20 ]]; then
  echo 'POST_STATE=CORE_MOVED_DURING_SAMPLE'
else
  echo 'POST_STATE=CORE_STABLE'
fi

echo '--- POST SERVICE CONTINUITY ---'
svc RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS"
svc CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"

echo '--- SAFETY TAIL ---'
echo 'MUTATION_COMMANDS=NONE'
echo 'SERVICE_RESTART=NO'
echo 'PROCESS_SIGNAL=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'NETWORK_PROBE=NO'
echo 'RAW_CMDLINE_OUTPUT=NO'
echo 'PROCESS_ENV_OUTPUT=NO'
echo 'TECHNOCORE_WRITE=NO'
echo '=== ISSUE364_PRESSURE_ATTRIBUTION_V2=COMPLETE_READ_ONLY ==='
echo 'DO_NOT_RERUN=YES'
exit 0
