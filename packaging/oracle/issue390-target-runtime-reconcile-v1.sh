#!/usr/bin/env bash
# Issue #390/#364: read-only reconcile when Production repo is already at TARGET.
set -u
umask 077

APP=/opt/technocore-safe-agent
APP_PY=$APP/.venv/bin/python
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
OBHB=$STATE/observer/observer-heartbeat.json
RESHB=$STATE/observer/resident-heartbeat.json

TARGET=473e4f73426069c682cfd716f611e0bfad7d4fe8
EXPECTED_CORE_EVENTS=119
EXPECTED_CORE_MESSAGES=5497275

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIGN=technocore-safe-agent-signer.service
DISC=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service

EXPECTED_TARGET_CAPTURE_BLOB=285a95c539611c87768634cba1d45cdb442beb14
EXPECTED_TARGET_BRIDGE_BLOB=b96f315dd6bd5c2baa0f5db35acd85479e52e993
EXPECTED_TARGET_ISOLATION_BLOB=6ac40ac32108e141320c1d87d5ce0268e71e986b

echo '=== ISSUE390 TARGET RUNTIME RECONCILE V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'ISSUE390_TARGETREC_V1=STOP:not_root'
  exit 0
fi

for path in "$APP/.git" "$APP_PY" "$OBS" "$OBHB" "$RESHB"; do
  if [[ ! -e "$path" ]]; then
    echo 'ISSUE390_TARGETREC_V1=STOP:required_path_missing'
    exit 0
  fi
done

HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
BRANCH=$(git -C "$APP" branch --show-current 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "HEAD=$HEAD"
echo "BRANCH=$BRANCH"
if [[ -z "$WORKTREE" ]]; then echo 'WORKTREE_CLEAN=YES'; else echo 'WORKTREE_CLEAN=NO'; fi

if [[ "$HEAD" != "$TARGET" || "$BRANCH" != main || -n "$WORKTREE" ]]; then
  echo 'ISSUE390_TARGETREC_V1=STOP:repo_not_exact_target'
  exit 0
fi

check_blob() {
  local path=$1 expected=$2 label=$3 actual
  actual=$(git -C "$APP" rev-parse "HEAD:$path" 2>/dev/null || true)
  echo "BLOB_$label=$actual"
  if [[ "$actual" != "$expected" ]]; then
    echo "ISSUE390_TARGETREC_V1=STOP:blob_mismatch:$label"
    exit 0
  fi
}
check_blob src/flop_agent/observer_lobby_capture.py "$EXPECTED_TARGET_CAPTURE_BLOB" CAPTURE
check_blob src/flop_agent/observer_lobby_startup_hole_bridge.py "$EXPECTED_TARGET_BRIDGE_BLOB" BRIDGE
check_blob src/flop_agent/observer_resident_isolation.py "$EXPECTED_TARGET_ISOLATION_BLOB" ISOLATION

echo '--- SERVICES ---'
service_row() {
  local label=$1 unit=$2
  local active pid nr result entered
  active=$(systemctl is-active "$unit" 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  entered=$(systemctl show "$unit" -p ActiveEnterTimestamp --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active PID=$pid NRESTARTS=$nr RESULT=$result ACTIVE_ENTER=$entered"
}
service_row RESIDENT "$RES"
service_row CAPTURE "$CAP"
service_row SIGNER "$SIGN"
service_row DISCORD "$DISC"
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
META_ENTER=$(systemctl show "$META" -p ActiveEnterTimestamp --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT ACTIVE_ENTER=$META_ENTER"

RES_PID=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
if [[ -z "$RES_PID" || "$RES_PID" == 0 || ! -e "/proc/$RES_PID/stat" ]]; then
  echo 'ISSUE390_TARGETREC_V1=STOP:resident_pid_missing'
  exit 0
fi

echo '--- GIT/PROCESS PROVENANCE ---'
"$APP_PY" - "$APP" "$TARGET" "$RES_PID" <<'PY'
import os
import pathlib
import re
import subprocess
import sys

app=sys.argv[1]
target=sys.argv[2]
pid=int(sys.argv[3])
clk=os.sysconf(os.sysconf_names["SC_CLK_TCK"])

def clean(v):
    return re.sub(r"[^A-Za-z0-9_.:/= +()-]", "", str(v))[:180] or "unknown"

btime=None
for line in pathlib.Path("/proc/stat").read_text("utf-8").splitlines():
    if line.startswith("btime "):
        btime=int(line.split()[1])
        break
if btime is None:
    print("RUNTIME_PROVENANCE=UNKNOWN_NO_BTIME")
    raise SystemExit(0)

raw=pathlib.Path(f"/proc/{pid}/stat").read_text("utf-8",errors="replace")
right=raw.rfind(")")
rest=raw[right+2:].split()
start_ticks=int(rest[19])
proc_start_epoch=btime+(start_ticks/clk)
state=rest[0]
rss_pages=int(rest[21])
page=os.sysconf("SC_PAGE_SIZE")
wchan=clean(pathlib.Path(f"/proc/{pid}/wchan").read_text("utf-8",errors="replace").strip())

swap=0
for line in pathlib.Path(f"/proc/{pid}/status").read_text("utf-8",errors="replace").splitlines():
    if line.startswith("VmSwap:"):
        parts=line.split()
        if len(parts)>1:
            swap=int(parts[1])*1024
        break

print(f"RESIDENT_PROCESS_START_EPOCH={proc_start_epoch:.3f}")
print(f"RESIDENT_PROCESS_STATE={state}")
print(f"RESIDENT_PROCESS_RSS_BYTES={rss_pages*page}")
print(f"RESIDENT_PROCESS_SWAP_BYTES={swap}")
print(f"RESIDENT_PROCESS_WCHAN={wchan}")

cp=subprocess.run(
    ["git","-C",app,"reflog","-n","30","--format=%H|%ct|%gs","HEAD"],
    check=False,text=True,capture_output=True,
)
rows=[]
for raw_line in cp.stdout.splitlines():
    parts=raw_line.split("|",2)
    if len(parts)!=3:
        continue
    sha,stamp,action=parts
    try:
        epoch=int(stamp)
    except ValueError:
        continue
    rows.append((sha,epoch,clean(action)))

target_run=[]
for sha,epoch,action in rows:
    if sha == target:
        target_run.append((sha,epoch,action))
    elif target_run:
        break

if not target_run:
    print("TARGET_REFLOG_PRESENT=NO")
    print("RUNTIME_PROVENANCE=UNKNOWN_NO_TARGET_REFLOG")
else:
    # Reflog is newest-first. The last target entry in the current contiguous
    # target run is the earliest known transition into this target state.
    _,target_epoch,target_action=target_run[-1]
    print("TARGET_REFLOG_PRESENT=YES")
    print(f"TARGET_FIRST_CONTIGUOUS_REFLOG_EPOCH={target_epoch}")
    print(f"TARGET_FIRST_CONTIGUOUS_REFLOG_ACTION={target_action}")
    delta=proc_start_epoch-target_epoch
    print(f"RESIDENT_START_MINUS_TARGET_REFLOG_SECONDS={delta:.3f}")
    if delta < -1.0:
        print("RUNTIME_PROVENANCE=PROVEN_PRE_TARGET")
    elif delta > 1.0:
        print("RUNTIME_PROVENANCE=PROVEN_POST_TARGET")
    else:
        print("RUNTIME_PROVENANCE=AMBIGUOUS_SAME_SECOND")

children_path=pathlib.Path(f"/proc/{pid}/task/{pid}/children")
child_ids=[]
try:
    child_ids=[int(x) for x in children_path.read_text("utf-8").split() if x.isdigit()]
except OSError:
    pass
print(f"RESIDENT_IMMEDIATE_CHILD_COUNT={len(child_ids)}")
for child in sorted(child_ids):
    stat_path=pathlib.Path(f"/proc/{child}/stat")
    if not stat_path.exists():
        continue
    raw=stat_path.read_text("utf-8",errors="replace")
    right=raw.rfind(")")
    rest=raw[right+2:].split()
    comm=clean(raw[raw.find("(")+1:right])
    state=rest[0]
    ticks=int(rest[11])+int(rest[12])
    rss=int(rest[21])*page
    start=btime+(int(rest[19])/clk)
    try:
        cwchan=clean(pathlib.Path(f"/proc/{child}/wchan").read_text("utf-8",errors="replace").strip())
    except OSError:
        cwchan="unavailable"
    cswap=0
    try:
        for line in pathlib.Path(f"/proc/{child}/status").read_text("utf-8",errors="replace").splitlines():
            if line.startswith("VmSwap:"):
                parts=line.split()
                if len(parts)>1:
                    cswap=int(parts[1])*1024
                break
    except OSError:
        pass
    print(
        f"RESIDENT_CHILD pid={child} comm={comm} state={state} "
        f"start_epoch={start:.3f} cpu_ticks={ticks} rss_bytes={rss} "
        f"swap_bytes={cswap} wchan={cwchan}"
    )
PY

echo '--- CONTINUITY ---'
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
print("PROTECTED_CORE_MATCH_EXPECTED="+("YES" if (events,messages)==(expected_events,expected_messages) else "NO"))
print(f"LOBBY_CURSOR={int(cursors.get('lobby',0) or 0)}")
print(f"OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
print(f"OBSERVER_HEALTH={(state.get('health') or {}).get('current','missing')}")
print(f"OBSERVER_HEARTBEAT_STATUS={obhb.get('status','missing')}")
print(f"OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")
PY

echo '--- LIGHTWEIGHT PRESSURE ---'
"$APP_PY" - <<'PY'
import pathlib
import re

def clean(v):
    return re.sub(r"[^A-Za-z0-9_.:/=-]", "", str(v))[:120] or "unknown"

for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
    if ":" not in line:
        continue
    key,val=line.split(":",1)
    if key in {"MemTotal","MemAvailable","SwapTotal","SwapFree","AnonPages","Dirty","Writeback"}:
        parts=val.strip().split()
        amount=int(parts[0])*1024 if parts else 0
        print(f"MEM_{key.upper()}_BYTES={amount}")
for kind in ("io","memory"):
    p=pathlib.Path(f"/proc/pressure/{kind}")
    if not p.exists():
        continue
    for idx,line in enumerate(p.read_text("utf-8").splitlines()[:2],1):
        print(f"PSI_{kind.upper()}_{idx}={clean(line)}")
PY

echo '--- SAFETY TAIL ---'
echo 'MUTATION_COMMANDS=NONE'
echo 'SERVICE_RESTART=NO'
echo 'PROCESS_SIGNAL=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'NETWORK_PROBE=NO'
echo 'RAW_CMDLINE_OUTPUT=NO'
echo 'PROCESS_ENV_OUTPUT=NO'
echo 'TECHNOCORE_WRITE=NO'
echo '=== ISSUE390_TARGET_RUNTIME_RECONCILE_V1=COMPLETE_READ_ONLY ==='
echo 'DO_NOT_RERUN=YES'
exit 0
