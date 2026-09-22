#!/usr/bin/env bash
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
EXPECTED_RES_PID=2181484
EXPECTED_RES_RESTARTS=1413

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIGN=technocore-safe-agent-signer.service
DISC=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service

EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0
EXPECTED_SIGN_PID=1539554
EXPECTED_SIGN_RESTARTS=1
EXPECTED_DISC_PID=1957840
EXPECTED_DISC_RESTARTS=0

F1=src/flop_agent/observer_lobby_capture.py
F2=src/flop_agent/observer_lobby_startup_hole_bridge.py
F3=src/flop_agent/observer_resident_isolation.py
B1=285a95c539611c87768634cba1d45cdb442beb14
B2=b96f315dd6bd5c2baa0f5db35acd85479e52e993
B3=6ac40ac32108e141320c1d87d5ce0268e71e986b

echo '=== ISSUE390 POST-PERMISSION RECOVERY ACCEPTANCE V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'ISSUE390_POSTPERM_V1=STOP:not_root'
  exit 0
fi

for path in "$APP/.git" "$APP_PY" "$OBS" "$OBHB" "$RESHB"; do
  if [[ ! -e "$path" ]]; then
    echo 'ISSUE390_POSTPERM_V1=STOP:required_path_missing'
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
  echo 'ISSUE390_POSTPERM_V1=STOP:repo_not_exact_target'
  exit 0
fi

check_file() {
  local rel=$1
  local expected_blob=$2
  local path="$APP/$rel"
  local blob mode owner group
  blob=$(git -C "$APP" hash-object "$path" 2>/dev/null || true)
  mode=$(stat -c '%a' "$path" 2>/dev/null || true)
  owner=$(stat -c '%U' "$path" 2>/dev/null || true)
  group=$(stat -c '%G' "$path" 2>/dev/null || true)
  echo "FILE path=$rel mode=$mode owner=$owner group=$group blob=$blob"
  if [[ "$blob" != "$expected_blob" || "$mode" != 644 || "$owner" != root || "$group" != root ]]; then
    echo "ISSUE390_POSTPERM_V1=STOP:file_repair_not_preserved:$rel"
    exit 0
  fi
}
check_file "$F1" "$B1"
check_file "$F2" "$B2"
check_file "$F3" "$B3"

service_exact() {
  local label=$1
  local unit=$2
  local expected_pid=$3
  local expected_nr=$4
  local active sub pid nr result
  active=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result"
  if [[ "$active" != active || "$sub" != running || "$pid" != "$expected_pid" || "$nr" != "$expected_nr" || "$result" != success ]]; then
    echo "ISSUE390_POSTPERM_V1=STOP:service_changed:$label"
    exit 0
  fi
}

echo '--- BASELINE SERVICES ---'
service_exact RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS"
service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS"
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS"
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
if [[ "$META_ACTIVE" != active || "$META_RESULT" != success ]]; then
  echo 'ISSUE390_POSTPERM_V1=STOP:metadata_block_changed'
  exit 0
fi

sample() {
  local tag=$1
  "$APP_PY" - "$tag" "$OBS" "$OBHB" "$RESHB" "$EXPECTED_CORE_EVENTS" "$EXPECTED_CORE_MESSAGES" "$EXPECTED_RES_PID" <<'PY'
import json
import os
import pathlib
import re
import sys
from datetime import UTC, datetime

tag=sys.argv[1]
state=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
obhb=json.loads(pathlib.Path(sys.argv[3]).read_text("utf-8"))
reshb=json.loads(pathlib.Path(sys.argv[4]).read_text("utf-8"))
expected_events=int(sys.argv[5])
expected_messages=int(sys.argv[6])
resident_pid=int(sys.argv[7])

def age(value):
    if not isinstance(value,str) or not value:
        return -1.0
    try:
        dt=datetime.fromisoformat(value)
    except Exception:
        return -1.0
    if dt.tzinfo is None:
        dt=dt.replace(tzinfo=UTC)
    return max(0.0,(datetime.now(UTC)-dt.astimezone(UTC)).total_seconds())

metrics=state.get("metrics") or {}
cursors=state.get("cursors") or {}
events=int(metrics.get("unrecoverable_core_gap_events",0) or 0)
messages=int(metrics.get("unrecoverable_core_gap_messages",0) or 0)
print(f"{tag}_PROTECTED_CORE={events}/{messages}")
print(f"{tag}_CORE_MATCH="+("YES" if (events,messages)==(expected_events,expected_messages) else "NO"))
print(f"{tag}_LOBBY_CURSOR={int(cursors.get('lobby',0) or 0)}")
print(f"{tag}_OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
print(f"{tag}_OBSERVER_HEARTBEAT_STATUS={obhb.get('status','missing')}")
print(f"{tag}_OBSERVER_HEARTBEAT_UPDATED_AT={obhb.get('updated_at','missing')}")
print(f"{tag}_OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"{tag}_RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"{tag}_RESIDENT_HEARTBEAT_UPDATED_AT={reshb.get('updated_at','missing')}")
print(f"{tag}_RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")

mem={}
for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
    if ":" not in line:
        continue
    key,val=line.split(":",1)
    if key in {"MemTotal","MemAvailable","SwapTotal","SwapFree","AnonPages","Dirty","Writeback"}:
        parts=val.strip().split()
        mem[key]=int(parts[0])*1024 if parts else 0
for key in ("MemTotal","MemAvailable","SwapTotal","SwapFree","AnonPages","Dirty","Writeback"):
    print(f"{tag}_MEM_{key.upper()}_BYTES={mem.get(key,0)}")

psi={}
def clean(value):
    return re.sub(r"[^A-Za-z0-9_.:/=-]", "", str(value))[:120] or "unknown"
for kind in ("io","memory"):
    path=pathlib.Path(f"/proc/pressure/{kind}")
    if not path.exists():
        continue
    for idx,line in enumerate(path.read_text("utf-8").splitlines()[:2],1):
        print(f"{tag}_PSI_{kind.upper()}_{idx}={clean(line)}")
        if line.startswith("full "):
            for field in line.split()[1:]:
                if field.startswith("avg10="):
                    try:
                        psi[kind]=float(field.split("=",1)[1])
                    except ValueError:
                        pass

guard = (
    mem.get("MemAvailable",0) < 256*1024*1024
    or psi.get("memory",0.0) > 5.0
    or psi.get("io",0.0) > 10.0
)
print(f"{tag}_PRESSURE_GUARD_CURRENT="+("ON" if guard else "OFF"))

proc=pathlib.Path(f"/proc/{resident_pid}")
if proc.exists():
    raw=(proc/"stat").read_text("utf-8",errors="replace")
    right=raw.rfind(")")
    rest=raw[right+2:].split()
    page=os.sysconf("SC_PAGE_SIZE")
    state_code=rest[0]
    ticks=int(rest[11])+int(rest[12])
    rss=int(rest[21])*page
    try:
        wchan=clean((proc/"wchan").read_text("utf-8",errors="replace").strip())
    except OSError:
        wchan="unavailable"
    swap=0
    for line in (proc/"status").read_text("utf-8",errors="replace").splitlines():
        if line.startswith("VmSwap:"):
            parts=line.split()
            if len(parts)>1:
                swap=int(parts[1])*1024
            break
    print(f"{tag}_RESIDENT_PROC state={state_code} cpu_ticks={ticks} rss_bytes={rss} swap_bytes={swap} wchan={wchan}")
    children=[]
    child_path=proc/"task"/str(resident_pid)/"children"
    try:
        children=[int(x) for x in child_path.read_text("utf-8").split() if x.isdigit()]
    except OSError:
        pass
    print(f"{tag}_RESIDENT_CHILD_COUNT={len(children)}")
    for child in children[:5]:
        cproc=pathlib.Path(f"/proc/{child}")
        if not cproc.exists():
            continue
        craw=(cproc/"stat").read_text("utf-8",errors="replace")
        cright=craw.rfind(")")
        crest=craw[cright+2:].split()
        comm=clean(craw[craw.find("(")+1:cright])
        cstate=crest[0]
        cticks=int(crest[11])+int(crest[12])
        crss=int(crest[21])*page
        try:
            cwchan=clean((cproc/"wchan").read_text("utf-8",errors="replace").strip())
        except OSError:
            cwchan="unavailable"
        print(f"{tag}_RESIDENT_CHILD pid={child} comm={comm} state={cstate} cpu_ticks={cticks} rss_bytes={crss} wchan={cwchan}")
else:
    print(f"{tag}_RESIDENT_PROC=MISSING")
PY
}

ensure_services() {
  service_exact RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS"
  service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"
  service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS"
  service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS"
}

echo '--- T0 ---'
sample T0
ensure_services
sleep 35

echo '--- T35 ---'
sample T35
ensure_services
sleep 35

echo '--- T70 ---'
sample T70
ensure_services

echo '--- FINAL ACCEPTANCE ---'
FINAL=$("$APP_PY" - "$OBS" "$OBHB" "$EXPECTED_CORE_EVENTS" "$EXPECTED_CORE_MESSAGES" <<'PY'
import json
import pathlib
import sys
from datetime import UTC, datetime

state=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
hb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
expected=(int(sys.argv[3]),int(sys.argv[4]))
metrics=state.get("metrics") or {}
events=int(metrics.get("unrecoverable_core_gap_events",0) or 0)
messages=int(metrics.get("unrecoverable_core_gap_messages",0) or 0)

value=hb.get("updated_at")
age=-1.0
if isinstance(value,str) and value:
    try:
        dt=datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt=dt.replace(tzinfo=UTC)
        age=max(0.0,(datetime.now(UTC)-dt.astimezone(UTC)).total_seconds())
    except Exception:
        pass

print(f"CORE_EVENTS={events}")
print(f"CORE_MESSAGES={messages}")
print(f"OBSERVER_HEARTBEAT_AGE={age:.1f}")
print(f"OBSERVER_HEARTBEAT_UPDATED_AT={value or 'missing'}")
print(f"OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
print(f"LOBBY_CURSOR={int((state.get('cursors') or {}).get('lobby',0) or 0)}")
print("CORE_OK="+("YES" if (events,messages)==expected else "NO"))
print("OBSERVER_HEARTBEAT_FRESH="+("YES" if 0 <= age <= 90.0 else "NO"))
PY
)
printf '%s\n' "$FINAL" | sed 's/^/FINAL_/'
FINAL_CORE_OK=$(printf '%s\n' "$FINAL" | awk -F= '$1=="CORE_OK"{print $2}')
FINAL_OBS_FRESH=$(printf '%s\n' "$FINAL" | awk -F= '$1=="OBSERVER_HEARTBEAT_FRESH"{print $2}')

if [[ "$FINAL_CORE_OK" != YES ]]; then
  echo 'ISSUE390_POSTPERM_V1=STOP:protected_core_changed'
  exit 0
fi
if [[ "$FINAL_OBS_FRESH" != YES ]]; then
  echo 'ISSUE390_POSTPERM_V1=STOP:observer_heartbeat_not_fresh'
  exit 0
fi

echo 'RESIDENT_PID_STABLE=YES'
echo 'RESIDENT_NRESTARTS_STABLE=YES'
echo 'FILE_PERMISSION_REPAIR_PRESERVED=YES'
echo 'PROTECTED_CORE_STABLE=YES'
echo 'OBSERVER_HEARTBEAT_RECOVERED=YES'
echo 'SERVICE_MUTATION=NO'
echo 'SERVICE_RESTART=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'NETWORK_PROBE=NO'
echo 'TECHNOCORE_WRITE=NO'
echo '=== ISSUE390_POST_PERMISSION_RECOVERY_ACCEPTANCE_V1=PASS ==='
echo 'DO_NOT_RERUN=YES'
exit 0
