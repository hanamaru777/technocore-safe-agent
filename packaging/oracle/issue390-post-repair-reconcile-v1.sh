#!/usr/bin/env bash
set -u
set -o pipefail
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

F1=src/flop_agent/observer_lobby_capture.py
F2=src/flop_agent/observer_lobby_startup_hole_bridge.py
F3=src/flop_agent/observer_resident_isolation.py
B1=285a95c539611c87768634cba1d45cdb442beb14
B2=b96f315dd6bd5c2baa0f5db35acd85479e52e993
B3=6ac40ac32108e141320c1d87d5ce0268e71e986b

TMP=$(mktemp /tmp/issue390-postrepair.XXXXXX)
trap 'rm -f -- "$TMP"' EXIT

echo '=== ISSUE390 POST-REPAIR RECONCILE V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'ISSUE390_POSTREPAIR_V1=STOP:not_root'
  exit 0
fi

for cmd in git systemctl stat runuser sleep journalctl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ISSUE390_POSTREPAIR_V1=STOP:missing_command:$cmd"
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
  echo 'ISSUE390_POSTREPAIR_V1=STOP:repo_not_exact_target'
  exit 0
fi

check_file() {
  local rel=$1
  local expected_blob=$2
  local path="$APP/$rel"
  local blob mode owner group readable
  blob=$(git -C "$APP" hash-object "$path" 2>/dev/null || true)
  mode=$(stat -c '%a' "$path" 2>/dev/null || true)
  owner=$(stat -c '%U' "$path" 2>/dev/null || true)
  group=$(stat -c '%G' "$path" 2>/dev/null || true)
  if runuser -u technocore -- test -r "$path"; then readable=YES; else readable=NO; fi
  echo "FILE path=$rel mode=$mode owner=$owner group=$group blob=$blob readable_as_technocore=$readable"
  if [[ "$blob" != "$expected_blob" || "$mode" != 644 || "$owner" != root || "$group" != root || "$readable" != YES ]]; then
    echo "ISSUE390_POSTREPAIR_V1=STOP:permission_repair_not_persistent:$rel"
    exit 0
  fi
}

echo '--- PERMISSION REPAIR PERSISTENCE ---'
check_file "$F1" "$B1"
check_file "$F2" "$B2"
check_file "$F3" "$B3"

service_row() {
  local tag=$1
  local label=$2
  local unit=$3
  local active sub pid nr result code status entered
  active=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  code=$(systemctl show "$unit" -p ExecMainCode --value 2>/dev/null || true)
  status=$(systemctl show "$unit" -p ExecMainStatus --value 2>/dev/null || true)
  entered=$(systemctl show "$unit" -p ActiveEnterTimestamp --value 2>/dev/null || true)
  echo "$tag SERVICE=$label ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result EXEC_CODE=$code EXEC_STATUS=$status ACTIVE_ENTER=$entered"
}

state_row() {
  local tag=$1
  "$APP_PY" - "$tag" "$OBS" "$OBHB" "$RESHB" "$EXPECTED_CORE_EVENTS" "$EXPECTED_CORE_MESSAGES" <<'PY'
import json
import pathlib
import sys
from datetime import UTC, datetime

tag=sys.argv[1]
state=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
obhb=json.loads(pathlib.Path(sys.argv[3]).read_text("utf-8"))
reshb=json.loads(pathlib.Path(sys.argv[4]).read_text("utf-8"))
expected=(int(sys.argv[5]),int(sys.argv[6]))
metrics=state.get("metrics") or {}
cursors=state.get("cursors") or {}
events=int(metrics.get("unrecoverable_core_gap_events",0) or 0)
messages=int(metrics.get("unrecoverable_core_gap_messages",0) or 0)

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

print(f"{tag}_PROTECTED_CORE={events}/{messages}")
print(f"{tag}_PROTECTED_CORE_MATCH_EXPECTED={'YES' if (events,messages)==expected else 'NO'}")
print(f"{tag}_LOBBY_CURSOR={int(cursors.get('lobby',0) or 0)}")
print(f"{tag}_OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
print(f"{tag}_OBSERVER_HEALTH={(state.get('health') or {}).get('current','missing')}")
print(f"{tag}_OBSERVER_HEARTBEAT_STATUS={obhb.get('status','missing')}")
print(f"{tag}_OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"{tag}_RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"{tag}_RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")
PY
}

process_row() {
  local tag=$1
  local pid
  pid=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
  "$APP_PY" - "$tag" "$pid" <<'PY'
import os
import pathlib
import re
import sys

tag=sys.argv[1]
try:
    root=int(sys.argv[2])
except Exception:
    root=0
page=os.sysconf("SC_PAGE_SIZE")

def clean(value):
    return re.sub(r"[^A-Za-z0-9_.:/=-]", "", str(value))[:100] or "unknown"

def read_text(path):
    try:
        return pathlib.Path(path).read_text("utf-8",errors="replace")
    except Exception:
        return ""

def one(pid,role):
    raw=read_text(f"/proc/{pid}/stat")
    if not raw:
        print(f"{tag}_{role}_PID={pid} PRESENT=NO")
        return
    right=raw.rfind(")")
    rest=raw[right+2:].split()
    if len(rest)<22:
        print(f"{tag}_{role}_PID={pid} PRESENT=INVALID")
        return
    state=rest[0]
    ppid=int(rest[1])
    minflt=int(rest[7])
    majflt=int(rest[9])
    ticks=int(rest[11])+int(rest[12])
    rss=int(rest[21])*page
    comm=clean(raw[raw.find("(")+1:right])
    wchan=clean(read_text(f"/proc/{pid}/wchan").strip())
    swap=0
    for line in read_text(f"/proc/{pid}/status").splitlines():
        if line.startswith("VmSwap:"):
            parts=line.split()
            if len(parts)>1:
                swap=int(parts[1])*1024
            break
    read_bytes=write_bytes=0
    for line in read_text(f"/proc/{pid}/io").splitlines():
        if line.startswith("read_bytes:"):
            read_bytes=int(line.split()[1])
        elif line.startswith("write_bytes:"):
            write_bytes=int(line.split()[1])
    print(
        f"{tag}_{role} pid={pid} ppid={ppid} comm={comm} state={state} "
        f"cpu_ticks={ticks} minflt={minflt} majflt={majflt} rss_bytes={rss} "
        f"swap_bytes={swap} read_bytes={read_bytes} write_bytes={write_bytes} wchan={wchan}"
    )

if root <= 0:
    print(f"{tag}_RESIDENT_MAIN_PID={root} PRESENT=NO")
    raise SystemExit(0)

one(root,"RESIDENT_MAIN")
children_path=pathlib.Path(f"/proc/{root}/task/{root}/children")
children=[]
try:
    children=[int(x) for x in children_path.read_text("utf-8").split() if x.isdigit()]
except OSError:
    pass
print(f"{tag}_RESIDENT_IMMEDIATE_CHILD_COUNT={len(children)}")
for child in sorted(children):
    one(child,"RESIDENT_CHILD")
PY
}

pressure_row() {
  local tag=$1
  "$APP_PY" - "$tag" <<'PY'
import pathlib
import re
import sys

tag=sys.argv[1]
def clean(v):
    return re.sub(r"[^A-Za-z0-9_.:/=-]", "", str(v))[:120] or "unknown"

for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
    if ":" not in line:
        continue
    key,val=line.split(":",1)
    if key in {"MemAvailable","SwapTotal","SwapFree","AnonPages","Dirty","Writeback"}:
        parts=val.strip().split()
        print(f"{tag}_MEM_{key.upper()}_BYTES={int(parts[0])*1024 if parts else 0}")
for kind in ("io","memory"):
    path=pathlib.Path(f"/proc/pressure/{kind}")
    if not path.exists():
        continue
    for idx,line in enumerate(path.read_text("utf-8").splitlines()[:2],1):
        print(f"{tag}_PSI_{kind.upper()}_{idx}={clean(line)}")
PY
}

sample_all() {
  local tag=$1
  service_row "$tag" RESIDENT "$RES"
  service_row "$tag" CAPTURE "$CAP"
  service_row "$tag" SIGNER "$SIGN"
  service_row "$tag" DISCORD "$DISC"
  service_row "$tag" METADATA_BLOCK "$META"
  state_row "$tag"
  process_row "$tag"
  pressure_row "$tag"
}

echo '--- T0 ---'
sample_all T0
sleep 15
echo '--- T15 ---'
sample_all T15
sleep 15
echo '--- T30 ---'
sample_all T30

echo '--- SANITIZED POST-REPAIR JOURNAL ---'
journalctl -u "$RES" --since '2026-09-22 11:31:00 UTC' --no-pager --output=cat >"$TMP" 2>/dev/null || true

"$APP_PY" - "$TMP" <<'PY'
import collections
import pathlib
import re
import sys

text=pathlib.Path(sys.argv[1]).read_text("utf-8",errors="replace")
patterns={
    "TRACEBACK": r"Traceback \(most recent call last\):",
    "PERMISSION_ERROR": r"\bPermissionError\b",
    "MEMORY_ERROR": r"\bMemoryError\b",
    "RUNTIME_ERROR": r"\bRuntimeError\b",
    "SQLITE_OPERATIONAL": r"\bsqlite3\.OperationalError\b",
    "MAINTENANCE_EXIT": r"resident maintenance process exited unexpectedly",
    "EXPORT_TOO_LARGE": r"export_too_large|capture_export_too_large",
}
for label,pattern in patterns.items():
    print(f"POSTREPAIR_JOURNAL_CLASS_{label}={len(re.findall(pattern,text))}")

frames=collections.Counter()
frame_re=re.compile(r'File "(/opt/technocore-safe-agent/[^"]+\.py)", line (\d+), in ([A-Za-z0-9_<>]+)')
for line in text.splitlines():
    m=frame_re.search(line)
    if not m:
        continue
    path=m.group(1).replace("/opt/technocore-safe-agent/","")
    frames[(path,m.group(2),m.group(3))]+=1
for idx,((path,line_no,func),count) in enumerate(frames.most_common(20),1):
    print(f"POSTREPAIR_JOURNAL_FRAME idx={idx} path={path} line={line_no} func={func} count={count}")

print(f"POSTREPAIR_JOURNAL_TOTAL_LINES={len(text.splitlines())}")
PY

echo '--- SAFETY TAIL ---'
echo 'MUTATION_COMMANDS=NONE'
echo 'SERVICE_RESTART=NO'
echo 'PROCESS_SIGNAL=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'NETWORK_PROBE=NO'
echo 'RAW_JOURNAL_OUTPUT=NO'
echo 'RAW_CMDLINE_OUTPUT=NO'
echo 'PROCESS_ENV_OUTPUT=NO'
echo 'TECHNOCORE_WRITE=NO'
echo '=== ISSUE390_POST_REPAIR_RECONCILE_V1=COMPLETE_READ_ONLY ==='
echo 'DO_NOT_RERUN=YES'
exit 0
