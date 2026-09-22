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

TARGET=9d635be14de715d61e680136dd688bd8598e9403
EXPECTED_CORE_EVENTS=120
EXPECTED_CORE_MESSAGES=5650166

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIGN=technocore-safe-agent-signer.service
DISC=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service

EXPECTED_RES_PID=2195965
EXPECTED_RES_RESTARTS=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0
EXPECTED_SIGN_PID=1539554
EXPECTED_SIGN_RESTARTS=1
EXPECTED_DISC_PID=1957840
EXPECTED_DISC_RESTARTS=0

CAPTURE_FILE=src/flop_agent/observer_lobby_capture.py
BRIDGE_FILE=src/flop_agent/observer_lobby_startup_hole_bridge.py
ISOLATION_FILE=src/flop_agent/observer_resident_isolation.py
CAPTURE_BLOB=285a95c539611c87768634cba1d45cdb442beb14
BRIDGE_BLOB=b96f315dd6bd5c2baa0f5db35acd85479e52e993
ISOLATION_BLOB=6ea86a3f7350162727763e58f95116970eb43f35

echo '=== ISSUE364 POST-ROLLOUT RECONCILE V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

stop_now() {
  echo "ISSUE364_POSTV1=STOP:$1"
  exit 0
}

if [[ $EUID -ne 0 ]]; then stop_now not_root; fi
for cmd in git systemctl stat sleep; do
  command -v "$cmd" >/dev/null 2>&1 || stop_now "missing_command:$cmd"
done
[[ -x "$APP_PY" && -f "$OBS" && -f "$OBHB" && -f "$RESHB" ]] || stop_now required_path_missing

HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
BRANCH=$(git -C "$APP" branch --show-current 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "HEAD=$HEAD"
echo "BRANCH=$BRANCH"
if [[ -z "$WORKTREE" ]]; then echo 'WORKTREE_CLEAN=YES'; else echo 'WORKTREE_CLEAN=NO'; fi
[[ "$HEAD" == "$TARGET" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_now repo_not_exact_target

check_file() {
  local rel=$1 expected=$2
  local path="$APP/$rel" blob mode owner group
  blob=$(git -C "$APP" hash-object "$path" 2>/dev/null || true)
  mode=$(stat -c '%a' "$path" 2>/dev/null || true)
  owner=$(stat -c '%U' "$path" 2>/dev/null || true)
  group=$(stat -c '%G' "$path" 2>/dev/null || true)
  echo "FILE path=$rel mode=$mode owner=$owner group=$group blob=$blob"
  [[ "$blob" == "$expected" && "$mode" == 644 && "$owner" == root && "$group" == root ]]
}

check_file "$CAPTURE_FILE" "$CAPTURE_BLOB" || stop_now capture_file_changed
check_file "$BRIDGE_FILE" "$BRIDGE_BLOB" || stop_now bridge_file_changed
check_file "$ISOLATION_FILE" "$ISOLATION_BLOB" || stop_now isolation_file_changed

service_exact() {
  local label=$1 unit=$2 expected_pid=$3 expected_nr=$4
  local active sub pid nr result
  active=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result"
  [[ "$active" == active && "$sub" == running && "$pid" == "$expected_pid" && "$nr" == "$expected_nr" && "$result" == success ]]
}

echo '--- ENTRY SERVICE GATES ---'
service_exact RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS" || stop_now resident_entry_changed
service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS" || stop_now capture_changed
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS" || stop_now signer_changed
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS" || stop_now discord_changed
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || stop_now metadata_block_changed

BASE=$("$APP_PY" - "$OBS" <<'PY'
import json,pathlib,sys
state=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m=state.get("metrics") or {}
c=state.get("cursors") or {}
print(f"{int(m.get('unrecoverable_core_gap_events',0) or 0)}|{int(m.get('unrecoverable_core_gap_messages',0) or 0)}|{int(c.get('lobby',0) or 0)}|{state.get('updated_at','missing')}")
PY
)
BASE_EVENTS=$(printf '%s' "$BASE" | cut -d'|' -f1)
BASE_MESSAGES=$(printf '%s' "$BASE" | cut -d'|' -f2)
BASE_CURSOR=$(printf '%s' "$BASE" | cut -d'|' -f3)
BASE_UPDATED=$(printf '%s' "$BASE" | cut -d'|' -f4)
echo "BASE_PROTECTED_CORE=$BASE_EVENTS/$BASE_MESSAGES"
echo "BASE_LOBBY_CURSOR=$BASE_CURSOR"
echo "BASE_OBSERVER_UPDATED_AT=$BASE_UPDATED"
[[ "$BASE_EVENTS" == "$EXPECTED_CORE_EVENTS" && "$BASE_MESSAGES" == "$EXPECTED_CORE_MESSAGES" ]] || stop_now protected_core_changed_before_watch

sample() {
  local label=$1
  local pid
  pid=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
  echo "--- $label ---"
  "$APP_PY" - "$label" "$pid" "$OBS" "$OBHB" "$RESHB" <<'PY'
import json,pathlib,re,sys
from datetime import UTC,datetime
label,pid_s,obs_s,obhb_s,reshb_s=sys.argv[1:]
pid=int(pid_s or 0)
state=json.loads(pathlib.Path(obs_s).read_text("utf-8"))
obhb=json.loads(pathlib.Path(obhb_s).read_text("utf-8"))
reshb=json.loads(pathlib.Path(reshb_s).read_text("utf-8"))
m=state.get("metrics") or {}
c=state.get("cursors") or {}

def age(value):
    try:
        dt=datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt=dt.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-dt.astimezone(UTC)).total_seconds())
    except Exception:
        return -1.0

print(f"{label}_PROTECTED_CORE={int(m.get('unrecoverable_core_gap_events',0) or 0)}/{int(m.get('unrecoverable_core_gap_messages',0) or 0)}")
print(f"{label}_LOBBY_CURSOR={int(c.get('lobby',0) or 0)}")
print(f"{label}_OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
print(f"{label}_OBSERVER_HEARTBEAT_STATUS={obhb.get('status','missing')}")
print(f"{label}_OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"{label}_RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"{label}_RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")

mem={}
for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
    if ":" not in line:
        continue
    key,val=line.split(":",1)
    if key in {"MemTotal","MemAvailable","SwapTotal","SwapFree","AnonPages"}:
        mem[key]=int(val.strip().split()[0])*1024
        print(f"{label}_MEM_{key.upper()}_BYTES={mem[key]}")

psi={}
for kind in ("io","memory"):
    p=pathlib.Path(f"/proc/pressure/{kind}")
    if not p.exists():
        continue
    for idx,line in enumerate(p.read_text("utf-8").splitlines()[:2],1):
        cleaned=re.sub(r"[^A-Za-z0-9_.:/=-]","",line)[:160]
        print(f"{label}_PSI_{kind.upper()}_{idx}={cleaned}")
        if line.startswith("full "):
            for field in line.split()[1:]:
                if field.startswith("avg10="):
                    try:
                        psi[kind]=float(field.split("=",1)[1])
                    except ValueError:
                        pass

pressure=(
    mem.get("MemAvailable",0) < 256*1024*1024
    or psi.get("memory",0.0) > 5.0
    or psi.get("io",0.0) > 10.0
)
print(f"{label}_PRESSURE_GUARD_CURRENT={'ON' if pressure else 'OFF'}")

tracker=0
maintenance=[]
children_path=pathlib.Path(f"/proc/{pid}/task/{pid}/children")
if pid and children_path.exists():
    for raw in children_path.read_text("utf-8").split():
        try:
            child=int(raw)
        except ValueError:
            continue
        cmd=b""
        try:
            cmd=pathlib.Path(f"/proc/{child}/cmdline").read_bytes()
        except OSError:
            pass
        try:
            stat=pathlib.Path(f"/proc/{child}/stat").read_text("utf-8").split()
        except OSError:
            stat=[]
        state_code=stat[2] if len(stat)>2 else "?"
        if b"resource_tracker" in cmd:
            tracker+=1
        else:
            maintenance.append(state_code)
print(f"{label}_RESOURCE_TRACKER_CHILD_COUNT={tracker}")
print(f"{label}_MAINTENANCE_CHILD_COUNT={len(maintenance)}")
print(f"{label}_MAINTENANCE_CHILD_STATES={','.join(maintenance) if maintenance else 'NONE'}")
PY
  local active sub nr result
  active=$(systemctl show "$RES" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$RES" -p SubState --value 2>/dev/null || true)
  nr=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$RES" -p Result --value 2>/dev/null || true)
  echo "$label RESIDENT_ACTIVE=$active RESIDENT_SUB=$sub RESIDENT_PID=$pid RESIDENT_NRESTARTS=$nr RESIDENT_RESULT=$result"
}

sample T0
sleep 60
sample T60
sleep 60
sample T120

echo '--- FINAL ACCEPTANCE ---'
service_exact RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS" || stop_now resident_not_stable
service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS" || stop_now capture_changed_final
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS" || stop_now signer_changed_final
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS" || stop_now discord_changed_final
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "FINAL_METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || stop_now metadata_block_changed_final

FINAL=$("$APP_PY" - "$OBS" "$OBHB" "$BASE_CURSOR" "$BASE_UPDATED" <<'PY'
import json,pathlib,sys
from datetime import UTC,datetime
state=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
hb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
base_cursor=int(sys.argv[3])
base_updated=sys.argv[4]
m=state.get("metrics") or {}
c=state.get("cursors") or {}
events=int(m.get("unrecoverable_core_gap_events",0) or 0)
messages=int(m.get("unrecoverable_core_gap_messages",0) or 0)
cursor=int(c.get("lobby",0) or 0)
updated=state.get("updated_at","missing")
try:
    dt=datetime.fromisoformat(hb.get("updated_at",""))
    if dt.tzinfo is None:
        dt=dt.replace(tzinfo=UTC)
    age=max(0.0,(datetime.now(UTC)-dt.astimezone(UTC)).total_seconds())
except Exception:
    age=-1.0
print(f"{events}|{messages}|{cursor}|{updated}|{age:.1f}|{1 if updated!=base_updated else 0}|{1 if cursor>=base_cursor else 0}")
PY
)
F_EVENTS=$(printf '%s' "$FINAL" | cut -d'|' -f1)
F_MESSAGES=$(printf '%s' "$FINAL" | cut -d'|' -f2)
F_CURSOR=$(printf '%s' "$FINAL" | cut -d'|' -f3)
F_UPDATED=$(printf '%s' "$FINAL" | cut -d'|' -f4)
F_HB_AGE=$(printf '%s' "$FINAL" | cut -d'|' -f5)
F_UPDATED_MOVED=$(printf '%s' "$FINAL" | cut -d'|' -f6)
F_CURSOR_OK=$(printf '%s' "$FINAL" | cut -d'|' -f7)
echo "FINAL_PROTECTED_CORE=$F_EVENTS/$F_MESSAGES"
echo "FINAL_LOBBY_CURSOR=$F_CURSOR"
echo "FINAL_OBSERVER_UPDATED_AT=$F_UPDATED"
echo "FINAL_OBSERVER_HEARTBEAT_AGE=$F_HB_AGE"
echo "FINAL_OBSERVER_UPDATED_MOVED=$F_UPDATED_MOVED"
echo "FINAL_CURSOR_NONDECREASING=$F_CURSOR_OK"

[[ "$F_EVENTS" == "$EXPECTED_CORE_EVENTS" && "$F_MESSAGES" == "$EXPECTED_CORE_MESSAGES" ]] || stop_now protected_core_changed_during_watch
[[ "$F_UPDATED_MOVED" == 1 && "$F_CURSOR_OK" == 1 ]] || stop_now observer_not_progressing
"$APP_PY" - "$F_HB_AGE" <<'PY'
import sys
raise SystemExit(0 if 0 <= float(sys.argv[1]) <= 180 else 1)
PY
[[ $? -eq 0 ]] || stop_now observer_heartbeat_not_fresh

echo 'SERVICE_MUTATION=NO'
echo 'SERVICE_RESTART=NO'
echo 'SOURCE_MUTATION=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'NETWORK_PROBE=NO'
echo 'RAW_CMDLINE_OUTPUT=NO'
echo 'TECHNOCORE_WRITE=NO'
echo '=== ISSUE364_POST_ROLLOUT_RECONCILE_V1=PASS ==='
echo 'DO_NOT_RERUN=YES'
exit 0
