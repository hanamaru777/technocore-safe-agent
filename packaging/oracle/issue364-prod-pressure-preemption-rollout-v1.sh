#!/usr/bin/env bash
set -u
set -o pipefail
umask 022

APP=/opt/technocore-safe-agent
APP_PY=$APP/.venv/bin/python
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
OBHB=$STATE/observer/observer-heartbeat.json
RESHB=$STATE/observer/resident-heartbeat.json

PRE=473e4f73426069c682cfd716f611e0bfad7d4fe8
TARGET=9d635be14de715d61e680136dd688bd8598e9403
EXPECTED_CORE_EVENTS=120
EXPECTED_CORE_MESSAGES=5650166

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIGN=technocore-safe-agent-signer.service
DISC=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service

EXPECTED_RES_PID=2181484
EXPECTED_RES_RESTARTS=1413
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
PRE_ISOLATION_BLOB=6ac40ac32108e141320c1d87d5ce0268e71e986b
TARGET_ISOLATION_BLOB=6ea86a3f7350162727763e58f95116970eb43f35

echo '=== ISSUE364 PROD PRESSURE PREEMPTION ROLLOUT V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

stop_pre() {
  echo "PROD364V1=STOP:$1"
  exit 0
}

if [[ $EUID -ne 0 ]]; then stop_pre not_root; fi

for cmd in git systemctl stat runuser timeout sleep awk cut seq; do
  command -v "$cmd" >/dev/null 2>&1 || stop_pre "missing_command:$cmd"
done
[[ -x "$APP_PY" && -f "$OBS" && -f "$OBHB" && -f "$RESHB" ]] || stop_pre required_path_missing

HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
BRANCH=$(git -C "$APP" branch --show-current 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "PRE_HEAD=$HEAD"
echo "PRE_BRANCH=$BRANCH"
if [[ -z "$WORKTREE" ]]; then echo 'PRE_WORKTREE_CLEAN=YES'; else echo 'PRE_WORKTREE_CLEAN=NO'; fi
[[ "$HEAD" == "$PRE" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_pre repo_baseline_changed

service_exact() {
  local label=$1 unit=$2 pid_expected=$3 nr_expected=$4
  local active sub pid nr result
  active=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result"
  [[ "$active" == active && "$sub" == running && "$pid" == "$pid_expected" && "$nr" == "$nr_expected" && "$result" == success ]]
}

echo '--- PRE SERVICE GATES ---'
service_exact RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS" || stop_pre resident_baseline_changed
service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS" || stop_pre capture_baseline_changed
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS" || stop_pre signer_baseline_changed
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS" || stop_pre discord_baseline_changed
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || stop_pre metadata_block_changed

PRE_STATE=$("$APP_PY" - "$OBS" "$OBHB" <<'PY'
import json,pathlib,sys
from datetime import UTC,datetime
state=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
hb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
m=state.get("metrics") or {}
c=state.get("cursors") or {}
def age(v):
    try:
        d=datetime.fromisoformat(v)
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:return -1.0
print(f"{int(m.get('unrecoverable_core_gap_events',0) or 0)}|{int(m.get('unrecoverable_core_gap_messages',0) or 0)}|{int(c.get('lobby',0) or 0)}|{state.get('updated_at','missing')}|{age(hb.get('updated_at')):.1f}")
PY
)
PRE_CORE_EVENTS=$(printf '%s' "$PRE_STATE"|cut -d'|' -f1)
PRE_CORE_MESSAGES=$(printf '%s' "$PRE_STATE"|cut -d'|' -f2)
PRE_CURSOR=$(printf '%s' "$PRE_STATE"|cut -d'|' -f3)
PRE_OBSERVER_UPDATED=$(printf '%s' "$PRE_STATE"|cut -d'|' -f4)
PRE_OBSERVER_HB_AGE=$(printf '%s' "$PRE_STATE"|cut -d'|' -f5)
echo "PRE_PROTECTED_CORE=$PRE_CORE_EVENTS/$PRE_CORE_MESSAGES"
echo "PRE_LOBBY_CURSOR=$PRE_CURSOR"
echo "PRE_OBSERVER_UPDATED_AT=$PRE_OBSERVER_UPDATED"
echo "PRE_OBSERVER_HEARTBEAT_AGE=$PRE_OBSERVER_HB_AGE"
[[ "$PRE_CORE_EVENTS" == "$EXPECTED_CORE_EVENTS" && "$PRE_CORE_MESSAGES" == "$EXPECTED_CORE_MESSAGES" ]] || stop_pre protected_core_changed

check_file() {
  local rel=$1 expected=$2 phase=$3
  local path="$APP/$rel" blob mode owner group
  blob=$(git -C "$APP" hash-object "$path" 2>/dev/null || true)
  mode=$(stat -c '%a' "$path" 2>/dev/null || true)
  owner=$(stat -c '%U' "$path" 2>/dev/null || true)
  group=$(stat -c '%G' "$path" 2>/dev/null || true)
  echo "\${phase}_FILE path=$rel mode=$mode owner=$owner group=$group blob=$blob"
  [[ "$blob" == "$expected" && "$mode" == 644 && "$owner" == root && "$group" == root ]]
}

echo '--- PRE RUNTIME FILE GATES ---'
check_file "$CAPTURE_FILE" "$CAPTURE_BLOB" PRE || stop_pre capture_file_baseline_changed
check_file "$BRIDGE_FILE" "$BRIDGE_BLOB" PRE || stop_pre bridge_file_baseline_changed
check_file "$ISOLATION_FILE" "$PRE_ISOLATION_BLOB" PRE || stop_pre isolation_file_baseline_changed

echo '--- PRE LIGHTWEIGHT PRESSURE ---'
"$APP_PY" - <<'PY'
import pathlib,re
for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
    if ":" not in line: continue
    k,v=line.split(":",1)
    if k in {"MemTotal","MemAvailable","SwapTotal","SwapFree","AnonPages"}:
        print(f"PRE_MEM_{k.upper()}_BYTES={int(v.strip().split()[0])*1024}")
for kind in ("io","memory"):
    p=pathlib.Path(f"/proc/pressure/{kind}")
    if p.exists():
        for i,line in enumerate(p.read_text("utf-8").splitlines()[:2],1):
            print(f"PRE_PSI_{kind.upper()}_{i}={re.sub(r'[^A-Za-z0-9_.:/=-]','',line)[:160]}")
PY

echo '--- FETCH / EXACT TARGET ---'
if ! git -C "$APP" fetch --no-tags origin main; then stop_pre fetch_failed; fi
REMOTE_MAIN=$(git -C "$APP" rev-parse origin/main 2>/dev/null || true)
echo "REMOTE_MAIN=$REMOTE_MAIN"
[[ "$REMOTE_MAIN" == "$TARGET" ]] || stop_pre remote_main_moved
git -C "$APP" merge-base --is-ancestor "$PRE" "$TARGET" || stop_pre target_not_descendant

echo '--- FAST-FORWARD TARGET ---'
if ! git -C "$APP" merge --ff-only "$TARGET"; then
  echo 'PROD364V1=STOP:ff_only_failed'
  exit 0
fi
POST_HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
echo "POST_HEAD=$POST_HEAD"
if [[ "$POST_HEAD" != "$TARGET" ]]; then
  echo 'PROD364V1=STOP:post_head_wrong'
  echo 'TARGET_MAY_BE_PARTIALLY_APPLIED=YES'
  exit 0
fi

chmod 0644 "$APP/$CAPTURE_FILE" "$APP/$BRIDGE_FILE" "$APP/$ISOLATION_FILE"

echo '--- POST RUNTIME FILE VERIFY ---'
check_file "$CAPTURE_FILE" "$CAPTURE_BLOB" POST || { echo 'PROD364V1=STOP:capture_file_post_invalid'; exit 0; }
check_file "$BRIDGE_FILE" "$BRIDGE_BLOB" POST || { echo 'PROD364V1=STOP:bridge_file_post_invalid'; exit 0; }
check_file "$ISOLATION_FILE" "$TARGET_ISOLATION_BLOB" POST || { echo 'PROD364V1=STOP:isolation_file_post_invalid'; exit 0; }

POST_WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
if [[ -z "$POST_WORKTREE" ]]; then echo 'POST_WORKTREE_CLEAN=YES'; else echo 'POST_WORKTREE_CLEAN=NO'; fi
[[ -z "$POST_WORKTREE" ]] || { echo 'PROD364V1=STOP:worktree_dirty_after_deploy'; exit 0; }

echo '--- IMPORT SMOKE AS RESIDENT USER ---'
if ! runuser -u technocore -- env PYTHONPATH="$APP/src" PYTHONDONTWRITEBYTECODE=1 FLOP_STATE_DIR="$STATE" "$APP_PY" - <<'PY'
import flop_agent.observer_resident_isolation
import flop_agent.resident_daemon
print("IMPORT_SMOKE=PASS")
PY
then
  echo 'PROD364V1=STOP:import_smoke_failed'
  exit 0
fi

echo '--- RESTART RESIDENT ONLY ---'
timeout 120 systemctl restart "$RES"
RESTART_RC=$?
echo "RESIDENT_RESTART_COMMAND_RC=$RESTART_RC"

NEW_PID=
NEW_NR=
for i in $(seq 1 30); do
  active=$(systemctl show "$RES" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$RES" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$RES" -p Result --value 2>/dev/null || true)
  echo "START_SAMPLE_$i ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result"
  if [[ "$active" == active && "$sub" == running && "$pid" =~ ^[1-9][0-9]*$ && "$pid" != "$EXPECTED_RES_PID" && "$result" == success ]]; then
    NEW_PID=$pid
    NEW_NR=$nr
    break
  fi
  sleep 2
done
if [[ -z "$NEW_PID" ]]; then
  echo 'PROD364V1=STOP:resident_not_recovered'
  echo 'TARGET_REMAINS_DEPLOYED=YES'
  exit 0
fi
if [[ "$NEW_NR" != "$EXPECTED_RES_RESTARTS" ]]; then
  echo "PROD364V1=STOP:resident_auto_restart_detected:$NEW_NR"
  echo 'TARGET_REMAINS_DEPLOYED=YES'
  exit 0
fi

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
m=state.get("metrics") or {}; c=state.get("cursors") or {}
def age(v):
    try:
        d=datetime.fromisoformat(v)
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:return -1.0
print(f"{label}_PROTECTED_CORE={int(m.get('unrecoverable_core_gap_events',0) or 0)}/{int(m.get('unrecoverable_core_gap_messages',0) or 0)}")
print(f"{label}_LOBBY_CURSOR={int(c.get('lobby',0) or 0)}")
print(f"{label}_OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
print(f"{label}_OBSERVER_HEARTBEAT_STATUS={obhb.get('status','missing')}")
print(f"{label}_OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"{label}_RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"{label}_RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")
mem={}
for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
    if ":" not in line:continue
    k,v=line.split(":",1)
    if k in {"MemTotal","MemAvailable","SwapTotal","SwapFree","AnonPages"}:
        mem[k]=int(v.strip().split()[0])*1024
        print(f"{label}_MEM_{k.upper()}_BYTES={mem[k]}")
psi={}
for kind in ("io","memory"):
    p=pathlib.Path(f"/proc/pressure/{kind}")
    if not p.exists():continue
    for i,line in enumerate(p.read_text("utf-8").splitlines()[:2],1):
        print(f"{label}_PSI_{kind.upper()}_{i}={re.sub(r'[^A-Za-z0-9_.:/=-]','',line)[:160]}")
        if line.startswith("full "):
            for field in line.split()[1:]:
                if field.startswith("avg10="):
                    try:psi[kind]=float(field.split("=",1)[1])
                    except ValueError:pass
pressure=(mem.get("MemAvailable",0)<256*1024*1024 or psi.get("memory",0)>5.0 or psi.get("io",0)>10.0)
print(f"{label}_PRESSURE_GUARD_CURRENT={'ON' if pressure else 'OFF'}")
tracker=0; maintenance=[]
children_path=pathlib.Path(f"/proc/{pid}/task/{pid}/children")
if pid and children_path.exists():
    for raw in children_path.read_text("utf-8").split():
        try:child=int(raw)
        except ValueError:continue
        cmd=b""
        try:cmd=pathlib.Path(f"/proc/{child}/cmdline").read_bytes()
        except OSError:pass
        try:stat=pathlib.Path(f"/proc/{child}/stat").read_text("utf-8").split()
        except OSError:stat=[]
        state_code=stat[2] if len(stat)>2 else "?"
        if b"resource_tracker" in cmd:
            tracker+=1
        else:
            maintenance.append(state_code)
print(f"{label}_RESOURCE_TRACKER_CHILD_COUNT={tracker}")
print(f"{label}_MAINTENANCE_CHILD_COUNT={len(maintenance)}")
print(f"{label}_MAINTENANCE_CHILD_STATES={','.join(maintenance) if maintenance else 'NONE'}")
PY
  active=$(systemctl show "$RES" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$RES" -p SubState --value 2>/dev/null || true)
  rp=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$RES" -p Result --value 2>/dev/null || true)
  echo "\${label}_RESIDENT ACTIVE=$active SUB=$sub PID=$rp NRESTARTS=$nr RESULT=$result"
}

sample T0
sleep 45
sample T45
sleep 45
sample T90

echo '--- FINAL ACCEPTANCE ---'
FINAL_ACTIVE=$(systemctl show "$RES" -p ActiveState --value 2>/dev/null || true)
FINAL_SUB=$(systemctl show "$RES" -p SubState --value 2>/dev/null || true)
FINAL_PID=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
FINAL_NR=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
FINAL_RESULT=$(systemctl show "$RES" -p Result --value 2>/dev/null || true)
echo "FINAL_RESIDENT ACTIVE=$FINAL_ACTIVE SUB=$FINAL_SUB PID=$FINAL_PID NRESTARTS=$FINAL_NR RESULT=$FINAL_RESULT"
if [[ "$FINAL_ACTIVE" != active || "$FINAL_SUB" != running || "$FINAL_PID" != "$NEW_PID" || "$FINAL_NR" != "$EXPECTED_RES_RESTARTS" || "$FINAL_RESULT" != success ]]; then
  echo 'PROD364V1=STOP:resident_unstable'
  echo 'TARGET_REMAINS_DEPLOYED=YES'
  exit 0
fi

FINAL=$("$APP_PY" - "$OBS" "$OBHB" "$PRE_CURSOR" "$PRE_OBSERVER_UPDATED" <<'PY'
import json,pathlib,sys
from datetime import UTC,datetime
state=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
hb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
pre_cursor=int(sys.argv[3]); pre_updated=sys.argv[4]
m=state.get("metrics") or {}; c=state.get("cursors") or {}
def age(v):
    try:
        d=datetime.fromisoformat(v)
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:return -1.0
events=int(m.get("unrecoverable_core_gap_events",0) or 0)
messages=int(m.get("unrecoverable_core_gap_messages",0) or 0)
cursor=int(c.get("lobby",0) or 0)
updated=state.get("updated_at","missing")
hb_age=age(hb.get("updated_at"))
print(f"{events}|{messages}|{cursor}|{updated}|{hb_age:.1f}|{1 if updated!=pre_updated else 0}|{1 if cursor>=pre_cursor else 0}")
PY
)
F_EVENTS=$(printf '%s' "$FINAL"|cut -d'|' -f1)
F_MESSAGES=$(printf '%s' "$FINAL"|cut -d'|' -f2)
F_CURSOR=$(printf '%s' "$FINAL"|cut -d'|' -f3)
F_UPDATED=$(printf '%s' "$FINAL"|cut -d'|' -f4)
F_HB_AGE=$(printf '%s' "$FINAL"|cut -d'|' -f5)
F_UPDATED_MOVED=$(printf '%s' "$FINAL"|cut -d'|' -f6)
F_CURSOR_OK=$(printf '%s' "$FINAL"|cut -d'|' -f7)
echo "FINAL_PROTECTED_CORE=$F_EVENTS/$F_MESSAGES"
echo "FINAL_LOBBY_CURSOR=$F_CURSOR"
echo "FINAL_OBSERVER_UPDATED_AT=$F_UPDATED"
echo "FINAL_OBSERVER_HEARTBEAT_AGE=$F_HB_AGE"
echo "FINAL_OBSERVER_UPDATED_MOVED=$F_UPDATED_MOVED"
echo "FINAL_CURSOR_NONDECREASING=$F_CURSOR_OK"
if [[ "$F_EVENTS" != "$EXPECTED_CORE_EVENTS" || "$F_MESSAGES" != "$EXPECTED_CORE_MESSAGES" ]]; then
  echo 'PROD364V1=STOP:protected_core_changed'
  echo 'TARGET_REMAINS_DEPLOYED=YES'
  exit 0
fi
if [[ "$F_UPDATED_MOVED" != 1 || "$F_CURSOR_OK" != 1 ]]; then
  echo 'PROD364V1=STOP:observer_not_progressing'
  echo 'TARGET_REMAINS_DEPLOYED=YES'
  exit 0
fi
if ! "$APP_PY" - "$F_HB_AGE" <<'PY'
import sys
raise SystemExit(0 if 0 <= float(sys.argv[1]) <= 180 else 1)
PY
then
  echo 'PROD364V1=STOP:observer_heartbeat_not_fresh'
  echo 'TARGET_REMAINS_DEPLOYED=YES'
  exit 0
fi

service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS" || { echo 'PROD364V1=STOP:capture_changed'; exit 0; }
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS" || { echo 'PROD364V1=STOP:signer_changed'; exit 0; }
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS" || { echo 'PROD364V1=STOP:discord_changed'; exit 0; }
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "FINAL_METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || { echo 'PROD364V1=STOP:metadata_block_changed_post'; exit 0; }

echo 'SOURCE_ROLLOUT=PASS'
echo 'RESIDENT_RESTART=EXACTLY_ONCE'
echo 'CAPTURE_RESTART=NO'
echo 'SIGNER_RESTART=NO'
echo 'DISCORD_RESTART=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'TECHNOCORE_WRITE=NO'
echo '=== PROD364_PRESSURE_PREEMPTION_ROLLOUT_V1=PASS ==='
echo 'DO_NOT_RERUN=YES'
exit 0
