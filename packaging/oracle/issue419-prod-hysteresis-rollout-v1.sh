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

PRE=254c2328bcb2bffc27d1f123b93296ebe7b48661
TARGET=077d1e478363751bf5b73d810326f95f3a36b7a3
EXPECTED_CORE_EVENTS=120
EXPECTED_CORE_MESSAGES=5650166

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIGN=technocore-safe-agent-signer.service
DISC=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service

EXPECTED_RES_PID=2232290
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
RESIDENT_FILE=src/flop_agent/resident.py

CAPTURE_BLOB=285a95c539611c87768634cba1d45cdb442beb14
BRIDGE_BLOB=b96f315dd6bd5c2baa0f5db35acd85479e52e993
PRE_ISOLATION_BLOB=2de08f76a8bdcb9a1c5449230c8d6ea7940bd5c0
TARGET_ISOLATION_BLOB=ce7193a5fe7e80dbb86cea2b0e3307c7124f30dc
RESIDENT_BLOB=7e74f2f00a4e5caa251d28b4dacf51f867ba64cf

echo '=== ISSUE419 PROD HYSTERESIS ROLLOUT V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

stop_pre() {
  echo "PROD419V1=STOP:$1"
  exit 0
}

if [[ $EUID -ne 0 ]]; then stop_pre not_root; fi
for cmd in git systemctl stat runuser timeout sleep cut seq awk; do
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

echo '--- PRE SERVICE GATES ---'
service_exact RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS" || stop_pre resident_baseline_changed
service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS" || stop_pre capture_baseline_changed
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS" || stop_pre signer_baseline_changed
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS" || stop_pre discord_baseline_changed
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || stop_pre metadata_block_changed

PRE_STATE=$("$APP_PY" - "$OBS" "$OBHB" "$RESHB" <<'PY'
import json,pathlib,sys
from datetime import UTC,datetime
obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
obhb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
reshb=json.loads(pathlib.Path(sys.argv[3]).read_text("utf-8"))
m=obs.get("metrics") or {}
c=obs.get("cursors") or {}
def age(v):
    try:
        d=datetime.fromisoformat(v)
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:return -1.0
print(
    f"{int(m.get('unrecoverable_core_gap_events',0) or 0)}|"
    f"{int(m.get('unrecoverable_core_gap_messages',0) or 0)}|"
    f"{int(c.get('lobby',0) or 0)}|"
    f"{obs.get('updated_at','missing')}|"
    f"{age(obhb.get('updated_at')):.1f}|"
    f"{age(reshb.get('updated_at')):.1f}|"
    f"{reshb.get('status','missing')}"
)
PY
)
PRE_EVENTS=$(printf '%s' "$PRE_STATE"|cut -d'|' -f1)
PRE_MESSAGES=$(printf '%s' "$PRE_STATE"|cut -d'|' -f2)
PRE_CURSOR=$(printf '%s' "$PRE_STATE"|cut -d'|' -f3)
PRE_OBS_UPDATED=$(printf '%s' "$PRE_STATE"|cut -d'|' -f4)
PRE_OBS_HB_AGE=$(printf '%s' "$PRE_STATE"|cut -d'|' -f5)
PRE_RES_HB_AGE=$(printf '%s' "$PRE_STATE"|cut -d'|' -f6)
PRE_RES_HB_STATUS=$(printf '%s' "$PRE_STATE"|cut -d'|' -f7)
echo "PRE_PROTECTED_CORE=$PRE_EVENTS/$PRE_MESSAGES"
echo "PRE_LOBBY_CURSOR=$PRE_CURSOR"
echo "PRE_OBSERVER_UPDATED_AT=$PRE_OBS_UPDATED"
echo "PRE_OBSERVER_HEARTBEAT_AGE=$PRE_OBS_HB_AGE"
echo "PRE_RESIDENT_HEARTBEAT_AGE=$PRE_RES_HB_AGE"
echo "PRE_RESIDENT_HEARTBEAT_STATUS=$PRE_RES_HB_STATUS"
[[ "$PRE_EVENTS" == "$EXPECTED_CORE_EVENTS" && "$PRE_MESSAGES" == "$EXPECTED_CORE_MESSAGES" ]] || stop_pre protected_core_changed

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

echo '--- PRE FILE GATES ---'
check_file "$CAPTURE_FILE" "$CAPTURE_BLOB" || stop_pre capture_file_changed
check_file "$BRIDGE_FILE" "$BRIDGE_BLOB" || stop_pre bridge_file_changed
check_file "$ISOLATION_FILE" "$PRE_ISOLATION_BLOB" || stop_pre isolation_file_changed
check_file "$RESIDENT_FILE" "$RESIDENT_BLOB" || stop_pre resident_file_changed

echo '--- FETCH / EXACT TARGET ---'
git -C "$APP" fetch --no-tags origin main || stop_pre fetch_failed
REMOTE_MAIN=$(git -C "$APP" rev-parse origin/main 2>/dev/null || true)
echo "REMOTE_MAIN=$REMOTE_MAIN"
[[ "$REMOTE_MAIN" == "$TARGET" ]] || stop_pre remote_main_moved
git -C "$APP" merge-base --is-ancestor "$PRE" "$TARGET" || stop_pre target_not_descendant

echo '--- FAST-FORWARD TARGET ---'
git -C "$APP" merge --ff-only "$TARGET" || { echo 'PROD419V1=STOP:ff_only_failed'; exit 0; }
POST_HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
echo "POST_HEAD=$POST_HEAD"
[[ "$POST_HEAD" == "$TARGET" ]] || { echo 'PROD419V1=STOP:post_head_wrong'; echo 'TARGET_MAY_BE_PARTIALLY_APPLIED=YES'; exit 0; }

chmod 0644 \
  "$APP/$CAPTURE_FILE" \
  "$APP/$BRIDGE_FILE" \
  "$APP/$ISOLATION_FILE" \
  "$APP/$RESIDENT_FILE"

echo '--- POST FILE VERIFY ---'
check_file "$CAPTURE_FILE" "$CAPTURE_BLOB" || { echo 'PROD419V1=STOP:capture_file_post_invalid'; exit 0; }
check_file "$BRIDGE_FILE" "$BRIDGE_BLOB" || { echo 'PROD419V1=STOP:bridge_file_post_invalid'; exit 0; }
check_file "$ISOLATION_FILE" "$TARGET_ISOLATION_BLOB" || { echo 'PROD419V1=STOP:isolation_file_post_invalid'; exit 0; }
check_file "$RESIDENT_FILE" "$RESIDENT_BLOB" || { echo 'PROD419V1=STOP:resident_file_post_invalid'; exit 0; }

POST_WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
if [[ -z "$POST_WORKTREE" ]]; then echo 'POST_WORKTREE_CLEAN=YES'; else echo 'POST_WORKTREE_CLEAN=NO'; fi
[[ -z "$POST_WORKTREE" ]] || { echo 'PROD419V1=STOP:worktree_dirty_after_deploy'; exit 0; }

echo '--- IMPORT SMOKE AS RESIDENT USER ---'
if ! runuser -u technocore -- env FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" PYTHONDONTWRITEBYTECODE=1 "$APP_PY" - <<'PY'
from flop_agent import observer_resident_isolation
import flop_agent.resident_daemon
assert observer_resident_isolation._PRESSURE_CLEAR_STABLE_SECONDS == 60.0
print("IMPORT_SMOKE=PASS")
PY
then
  echo 'PROD419V1=STOP:import_smoke_failed'
  exit 0
fi

echo '--- RESTART RESIDENT ONLY ---'
timeout 120 systemctl restart "$RES"
RESTART_RC=$?
echo "RESIDENT_RESTART_COMMAND_RC=$RESTART_RC"
[[ "$RESTART_RC" == 0 ]] || { echo 'PROD419V1=STOP:resident_restart_command_failed'; echo 'TARGET_REMAINS_DEPLOYED=YES'; exit 0; }

NEW_PID=
for i in $(seq 1 30); do
  active=$(systemctl show "$RES" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$RES" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$RES" -p Result --value 2>/dev/null || true)
  echo "START_SAMPLE_$i ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result"
  if [[ "$active" == active && "$sub" == running && "$pid" =~ ^[1-9][0-9]*$ && "$pid" != "$EXPECTED_RES_PID" && "$nr" == 0 && "$result" == success ]]; then
    NEW_PID=$pid
    break
  fi
  sleep 2
done
[[ -n "$NEW_PID" ]] || { echo 'PROD419V1=STOP:resident_not_recovered'; echo 'TARGET_REMAINS_DEPLOYED=YES'; exit 0; }

sample() {
  local label=$1
  local require_no_maintenance=$2
  local pid
  pid=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
  echo "--- $label ---"
  SAMPLE=$(
    FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" "$APP_PY" - "$label" "$pid" "$OBS" "$OBHB" "$RESHB" <<'PY'
import json,pathlib,sys
from datetime import UTC,datetime
from flop_agent import resident

label,pid_s,obs_s,obhb_s,reshb_s=sys.argv[1:]
pid=int(pid_s or 0)
obs=json.loads(pathlib.Path(obs_s).read_text("utf-8"))
obhb=json.loads(pathlib.Path(obhb_s).read_text("utf-8"))
reshb=json.loads(pathlib.Path(reshb_s).read_text("utf-8"))
op=resident.resident_status()
m=obs.get("metrics") or {}
c=obs.get("cursors") or {}

def age(value):
    try:
        dt=datetime.fromisoformat(value)
        if dt.tzinfo is None:dt=dt.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-dt.astimezone(UTC)).total_seconds())
    except Exception:return -1.0

raw=reshb.get("resident_status") if isinstance(reshb.get("resident_status"),dict) else {}
semantics=True
if reshb.get("status") == resident.PRESSURE_PAUSED_HEARTBEAT_STATUS:
    semantics=(
        op.get("maintenance_status") == resident.PRESSURE_PAUSED_HEARTBEAT_STATUS
        and op.get("maintenance_last_refresh_at") == raw.get("last_refresh_at")
        and op.get("last_refresh_at") == reshb.get("updated_at")
    )
elif reshb.get("status") != "ok":
    semantics=False

mem={}
for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
    if ":" not in line:continue
    k,v=line.split(":",1)
    if k in {"MemTotal","MemAvailable","SwapTotal","SwapFree","AnonPages"}:
        mem[k]=int(v.strip().split()[0])*1024
psi={}
for kind in ("io","memory"):
    p=pathlib.Path(f"/proc/pressure/{kind}")
    if not p.exists():continue
    for line in p.read_text("utf-8").splitlines():
        if not line.startswith("full "):continue
        for field in line.split()[1:]:
            if field.startswith("avg10="):
                try:psi[kind]=float(field.split("=",1)[1])
                except ValueError:pass
pressure=(
    mem.get("MemAvailable",0) < 256*1024*1024
    or psi.get("memory",0.0) > 5.0
    or psi.get("io",0.0) > 10.0
)

tracker=0
maintenance=[]
children=pathlib.Path(f"/proc/{pid}/task/{pid}/children")
if pid and children.exists():
    for raw_pid in children.read_text("utf-8").split():
        try:child=int(raw_pid)
        except ValueError:continue
        try:cmd=pathlib.Path(f"/proc/{child}/cmdline").read_bytes()
        except OSError:cmd=b""
        try:stat=pathlib.Path(f"/proc/{child}/stat").read_text("utf-8").split()
        except OSError:stat=[]
        state=stat[2] if len(stat)>2 else "?"
        if b"resource_tracker" in cmd:tracker+=1
        else:maintenance.append(state)

print(f"{label}_PROTECTED_CORE={int(m.get('unrecoverable_core_gap_events',0) or 0)}/{int(m.get('unrecoverable_core_gap_messages',0) or 0)}")
print(f"{label}_LOBBY_CURSOR={int(c.get('lobby',0) or 0)}")
print(f"{label}_OBSERVER_UPDATED_AT={obs.get('updated_at','missing')}")
print(f"{label}_OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"{label}_RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"{label}_RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")
print(f"{label}_RESIDENT_HEARTBEAT_SEMANTICS={'PASS' if semantics else 'FAIL'}")
print(f"{label}_MEMAVAILABLE_BYTES={mem.get('MemAvailable',0)}")
print(f"{label}_PSI_IO_FULL_AVG10={psi.get('io',-1.0):.2f}")
print(f"{label}_PSI_MEMORY_FULL_AVG10={psi.get('memory',-1.0):.2f}")
print(f"{label}_PRESSURE_GUARD_CURRENT={'ON' if pressure else 'OFF'}")
print(f"{label}_RESOURCE_TRACKER_CHILD_COUNT={tracker}")
print(f"{label}_MAINTENANCE_CHILD_COUNT={len(maintenance)}")
print(f"{label}_MAINTENANCE_CHILD_STATES={','.join(maintenance) if maintenance else 'NONE'}")
print(f"{label}_SEMANTICS_FLAG={1 if semantics else 0}")
print(f"{label}_MAINTENANCE_COUNT_VALUE={len(maintenance)}")
PY
  )
  printf '%s\n' "$SAMPLE"

  local count semantics
  count=$(printf '%s\n' "$SAMPLE" | awk -F= -v k="$label"_MAINTENANCE_COUNT_VALUE '$1==k{print $2}')
  semantics=$(printf '%s\n' "$SAMPLE" | awk -F= -v k="$label"_SEMANTICS_FLAG '$1==k{print $2}')
  [[ "$semantics" == 1 ]] || return 12
  if [[ "$require_no_maintenance" == YES && "$count" != 0 ]]; then
    return 13
  fi

  local active sub current_pid nr result
  active=$(systemctl show "$RES" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$RES" -p SubState --value 2>/dev/null || true)
  current_pid=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$RES" -p Result --value 2>/dev/null || true)
  echo "$label RESIDENT_ACTIVE=$active RESIDENT_SUB=$sub RESIDENT_PID=$current_pid RESIDENT_NRESTARTS=$nr RESIDENT_RESULT=$result"
  [[ "$active" == active && "$sub" == running && "$current_pid" == "$NEW_PID" && "$nr" == 0 && "$result" == success ]]
}

sample T0 YES || { rc=$?; echo "PROD419V1=STOP:t0_acceptance_rc_$rc"; echo 'TARGET_REMAINS_DEPLOYED=YES'; exit 0; }
sleep 20
sample T20 YES || { rc=$?; echo "PROD419V1=STOP:t20_acceptance_rc_$rc"; echo 'TARGET_REMAINS_DEPLOYED=YES'; exit 0; }
sleep 20
sample T40 YES || { rc=$?; echo "PROD419V1=STOP:hysteresis_early_admission_rc_$rc"; echo 'TARGET_REMAINS_DEPLOYED=YES'; exit 0; }
sleep 40
sample T80 NO || { rc=$?; echo "PROD419V1=STOP:t80_acceptance_rc_$rc"; echo 'TARGET_REMAINS_DEPLOYED=YES'; exit 0; }
sleep 40
sample T120 NO || { rc=$?; echo "PROD419V1=STOP:t120_acceptance_rc_$rc"; echo 'TARGET_REMAINS_DEPLOYED=YES'; exit 0; }

echo '--- FINAL ACCEPTANCE ---'
FINAL_ACTIVE=$(systemctl show "$RES" -p ActiveState --value 2>/dev/null || true)
FINAL_SUB=$(systemctl show "$RES" -p SubState --value 2>/dev/null || true)
FINAL_PID=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
FINAL_NR=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
FINAL_RESULT=$(systemctl show "$RES" -p Result --value 2>/dev/null || true)
echo "FINAL_RESIDENT ACTIVE=$FINAL_ACTIVE SUB=$FINAL_SUB PID=$FINAL_PID NRESTARTS=$FINAL_NR RESULT=$FINAL_RESULT"
[[ "$FINAL_ACTIVE" == active && "$FINAL_SUB" == running && "$FINAL_PID" == "$NEW_PID" && "$FINAL_NR" == 0 && "$FINAL_RESULT" == success ]] || {
  echo 'PROD419V1=STOP:resident_unstable'
  echo 'TARGET_REMAINS_DEPLOYED=YES'
  exit 0
}

FINAL=$("$APP_PY" - "$OBS" "$OBHB" "$RESHB" "$PRE_CURSOR" "$PRE_OBS_UPDATED" <<'PY'
import json,pathlib,sys
from datetime import UTC,datetime
obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
obhb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
reshb=json.loads(pathlib.Path(sys.argv[3]).read_text("utf-8"))
pre_cursor=int(sys.argv[4]);pre_updated=sys.argv[5]
m=obs.get("metrics") or {}
c=obs.get("cursors") or {}
def age(v):
    try:
        d=datetime.fromisoformat(v)
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:return -1.0
print(
    f"{int(m.get('unrecoverable_core_gap_events',0) or 0)}|"
    f"{int(m.get('unrecoverable_core_gap_messages',0) or 0)}|"
    f"{int(c.get('lobby',0) or 0)}|"
    f"{obs.get('updated_at','missing')}|"
    f"{age(obhb.get('updated_at')):.1f}|"
    f"{age(reshb.get('updated_at')):.1f}|"
    f"{1 if obs.get('updated_at') != pre_updated else 0}|"
    f"{1 if int(c.get('lobby',0) or 0) >= pre_cursor else 0}"
)
PY
)
F_EVENTS=$(printf '%s' "$FINAL"|cut -d'|' -f1)
F_MESSAGES=$(printf '%s' "$FINAL"|cut -d'|' -f2)
F_CURSOR=$(printf '%s' "$FINAL"|cut -d'|' -f3)
F_UPDATED=$(printf '%s' "$FINAL"|cut -d'|' -f4)
F_OBS_HB_AGE=$(printf '%s' "$FINAL"|cut -d'|' -f5)
F_RES_HB_AGE=$(printf '%s' "$FINAL"|cut -d'|' -f6)
F_UPDATED_MOVED=$(printf '%s' "$FINAL"|cut -d'|' -f7)
F_CURSOR_OK=$(printf '%s' "$FINAL"|cut -d'|' -f8)
echo "FINAL_PROTECTED_CORE=$F_EVENTS/$F_MESSAGES"
echo "FINAL_LOBBY_CURSOR=$F_CURSOR"
echo "FINAL_OBSERVER_UPDATED_AT=$F_UPDATED"
echo "FINAL_OBSERVER_HEARTBEAT_AGE=$F_OBS_HB_AGE"
echo "FINAL_RESIDENT_HEARTBEAT_AGE=$F_RES_HB_AGE"
echo "FINAL_OBSERVER_UPDATED_MOVED=$F_UPDATED_MOVED"
echo "FINAL_CURSOR_NONDECREASING=$F_CURSOR_OK"

[[ "$F_EVENTS" == "$EXPECTED_CORE_EVENTS" && "$F_MESSAGES" == "$EXPECTED_CORE_MESSAGES" ]] || { echo 'PROD419V1=STOP:protected_core_changed'; echo 'TARGET_REMAINS_DEPLOYED=YES'; exit 0; }
[[ "$F_UPDATED_MOVED" == 1 && "$F_CURSOR_OK" == 1 ]] || { echo 'PROD419V1=STOP:observer_not_progressing'; echo 'TARGET_REMAINS_DEPLOYED=YES'; exit 0; }

if ! "$APP_PY" - "$F_OBS_HB_AGE" "$F_RES_HB_AGE" <<'PY'
import sys
obs=float(sys.argv[1]);resident=float(sys.argv[2])
raise SystemExit(0 if 0 <= obs <= 180 and 0 <= resident <= 120 else 1)
PY
then
  echo 'PROD419V1=STOP:heartbeat_not_fresh'
  echo 'TARGET_REMAINS_DEPLOYED=YES'
  exit 0
fi

service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS" || { echo 'PROD419V1=STOP:capture_changed'; exit 0; }
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS" || { echo 'PROD419V1=STOP:signer_changed'; exit 0; }
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS" || { echo 'PROD419V1=STOP:discord_changed'; exit 0; }
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "FINAL_METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || { echo 'PROD419V1=STOP:metadata_block_changed'; exit 0; }

echo 'SOURCE_ROLLOUT=PASS'
echo 'HYSTERESIS_EARLY_WINDOW=PASS'
echo 'RESIDENT_RESTART=EXACTLY_ONCE'
echo 'CAPTURE_RESTART=NO'
echo 'SIGNER_RESTART=NO'
echo 'DISCORD_RESTART=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'TECHNOCORE_WRITE=NO'
echo '=== PROD419_HYSTERESIS_ROLLOUT_V1=PASS ==='
echo 'DO_NOT_RERUN=YES'
exit 0
