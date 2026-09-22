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

echo '=== ISSUE390 PERMISSION REPAIR V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'PROD390_PERMREPAIR_V1=STOP:not_root'
  exit 0
fi

for cmd in git systemctl stat runuser chmod sleep awk cut seq env; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "PROD390_PERMREPAIR_V1=STOP:missing_command:$cmd"
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
  echo 'PROD390_PERMREPAIR_V1=STOP:repo_not_exact_target'
  exit 0
fi

RES_USER=$(systemctl show "$RES" -p User --value 2>/dev/null || true)
echo "RESIDENT_USER=$RES_USER"
if [[ "$RES_USER" != technocore ]]; then
  echo 'PROD390_PERMREPAIR_V1=STOP:resident_user_changed'
  exit 0
fi

service_exact() {
  local label=$1
  local unit=$2
  local expected_pid=$3
  local expected_nr=$4
  local active pid nr result
  active=$(systemctl is-active "$unit" 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active PID=$pid NRESTARTS=$nr RESULT=$result"
  if [[ "$active" != active || "$pid" != "$expected_pid" || "$nr" != "$expected_nr" || "$result" != success ]]; then
    echo "PROD390_PERMREPAIR_V1=STOP:service_baseline_changed:$label"
    exit 0
  fi
}

echo '--- PRESERVED SERVICE BASELINE ---'
service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS"
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS"
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
if [[ "$META_ACTIVE" != active || "$META_RESULT" != success ]]; then
  echo 'PROD390_PERMREPAIR_V1=STOP:metadata_block_changed'
  exit 0
fi

echo '--- RESIDENT CRASHLOOP BASELINE ---'
RES_ACTIVE=$(systemctl show "$RES" -p ActiveState --value 2>/dev/null || true)
RES_SUB=$(systemctl show "$RES" -p SubState --value 2>/dev/null || true)
RES_NR=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
RES_RESULT=$(systemctl show "$RES" -p Result --value 2>/dev/null || true)
RES_CODE=$(systemctl show "$RES" -p ExecMainCode --value 2>/dev/null || true)
RES_STATUS=$(systemctl show "$RES" -p ExecMainStatus --value 2>/dev/null || true)
echo "RESIDENT ACTIVE=$RES_ACTIVE SUB=$RES_SUB NRESTARTS=$RES_NR RESULT=$RES_RESULT EXEC_CODE=$RES_CODE EXEC_STATUS=$RES_STATUS"
if [[ ! "$RES_NR" =~ ^[0-9]+$ || "$RES_NR" -lt 1000 ]]; then
  echo 'PROD390_PERMREPAIR_V1=STOP:resident_crashloop_not_confirmed'
  exit 0
fi
if [[ "$RES_RESULT" != exit-code || "$RES_CODE" != 1 || "$RES_STATUS" != 1 ]]; then
  echo 'PROD390_PERMREPAIR_V1=STOP:resident_failure_signature_changed'
  exit 0
fi

echo '--- PROTECTED CORE GATE ---'
CORE=$("$APP_PY" - "$OBS" <<'PY'
import json, pathlib, sys
state=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
metrics=state.get("metrics") or {}
events=int(metrics.get("unrecoverable_core_gap_events",0) or 0)
messages=int(metrics.get("unrecoverable_core_gap_messages",0) or 0)
cursor=int((state.get("cursors") or {}).get("lobby",0) or 0)
print(f"{events}|{messages}|{cursor}")
PY
)
CORE_EVENTS=$(printf '%s' "$CORE" | cut -d'|' -f1)
CORE_MESSAGES=$(printf '%s' "$CORE" | cut -d'|' -f2)
PRE_CURSOR=$(printf '%s' "$CORE" | cut -d'|' -f3)
echo "PROTECTED_CORE=$CORE_EVENTS/$CORE_MESSAGES"
echo "PRE_LOBBY_CURSOR=$PRE_CURSOR"
if [[ "$CORE_EVENTS" != "$EXPECTED_CORE_EVENTS" || "$CORE_MESSAGES" != "$EXPECTED_CORE_MESSAGES" ]]; then
  echo 'PROD390_PERMREPAIR_V1=STOP:core_moved_again'
  exit 0
fi

precheck_file() {
  local rel=$1
  local expected_blob=$2
  local path="$APP/$rel"
  local actual_blob index_blob mode owner group
  actual_blob=$(git -C "$APP" hash-object "$path" 2>/dev/null || true)
  index_blob=$(git -C "$APP" rev-parse "HEAD:$rel" 2>/dev/null || true)
  mode=$(stat -c '%a' "$path" 2>/dev/null || true)
  owner=$(stat -c '%U' "$path" 2>/dev/null || true)
  group=$(stat -c '%G' "$path" 2>/dev/null || true)
  echo "PRE_FILE path=$rel mode=$mode owner=$owner group=$group blob=$actual_blob index_blob=$index_blob"
  if [[ "$actual_blob" != "$expected_blob" || "$index_blob" != "$expected_blob" ]]; then
    echo "PROD390_PERMREPAIR_V1=STOP:blob_mismatch:$rel"
    exit 0
  fi
  if [[ "$mode" != 600 || "$owner" != root || "$group" != root ]]; then
    echo "PROD390_PERMREPAIR_V1=STOP:permission_baseline_changed:$rel"
    exit 0
  fi
  if runuser -u "$RES_USER" -- test -r "$path"; then
    echo "PROD390_PERMREPAIR_V1=STOP:file_unexpectedly_readable:$rel"
    exit 0
  fi
}

echo '--- EXACT FILE PRECHECK ---'
precheck_file "$F1" "$B1"
precheck_file "$F2" "$B2"
precheck_file "$F3" "$B3"
echo 'PRECHECK=PASS'

echo '--- PERMISSION REPAIR ---'
chmod 0644 "$APP/$F1" "$APP/$F2" "$APP/$F3"
echo 'CHMOD_0644_EXACT_THREE=PASS'

postcheck_file() {
  local rel=$1
  local expected_blob=$2
  local path="$APP/$rel"
  local actual_blob mode owner group
  actual_blob=$(git -C "$APP" hash-object "$path" 2>/dev/null || true)
  mode=$(stat -c '%a' "$path" 2>/dev/null || true)
  owner=$(stat -c '%U' "$path" 2>/dev/null || true)
  group=$(stat -c '%G' "$path" 2>/dev/null || true)
  echo "POST_FILE path=$rel mode=$mode owner=$owner group=$group blob=$actual_blob"
  if [[ "$actual_blob" != "$expected_blob" || "$mode" != 644 || "$owner" != root || "$group" != root ]]; then
    echo "PROD390_PERMREPAIR_V1=STOP:post_repair_file_invalid:$rel"
    echo 'PERMISSIONS_REMAIN_REPAIRED=YES'
    exit 0
  fi
  if ! runuser -u "$RES_USER" -- test -r "$path"; then
    echo "PROD390_PERMREPAIR_V1=STOP:file_still_unreadable:$rel"
    echo 'PERMISSIONS_REMAIN_REPAIRED=YES'
    exit 0
  fi
}

echo '--- POST FILE VERIFY ---'
postcheck_file "$F1" "$B1"
postcheck_file "$F2" "$B2"
postcheck_file "$F3" "$B3"

POST_WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
if [[ -z "$POST_WORKTREE" ]]; then echo 'POST_WORKTREE_CLEAN=YES'; else echo 'POST_WORKTREE_CLEAN=NO'; fi
if [[ -n "$POST_WORKTREE" ]]; then
  echo 'PROD390_PERMREPAIR_V1=STOP:worktree_dirty_after_permission_repair'
  echo 'PERMISSIONS_REMAIN_REPAIRED=YES'
  exit 0
fi

echo '--- IMPORT SMOKE AS RESIDENT USER ---'
if ! runuser -u "$RES_USER" -- env \
  PYTHONPATH="$APP/src" \
  PYTHONDONTWRITEBYTECODE=1 \
  FLOP_STATE_DIR="$STATE" \
  "$APP_PY" - <<'PY'
import flop_agent.observer_lobby_capture
import flop_agent.observer_lobby_startup_hole_bridge
import flop_agent.observer_resident_isolation
import flop_agent.resident_daemon
print("IMPORT_SMOKE=PASS")
PY
then
  echo 'PROD390_PERMREPAIR_V1=STOP:resident_import_smoke_failed'
  echo 'PERMISSIONS_REMAIN_REPAIRED=YES'
  exit 0
fi

echo '--- WAIT FOR EXISTING SYSTEMD AUTO-RESTART ---'
STABLE_PID=
STABLE_NR=
for step in $(seq 1 12); do
  sleep 5
  active=$(systemctl show "$RES" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$RES" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$RES" -p Result --value 2>/dev/null || true)
  code=$(systemctl show "$RES" -p ExecMainCode --value 2>/dev/null || true)
  status=$(systemctl show "$RES" -p ExecMainStatus --value 2>/dev/null || true)
  echo "AUTO_SAMPLE_$step ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result EXEC_CODE=$code EXEC_STATUS=$status"
  if [[ "$active" == active && "$sub" == running && "$pid" =~ ^[1-9][0-9]*$ && "$result" == success ]]; then
    if [[ "$STABLE_PID" == "$pid" && "$STABLE_NR" == "$nr" ]]; then
      echo 'AUTO_RESTART_RECOVERY_STABLE=YES'
      break
    fi
    STABLE_PID=$pid
    STABLE_NR=$nr
  else
    STABLE_PID=
    STABLE_NR=
  fi
done

if [[ -z "$STABLE_PID" ]]; then
  echo 'PROD390_PERMREPAIR_V1=STOP:resident_not_recovered_within_window'
  echo 'PERMISSIONS_REMAIN_REPAIRED=YES'
  exit 0
fi

echo '--- POST-RECOVERY ACCEPTANCE ---'
sleep 10
FINAL_ACTIVE=$(systemctl show "$RES" -p ActiveState --value 2>/dev/null || true)
FINAL_SUB=$(systemctl show "$RES" -p SubState --value 2>/dev/null || true)
FINAL_PID=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
FINAL_NR=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
FINAL_RESULT=$(systemctl show "$RES" -p Result --value 2>/dev/null || true)
echo "FINAL_RESIDENT ACTIVE=$FINAL_ACTIVE SUB=$FINAL_SUB PID=$FINAL_PID NRESTARTS=$FINAL_NR RESULT=$FINAL_RESULT"
if [[ "$FINAL_ACTIVE" != active || "$FINAL_SUB" != running || "$FINAL_PID" != "$STABLE_PID" || "$FINAL_NR" != "$STABLE_NR" || "$FINAL_RESULT" != success ]]; then
  echo 'PROD390_PERMREPAIR_V1=STOP:resident_not_stable_at_acceptance'
  echo 'PERMISSIONS_REMAIN_REPAIRED=YES'
  exit 0
fi

FINAL=$("$APP_PY" - "$OBS" "$OBHB" "$RESHB" <<'PY'
import json, pathlib, sys
from datetime import UTC, datetime
state=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
obhb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
reshb=json.loads(pathlib.Path(sys.argv[3]).read_text("utf-8"))
metrics=state.get("metrics") or {}
events=int(metrics.get("unrecoverable_core_gap_events",0) or 0)
messages=int(metrics.get("unrecoverable_core_gap_messages",0) or 0)
cursor=int((state.get("cursors") or {}).get("lobby",0) or 0)

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

print(f"CORE_EVENTS={events}")
print(f"CORE_MESSAGES={messages}")
print(f"LOBBY_CURSOR={cursor}")
print(f"OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
print(f"OBSERVER_HEALTH={(state.get('health') or {}).get('current','missing')}")
print(f"OBSERVER_HEARTBEAT_STATUS={obhb.get('status','missing')}")
print(f"OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")
PY
)
printf '%s\n' "$FINAL" | sed 's/^/FINAL_/'
FINAL_EVENTS=$(printf '%s\n' "$FINAL" | awk -F= '$1=="CORE_EVENTS"{print $2}')
FINAL_MESSAGES=$(printf '%s\n' "$FINAL" | awk -F= '$1=="CORE_MESSAGES"{print $2}')
if [[ "$FINAL_EVENTS" != "$EXPECTED_CORE_EVENTS" || "$FINAL_MESSAGES" != "$EXPECTED_CORE_MESSAGES" ]]; then
  echo 'PROD390_PERMREPAIR_V1=STOP:protected_core_changed'
  echo 'PERMISSIONS_REMAIN_REPAIRED=YES'
  exit 0
fi

service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS"
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS"
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "FINAL_METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
if [[ "$META_ACTIVE" != active || "$META_RESULT" != success ]]; then
  echo 'PROD390_PERMREPAIR_V1=STOP:final_metadata_block_changed'
  exit 0
fi

echo 'FILE_CONTENT_CHANGED=NO'
echo 'PERMISSION_REPAIR=EXACT_THREE_0600_TO_0644'
echo 'MANUAL_SERVICE_RESTART=NO'
echo 'SYSTEMD_AUTO_RESTART_USED=YES'
echo 'CAPTURE_RESTART=NO'
echo 'SIGNER_RESTART=NO'
echo 'DISCORD_RESTART=NO'
echo 'METADATA_BLOCK_RESTART=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'NETWORK_PROBE=NO'
echo 'TECHNOCORE_WRITE=NO'
echo '=== PROD390_PERMISSION_REPAIR_V1=PASS ==='
echo 'DO_NOT_RERUN=YES'
exit 0
