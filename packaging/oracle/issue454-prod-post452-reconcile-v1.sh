#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
RES_HB=/var/lib/technocore-safe-agent/observer/resident-heartbeat.json
PY=$APP/.venv/bin/python
EXPECTED_HEAD=b8c63f865856d5004f8d310eb8ff4c31dbd7ffb0
EXPECTED_CORE_EVENTS=121
EXPECTED_CORE_MESSAGES=5650187
EXPECTED_BRIDGE_EVENTS=4
EXPECTED_BRIDGE_MESSAGES=567032
EXPECTED_RESIDENT_PID=2256397
EXPECTED_CAPTURE_PID=2349223
EXPECTED_SIGNER_PID=2256324
EXPECTED_DISCORD_PID=2349270

echo '=== PROD454 POST-452 READ-ONLY RECONCILE V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

stop_diag() {
  echo "PROD454V1=STOP:$1"
  echo 'DO_NOT_RERUN=YES'
  exit 0
}

on_error() {
  local rc=$?
  trap - ERR
  echo "PROD454V1=ERROR:rc_$rc"
  echo 'DO_NOT_RERUN=YES'
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_diag not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" && -f "$RES_HB" ]] || stop_diag required_path_missing

OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_diag git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

snapshot_service() {
  local unit=$1
  local active sub pid nr result
  active=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  printf '%s|%s|%s|%s|%s\n' "$active" "$sub" "$pid" "$nr" "$result"
}

runtime_snapshot() {
  "$PY" - "$OBS" "$RES_HB" <<'PY'
import json
import pathlib
import sys
from datetime import UTC, datetime

obs = json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
hb = json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
now = datetime.now(UTC)

def parse(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None

def age(value):
    stamp = parse(value)
    return -1.0 if stamp is None else (now - stamp).total_seconds()

m = obs.get("metrics") or {}
status = hb.get("resident_status")
if not isinstance(status, dict):
    status = {}

print("|".join([
    str(int(m.get("unrecoverable_core_gap_events", 0) or 0)),
    str(int(m.get("unrecoverable_core_gap_messages", 0) or 0)),
    str(int(m.get("lobby_startup_bridge_unrecoverable_events", 0) or 0)),
    str(int(m.get("lobby_startup_bridge_unrecoverable_messages", 0) or 0)),
    str(int((obs.get("cursors") or {}).get("lobby", 0) or 0)),
    str((obs.get("health") or {}).get("current") or "unknown"),
    f"{age(obs.get('updated_at')):.1f}",
    str(hb.get("status") or "unknown"),
    f"{age(hb.get('updated_at')):.1f}",
    str(hb.get("updated_at") or ""),
    "true" if status.get("read_only") is True else "false",
    str(status.get("last_refresh_at") or ""),
    f"{age(status.get('last_refresh_at')):.1f}",
    str(((status.get("health") or {}).get("current")) or "unknown"),
]))
PY
}

STATE_CURSOR=''
HB_STAMP=''
require_runtime() {
  local phase=$1 line ce cm be bm cursor health state_age hb_status hb_age hb_stamp ro last_refresh last_refresh_age resident_health
  if ! line=$(runtime_snapshot); then
    stop_diag "${phase}_state_read_failed"
  fi
  IFS='|' read -r ce cm be bm cursor health state_age hb_status hb_age hb_stamp ro last_refresh last_refresh_age resident_health <<<"$line"

  echo "RUNTIME=$phase CORE=$ce/$cm BRIDGE=$be/$bm LOBBY_CURSOR=$cursor OBS_HEALTH=$health OBS_STATE_AGE=$state_age RES_HB_STATUS=$hb_status RES_HB_AGE=$hb_age RESIDENT_HEALTH=$resident_health RESIDENT_LAST_REFRESH_AGE=$last_refresh_age"
  echo "LIVENESS_SOURCE=resident-heartbeat.json:updated_at"
  echo "OBSERVER_STATE_UPDATED_AT_LIVENESS_GATE=NO"

  [[ "$ce" == "$EXPECTED_CORE_EVENTS" && "$cm" == "$EXPECTED_CORE_MESSAGES" ]] || stop_diag "${phase}_protected_core_changed"
  [[ "$be" == "$EXPECTED_BRIDGE_EVENTS" && "$bm" == "$EXPECTED_BRIDGE_MESSAGES" ]] || stop_diag "${phase}_startup_bridge_changed"
  [[ "$health" == ok ]] || stop_diag "${phase}_observer_health_not_ok"
  [[ "$hb_status" == ok || "$hb_status" == pressure_paused ]] || stop_diag "${phase}_resident_heartbeat_status_bad"
  [[ "$ro" == true ]] || stop_diag "${phase}_resident_status_not_read_only"

  if ! "$PY" - "$hb_age" <<'PY'
import sys
value=float(sys.argv[1])
raise SystemExit(0 if 0 <= value <= 120 else 1)
PY
  then
    stop_diag "${phase}_resident_heartbeat_stale"
  fi

  STATE_CURSOR=$cursor
  HB_STAMP=$hb_stamp
}

echo '--- REPO / SERVICE BASELINE ---'
HEAD=$(git_owner rev-parse HEAD 2>/dev/null || true)
BRANCH=$(git_owner branch --show-current 2>/dev/null || true)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "HEAD=$HEAD"
echo "BRANCH=$BRANCH"
[[ -z "$WORKTREE" ]] && echo 'WORKTREE_CLEAN=YES' || echo 'WORKTREE_CLEAN=NO'
[[ "$HEAD" == "$EXPECTED_HEAD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_diag repo_state_unexpected

RES=$(snapshot_service technocore-safe-agent-resident.service)
CAP=$(snapshot_service technocore-safe-agent-lobby-capture.service)
SIG=$(snapshot_service technocore-safe-agent-signer.service)
DIS=$(snapshot_service technocore-safe-agent-discord.service)
echo "SERVICE=RESIDENT SNAPSHOT=$RES"
echo "SERVICE=CAPTURE SNAPSHOT=$CAP"
echo "SERVICE=SIGNER SNAPSHOT=$SIG"
echo "SERVICE=DISCORD SNAPSHOT=$DIS"
[[ "$RES" == "active|running|$EXPECTED_RESIDENT_PID|0|success" ]] || stop_diag resident_state_changed
[[ "$CAP" == "active|running|$EXPECTED_CAPTURE_PID|0|success" ]] || stop_diag capture_state_changed
[[ "$SIG" == "active|running|$EXPECTED_SIGNER_PID|0|success" ]] || stop_diag signer_state_changed
[[ "$DIS" == "active|running|$EXPECTED_DISCORD_PID|0|success" ]] || stop_diag discord_state_changed

META_ACTIVE=$(systemctl show technocore-safe-agent-metadata-block.service -p ActiveState --value 2>/dev/null || true)
META_RESULT=$(systemctl show technocore-safe-agent-metadata-block.service -p Result --value 2>/dev/null || true)
echo "METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || stop_diag metadata_block_changed

echo '--- T0 ---'
require_runtime T0
START_CURSOR=$STATE_CURSOR
START_HB=$HB_STAMP
LAST_CURSOR=$START_CURSOR

for phase in T60 T120; do
  sleep 60
  [[ "$(snapshot_service technocore-safe-agent-resident.service)" == "$RES" ]] || stop_diag "${phase}_resident_changed"
  [[ "$(snapshot_service technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_diag "${phase}_capture_changed"
  [[ "$(snapshot_service technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_diag "${phase}_signer_changed"
  [[ "$(snapshot_service technocore-safe-agent-discord.service)" == "$DIS" ]] || stop_diag "${phase}_discord_changed"
  require_runtime "$phase"
  [[ "$STATE_CURSOR" -ge "$LAST_CURSOR" ]] || stop_diag "${phase}_lobby_cursor_regressed"
  LAST_CURSOR=$STATE_CURSOR
done

if ! "$PY" - "$START_HB" "$HB_STAMP" <<'PY'
import sys
from datetime import datetime
a=datetime.fromisoformat(sys.argv[1].replace("Z","+00:00"))
b=datetime.fromisoformat(sys.argv[2].replace("Z","+00:00"))
raise SystemExit(0 if b > a else 1)
PY
then
  stop_diag resident_supervisor_heartbeat_did_not_advance
fi

echo "LOBBY_CURSOR_DELTA=$((LAST_CURSOR-START_CURSOR))"
echo "RESIDENT_HEARTBEAT_ADVANCED=YES"

MON_ACTIVE=$(systemctl is-active technocore-safe-agent-airdrop-monitor.timer 2>/dev/null || true)
MON_ENABLED=$(systemctl is-enabled technocore-safe-agent-airdrop-monitor.timer 2>/dev/null || true)
NOT_ACTIVE=$(systemctl is-active technocore-safe-agent-airdrop-notifier.timer 2>/dev/null || true)
NOT_ENABLED=$(systemctl is-enabled technocore-safe-agent-airdrop-notifier.timer 2>/dev/null || true)
echo "AIRDROP_MONITOR_TIMER ACTIVE=$MON_ACTIVE ENABLED=$MON_ENABLED"
echo "AIRDROP_NOTIFIER_TIMER ACTIVE=$NOT_ACTIVE ENABLED=$NOT_ENABLED"
[[ "$MON_ACTIVE" == active && "$MON_ENABLED" == enabled ]] || stop_diag airdrop_monitor_timer_not_ready
[[ "$NOT_ACTIVE" == active && "$NOT_ENABLED" == enabled ]] || stop_diag airdrop_notifier_timer_not_ready

echo 'GIT_MUTATION=NO'
echo 'NETWORK_PROBE=NO'
echo 'JOURNAL_READ=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'SYSTEMD_MUTATION=NO'
echo 'RUNNING_SERVICE_RESTART=NO'
echo 'SIGNER_ACTION=NO'
echo 'SYNTHETIC_DISCORD_MESSAGE=NO'
echo 'TECHNOCORE_WRITE=NO'
echo 'FLOP_WRITE=NO'
echo 'X_WRITE=NO'
echo '=== PROD454_POST452_READ_ONLY_RECONCILE=PASS ==='
echo 'DO_NOT_RERUN=YES'
