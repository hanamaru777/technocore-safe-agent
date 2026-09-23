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

EXPECTED_HEAD=576d06dae3550ca7f32b3857d17ff79e911be0d0
EXPECTED_CORE_EVENTS=120
EXPECTED_CORE_MESSAGES=5650166

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIGN=technocore-safe-agent-signer.service
DISC=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service
MON_TIMER=technocore-safe-agent-airdrop-monitor.timer
MON_SERVICE=technocore-safe-agent-airdrop-monitor.service
NOT_TIMER=technocore-safe-agent-airdrop-notifier.timer
NOT_SERVICE=technocore-safe-agent-airdrop-notifier.service

echo '=== PROD436 RESIDENT PID DRIFT READ-ONLY DIAG V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "HOST_BOOT=$(uptime -s 2>/dev/null || true)"

stop_diag() {
  echo "DIAG436=STOP:$1"
  echo 'MUTATION=NO'
  echo 'DO_NOT_RERUN=YES'
  exit 0
}

if [[ $EUID -ne 0 ]]; then stop_diag not_root; fi
for cmd in git systemctl stat runuser journalctl uptime grep tail; do
  command -v "$cmd" >/dev/null 2>&1 || stop_diag "missing_command:$cmd"
done
[[ -x "$APP_PY" && -f "$OBS" && -f "$OBHB" && -f "$RESHB" && -d "$APP/.git" ]] || stop_diag required_path_missing

OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_diag git_owner_missing

git_owner() {
  runuser -u "$OWNER" -- git -C "$APP" "$@"
}

HEAD=$(git_owner rev-parse HEAD 2>/dev/null || true)
BRANCH=$(git_owner branch --show-current 2>/dev/null || true)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "REPO_HEAD=$HEAD"
echo "REPO_BRANCH=$BRANCH"
if [[ -z "$WORKTREE" ]]; then echo 'REPO_WORKTREE_CLEAN=YES'; else echo 'REPO_WORKTREE_CLEAN=NO'; fi
[[ "$HEAD" == "$EXPECTED_HEAD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_diag repo_state_unexpected

show_service() {
  local label=$1 unit=$2
  local active sub pid nr result started entered changed
  active=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  started=$(systemctl show "$unit" -p ExecMainStartTimestamp --value 2>/dev/null || true)
  entered=$(systemctl show "$unit" -p ActiveEnterTimestamp --value 2>/dev/null || true)
  changed=$(systemctl show "$unit" -p StateChangeTimestamp --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result"
  echo "SERVICE_TIME=$label EXEC_START=$started"
  echo "SERVICE_TIME=$label ACTIVE_ENTER=$entered"
  echo "SERVICE_TIME=$label STATE_CHANGE=$changed"
}

echo '--- CURRENT SERVICES ---'
show_service RESIDENT "$RES"
show_service CAPTURE "$CAP"
show_service SIGNER "$SIGN"
show_service DISCORD "$DISC"
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
META_ENTER=$(systemctl show "$META" -p ActiveEnterTimestamp --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT ACTIVE_ENTER=$META_ENTER"

echo '--- RESIDENT SYSTEMD LIFECYCLE SINCE FINAL ACCEPTANCE WINDOW ---'
journalctl -u "$RES" --since '2026-09-23 06:00:00 UTC' -n 120 --no-pager -o short-iso 2>/dev/null \
  | grep -E 'systemd\[[0-9]+\]: (Starting|Started|Stopping|Stopped|.*Main process exited|.*Scheduled restart|.*Failed)' \
  | tail -n 30 || true

echo '--- OBSERVER / RESIDENT CONTINUITY ---'
"$APP_PY" - "$OBS" "$OBHB" "$RESHB" "$EXPECTED_CORE_EVENTS" "$EXPECTED_CORE_MESSAGES" <<'PY'
import json, pathlib, sys
from datetime import UTC, datetime

obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
obhb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
reshb=json.loads(pathlib.Path(sys.argv[3]).read_text("utf-8"))
expected_events=int(sys.argv[4])
expected_messages=int(sys.argv[5])

def age(value):
    try:
        dt=datetime.fromisoformat(str(value).replace("Z","+00:00"))
        if dt.tzinfo is None:
            dt=dt.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-dt.astimezone(UTC)).total_seconds())
    except Exception:
        return -1.0

m=obs.get("metrics") or {}
c=obs.get("cursors") or {}
events=int(m.get("unrecoverable_core_gap_events",0) or 0)
messages=int(m.get("unrecoverable_core_gap_messages",0) or 0)
print(f"PROTECTED_CORE={events}/{messages}")
print(f"PROTECTED_CORE_EXPECTED={expected_events}/{expected_messages}")
print(f"PROTECTED_CORE_MATCH={'YES' if (events,messages)==(expected_events,expected_messages) else 'NO'}")
print(f"LOBBY_CURSOR={int(c.get('lobby',0) or 0)}")
print(f"OBSERVER_UPDATED_AT={obs.get('updated_at')}")
print(f"OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"OBSERVER_TCLK_REVISION={obhb.get('tclk_revision')}")
print(f"RESIDENT_HEARTBEAT_STATUS={reshb.get('status')}")
print(f"RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")
PY

echo '--- AIRDROP TIMERS / ONESHOTS ---'
for pair in \
  "MONITOR_TIMER:$MON_TIMER" \
  "NOTIFIER_TIMER:$NOT_TIMER"
do
  label=\${pair%%:*}
  unit=\${pair#*:}
  active=$(systemctl is-active "$unit" 2>/dev/null || true)
  enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)
  next=$(systemctl show "$unit" -p NextElapseUSecRealtime --value 2>/dev/null || true)
  echo "TIMER=$label ACTIVE=$active ENABLED=$enabled NEXT=$next"
done

for pair in \
  "MONITOR_SERVICE:$MON_SERVICE" \
  "NOTIFIER_SERVICE:$NOT_SERVICE"
do
  label=\${pair%%:*}
  unit=\${pair#*:}
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  rc=$(systemctl show "$unit" -p ExecMainStatus --value 2>/dev/null || true)
  started=$(systemctl show "$unit" -p ExecMainStartTimestamp --value 2>/dev/null || true)
  exited=$(systemctl show "$unit" -p ExecMainExitTimestamp --value 2>/dev/null || true)
  echo "ONESHOT=$label RESULT=$result EXEC_MAIN_STATUS=$rc"
  echo "ONESHOT_TIME=$label START=$started EXIT=$exited"
done

echo '--- AIRDROP LOCAL STATE ---'
if ! runuser -u technocore -- env FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" PYTHONDONTWRITEBYTECODE=1 "$APP_PY" - <<'PY'
from flop_agent import airdrop_monitor, airdrop_notifier
m=airdrop_monitor.monitor_status()
n=airdrop_notifier.status()
print(f"MONITOR_OUTCOME={m.get('outcome')}")
print(f"MONITOR_LAST_ATTEMPT={m.get('last_attempt_at')}")
print(f"MONITOR_LAST_COMPLETED={m.get('last_completed_at')}")
print(f"MONITOR_HEARTBEAT_AGE={m.get('heartbeat_age_seconds')}")
print(f"MONITOR_HEARTBEAT_STALE={m.get('heartbeat_stale')}")
print(f"RADAR_HEALTH={m.get('radar_health')}")
print(f"LEDGER_INTEGRITY={m.get('ledger_integrity_valid')}")
print(f"LEDGER_COUNT={m.get('ledger_count')}")
print(f"PENDING_IMMEDIATE={m.get('pending_immediate_alerts')}")
print(f"PENDING_DIGEST={m.get('pending_digest_alerts')}")
print(f"ADAPTER_READINESS={m.get('adapter_readiness',{}).get('overall')}")
print(f"NOTIFIER_LAST_RUN={n.get('last_run_at')}")
print(f"NOTIFIER_LAST_SUCCESS={n.get('last_success_at')}")
print(f"NOTIFIER_FAILURE_COUNT={n.get('failure_count')}")
print(f"NOTIFIER_BACKOFF_ACTIVE={n.get('backoff_active')}")
print(f"NOTIFIER_LAST_ERROR={n.get('last_error_type')}")
PY
then
  stop_diag airdrop_local_state_read_failed
fi

echo 'GIT_FETCH_INSIDE_DIAG=NO'
echo 'SYSTEMD_MUTATION=NO'
echo 'RUNNING_SERVICE_RESTART=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'SIGNER_ACTION=NO'
echo 'TECHNOCORE_WRITE=NO'
echo 'FLOP_WRITE=NO'
echo 'X_WRITE=NO'
echo '=== DIAG436_READ_ONLY_SNAPSHOT=PASS ==='
echo 'DO_NOT_RERUN=YES'
exit 0
