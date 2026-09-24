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
EXPECTED_HEAD=041b830d3b0ffd17ef95f8d889922f20d3ac6631

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIGN=technocore-safe-agent-signer.service
DISC=technocore-safe-agent-discord.service
MON_TIMER=technocore-safe-agent-airdrop-monitor.timer
MON_SERVICE=technocore-safe-agent-airdrop-monitor.service
NOT_TIMER=technocore-safe-agent-airdrop-notifier.timer
NOT_SERVICE=technocore-safe-agent-airdrop-notifier.service

echo '=== PROD445 FRESH CORE GAP READ-ONLY DIAG V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

stop_diag() {
  echo "DIAG445=STOP:$1"
  echo 'MUTATION=NO'
  echo 'DO_NOT_RERUN=YES'
  exit 0
}

if [[ $EUID -ne 0 ]]; then stop_diag not_root; fi
for cmd in git systemctl stat runuser journalctl tail grep; do
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
  local active sub pid nr result started entered
  active=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  started=$(systemctl show "$unit" -p ExecMainStartTimestamp --value 2>/dev/null || true)
  entered=$(systemctl show "$unit" -p ActiveEnterTimestamp --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result"
  echo "SERVICE_TIME=$label EXEC_START=$started ACTIVE_ENTER=$entered"
}

echo '--- SERVICES ---'
show_service RESIDENT "$RES"
show_service CAPTURE "$CAP"
show_service SIGNER "$SIGN"
show_service DISCORD "$DISC"

echo '--- OBSERVER STATE FORENSICS ---'
"$APP_PY" - "$OBS" "$OBHB" "$RESHB" <<'PY'
import json
import pathlib
import sys
from datetime import UTC, datetime

obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
obhb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
reshb=json.loads(pathlib.Path(sys.argv[3]).read_text("utf-8"))

def age(value):
    try:
        dt=datetime.fromisoformat(str(value).replace("Z","+00:00"))
        if dt.tzinfo is None:
            dt=dt.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-dt.astimezone(UTC)).total_seconds())
    except Exception:
        return -1.0

m=obs.get("metrics") or {}
last=obs.get("last_unrecoverable_gap")
print(f"OBSERVER_UPDATED_AT={obs.get('updated_at')}")
print(f"OBSERVER_HEALTH={((obs.get('health') or {}).get('current'))}")
print(f"OBSERVER_HEARTBEAT_STATUS={obhb.get('status')}")
print(f"OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"RESIDENT_HEARTBEAT_STATUS={reshb.get('status')}")
print(f"RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")
print(f"TOTAL_MESSAGE_GAPS={int(m.get('message_gaps',0) or 0)}")
print(f"TOTAL_ESTIMATED_MISSING={int(m.get('estimated_missing_messages',0) or 0)}")
print(f"UNRECOVERABLE_TOTAL={int(m.get('unrecoverable_gap_events',0) or 0)}/{int(m.get('unrecoverable_gap_messages',0) or 0)}")
print(f"UNRECOVERABLE_CORE={int(m.get('unrecoverable_core_gap_events',0) or 0)}/{int(m.get('unrecoverable_core_gap_messages',0) or 0)}")
print(f"UNRECOVERABLE_OPTIONAL={int(m.get('unrecoverable_optional_gap_events',0) or 0)}/{int(m.get('unrecoverable_optional_gap_messages',0) or 0)}")
print(f"GAP_RECOVERY_ATTEMPTS={int(m.get('gap_recovery_attempts',0) or 0)}")
print(f"GAP_RECOVERY_BATCHES={int(m.get('gap_recovery_batches',0) or 0)}")
print(f"GAP_RECOVERED_MESSAGES={int(m.get('gap_recovered_messages',0) or 0)}")
print(f"UNRECOVERABLE_RETAINED_START={int(m.get('unrecoverable_retained_ring_start_events',0) or 0)}/{int(m.get('unrecoverable_retained_ring_start_messages',0) or 0)}")
print(f"UNRECOVERABLE_NOT_IN_EXPORT={int(m.get('unrecoverable_not_in_retained_export_events',0) or 0)}/{int(m.get('unrecoverable_not_in_retained_export_messages',0) or 0)}")
print(f"LOBBY_SPOOL_RECOVERY_EVENTS={int(m.get('lobby_spool_recovery_events',0) or 0)}")
print(f"LOBBY_SPOOL_RECOVERED_MESSAGES={int(m.get('lobby_spool_recovered_messages',0) or 0)}")
print(f"LOBBY_SPOOL_PARTIAL_RECOVERY_MESSAGES={int(m.get('lobby_spool_partial_recovery_messages',0) or 0)}")
print("LAST_UNRECOVERABLE_GAP="+json.dumps(last,sort_keys=True,separators=(",",":")))

room = last.get("room") if isinstance(last,dict) else None
if isinstance(room,str):
    print(f"LAST_GAP_ROOM={room}")
    print(f"LAST_GAP_ROOM_CURSOR={int((obs.get('cursors') or {}).get(room,0) or 0)}")
    print("LAST_GAP_ROOM_HEALTH="+json.dumps(((obs.get("health") or {}).get("rooms") or {}).get(room),sort_keys=True,separators=(",",":")))
print(f"LOBBY_CURSOR={int((obs.get('cursors') or {}).get('lobby',0) or 0)}")
print(f"EVENTS_CURSOR={int((obs.get('cursors') or {}).get('events',0) or 0)}")

print("RECENT_ERROR_HISTORY_BEGIN")
for row in (obs.get("error_history") or [])[-30:]:
    if isinstance(row,dict):
        print(json.dumps({
            "room":row.get("room"),
            "kind":row.get("kind"),
            "at":row.get("at"),
            "detail":row.get("detail"),
        },sort_keys=True,separators=(",",":")))
print("RECENT_ERROR_HISTORY_END")

print("RECENT_GAP_EVENTS_BEGIN")
rows=[]
for row in (obs.get("opportunities") or []):
    if not isinstance(row,dict):
        continue
    if row.get("kind") in {"message_gap","message_gap_recovered"}:
        rows.append({
            "kind":row.get("kind"),
            "room":row.get("room"),
            "seq":row.get("seq"),
            "observed_at":row.get("observed_at"),
            "missing_from":row.get("missing_from"),
            "missing_to":row.get("missing_to"),
            "estimated_missing":row.get("estimated_missing"),
            "recovered_from":row.get("recovered_from"),
            "recovered_to":row.get("recovered_to"),
            "recovered_count":row.get("recovered_count"),
            "recovery":row.get("recovery"),
            "recovery_reason":row.get("recovery_reason"),
        })
for row in rows[-20:]:
    print(json.dumps(row,sort_keys=True,separators=(",",":")))
print("RECENT_GAP_EVENTS_END")
PY

echo '--- AIRDROP HEALTH ---'
runuser -u technocore -- env FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" PYTHONDONTWRITEBYTECODE=1 "$APP_PY" - <<'PY'
from flop_agent import airdrop_monitor, airdrop_notifier
m=airdrop_monitor.monitor_status()
n=airdrop_notifier.status()
print(f"MONITOR_OUTCOME={m.get('outcome')}")
print(f"MONITOR_HEARTBEAT_AGE={m.get('heartbeat_age_seconds')}")
print(f"MONITOR_HEARTBEAT_STALE={m.get('heartbeat_stale')}")
print(f"RADAR_HEALTH={m.get('radar_health')}")
print(f"LEDGER_INTEGRITY={m.get('ledger_integrity_valid')}")
print(f"PENDING_IMMEDIATE={m.get('pending_immediate_alerts')}")
print(f"PENDING_DIGEST={m.get('pending_digest_alerts')}")
print(f"NOTIFIER_FAILURE_COUNT={n.get('failure_count')}")
print(f"NOTIFIER_BACKOFF_ACTIVE={n.get('backoff_active')}")
PY

for pair in \
  "MONITOR_TIMER:$MON_TIMER" \
  "NOTIFIER_TIMER:$NOT_TIMER"
do
  label=${pair%%:*}
  unit=${pair#*:}
  echo "TIMER=$label ACTIVE=$(systemctl is-active "$unit" 2>/dev/null || true) ENABLED=$(systemctl is-enabled "$unit" 2>/dev/null || true)"
done

for pair in \
  "MONITOR_SERVICE:$MON_SERVICE" \
  "NOTIFIER_SERVICE:$NOT_SERVICE"
do
  label=${pair%%:*}
  unit=${pair#*:}
  echo "ONESHOT=$label RESULT=$(systemctl show "$unit" -p Result --value 2>/dev/null || true) EXEC_MAIN_STATUS=$(systemctl show "$unit" -p ExecMainStatus --value 2>/dev/null || true)"
done

echo '--- RESIDENT JOURNAL AROUND CORE GAP ---'
journalctl -u "$RES" \
  --since '2026-09-23 15:00:00 UTC' \
  --until '2026-09-23 16:30:00 UTC' \
  --no-pager -o short-iso 2>/dev/null \
  | grep -Ei 'gap|recover|retention|export|timeout|pressure|rate|error|fail|stopp|start|kill' \
  | tail -n 120 || true

echo '--- CAPTURE JOURNAL AROUND CORE GAP ---'
journalctl -u "$CAP" \
  --since '2026-09-23 15:00:00 UTC' \
  --until '2026-09-23 16:30:00 UTC' \
  --no-pager -o short-iso 2>/dev/null \
  | grep -Ei 'gap|recover|capture|export|timeout|pressure|rate|error|fail|stopp|start|kill' \
  | tail -n 120 || true

echo 'GIT_MUTATION=NO'
echo 'NETWORK_PROBE=NO'
echo 'SYSTEMD_MUTATION=NO'
echo 'RUNNING_SERVICE_RESTART=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'SIGNER_ACTION=NO'
echo 'TECHNOCORE_WRITE=NO'
echo 'FLOP_WRITE=NO'
echo 'X_WRITE=NO'
echo '=== DIAG445_READ_ONLY_SNAPSHOT=PASS ==='
echo 'DO_NOT_RERUN=YES'
exit 0
