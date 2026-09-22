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
EXPECTED_CORE_EVENTS=120
EXPECTED_CORE_MESSAGES=5650166
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

echo '=== ISSUE390 CORE120 ATTRIBUTION V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'ISSUE390_CORE120_V1=STOP:not_root'
  exit 0
fi

for cmd in git systemctl stat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ISSUE390_CORE120_V1=STOP:missing_command:$cmd"
    exit 0
  fi
done

for path in "$APP/.git" "$APP_PY" "$OBS" "$OBHB" "$RESHB"; do
  if [[ ! -e "$path" ]]; then
    echo 'ISSUE390_CORE120_V1=STOP:required_path_missing'
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
  echo 'ISSUE390_CORE120_V1=STOP:repo_not_exact_target'
  exit 0
fi

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
    echo "ISSUE390_CORE120_V1=STOP:service_changed:$label"
    exit 0
  fi
}

echo '--- SERVICE GATES ---'
service_exact RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS"
service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS"
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS"
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
if [[ "$META_ACTIVE" != active || "$META_RESULT" != success ]]; then
  echo 'ISSUE390_CORE120_V1=STOP:metadata_block_changed'
  exit 0
fi

echo '--- PERSISTED STATE ATTRIBUTION ---'
"$APP_PY" - "$OBS" "$OBHB" "$RESHB" "$EXPECTED_CORE_EVENTS" "$EXPECTED_CORE_MESSAGES" <<'PY'
import json
import pathlib
import re
import sys
from datetime import UTC, datetime

state_path=pathlib.Path(sys.argv[1])
observer_hb_path=pathlib.Path(sys.argv[2])
resident_hb_path=pathlib.Path(sys.argv[3])
expected_events=int(sys.argv[4])
expected_messages=int(sys.argv[5])

state=json.loads(state_path.read_text("utf-8"))
observer_hb=json.loads(observer_hb_path.read_text("utf-8"))
resident_hb=json.loads(resident_hb_path.read_text("utf-8"))
metrics=state.get("metrics") or {}
health=state.get("health") or {}
cursors=state.get("cursors") or {}

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

events=int(metrics.get("unrecoverable_core_gap_events",0) or 0)
messages=int(metrics.get("unrecoverable_core_gap_messages",0) or 0)
print(f"PROTECTED_CORE={events}/{messages}")
print("PROTECTED_CORE_MATCH="+("YES" if (events,messages)==(expected_events,expected_messages) else "NO"))
print(f"STATE_UPDATED_AT={state.get('updated_at','missing')}")
print(f"STATE_HEALTH_CURRENT={health.get('current','missing')}")
for room in ("lobby","events"):
    print(f"CURSOR_{room.upper()}={int(cursors.get(room,0) or 0)}")

gap=state.get("last_unrecoverable_gap")
if isinstance(gap,dict):
    allowed=("room","lane","observed_at","missing_from","missing_to","estimated_missing","recovery_reason")
    for key in allowed:
        value=gap.get(key,"missing")
        print(f"LAST_GAP_{key.upper()}={value}")
else:
    print("LAST_GAP=MISSING")

opps=state.get("opportunities")
rows=[]
if isinstance(opps,list):
    for item in opps:
        if not isinstance(item,dict):
            continue
        if item.get("kind")!="message_gap" or item.get("recovery")!="unrecoverable":
            continue
        rows.append(item)
for idx,item in enumerate(rows[-8:],1):
    fields={
        "room":item.get("room","missing"),
        "observed_at":item.get("observed_at","missing"),
        "missing_from":item.get("missing_from","missing"),
        "missing_to":item.get("missing_to","missing"),
        "estimated_missing":item.get("estimated_missing","missing"),
        "recovery_reason":item.get("recovery_reason","missing"),
    }
    print(
        "RECENT_UNRECOVERABLE"
        f" idx={idx}"
        f" room={fields['room']}"
        f" observed_at={fields['observed_at']}"
        f" missing_from={fields['missing_from']}"
        f" missing_to={fields['missing_to']}"
        f" estimated_missing={fields['estimated_missing']}"
        f" recovery_reason={fields['recovery_reason']}"
    )
print(f"RECENT_UNRECOVERABLE_COUNT={len(rows[-8:])}")

metric_names=(
    "unrecoverable_gap_events",
    "unrecoverable_gap_messages",
    "unrecoverable_core_gap_events",
    "unrecoverable_core_gap_messages",
    "unrecoverable_optional_gap_events",
    "unrecoverable_optional_gap_messages",
    "unrecoverable_retained_ring_start_events",
    "unrecoverable_retained_ring_start_messages",
    "unrecoverable_not_in_retained_export_events",
    "unrecoverable_not_in_retained_export_messages",
    "gap_recovery_attempts",
    "gap_recovery_batches",
    "gap_recovered_messages",
    "lobby_startup_bridge_attempts",
    "lobby_startup_bridge_successes",
    "lobby_startup_bridge_messages",
    "lobby_startup_bridge_failures",
    "lobby_startup_bridge_bytes",
    "lobby_startup_bridge_unrecoverable_events",
    "lobby_startup_bridge_unrecoverable_messages",
    "lobby_startup_bridge_local_suffix_handoffs",
    "lobby_startup_bridge_avoided_unrecoverable_messages",
    "lobby_startup_local_liveness_slices",
    "lobby_startup_local_liveness_messages",
    "lobby_startup_local_liveness_bridge_attempts",
    "lobby_startup_local_liveness_delegations",
    "lobby_startup_local_liveness_stale_bridge_attempts",
    "lobby_startup_local_liveness_caught_up_waits",
    "lobby_startup_local_liveness_capture_stall_waits",
    "lobby_startup_spool_attempts",
    "lobby_startup_spool_recoveries",
    "lobby_startup_spool_messages",
    "startup_export_attempts",
    "startup_export_successes",
    "startup_export_messages",
    "startup_export_failures",
    "startup_live_probe_attempts",
    "startup_live_probe_successes",
    "startup_live_probe_messages",
    "startup_live_probe_fallbacks",
    "startup_live_probe_failures",
    "startup_stream_export_attempts",
    "startup_stream_export_successes",
    "startup_stream_export_messages",
    "startup_stream_export_failures",
    "startup_stream_export_bytes",
    "events_startup_snapshot_unrecoverable_events",
    "events_startup_snapshot_unrecoverable_messages",
)
for name in metric_names:
    print(f"METRIC_{name.upper()}={int(metrics.get(name,0) or 0)}")

rooms=health.get("rooms") if isinstance(health.get("rooms"),dict) else {}
for room in ("lobby","events"):
    rec=rooms.get(room)
    if isinstance(rec,dict):
        status=str(rec.get("status","missing"))
        kind=str(rec.get("kind","missing"))
        at=str(rec.get("at","missing"))
        safe_kind=re.sub(r"[^A-Za-z0-9_.:-]","",kind)[:120] or "missing"
        print(f"HEALTH_{room.upper()} status={status} kind={safe_kind} at={at}")
    else:
        print(f"HEALTH_{room.upper()}=MISSING")

history=state.get("error_history")
safe=[]
if isinstance(history,list):
    for rec in history:
        if not isinstance(rec,dict):
            continue
        room=rec.get("room")
        if room not in {"lobby","events"}:
            continue
        kind=str(rec.get("kind",""))
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}",kind):
            kind="redacted"
        safe.append((room,kind,str(rec.get("at","missing"))))
for idx,(room,kind,at) in enumerate(safe[-20:],1):
    print(f"RECENT_CORE_ERROR idx={idx} room={room} kind={kind} at={at}")
print(f"RECENT_CORE_ERROR_COUNT={len(safe[-20:])}")

print(f"OBSERVER_HEARTBEAT_STATUS={observer_hb.get('status','missing')}")
print(f"OBSERVER_HEARTBEAT_UPDATED_AT={observer_hb.get('updated_at','missing')}")
print(f"OBSERVER_HEARTBEAT_AGE={age(observer_hb.get('updated_at')):.1f}")
print(f"RESIDENT_HEARTBEAT_STATUS={resident_hb.get('status','missing')}")
print(f"RESIDENT_HEARTBEAT_UPDATED_AT={resident_hb.get('updated_at','missing')}")
print(f"RESIDENT_HEARTBEAT_AGE={age(resident_hb.get('updated_at')):.1f}")
PY

echo '--- LIGHTWEIGHT PRESSURE ---'
"$APP_PY" - <<'PY'
import pathlib
import re

for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
    if ":" not in line:
        continue
    key,val=line.split(":",1)
    if key in {"MemTotal","MemAvailable","SwapTotal","SwapFree","AnonPages","Dirty","Writeback"}:
        parts=val.strip().split()
        n=int(parts[0])*1024 if parts else 0
        print(f"MEM_{key.upper()}_BYTES={n}")
for kind in ("io","memory"):
    path=pathlib.Path(f"/proc/pressure/{kind}")
    if not path.exists():
        continue
    for idx,line in enumerate(path.read_text("utf-8").splitlines()[:2],1):
        cleaned=re.sub(r"[^A-Za-z0-9_.:/=-]","",line)[:160]
        print(f"PSI_{kind.upper()}_{idx}={cleaned}")
PY

echo '--- FINAL SERVICE CHECK ---'
service_exact RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS"
service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS"
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS"

echo 'SERVICE_MUTATION=NO'
echo 'SERVICE_RESTART=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'NETWORK_PROBE=NO'
echo 'RAW_JOURNAL_OUTPUT=NO'
echo 'TECHNOCORE_WRITE=NO'
echo '=== ISSUE390_CORE120_ATTRIBUTION_V1=COMPLETE_READ_ONLY ==='
echo 'DO_NOT_RERUN=YES'
exit 0
