#!/usr/bin/env bash
# Issue #390: fresh read-only forensic for the second protected-core regression.
set -u
umask 077

APP=/opt/technocore-safe-agent
APP_PY=$APP/.venv/bin/python
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
OBHB=$STATE/observer/observer-heartbeat.json
RESHB=$STATE/observer/resident-heartbeat.json
OBSCFG=$STATE/observer/observer-config.json
CAP_DB=$STATE/observer/lobby-capture-service.sqlite3
CAP_WAL=$STATE/observer/lobby-capture-service.sqlite3-wal
CAP_SHM=$STATE/observer/lobby-capture-service.sqlite3-shm

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service

EXPECTED_APP_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe
EXPECTED_CORE_EVENTS=119
EXPECTED_CORE_MESSAGES=5497275
EXPECTED_LOBBY_CURSOR=59984825
PRIOR_CORE_EVENTS=118
PRIOR_CORE_MESSAGES=5092411
PRIOR_LOBBY_CURSOR=59579961
EXPECTED_RES_PID=1868797
EXPECTED_RES_RESTARTS=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0

TMPDIR=$(mktemp -d /tmp/issue390-gapv2.XXXXXX)
cleanup() { rm -rf -- "$TMPDIR"; }
trap cleanup EXIT

echo '=== ISSUE390 SECOND CORE GAP READ-ONLY FORENSIC V2 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'ISSUE390_GAPV2=STOP:not_root'
  exit 0
fi

for path in "$APP/.git" "$APP_PY" "$OBS" "$OBHB" "$RESHB" "$OBSCFG"; do
  if [[ ! -e "$path" ]]; then
    echo 'ISSUE390_GAPV2=STOP:required_path_missing'
    exit 0
  fi
done

APP_HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "APP_HEAD=$APP_HEAD"
if [[ -z "$WORKTREE" ]]; then echo 'WORKTREE_CLEAN=YES'; else echo 'WORKTREE_CLEAN=NO'; fi
if [[ "$APP_HEAD" != "$EXPECTED_APP_HEAD" || -n "$WORKTREE" ]]; then
  echo 'ISSUE390_GAPV2=STOP:repo_baseline_changed'
  exit 0
fi

svc() {
  local label=$1 unit=$2 expected_pid=$3 expected_restarts=$4
  local active pid nr result
  active=$(systemctl is-active "$unit" 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active PID=$pid NRESTARTS=$nr RESULT=$result"
  if [[ "$active" != active || "$pid" != "$expected_pid" || "$nr" != "$expected_restarts" || "$result" != success ]]; then
    echo "ISSUE390_GAPV2=STOP:service_baseline_changed:$label"
    exit 0
  fi
}

svc RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS"
svc CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"

STATE_OUT=$("$APP_PY" - \
  "$OBS" "$OBHB" "$RESHB" "$OBSCFG" \
  "$EXPECTED_CORE_EVENTS" "$EXPECTED_CORE_MESSAGES" "$EXPECTED_LOBBY_CURSOR" \
  "$PRIOR_CORE_EVENTS" "$PRIOR_CORE_MESSAGES" "$PRIOR_LOBBY_CURSOR" <<'PY'
import hashlib
import json
import pathlib
import sys
from datetime import UTC, datetime

OBS=pathlib.Path(sys.argv[1])
OBHB=pathlib.Path(sys.argv[2])
RESHB=pathlib.Path(sys.argv[3])
CFG=pathlib.Path(sys.argv[4])
EXPECTED_EVENTS=int(sys.argv[5])
EXPECTED_MESSAGES=int(sys.argv[6])
EXPECTED_CURSOR=int(sys.argv[7])
PRIOR_EVENTS=int(sys.argv[8])
PRIOR_MESSAGES=int(sys.argv[9])
PRIOR_CURSOR=int(sys.argv[10])

def load(path):
    return json.loads(path.read_text("utf-8"))

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

state=load(OBS)
obhb=load(OBHB)
reshb=load(RESHB)
cfg=load(CFG)

metrics=state.get("metrics") if isinstance(state,dict) else {}
if not isinstance(metrics,dict):
    metrics={}

events=int(metrics.get("unrecoverable_core_gap_events",0) or 0)
messages=int(metrics.get("unrecoverable_core_gap_messages",0) or 0)
cursors=state.get("cursors") if isinstance(state,dict) else {}
if not isinstance(cursors,dict):
    cursors={}
lobby_cursor=int(cursors.get("lobby",0) or 0)

print(f"PROTECTED_CORE={events}/{messages}")
print(f"LOBBY_CURSOR={lobby_cursor}")
print(f"CORE_EVENT_DELTA_FROM_PRIOR={events-PRIOR_EVENTS}")
print(f"CORE_MESSAGE_DELTA_FROM_PRIOR={messages-PRIOR_MESSAGES}")
print(f"LOBBY_CURSOR_DELTA_FROM_PRIOR={lobby_cursor-PRIOR_CURSOR}")
print(
    "CORE_MESSAGE_DELTA_EQUALS_LOBBY_CURSOR_DELTA="
    + ("YES" if messages-PRIOR_MESSAGES == lobby_cursor-PRIOR_CURSOR else "NO")
)
print(f"OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
print(f"OBSERVER_HEALTH_CURRENT={(state.get('health') or {}).get('current','missing')}")
print(f"OBSERVER_HEARTBEAT_STATUS={obhb.get('status','missing')}")
print(f"OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")

if events != EXPECTED_EVENTS or messages != EXPECTED_MESSAGES:
    print("ISSUE390_GAPV2_STATE=STOP:core_moved_again")
    raise SystemExit(20)
if lobby_cursor != EXPECTED_CURSOR:
    print("ISSUE390_GAPV2_STATE=STOP:lobby_cursor_moved")
    raise SystemExit(21)

mailbox=cfg.get("mailbox") if isinstance(cfg,dict) else None
watch=set(cfg.get("watch_rooms") or []) if isinstance(cfg,dict) else set()

def room_label(room):
    if room == "events":
        return "EVENTS"
    if room == "lobby":
        return "LOBBY"
    if isinstance(mailbox,str) and room == mailbox:
        return "MAILBOX"
    if isinstance(room,str) and room in watch:
        return "WATCH"
    return "OTHER"

def room_hash(room):
    if not isinstance(room,str) or not room:
        return "NONE"
    return hashlib.sha256(room.encode("utf-8")).hexdigest()[:12]

print("--- LAST UNRECOVERABLE GAP ---")
last=state.get("last_unrecoverable_gap")
if isinstance(last,dict):
    room=last.get("room")
    print("LAST_GAP_PRESENT=YES")
    print(f"LAST_GAP_ROOM_LABEL={room_label(room)}")
    print(f"LAST_GAP_ROOM_HASH={room_hash(room)}")
    print(f"LAST_GAP_LANE={last.get('lane','missing')}")
    print(f"LAST_GAP_OBSERVED_AT={last.get('observed_at','missing')}")
    print(f"LAST_GAP_MISSING_FROM={last.get('missing_from','missing')}")
    print(f"LAST_GAP_MISSING_TO={last.get('missing_to','missing')}")
    print(f"LAST_GAP_ESTIMATED_MISSING={last.get('estimated_missing','missing')}")
    print(f"LAST_GAP_RECOVERY_REASON={last.get('recovery_reason','missing')}")
    mf=last.get("missing_from")
    mt=last.get("missing_to")
    if isinstance(mf,int) and isinstance(mt,int):
        print(f"LAST_GAP_RANGE_LENGTH={mt-mf+1}")
        print("LAST_GAP_STARTS_AT_PRIOR_CURSOR_NEXT="+("YES" if mf == PRIOR_CURSOR+1 else "NO"))
        print("LAST_GAP_ENDS_AT_CURRENT_CURSOR="+("YES" if mt == lobby_cursor else "NO"))
        print("LAST_GAP_LENGTH_EQUALS_CORE_DELTA="+(
            "YES" if mt-mf+1 == messages-PRIOR_MESSAGES else "NO"
        ))
else:
    print("LAST_GAP_PRESENT=NO")

metric_keys=[
    "message_gaps",
    "estimated_missing_messages",
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
    "lobby_startup_bridge_attempts",
    "lobby_startup_bridge_successes",
    "lobby_startup_bridge_messages",
    "lobby_startup_bridge_failures",
    "lobby_startup_bridge_unrecoverable_events",
    "lobby_startup_bridge_unrecoverable_messages",
    "lobby_startup_local_liveness_slices",
    "lobby_startup_local_liveness_messages",
    "lobby_startup_local_liveness_bridge_attempts",
    "lobby_startup_local_liveness_delegations",
    "lobby_startup_local_liveness_stale_bridge_attempts",
    "lobby_startup_local_liveness_caught_up_waits",
    "lobby_startup_local_liveness_capture_stall_waits",
    "lobby_spool_recovery_events",
    "lobby_spool_recovered_messages",
    "lobby_spool_live_error_recoveries",
    "lobby_spool_partial_recovery_messages",
    "lobby_spool_catchup_waits",
    "lobby_spool_catchup_successes",
    "lobby_spool_catchup_timeouts",
    "lobby_startup_spool_attempts",
    "lobby_startup_spool_recoveries",
    "lobby_startup_spool_messages",
    "lobby_capture_pending_cycles",
    "lobby_live_error_capture_pending_cycles",
    "lobby_startup_capture_checks",
    "lobby_startup_capture_waits",
    "lobby_startup_capture_shortcuts",
    "lobby_startup_capture_messages",
    "startup_stream_export_attempts",
    "startup_stream_export_successes",
    "startup_stream_export_failures",
    "startup_stream_export_messages",
]
print("--- CONTINUITY METRICS ---")
for key in metric_keys:
    print(f"METRIC_{key.upper()}={metrics.get(key,'missing')}")

print("--- RECENT UNRECOVERABLE GAPS ---")
records=[]
for item in state.get("opportunities") or []:
    if not isinstance(item,dict):
        continue
    if item.get("kind") != "message_gap" or item.get("recovery") != "unrecoverable":
        continue
    records.append(item)
for idx,item in enumerate(records[-12:],1):
    room=item.get("room")
    print(
        "GAP_RECORD "
        f"idx={idx} room_label={room_label(room)} room_hash={room_hash(room)} "
        f"seq={item.get('seq','missing')} observed_at={item.get('observed_at','missing')} "
        f"missing_from={item.get('missing_from','missing')} missing_to={item.get('missing_to','missing')} "
        f"estimated_missing={item.get('estimated_missing','missing')} "
        f"reason={item.get('recovery_reason','missing')}"
    )
print(f"RECENT_UNRECOVERABLE_GAP_COUNT={len(records[-12:])}")

print("--- CORE ROOM HEALTH ---")
health=(state.get("health") or {}).get("rooms") or {}
if not isinstance(health,dict):
    health={}
for key in ("events","lobby"):
    item=health.get(key) if isinstance(health.get(key),dict) else {}
    safe_kind="".join(ch for ch in str(item.get("kind","missing")) if ch.isalnum() or ch in "._-/")[:80]
    print(f"HEALTH_{key.upper()}_STATUS={item.get('status','missing')}")
    print(f"HEALTH_{key.upper()}_KIND={safe_kind}")
    print(f"HEALTH_{key.upper()}_AT={item.get('at','missing')}")

print("--- RECENT ERROR HISTORY SANITIZED ---")
errors=[]
for item in state.get("error_history") or []:
    if not isinstance(item,dict):
        continue
    room=item.get("room")
    kind="".join(ch for ch in str(item.get("kind","missing")) if ch.isalnum() or ch in "._-/")[:80]
    errors.append((room_label(room),room_hash(room),kind,item.get("at","missing")))
for idx,(label,rhash,kind,at) in enumerate(errors[-16:],1):
    print(f"ERROR_RECORD idx={idx} room_label={label} room_hash={rhash} kind={kind} at={at}")
print(f"RECENT_ERROR_COUNT={len(errors[-16:])}")

print("ISSUE390_GAPV2_STATE_FORENSIC=PASS")
PY
)
STATE_RC=$?
printf '%s\n' "$STATE_OUT"
if [[ "$STATE_RC" -eq 20 ]]; then
  echo 'ISSUE390_GAPV2=STOP:core_moved_again'
  exit 0
fi
if [[ "$STATE_RC" -eq 21 ]]; then
  echo 'ISSUE390_GAPV2=STOP:lobby_cursor_moved'
  exit 0
fi
if [[ "$STATE_RC" -ne 0 ]]; then
  echo 'ISSUE390_GAPV2=STOP:state_forensic_failed'
  exit 0
fi

proc_snapshot() {
  local tag=$1
  "$APP_PY" - "$EXPECTED_CAP_PID" "$tag" "$CAP_DB" "$CAP_WAL" "$CAP_SHM" <<'PY'
import pathlib
import sys

pid=int(sys.argv[1]); tag=sys.argv[2]
stat_path=pathlib.Path(f"/proc/{pid}/stat")
if not stat_path.exists():
    print(f"CAPTURE_PROC_{tag}=MISSING")
    raise SystemExit
raw=stat_path.read_text("utf-8",errors="replace")
right=raw.rfind(")")
rest=raw[right+2:].split()
state=rest[0]
ticks=int(rest[11])+int(rest[12])
print(f"CAPTURE_PROC_{tag}=PRESENT state={state} cpu_ticks={ticks}")
for label,arg in (("DB",sys.argv[3]),("WAL",sys.argv[4]),("SHM",sys.argv[5])):
    path=pathlib.Path(arg)
    if not path.exists():
        print(f"CAPTURE_{label}_{tag}=exists:NO size:0 mtime_ns:0")
        continue
    st=path.stat()
    print(f"CAPTURE_{label}_{tag}=exists:YES size:{st.st_size} mtime_ns:{st.st_mtime_ns}")
PY
}

echo '--- CAPTURE PROCESS / FILE ACTIVITY ---'
proc_snapshot T0
sleep 5
proc_snapshot T5

journalctl -u "$CAP" --since '8 hours ago' --no-pager --output=cat >"$TMPDIR/capture.log" 2>/dev/null || true
"$APP_PY" - "$TMPDIR/capture.log" <<'PY'
import pathlib
import sys

text=pathlib.Path(sys.argv[1]).read_text("utf-8",errors="replace").lower()
patterns={
    "TRACEBACK":("traceback",),
    "HTTP_429":("429",),
    "TIMEOUT":("timeout","timed out"),
    "CONNECTION":("connectionerror","connecterror","connection reset"),
    "CAPTURE_HOLE":("capture hole","capture_hole"),
    "OOM":("out of memory","oom-kill","oom kill"),
}
for label,needles in patterns.items():
    print("CAPTURE_JOURNAL_CLASS_"+label+"="+str(sum(text.count(n) for n in needles)))
PY

echo '--- POST SERVICE CONTINUITY ---'
svc RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS"
svc CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"

echo '--- SAFETY TAIL ---'
echo 'MUTATION_COMMANDS=NONE'
echo 'SERVICE_RESTART=NO'
echo 'PROCESS_SIGNAL=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'NETWORK_PROBE=NO'
echo 'TECHNOCORE_WRITE=NO'
echo 'RAW_JOURNAL_OUTPUT=NO'
echo 'RAW_UNTRUSTED_TEXT_OUTPUT=NO'
echo 'DID_OUTPUT=NO'
echo 'RAW_PRIVATE_ROOM_OUTPUT=NO'
echo '=== ISSUE390_SECOND_CORE_GAP_FORENSIC_V2=COMPLETE_READ_ONLY ==='
echo 'DO_NOT_RERUN=YES'
exit 0
