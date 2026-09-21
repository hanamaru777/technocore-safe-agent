#!/usr/bin/env bash
# Issue #390: read-only forensic for a newly increased protected-core gap baseline.
set -u
umask 077

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
OBHB=$STATE/observer/observer-heartbeat.json
RESHB=$STATE/observer/resident-heartbeat.json
RESCFG=$STATE/observer/resident-config.json
OBSCFG=$STATE/observer/observer-config.json
CAP_WAL=$STATE/observer/lobby-capture-service.sqlite3-wal
CAP_SHM=$STATE/observer/lobby-capture-service.sqlite3-shm

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service

EXPECTED_APP_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe
EXPECTED_CORE_EVENTS=118
EXPECTED_CORE_MESSAGES=5092411
EXPECTED_RES_PID=1868797
EXPECTED_RES_RESTARTS=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0
EXPECTED_SIG_PID=1539554
EXPECTED_SIG_RESTARTS=1
EXPECTED_DIS_PID=1957840
EXPECTED_DIS_RESTARTS=0

TMPDIR=$(mktemp -d /tmp/issue390.XXXXXX)
cleanup() { rm -rf -- "$TMPDIR"; }
trap cleanup EXIT

echo '=== ISSUE390 NEW PROTECTED-CORE GAP READ-ONLY FORENSIC ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'ISSUE390=STOP:not_root'
  exit 0
fi

for path in "$APP/.git" "$OBS" "$OBHB" "$RESHB" "$RESCFG" "$OBSCFG"; do
  if [[ ! -e "$path" ]]; then
    echo 'ISSUE390=STOP:required_path_missing'
    exit 0
  fi
done

APP_HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)

echo "APP_HEAD=$APP_HEAD"
if [[ -z "$WORKTREE" ]]; then echo 'WORKTREE_CLEAN=YES'; else echo 'WORKTREE_CLEAN=NO'; fi

if [[ "$APP_HEAD" != "$EXPECTED_APP_HEAD" ]]; then
  echo 'ISSUE390=STOP:app_head_changed'
  exit 0
fi
if [[ -n "$WORKTREE" ]]; then
  echo 'ISSUE390=STOP:worktree_not_clean'
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
    echo "ISSUE390=STOP:service_baseline_changed:$label"
    exit 0
  fi
}

svc RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS"
svc CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"
svc SIGNER "$SIG" "$EXPECTED_SIG_PID" "$EXPECTED_SIG_RESTARTS"
svc DISCORD "$DIS" "$EXPECTED_DIS_PID" "$EXPECTED_DIS_RESTARTS"

python3 - "$OBS" "$OBHB" "$RESHB" "$OBSCFG" "$EXPECTED_CORE_EVENTS" "$EXPECTED_CORE_MESSAGES" <<'PY'
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
    return max(0.0,(datetime.now(UTC)-dt).total_seconds())

state=load(OBS)
obhb=load(OBHB)
reshb=load(RESHB)
cfg=load(CFG)

metrics=state.get("metrics") if isinstance(state,dict) else {}
if not isinstance(metrics,dict):
    metrics={}

events=int(metrics.get("unrecoverable_core_gap_events",0) or 0)
messages=int(metrics.get("unrecoverable_core_gap_messages",0) or 0)
print(f"PROTECTED_CORE={events}/{messages}")
if events != EXPECTED_EVENTS or messages != EXPECTED_MESSAGES:
    print("ISSUE390_STATE=STOP:core_moved_again")
    raise SystemExit(20)

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

print(f"OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
print(f"OBSERVER_HEALTH_CURRENT={(state.get('health') or {}).get('current','missing')}")
print(f"OBSERVER_HEARTBEAT_STATUS={obhb.get('status','missing')}")
print(f"OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")

keys=[
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
    "events_startup_snapshot_unrecoverable_events",
    "events_startup_snapshot_unrecoverable_messages",
    "startup_stream_export_attempts",
    "startup_stream_export_successes",
    "startup_stream_export_failures",
    "startup_stream_export_messages",
    "lobby_capture_pending_cycles",
    "lobby_live_error_capture_pending_cycles",
    "lobby_startup_capture_checks",
    "lobby_startup_capture_waits",
    "lobby_startup_capture_shortcuts",
    "lobby_startup_capture_messages",
]
for key in keys:
    print(f"METRIC_{key.upper()}={metrics.get(key,'missing')}")

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
else:
    print("LAST_GAP_PRESENT=NO")

print("--- RECENT_UNRECOVERABLE_GAPS ---")
records=[]
for item in state.get("opportunities") or []:
    if not isinstance(item,dict):
        continue
    if item.get("kind") != "message_gap" or item.get("recovery") != "unrecoverable":
        continue
    records.append(item)
for idx,item in enumerate(records[-8:],1):
    room=item.get("room")
    print(
        "GAP_RECORD "
        f"idx={idx} room_label={room_label(room)} room_hash={room_hash(room)} "
        f"seq={item.get('seq','missing')} observed_at={item.get('observed_at','missing')} "
        f"missing_from={item.get('missing_from','missing')} missing_to={item.get('missing_to','missing')} "
        f"estimated_missing={item.get('estimated_missing','missing')} "
        f"reason={item.get('recovery_reason','missing')}"
    )
print(f"RECENT_UNRECOVERABLE_GAP_COUNT={len(records[-8:])}")

print("--- CORE CURSORS ---")
cursors=state.get("cursors") if isinstance(state,dict) else {}
if not isinstance(cursors,dict): cursors={}
for key in ("events","lobby"):
    print(f"CURSOR_{key.upper()}={cursors.get(key,'missing')}")
if isinstance(mailbox,str):
    print(f"CURSOR_MAILBOX={cursors.get(mailbox,'missing')}")
else:
    print("CURSOR_MAILBOX=UNCONFIGURED")

print("--- HEALTH ROOMS ---")
health=(state.get("health") or {}).get("rooms") or {}
if not isinstance(health,dict): health={}
for key in ("events","lobby"):
    item=health.get(key) if isinstance(health.get(key),dict) else {}
    print(f"HEALTH_{key.upper()}_STATUS={item.get('status','missing')}")
    print(f"HEALTH_{key.upper()}_AT={item.get('at','missing')}")
if isinstance(mailbox,str):
    item=health.get(mailbox) if isinstance(health.get(mailbox),dict) else {}
    print(f"HEALTH_MAILBOX_STATUS={item.get('status','missing')}")
    print(f"HEALTH_MAILBOX_AT={item.get('at','missing')}")
else:
    print("HEALTH_MAILBOX_STATUS=UNCONFIGURED")

print("--- RECENT_ERROR_HISTORY_SANITIZED ---")
errors=[]
for item in state.get("error_history") or []:
    if not isinstance(item,dict): continue
    room=item.get("room")
    errors.append((room_label(room),room_hash(room),item.get("kind","missing"),item.get("at","missing")))
for idx,(label,rhash,kind,at) in enumerate(errors[-10:],1):
    safe_kind="".join(ch for ch in str(kind) if ch.isalnum() or ch in "._-/")[:80]
    print(f"ERROR_RECORD idx={idx} room_label={label} room_hash={rhash} kind={safe_kind} at={at}")
print(f"RECENT_ERROR_COUNT={len(errors[-10:])}")

print("ISSUE390_STATE_FORENSIC=PASS")
PY
STATE_RC=$?
echo "ISSUE390_STATE_RC=$STATE_RC"
if [[ "$STATE_RC" -ne 0 ]]; then
  echo 'ISSUE390=STOP:state_forensic_failed'
  exit 0
fi

proc_snapshot() {
  local pid=$1 tag=$2
  python3 - "$pid" "$tag" "$CAP_WAL" "$CAP_SHM" <<'PY'
import os
import pathlib
import sys
import time

pid=int(sys.argv[1]); tag=sys.argv[2]
wal=pathlib.Path(sys.argv[3]); shm=pathlib.Path(sys.argv[4])
p=pathlib.Path(f"/proc/{pid}/stat")
if not p.exists():
    print(f"CAPTURE_PROC_{tag}=MISSING")
    raise SystemExit
raw=p.read_text("utf-8",errors="replace")
right=raw.rfind(")")
rest=raw[right+2:].split()
utime=int(rest[11]); stime=int(rest[12]); state=rest[0]
def meta(path):
    if not path.exists(): return ("NO",0,0)
    st=path.stat()
    return ("YES",st.st_size,int(st.st_mtime_ns))
wal_e,wal_s,wal_m=meta(wal)
shm_e,shm_s,shm_m=meta(shm)
print(f"CAPTURE_PROC_{tag}=PRESENT state={state} cpu_ticks={utime+stime}")
print(f"CAPTURE_WAL_{tag}=exists:{wal_e} size:{wal_s} mtime_ns:{wal_m}")
print(f"CAPTURE_SHM_{tag}=exists:{shm_e} size:{shm_s} mtime_ns:{shm_m}")
PY
}

echo '--- CAPTURE PROCESS / FILE ACTIVITY ---'
proc_snapshot "$EXPECTED_CAP_PID" T0
sleep 10
proc_snapshot "$EXPECTED_CAP_PID" T10

journalctl -u "$CAP" --since '8 hours ago' --no-pager --output=cat >"$TMPDIR/capture.log" 2>/dev/null || true
python3 - "$TMPDIR/capture.log" <<'PY'
import pathlib,sys
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
svc SIGNER "$SIG" "$EXPECTED_SIG_PID" "$EXPECTED_SIG_RESTARTS"
svc DISCORD "$DIS" "$EXPECTED_DIS_PID" "$EXPECTED_DIS_RESTARTS"

echo '--- SAFETY TAIL ---'
echo 'MUTATION_COMMANDS=NONE'
echo 'SERVICE_RESTART=NO'
echo 'PROCESS_SIGNAL=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'NETWORK_PROBE=NO'
echo 'TECHNOCORE_WRITE=NO'
echo 'SNAP_MUTATION=NO'
echo 'RAW_JOURNAL_OUTPUT=NO'
echo 'RAW_UNTRUSTED_TEXT_OUTPUT=NO'
echo 'DID_OUTPUT=NO'
echo 'RAW_PRIVATE_ROOM_OUTPUT=NO'
echo '=== ISSUE390_CORE_GAP_FORENSIC=COMPLETE_READ_ONLY ==='
echo 'DO_NOT_RERUN=YES'
exit 0
