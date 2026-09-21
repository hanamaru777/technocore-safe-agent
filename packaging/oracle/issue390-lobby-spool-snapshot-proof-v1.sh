#!/usr/bin/env bash
# Issue #390: prove whether the current server-retention missing prefix still exists
# in a transactionally consistent snapshot of the standalone capture spool.
set -u
umask 077

APP=/opt/technocore-safe-agent
APP_PY=$APP/.venv/bin/python
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
OBHB=$STATE/observer/observer-heartbeat.json
RESHB=$STATE/observer/resident-heartbeat.json
CAP_DB=$STATE/observer/lobby-capture-service.sqlite3
CAP_WAL=$STATE/observer/lobby-capture-service.sqlite3-wal
CAP_SHM=$STATE/observer/lobby-capture-service.sqlite3-shm

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service

EXPECTED_APP_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe
EXPECTED_CORE_EVENTS=118
EXPECTED_CORE_MESSAGES=5092411
EXPECTED_LOBBY_CURSOR=59579961
EXPECTED_RES_PID=1868797
EXPECTED_RES_RESTARTS=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0

TMPDIR=$(mktemp -d /tmp/issue390-spool-proof.XXXXXX)
SNAPSHOT=$TMPDIR/lobby-capture-snapshot.sqlite3
cleanup() { rm -rf -- "$TMPDIR"; }
trap cleanup EXIT

echo '=== ISSUE390 LOBBY SPOOL SNAPSHOT PROOF V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'ISSUE390_SPOOLV1=STOP:not_root'
  exit 0
fi

for path in "$APP/.git" "$APP_PY" "$OBS" "$OBHB" "$RESHB" "$CAP_DB"; do
  if [[ ! -e "$path" ]]; then
    echo 'ISSUE390_SPOOLV1=STOP:required_path_missing'
    exit 0
  fi
done

if ! command -v timeout >/dev/null 2>&1; then
  echo 'ISSUE390_SPOOLV1=STOP:timeout_command_missing'
  exit 0
fi

APP_HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "APP_HEAD=$APP_HEAD"
if [[ -z "$WORKTREE" ]]; then echo 'WORKTREE_CLEAN=YES'; else echo 'WORKTREE_CLEAN=NO'; fi
if [[ "$APP_HEAD" != "$EXPECTED_APP_HEAD" || -n "$WORKTREE" ]]; then
  echo 'ISSUE390_SPOOLV1=STOP:repo_baseline_changed'
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
    echo "ISSUE390_SPOOLV1=STOP:service_baseline_changed:$label"
    exit 0
  fi
}

svc RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS"
svc CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"

if ! "$APP_PY" - <<'PY' >/dev/null 2>&1
import httpx
import sqlite3
PY
then
  echo 'ISSUE390_SPOOLV1=STOP:app_runtime_missing_dependency'
  exit 0
fi
echo 'APP_RUNTIME_HTTPX_SQLITE=YES'

STATE_OUT=$("$APP_PY" - "$OBS" "$OBHB" "$RESHB" "$EXPECTED_CORE_EVENTS" "$EXPECTED_CORE_MESSAGES" "$EXPECTED_LOBBY_CURSOR" <<'PY'
import json
import pathlib
import sys
from datetime import UTC, datetime

obs_path=pathlib.Path(sys.argv[1])
obhb_path=pathlib.Path(sys.argv[2])
reshb_path=pathlib.Path(sys.argv[3])
expected_events=int(sys.argv[4])
expected_messages=int(sys.argv[5])
expected_cursor=int(sys.argv[6])

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

state=load(obs_path)
obhb=load(obhb_path)
reshb=load(reshb_path)
metrics=state.get("metrics") or {}
events=int(metrics.get("unrecoverable_core_gap_events",0) or 0)
messages=int(metrics.get("unrecoverable_core_gap_messages",0) or 0)
cursor=int((state.get("cursors") or {}).get("lobby",0) or 0)

print(f"PROTECTED_CORE={events}/{messages}")
print(f"LOBBY_CURSOR={cursor}")
print(f"OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
print(f"OBSERVER_HEALTH_CURRENT={(state.get('health') or {}).get('current','missing')}")
print(f"OBSERVER_HEARTBEAT_STATUS={obhb.get('status','missing')}")
print(f"OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")

if (events,messages)!=(expected_events,expected_messages):
    print("ISSUE390_SPOOLV1_STATE=STOP:core_moved_again")
    raise SystemExit(20)
if cursor != expected_cursor:
    print("ISSUE390_SPOOLV1_STATE=STOP:cursor_moved")
    raise SystemExit(21)
print("ISSUE390_SPOOLV1_STATE=BASELINE_STILL_STALLED")
PY
)
STATE_RC=$?
printf '%s\n' "$STATE_OUT"
if [[ "$STATE_RC" -eq 20 ]]; then
  echo 'ISSUE390_SPOOLV1=STOP:core_moved_again'
  exit 0
fi
if [[ "$STATE_RC" -eq 21 ]]; then
  echo 'ISSUE390_SPOOLV1=STOP:cursor_moved'
  exit 0
fi
if [[ "$STATE_RC" -ne 0 ]]; then
  echo 'ISSUE390_SPOOLV1=STOP:state_read_failed'
  exit 0
fi

proc_meta() {
  local tag=$1
  "$APP_PY" - "$EXPECTED_CAP_PID" "$tag" "$CAP_DB" "$CAP_WAL" "$CAP_SHM" <<'PY'
import pathlib
import sys

pid=int(sys.argv[1]); tag=sys.argv[2]
paths=[("DB",pathlib.Path(sys.argv[3])),("WAL",pathlib.Path(sys.argv[4])),("SHM",pathlib.Path(sys.argv[5]))]
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
for label,path in paths:
    if not path.exists():
        print(f"CAPTURE_{label}_{tag}=exists:NO size:0 mtime_ns:0")
        continue
    st=path.stat()
    print(f"CAPTURE_{label}_{tag}=exists:YES size:{st.st_size} mtime_ns:{st.st_mtime_ns}")
PY
}

echo '--- CAPTURE ACTIVITY T0 ---'
proc_meta T0

echo '--- CONSISTENT READ-ONLY ONLINE BACKUP + SNAPSHOT QUERY ---'
timeout 30s "$APP_PY" - "$CAP_DB" "$SNAPSHOT" "$OBS" "$EXPECTED_LOBBY_CURSOR" <<'PY'
import json
import pathlib
import sqlite3
import sys

source_path=pathlib.Path(sys.argv[1])
snapshot_path=pathlib.Path(sys.argv[2])
obs_path=pathlib.Path(sys.argv[3])
expected_cursor=int(sys.argv[4])

# Source is opened read-only. No SELECT/PRAGMA/schema operation is run against it.
# SQLite's online backup API creates a transactionally consistent disposable clone.
source=sqlite3.connect(f"file:{source_path.as_posix()}?mode=ro",uri=True,timeout=2.0)
dest=sqlite3.connect(str(snapshot_path),timeout=2.0)
try:
    source.backup(dest,pages=256,sleep=0.01)
    dest.commit()
finally:
    source.close()
    dest.close()

# All SQL below runs only against the disposable clone.
snap=sqlite3.connect(f"file:{snapshot_path.as_posix()}?mode=ro",uri=True,timeout=2.0)
try:
    quick=snap.execute("PRAGMA quick_check").fetchone()
    print("SNAPSHOT_QUICK_CHECK="+str(quick[0] if quick else "missing"))
    row=snap.execute("SELECT COUNT(*),MIN(seq),MAX(seq) FROM messages").fetchone()
    count=int(row[0]) if row else 0
    first=int(row[1]) if row and row[1] is not None else None
    last=int(row[2]) if row and row[2] is not None else None
    print(f"SNAPSHOT_ROW_COUNT={count}")
    print("SNAPSHOT_FIRST_SEQ="+(str(first) if first is not None else "NONE"))
    print("SNAPSHOT_LAST_SEQ="+(str(last) if last is not None else "NONE"))

    def meta(key):
        row=snap.execute("SELECT value FROM meta WHERE key=?",(key,)).fetchone()
        return str(row[0]) if row else None

    capture_cursor=int(meta("capture_cursor") or 0)
    print(f"SNAPSHOT_CAPTURE_CURSOR={capture_cursor}")
    print("SNAPSHOT_LAST_SUCCESS_AT="+str(meta("last_success_at") or "NONE"))
    last_error=str(meta("last_error") or "")
    safe_error="".join(ch for ch in last_error if ch.isalnum() or ch in "._-/")[:80]
    print("SNAPSHOT_LAST_ERROR="+(safe_error or "NONE"))
    hole=meta("last_capture_hole")
    if hole:
        try:
            parsed=json.loads(hole)
        except Exception:
            parsed={}
        print("SNAPSHOT_LAST_CAPTURE_HOLE_FROM="+str(parsed.get("missing_from","UNKNOWN")))
        print("SNAPSHOT_LAST_CAPTURE_HOLE_TO="+str(parsed.get("missing_to","UNKNOWN")))
    else:
        print("SNAPSHOT_LAST_CAPTURE_HOLE_FROM=NONE")
        print("SNAPSHOT_LAST_CAPTURE_HOLE_TO=NONE")
finally:
    snap.close()

state=json.loads(obs_path.read_text("utf-8"))
cursor=int((state.get("cursors") or {}).get("lobby",0) or 0)
print(f"POST_BACKUP_LOBBY_CURSOR={cursor}")
if cursor != expected_cursor:
    print("ISSUE390_SPOOLV1_BACKUP_STATE=CURSOR_MOVED_DURING_BACKUP")
else:
    print("ISSUE390_SPOOLV1_BACKUP_STATE=CURSOR_STILL_STALLED")
PY
BACKUP_RC=$?
echo "ISSUE390_SPOOLV1_BACKUP_RC=$BACKUP_RC"
if [[ "$BACKUP_RC" -eq 124 ]]; then
  echo 'ISSUE390_SPOOLV1=STOP:online_backup_timeout'
  exit 0
fi
if [[ "$BACKUP_RC" -ne 0 ]]; then
  echo 'ISSUE390_SPOOLV1=STOP:online_backup_failed'
  exit 0
fi

POST_CURSOR=$("$APP_PY" - "$OBS" <<'PY'
import json,pathlib,sys
state=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
print(int((state.get("cursors") or {}).get("lobby",0) or 0))
PY
)
if [[ "$POST_CURSOR" != "$EXPECTED_LOBBY_CURSOR" ]]; then
  echo "POST_BACKUP_CURSOR=$POST_CURSOR"
  echo 'ISSUE390_SPOOLV1=STOP:cursor_moved_during_probe'
  exit 0
fi

echo '--- CURRENT SERVER RETAINED WINDOW + SNAPSHOT COVERAGE ---'
timeout 25s "$APP_PY" - "$SNAPSHOT" "$EXPECTED_LOBBY_CURSOR" <<'PY'
import json
import pathlib
import sqlite3
import sys

import httpx

snapshot_path=pathlib.Path(sys.argv[1])
cursor=int(sys.argv[2])
base="https://technocore.chat"

timeout=httpx.Timeout(10.0,connect=3.0,pool=3.0)
count=0
first=None
last=None
invalid=0
try:
    with httpx.Client(timeout=timeout,follow_redirects=False) as client:
        with client.stream("GET",base+"/r/lobby/export") as response:
            print("EXPORT_HTTP_STATUS="+str(response.status_code))
            response.raise_for_status()
            for raw in response.iter_lines():
                if not raw or not raw.strip():
                    continue
                try:
                    item=json.loads(raw)
                except Exception:
                    invalid+=1
                    continue
                seq=item.get("seq") if isinstance(item,dict) else None
                if not isinstance(seq,int):
                    invalid+=1
                    continue
                count+=1
                if first is None:
                    first=seq
                last=seq
except Exception as exc:
    print("EXPORT_PROBE=FAIL")
    print("EXPORT_ERROR_TYPE="+type(exc).__name__)
    raise SystemExit(31)

print("EXPORT_VALID_ROW_COUNT="+str(count))
print("EXPORT_INVALID_ROW_COUNT="+str(invalid))
print("EXPORT_FIRST_SEQ="+(str(first) if first is not None else "NONE"))
print("EXPORT_LAST_SEQ="+(str(last) if last is not None else "NONE"))
if first is None:
    print("ISSUE390_SPOOLV1_COVERAGE=UNKNOWN:no_export_rows")
    raise SystemExit(32)

need_start=cursor+1
need_end=first-1
expected=max(0,need_end-need_start+1)
print(f"SERVER_MISSING_PREFIX_START={need_start}")
print(f"SERVER_MISSING_PREFIX_END={need_end}")
print(f"SERVER_MISSING_PREFIX_EXPECTED_ROWS={expected}")

snap=sqlite3.connect(f"file:{snapshot_path.as_posix()}?mode=ro",uri=True,timeout=2.0)
try:
    if expected == 0:
        have_count=0
        have_min=None
        have_max=None
        complete=True
    else:
        row=snap.execute(
            "SELECT COUNT(*),MIN(seq),MAX(seq) FROM messages WHERE seq BETWEEN ? AND ?",
            (need_start,need_end),
        ).fetchone()
        have_count=int(row[0]) if row else 0
        have_min=int(row[1]) if row and row[1] is not None else None
        have_max=int(row[2]) if row and row[2] is not None else None
        complete=(
            have_count == expected
            and have_min == need_start
            and have_max == need_end
        )
    print(f"SNAPSHOT_PREFIX_ROW_COUNT={have_count}")
    print("SNAPSHOT_PREFIX_MIN_SEQ="+(str(have_min) if have_min is not None else "NONE"))
    print("SNAPSHOT_PREFIX_MAX_SEQ="+(str(have_max) if have_max is not None else "NONE"))
    print("SNAPSHOT_HAS_SERVER_MISSING_PREFIX="+("YES" if complete else "NO"))
    if expected:
        print(f"SNAPSHOT_PREFIX_MISSING_ROWS={expected-have_count}")
finally:
    snap.close()

print("NETWORK_PROBE_MODE=GET_ONLY_SEQ_METADATA")
print("RAW_MESSAGE_OUTPUT=NO")
print("DID_OUTPUT=NO")
PY
COVERAGE_RC=$?
echo "ISSUE390_SPOOLV1_COVERAGE_RC=$COVERAGE_RC"
if [[ "$COVERAGE_RC" -eq 124 ]]; then
  echo 'ISSUE390_SPOOLV1=STOP:coverage_timeout'
  exit 0
fi
if [[ "$COVERAGE_RC" -ne 0 ]]; then
  echo 'ISSUE390_SPOOLV1=STOP:coverage_failed'
  exit 0
fi

sleep 5
echo '--- STALL / CAPTURE ACTIVITY T5 ---'
proc_meta T5

"$APP_PY" - "$OBS" "$EXPECTED_CORE_EVENTS" "$EXPECTED_CORE_MESSAGES" "$EXPECTED_LOBBY_CURSOR" <<'PY'
import json,pathlib,sys
state=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
metrics=state.get("metrics") or {}
events=int(metrics.get("unrecoverable_core_gap_events",0) or 0)
messages=int(metrics.get("unrecoverable_core_gap_messages",0) or 0)
cursor=int((state.get("cursors") or {}).get("lobby",0) or 0)
print(f"POST_PROTECTED_CORE={events}/{messages}")
print(f"POST_LOBBY_CURSOR={cursor}")
print(f"POST_OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
if (events,messages)!=(int(sys.argv[2]),int(sys.argv[3])):
    print("ISSUE390_SPOOLV1_POST_STATE=CORE_MOVED")
elif cursor != int(sys.argv[4]):
    print("ISSUE390_SPOOLV1_POST_STATE=CURSOR_MOVED")
else:
    print("ISSUE390_SPOOLV1_POST_STATE=STILL_STALLED")
PY

echo '--- POST SERVICE CONTINUITY ---'
svc RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS"
svc CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"

echo '--- SAFETY TAIL ---'
echo 'APPLICATION_STATE_MUTATION=NO'
echo 'SERVICE_MUTATION=NO'
echo 'SERVICE_RESTART=NO'
echo 'PROCESS_SIGNAL=NO'
echo 'ACTIVE_CAPTURE_SQLITE_SELECT=NO'
echo 'ACTIVE_CAPTURE_SQLITE_BACKUP_MODE=READ_ONLY_ONLINE_BACKUP'
echo 'SNAPSHOT_QUERY_ONLY=YES'
echo 'TEMP_SNAPSHOT_REMOVED_ON_EXIT=YES'
echo 'NETWORK_WRITE=NO'
echo 'NETWORK_READ=YES_GET_ONLY'
echo 'TECHNOCORE_WRITE=NO'
echo 'RAW_MESSAGE_OUTPUT=NO'
echo 'DID_OUTPUT=NO'
echo '=== ISSUE390_LOBBY_SPOOL_SNAPSHOT_PROOF_V1=COMPLETE ==='
echo 'DO_NOT_RERUN=YES'
exit 0
