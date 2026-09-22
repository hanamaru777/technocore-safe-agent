#!/usr/bin/env bash
# Issue #390: preserve and inspect a consistent Lobby capture snapshot without
# querying the active SQLite source, then measure the current retained export.
set -u
umask 077

APP=/opt/technocore-safe-agent
APP_PY=$APP/.venv/bin/python
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
OBHB=$STATE/observer/observer-heartbeat.json
RESHB=$STATE/observer/resident-heartbeat.json
CAP_DB=$STATE/observer/lobby-capture-service.sqlite3
FORENSICS_DIR=$STATE/forensics

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service

EXPECTED_APP_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe
EXPECTED_CORE_EVENTS=119
EXPECTED_CORE_MESSAGES=5497275
EXPECTED_RES_PID=1868797
EXPECTED_RES_RESTARTS=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0
EXPORT_LIMIT_BYTES=$((12 * 1024 * 1024))
MIN_MEM_AVAILABLE_BYTES=$((128 * 1024 * 1024))

TMPDIR=$(mktemp -d /tmp/issue390-capsnap.XXXXXX)
SNAPSHOT=$TMPDIR/lobby-capture.snapshot.sqlite3
ANALYSIS=$TMPDIR/analysis.txt
cleanup() { rm -rf -- "$TMPDIR"; }
trap cleanup EXIT

echo '=== ISSUE390 CAPTURE/EXPORT SNAPSHOT PROOF V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'ISSUE390_CAPSNAPV1=STOP:not_root'
  exit 0
fi

for path in "$APP/.git" "$APP_PY" "$OBS" "$OBHB" "$RESHB" "$CAP_DB"; do
  if [[ ! -e "$path" ]]; then
    echo 'ISSUE390_CAPSNAPV1=STOP:required_path_missing'
    exit 0
  fi
done

for cmd in stat df timeout sha256sum install nice awk sed cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ISSUE390_CAPSNAPV1=STOP:missing_command:$cmd"
    exit 0
  fi
done

APP_HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "APP_HEAD=$APP_HEAD"
if [[ -z "$WORKTREE" ]]; then echo 'WORKTREE_CLEAN=YES'; else echo 'WORKTREE_CLEAN=NO'; fi
if [[ "$APP_HEAD" != "$EXPECTED_APP_HEAD" || -n "$WORKTREE" ]]; then
  echo 'ISSUE390_CAPSNAPV1=STOP:repo_baseline_changed'
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
    echo "ISSUE390_CAPSNAPV1=STOP:service_baseline_changed:$label"
    exit 0
  fi
}

read_core() {
  "$APP_PY" - "$OBS" "$OBHB" "$RESHB" <<'PY'
import json, pathlib, sys
from datetime import UTC, datetime

state=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
obhb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
reshb=json.loads(pathlib.Path(sys.argv[3]).read_text("utf-8"))
metrics=state.get("metrics") or {}
cursors=state.get("cursors") or {}

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

print(f"CORE_EVENTS={int(metrics.get('unrecoverable_core_gap_events',0) or 0)}")
print(f"CORE_MESSAGES={int(metrics.get('unrecoverable_core_gap_messages',0) or 0)}")
print(f"LOBBY_CURSOR={int(cursors.get('lobby',0) or 0)}")
print(f"OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
print(f"OBSERVER_HEALTH={(state.get('health') or {}).get('current','missing')}")
print(f"OBSERVER_HEARTBEAT_STATUS={obhb.get('status','missing')}")
print(f"OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")
PY
}

svc RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS"
svc CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"

PRE_STATE=$(read_core)
printf '%s\n' "$PRE_STATE" | sed 's/^/PRE_/'
PRE_EVENTS=$(printf '%s\n' "$PRE_STATE" | awk -F= '$1=="CORE_EVENTS"{print $2}')
PRE_MESSAGES=$(printf '%s\n' "$PRE_STATE" | awk -F= '$1=="CORE_MESSAGES"{print $2}')
if [[ "$PRE_EVENTS" != "$EXPECTED_CORE_EVENTS" || "$PRE_MESSAGES" != "$EXPECTED_CORE_MESSAGES" ]]; then
  echo 'ISSUE390_CAPSNAPV1=STOP:core_moved_again'
  exit 0
fi

proc_sample() {
  local tag=$1
  "$APP_PY" - "$tag" "$EXPECTED_CAP_PID" "$EXPECTED_RES_PID" <<'PY'
import pathlib, re, sys

tag=sys.argv[1]
pids=[("CAPTURE",int(sys.argv[2])),("RESIDENT",int(sys.argv[3]))]

def clean(v):
    return re.sub(r"[^A-Za-z0-9_.:/= -]", "", v)[:180] or "unknown"

for label,pid in pids:
    base=pathlib.Path(f"/proc/{pid}")
    if not base.exists():
        print(f"{tag}_{label}_PROC=MISSING")
        continue
    raw=(base/"stat").read_text("utf-8",errors="replace")
    right=raw.rfind(")")
    rest=raw[right+2:].split()
    state=rest[0]
    ticks=int(rest[11])+int(rest[12])
    rss_pages=int(rest[21])
    try:
        wchan=clean((base/"wchan").read_text("utf-8",errors="replace").strip())
    except Exception:
        wchan="unavailable"
    print(f"{tag}_{label}_PROC=PRESENT state={state} cpu_ticks={ticks} rss_pages={rss_pages} wchan={wchan}")

mem={}
for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
    if ":" not in line:
        continue
    k,v=line.split(":",1)
    if k in {"MemAvailable","SwapTotal","SwapFree","Dirty","Writeback"}:
        parts=v.strip().split()
        mem[k]=int(parts[0])*1024 if parts else 0
for k in ("MemAvailable","SwapTotal","SwapFree","Dirty","Writeback"):
    print(f"{tag}_MEM_{k.upper()}_BYTES={mem.get(k,0)}")

for name in ("io","memory"):
    p=pathlib.Path(f"/proc/pressure/{name}")
    if p.exists():
        lines=p.read_text("utf-8",errors="replace").splitlines()
        for idx,line in enumerate(lines[:2],1):
            print(f"{tag}_PSI_{name.upper()}_{idx}={clean(line)}")
print(f"{tag}_LOADAVG={clean(pathlib.Path('/proc/loadavg').read_text('utf-8').strip())}")
PY
}

echo '--- PRESSURE T0 ---'
proc_sample T0

SOURCE_DB_BYTES=$(stat -c %s "$CAP_DB" 2>/dev/null || echo 0)
TMP_FREE_BYTES=$(df -B1 --output=avail /tmp 2>/dev/null | awk 'NR==2 {print $1}')
STATE_FREE_BYTES=$(df -B1 --output=avail "$STATE" 2>/dev/null | awk 'NR==2 {print $1}')
MEM_AVAILABLE_BYTES=$(awk '/^MemAvailable:/ {print $2*1024}' /proc/meminfo)
MIN_TMP_FREE_BYTES=$((SOURCE_DB_BYTES * 2 + 536870912))
MIN_STATE_FREE_BYTES=$((SOURCE_DB_BYTES + 536870912))

echo "SOURCE_DB_BYTES=$SOURCE_DB_BYTES"
echo "TMP_FREE_BYTES=$TMP_FREE_BYTES"
echo "STATE_FREE_BYTES=$STATE_FREE_BYTES"
echo "MEM_AVAILABLE_BYTES=$MEM_AVAILABLE_BYTES"
echo "MIN_TMP_FREE_BYTES=$MIN_TMP_FREE_BYTES"
echo "MIN_STATE_FREE_BYTES=$MIN_STATE_FREE_BYTES"

if [[ -z "$TMP_FREE_BYTES" ]]; then
  echo 'ISSUE390_CAPSNAPV1=STOP:tmp_space_unknown'
  exit 0
fi
if [[ "$TMP_FREE_BYTES" -lt "$MIN_TMP_FREE_BYTES" ]]; then
  echo 'ISSUE390_CAPSNAPV1=STOP:insufficient_tmp_space'
  exit 0
fi
if [[ -z "$STATE_FREE_BYTES" ]]; then
  echo 'ISSUE390_CAPSNAPV1=STOP:state_space_unknown'
  exit 0
fi
if [[ "$STATE_FREE_BYTES" -lt "$MIN_STATE_FREE_BYTES" ]]; then
  echo 'ISSUE390_CAPSNAPV1=STOP:insufficient_state_space'
  exit 0
fi
if [[ -z "$MEM_AVAILABLE_BYTES" ]]; then
  echo 'ISSUE390_CAPSNAPV1=STOP:mem_available_unknown'
  exit 0
fi
if [[ "$MEM_AVAILABLE_BYTES" -lt "$MIN_MEM_AVAILABLE_BYTES" ]]; then
  echo 'ISSUE390_CAPSNAPV1=STOP:low_mem_available'
  exit 0
fi
echo 'RESOURCE_PREFLIGHT=PASS'

echo '--- ONLINE BACKUP ---'
if ! timeout --signal=TERM --kill-after=5s 60s nice -n 19 "$APP_PY" - "$CAP_DB" "$SNAPSHOT" <<'PY'
import sqlite3
import sys

source_path=sys.argv[1]
dest_path=sys.argv[2]
source=sqlite3.connect(f"file:{source_path}?mode=ro",uri=True,timeout=2.0)
dest=sqlite3.connect(dest_path,timeout=2.0)
try:
    source.backup(dest,pages=128,sleep=0.02)
    dest.commit()
finally:
    dest.close()
    source.close()
print("ONLINE_BACKUP=PASS")
PY
then
  echo 'ISSUE390_CAPSNAPV1=STOP:online_backup_failed_or_timeout'
  exit 0
fi

chmod 600 "$SNAPSHOT"
SNAPSHOT_BYTES=$(stat -c %s "$SNAPSHOT" 2>/dev/null || echo 0)
SNAPSHOT_SHA256=$(sha256sum "$SNAPSHOT" | awk '{print $1}')
echo "SNAPSHOT_BYTES=$SNAPSHOT_BYTES"
echo "SNAPSHOT_SHA256=$SNAPSHOT_SHA256"

MID_STATE=$(read_core)
printf '%s\n' "$MID_STATE" | sed 's/^/MID_/'
MID_EVENTS=$(printf '%s\n' "$MID_STATE" | awk -F= '$1=="CORE_EVENTS"{print $2}')
MID_MESSAGES=$(printf '%s\n' "$MID_STATE" | awk -F= '$1=="CORE_MESSAGES"{print $2}')
MID_CURSOR=$(printf '%s\n' "$MID_STATE" | awk -F= '$1=="LOBBY_CURSOR"{print $2}')

echo '--- SNAPSHOT + SERVER EXPORT ANALYSIS ---'
if ! "$APP_PY" - "$SNAPSHOT" "$MID_CURSOR" "$EXPORT_LIMIT_BYTES" >"$ANALYSIS" <<'PY'
import json
import re
import sqlite3
import sys

import httpx

BASE_URL="https://technocore.chat"

snapshot=sys.argv[1]
observer_cursor=int(sys.argv[2])
export_limit=int(sys.argv[3])

def safe(v):
    return re.sub(r"[^A-Za-z0-9_.:+/-]", "", str(v))[:160] or "missing"

conn=sqlite3.connect(snapshot,timeout=2.0)
try:
    check=conn.execute("PRAGMA quick_check").fetchone()
    quick=str(check[0]) if check else "missing"
    row=conn.execute("SELECT COUNT(*), MIN(seq), MAX(seq) FROM messages").fetchone()
    count=int(row[0] or 0)
    first=int(row[1]) if row[1] is not None else None
    last=int(row[2]) if row[2] is not None else None
    meta=dict(conn.execute("SELECT key,value FROM meta").fetchall())
    local_next=conn.execute(
        "SELECT 1 FROM messages WHERE seq=? LIMIT 1",(observer_cursor+1,)
    ).fetchone() is not None
    row=conn.execute(
        "SELECT MIN(seq) FROM messages WHERE seq>?",(observer_cursor,)
    ).fetchone()
    local_first_after=int(row[0]) if row and row[0] is not None else None

    local_contiguous_end=observer_cursor
    expected=observer_cursor+1
    for (seq,) in conn.execute(
        "SELECT seq FROM messages WHERE seq>=? ORDER BY seq",(expected,)
    ):
        seq=int(seq)
        if seq != expected:
            break
        local_contiguous_end=seq
        expected+=1

    local_cursor=conn.execute(
        "SELECT seq FROM messages WHERE seq>? ORDER BY seq",(observer_cursor,)
    )
    local_iter=(int(row[0]) for row in local_cursor)
    local_current=next(local_iter,None)

    print(f"SNAPSHOT_QUICK_CHECK={safe(quick)}")
    print(f"SNAPSHOT_ROW_COUNT={count}")
    print(f"SNAPSHOT_FIRST_SEQ={first if first is not None else 'NONE'}")
    print(f"SNAPSHOT_LAST_SEQ={last if last is not None else 'NONE'}")
    print(f"SNAPSHOT_CAPTURE_CURSOR={safe(meta.get('capture_cursor','missing'))}")
    print(f"SNAPSHOT_LAST_SUCCESS_AT={safe(meta.get('last_success_at','missing'))}")
    last_error=safe(meta.get("last_error",""))
    print(f"SNAPSHOT_LAST_ERROR={last_error if last_error != 'missing' else 'NONE'}")
    raw_hole=meta.get("last_capture_hole")
    hole_from=hole_to="NONE"
    if raw_hole:
        try:
            hole=json.loads(raw_hole)
            if isinstance(hole,dict):
                if isinstance(hole.get("missing_from"),int):
                    hole_from=str(hole["missing_from"])
                if isinstance(hole.get("missing_to"),int):
                    hole_to=str(hole["missing_to"])
        except Exception:
            pass
    print(f"SNAPSHOT_LAST_CAPTURE_HOLE_FROM={hole_from}")
    print(f"SNAPSHOT_LAST_CAPTURE_HOLE_TO={hole_to}")
    print(f"ANALYSIS_OBSERVER_CURSOR={observer_cursor}")
    print("SNAPSHOT_HAS_CURSOR_NEXT="+("YES" if local_next else "NO"))
    print(f"SNAPSHOT_FIRST_AFTER_CURSOR={local_first_after if local_first_after is not None else 'NONE'}")
    print(f"SNAPSHOT_LOCAL_CONTIGUOUS_END={local_contiguous_end}")

    server_seqs=[]
    total_bytes=0
    invalid=0
    status="ERROR"
    error_kind="NONE"
    server_complete=False
    try:
        timeout=httpx.Timeout(30.0,connect=5.0,pool=5.0)
        with httpx.Client(timeout=timeout) as client:
            with client.stream("GET",f"{BASE_URL}/r/lobby/export") as response:
                status=str(response.status_code)
                response.raise_for_status()
                buf=b""
                for chunk in response.iter_bytes():
                    total_bytes+=len(chunk)
                    buf+=chunk
                    while b"\n" in buf:
                        raw,buf=buf.split(b"\n",1)
                        if not raw.strip():
                            continue
                        try:
                            item=json.loads(raw.decode("utf-8"))
                            seq=item.get("seq") if isinstance(item,dict) else None
                            if isinstance(seq,int):
                                server_seqs.append(seq)
                            else:
                                invalid+=1
                        except Exception:
                            invalid+=1
                    if len(buf) > 2*1024*1024:
                        raise RuntimeError("export_line_too_large")
                if buf.strip():
                    try:
                        item=json.loads(buf.decode("utf-8"))
                        seq=item.get("seq") if isinstance(item,dict) else None
                        if isinstance(seq,int):
                            server_seqs.append(seq)
                        else:
                            invalid+=1
                    except Exception:
                        invalid+=1
                server_complete=True
    except Exception as exc:
        error_kind=type(exc).__name__

    server_seqs=sorted(set(server_seqs))
    server_first=server_seqs[0] if server_seqs else None
    server_last=server_seqs[-1] if server_seqs else None
    authoritative_server_seqs=server_seqs if server_complete else []
    server_set=set(authoritative_server_seqs)
    server_next=(observer_cursor+1) in server_set

    print(f"SERVER_EXPORT_HTTP_STATUS={safe(status)}")
    print("SERVER_EXPORT_COMPLETE="+("YES" if server_complete else "NO"))
    print(f"SERVER_EXPORT_ERROR_KIND={safe(error_kind)}")
    print(f"SERVER_EXPORT_BYTES={total_bytes}")
    print(f"SERVER_EXPORT_LIMIT_BYTES={export_limit}")
    print("SERVER_EXPORT_EXCEEDS_12MIB="+("YES" if total_bytes>export_limit else "NO"))
    print(f"SERVER_EXPORT_VALID_SEQ_COUNT={len(server_seqs)}")
    print(f"SERVER_EXPORT_INVALID_ROW_COUNT={invalid}")
    print(f"SERVER_EXPORT_FIRST_SEQ={server_first if server_first is not None else 'NONE'}")
    print(f"SERVER_EXPORT_LAST_SEQ={server_last if server_last is not None else 'NONE'}")
    print("SERVER_HAS_CURSOR_NEXT="+("YES" if server_next else "NO"))

    server_iter=iter(authoritative_server_seqs)
    server_current=next(server_iter,None)
    expected=observer_cursor+1
    union_end=observer_cursor
    while True:
        while local_current is not None and local_current < expected:
            local_current=next(local_iter,None)
        while server_current is not None and server_current < expected:
            server_current=next(server_iter,None)
        if local_current == expected:
            union_end=expected
            expected+=1
            local_current=next(local_iter,None)
            if server_current == union_end:
                server_current=next(server_iter,None)
            continue
        if server_current == expected:
            union_end=expected
            expected+=1
            server_current=next(server_iter,None)
            continue
        break

    print("UNION_HAS_CURSOR_NEXT="+("YES" if union_end>=observer_cursor+1 else "NO"))
    print(f"UNION_CONTIGUOUS_END={union_end}")
    print(f"UNION_RECOVERABLE_MESSAGES={max(0,union_end-observer_cursor)}")
    print(f"UNION_FIRST_MISSING_SEQ={union_end+1}")

    preserve=(
        (not local_next and local_first_after is not None)
        or (not local_next and not server_next)
        or bool(str(meta.get("last_error","")).strip())
    )
    print("PRESERVE_RECOMMENDED="+("YES" if preserve else "NO"))
finally:
    conn.close()
PY
then
  echo 'ISSUE390_CAPSNAPV1=STOP:snapshot_or_export_analysis_failed'
  exit 0
fi

cat "$ANALYSIS"

PRESERVE=$(awk -F= '$1=="PRESERVE_RECOMMENDED"{print $2}' "$ANALYSIS" | tail -1)
if [[ "$PRESERVE" == YES ]]; then
  install -d -m 700 -o root -g root "$FORENSICS_DIR"
  STAMP=$(date -u '+%Y%m%dT%H%M%SZ')
  PERSISTED_PATH=$FORENSICS_DIR/issue390-lobby-capture-$STAMP.sqlite3
  if ! install -m 600 -o root -g root "$SNAPSHOT" "$PERSISTED_PATH"; then
    echo 'ISSUE390_CAPSNAPV1=STOP:forensic_preservation_failed'
    exit 0
  fi
  PERSISTED_SHA256=$(sha256sum "$PERSISTED_PATH" | awk '{print $1}')
  PERSISTED_BYTES=$(stat -c %s "$PERSISTED_PATH" 2>/dev/null || echo 0)
  echo 'FORENSIC_SNAPSHOT_PRESERVED=YES'
  echo "FORENSIC_SNAPSHOT_PATH=$PERSISTED_PATH"
  echo "FORENSIC_SNAPSHOT_BYTES=$PERSISTED_BYTES"
  echo "FORENSIC_SNAPSHOT_SHA256=$PERSISTED_SHA256"
else
  echo 'FORENSIC_SNAPSHOT_PRESERVED=NO'
fi

POST_STATE=$(read_core)
printf '%s\n' "$POST_STATE" | sed 's/^/POST_/'
POST_EVENTS=$(printf '%s\n' "$POST_STATE" | awk -F= '$1=="CORE_EVENTS"{print $2}')
POST_MESSAGES=$(printf '%s\n' "$POST_STATE" | awk -F= '$1=="CORE_MESSAGES"{print $2}')
POST_CURSOR=$(printf '%s\n' "$POST_STATE" | awk -F= '$1=="LOBBY_CURSOR"{print $2}')

echo '--- PRESSURE T1 ---'
proc_sample T1

if [[ "$POST_EVENTS" != "$EXPECTED_CORE_EVENTS" || "$POST_MESSAGES" != "$EXPECTED_CORE_MESSAGES" ]]; then
  echo 'POST_STATE=CORE_MOVED_DURING_PROBE'
else
  echo 'POST_STATE=CORE_STABLE'
fi
if [[ "$POST_CURSOR" == "$MID_CURSOR" ]]; then
  echo 'POST_LOBBY_PROGRESS=STALLED_DURING_PROBE'
else
  echo 'POST_LOBBY_PROGRESS=MOVED_DURING_PROBE'
fi

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
echo 'NETWORK_WRITE=NO'
echo 'NETWORK_READ=YES_GET_ONLY'
echo 'TECHNOCORE_WRITE=NO'
echo 'RAW_MESSAGE_OUTPUT=NO'
echo 'DID_OUTPUT=NO'
echo 'PERSISTENT_MUTATION_SCOPE=ROOT_ONLY_FORENSIC_SNAPSHOT_IF_RECOMMENDED'
echo '=== ISSUE390_CAPSNAPV1=COMPLETE ==='
echo 'DO_NOT_RERUN=YES'
exit 0
