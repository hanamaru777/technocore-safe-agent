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
EXPECTED_CORE_EVENTS=119
EXPECTED_CORE_MESSAGES=5497275

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIGN=technocore-safe-agent-signer.service
DISC=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service

TMP=$(mktemp /tmp/issue390-crashloop.XXXXXX)
trap 'rm -f -- "$TMP"' EXIT

echo '=== ISSUE390 RESIDENT CRASHLOOP FORENSIC V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'ISSUE390_CRASHV1=STOP:not_root'
  exit 0
fi

for path in "$APP/.git" "$APP_PY" "$OBS" "$OBHB" "$RESHB"; do
  if [[ ! -e "$path" ]]; then
    echo 'ISSUE390_CRASHV1=STOP:required_path_missing'
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
  echo 'ISSUE390_CRASHV1=STOP:repo_not_exact_target'
  exit 0
fi

sample_one() {
  local tag=$1
  local label=$2
  local unit=$3
  local active sub pid nr result code status started exited
  active=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  code=$(systemctl show "$unit" -p ExecMainCode --value 2>/dev/null || true)
  status=$(systemctl show "$unit" -p ExecMainStatus --value 2>/dev/null || true)
  started=$(systemctl show "$unit" -p ExecMainStartTimestamp --value 2>/dev/null || true)
  exited=$(systemctl show "$unit" -p ExecMainExitTimestamp --value 2>/dev/null || true)
  echo "$tag SERVICE=$label ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result EXEC_CODE=$code EXEC_STATUS=$status START=$started EXIT=$exited"
}

sample_all() {
  local tag=$1
  sample_one "$tag" RESIDENT "$RES"
  sample_one "$tag" CAPTURE "$CAP"
  sample_one "$tag" SIGNER "$SIGN"
  sample_one "$tag" DISCORD "$DISC"
  sample_one "$tag" METADATA_BLOCK "$META"
}

echo '--- SERVICE SAMPLES ---'
sample_all T0
sleep 5
sample_all T5
sleep 5
sample_all T10

echo '--- CONTINUITY ---'
"$APP_PY" - "$OBS" "$OBHB" "$RESHB" "$EXPECTED_CORE_EVENTS" "$EXPECTED_CORE_MESSAGES" <<'PY'
import json
import pathlib
import sys
from datetime import UTC, datetime

state=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
obhb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
reshb=json.loads(pathlib.Path(sys.argv[3]).read_text("utf-8"))
metrics=state.get("metrics") or {}
cursors=state.get("cursors") or {}
events=int(metrics.get("unrecoverable_core_gap_events",0) or 0)
messages=int(metrics.get("unrecoverable_core_gap_messages",0) or 0)
expected=(int(sys.argv[4]),int(sys.argv[5]))

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

print(f"PROTECTED_CORE={events}/{messages}")
print("PROTECTED_CORE_MATCH_EXPECTED="+("YES" if (events,messages)==expected else "NO"))
print(f"LOBBY_CURSOR={int(cursors.get('lobby',0) or 0)}")
print(f"OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
print(f"OBSERVER_HEALTH={(state.get('health') or {}).get('current','missing')}")
print(f"OBSERVER_HEARTBEAT_STATUS={obhb.get('status','missing')}")
print(f"OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")
PY

echo '--- TARGET REFLOG ---'
git -C "$APP" reflog -n 12 --format='REFLOG=%H|%ct|%gs' HEAD 2>/dev/null \
  | sed -E 's#(merge|reset|pull|checkout|fast-forward|fastforward|commit|update|moving from)[^|]*#\1#g' \
  | head -12

echo '--- SANITIZED RESIDENT JOURNAL CLASSIFICATION ---'
journalctl -u "$RES" --since '30 minutes ago' --no-pager --output=cat >"$TMP" 2>/dev/null || true

"$APP_PY" - "$TMP" <<'PY'
import collections
import pathlib
import re
import sys

text=pathlib.Path(sys.argv[1]).read_text("utf-8",errors="replace")
lines=text.splitlines()

patterns={
    "TRACEBACK": r"Traceback \(most recent call last\):",
    "MEMORY_ERROR": r"\bMemoryError\b",
    "RUNTIME_ERROR": r"\bRuntimeError\b",
    "TYPE_ERROR": r"\bTypeError\b",
    "ATTRIBUTE_ERROR": r"\bAttributeError\b",
    "NAME_ERROR": r"\bNameError\b",
    "KEY_ERROR": r"\bKeyError\b",
    "OS_ERROR": r"\bOSError\b",
    "FILE_NOT_FOUND": r"\bFileNotFoundError\b",
    "PERMISSION_ERROR": r"\bPermissionError\b",
    "MODULE_NOT_FOUND": r"\bModuleNotFoundError\b",
    "IMPORT_ERROR": r"\bImportError\b",
    "SQLITE_OPERATIONAL": r"\bsqlite3\.OperationalError\b",
    "MAINTENANCE_EXIT": r"resident maintenance process exited unexpectedly",
    "EXPORT_TOO_LARGE": r"export_too_large|capture_export_too_large",
}
for label,pattern in patterns.items():
    print(f"JOURNAL_CLASS_{label}={len(re.findall(pattern,text))}")

frames=collections.Counter()
frame_re=re.compile(r'File "(/opt/technocore-safe-agent/[^"]+\.py)", line (\d+), in ([A-Za-z0-9_<>]+)')
for line in lines:
    m=frame_re.search(line)
    if not m:
        continue
    path=m.group(1).replace("/opt/technocore-safe-agent/","")
    frames[(path,m.group(2),m.group(3))]+=1

for idx,((path,line_no,func),count) in enumerate(frames.most_common(20),1):
    print(f"JOURNAL_FRAME idx={idx} path={path} line={line_no} func={func} count={count}")

safe_reasons=collections.Counter()
for pattern in (
    r"resident maintenance process exited unexpectedly: -?\d+",
    r"capture_export_too_large",
    r"export_too_large",
    r"invalid_export_order",
    r"snapshot_ended_before_local_resume",
    r"database is locked",
    r"disk I/O error",
    r"unable to open database file",
    r"no such table: [A-Za-z0-9_]+",
    r"can't start new thread",
    r"can't start new process",
):
    for m in re.finditer(pattern,text):
        safe_reasons[m.group(0)]+=1
for idx,(reason,count) in enumerate(safe_reasons.most_common(20),1):
    print(f"JOURNAL_SAFE_REASON idx={idx} reason={reason.replace(' ','_')} count={count}")

print(f"JOURNAL_TOTAL_LINES={len(lines)}")
PY

echo '--- LIGHTWEIGHT PRESSURE ---'
"$APP_PY" - <<'PY'
import pathlib
import re

def clean(v):
    return re.sub(r"[^A-Za-z0-9_.:/=-]", "", str(v))[:120] or "unknown"

for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
    if ":" not in line:
        continue
    key,val=line.split(":",1)
    if key in {"MemTotal","MemAvailable","SwapTotal","SwapFree","AnonPages","Dirty","Writeback"}:
        parts=val.strip().split()
        amount=int(parts[0])*1024 if parts else 0
        print(f"MEM_{key.upper()}_BYTES={amount}")
for kind in ("io","memory"):
    p=pathlib.Path(f"/proc/pressure/{kind}")
    if not p.exists():
        continue
    for idx,line in enumerate(p.read_text("utf-8").splitlines()[:2],1):
        print(f"PSI_{kind.upper()}_{idx}={clean(line)}")
PY

echo '--- SAFETY TAIL ---'
echo 'MUTATION_COMMANDS=NONE'
echo 'SERVICE_RESTART=NO'
echo 'PROCESS_SIGNAL=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'NETWORK_PROBE=NO'
echo 'RAW_JOURNAL_OUTPUT=NO'
echo 'RAW_CMDLINE_OUTPUT=NO'
echo 'PROCESS_ENV_OUTPUT=NO'
echo 'TECHNOCORE_WRITE=NO'
echo '=== ISSUE390_RESIDENT_CRASHLOOP_FORENSIC_V1=COMPLETE_READ_ONLY ==='
echo 'DO_NOT_RERUN=YES'
exit 0
