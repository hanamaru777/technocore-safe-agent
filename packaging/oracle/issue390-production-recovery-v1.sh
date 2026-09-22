#!/usr/bin/env bash
# Issue #390 / #364: exact Production recovery rollout.
# Fast-forward accepted Production repo to the audited target, restart Resident only,
# and prove continuity/resource gates. Capture/Signer/Discord remain untouched.
set -u
set -o pipefail
umask 077

APP=/opt/technocore-safe-agent
APP_PY=$APP/.venv/bin/python
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
OBHB=$STATE/observer/observer-heartbeat.json
RESHB=$STATE/observer/resident-heartbeat.json

PRE=b7bf27dbaa605971d340aa926fdffc17489c3afe
TARGET=473e4f73426069c682cfd716f611e0bfad7d4fe8
EXPECTED_CORE_EVENTS=119
EXPECTED_CORE_MESSAGES=5497275

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIGN=technocore-safe-agent-signer.service
DISC=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service

EXPECTED_RES_PID=1868797
EXPECTED_RES_RESTARTS=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0
EXPECTED_SIGN_PID=1539554
EXPECTED_SIGN_RESTARTS=1
EXPECTED_DISC_PID=1957840
EXPECTED_DISC_RESTARTS=0

MIN_MEM_AVAILABLE_BYTES=$((96 * 1024 * 1024))

EXPECTED_PRE_CAPTURE_BLOB=56e2d142d1df78fe0b26577ab9abca24f111bbf0
EXPECTED_PRE_BRIDGE_BLOB=55d4c17b1b2a07d3f7740836d4d149c727ef0bcd
EXPECTED_PRE_ISOLATION_BLOB=12d7a7b139cb631203b11b7e6b20c1887ec9a3cc
EXPECTED_TARGET_CAPTURE_BLOB=285a95c539611c87768634cba1d45cdb442beb14
EXPECTED_TARGET_BRIDGE_BLOB=b96f315dd6bd5c2baa0f5db35acd85479e52e993
EXPECTED_TARGET_ISOLATION_BLOB=6ac40ac32108e141320c1d87d5ce0268e71e986b

echo '=== ISSUE390 PRODUCTION RECOVERY V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'PROD390V1=STOP:not_root'
  exit 0
fi

for cmd in git systemctl awk sort comm sleep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "PROD390V1=STOP:missing_command:$cmd"
    exit 0
  fi
done

for path in "$APP/.git" "$APP_PY" "$OBS" "$OBHB" "$RESHB"; do
  if [[ ! -e "$path" ]]; then
    echo 'PROD390V1=STOP:required_path_missing'
    exit 0
  fi
done

service_fields() {
  local label=$1 unit=$2
  local active pid nr result
  active=$(systemctl is-active "$unit" 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active PID=$pid NRESTARTS=$nr RESULT=$result"
}

require_service() {
  local label=$1 unit=$2 expected_pid=$3 expected_nr=$4
  local active pid nr result
  active=$(systemctl is-active "$unit" 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active PID=$pid NRESTARTS=$nr RESULT=$result"
  if [[ "$active" != active || "$pid" != "$expected_pid" || "$nr" != "$expected_nr" || "$result" != success ]]; then
    echo "PROD390V1=STOP:service_baseline_changed:$label"
    exit 0
  fi
}

read_state() {
  "$APP_PY" - "$OBS" "$OBHB" "$RESHB" <<'PY'
import json
import pathlib
import sys
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
print(f"OBSERVER_HEARTBEAT_UPDATED_AT={obhb.get('updated_at','missing')}")
print(f"OBSERVER_HEARTBEAT_STATUS={obhb.get('status','missing')}")
print(f"OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"RESIDENT_HEARTBEAT_UPDATED_AT={reshb.get('updated_at','missing')}")
print(f"RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")
PY
}

pressure() {
  local tag=$1
  "$APP_PY" - "$tag" <<'PY'
import pathlib
import re
import sys

tag=sys.argv[1]

def clean(v):
    return re.sub(r"[^A-Za-z0-9_.:/=-]", "", str(v))[:120] or "unknown"

mem={}
for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
    if ":" not in line:
        continue
    key,val=line.split(":",1)
    if key in {"MemTotal","MemAvailable","SwapTotal","SwapFree","AnonPages","Dirty","Writeback"}:
        parts=val.strip().split()
        mem[key]=int(parts[0])*1024 if parts else 0
for key in ("MemTotal","MemAvailable","SwapTotal","SwapFree","AnonPages","Dirty","Writeback"):
    print(f"{tag}_MEM_{key.upper()}_BYTES={mem.get(key,0)}")
for kind in ("io","memory"):
    p=pathlib.Path(f"/proc/pressure/{kind}")
    if not p.exists():
        continue
    for idx,line in enumerate(p.read_text("utf-8").splitlines()[:2],1):
        print(f"{tag}_PSI_{kind.upper()}_{idx}={clean(line)}")
PY
}

process_tree() {
  local tag=$1 root=$2
  "$APP_PY" - "$tag" "$root" <<'PY'
import os
import pathlib
import re
import sys

tag=sys.argv[1]
root=int(sys.argv[2])
page=os.sysconf("SC_PAGE_SIZE")

def clean(v):
    return re.sub(r"[^A-Za-z0-9_.:/=-]", "", str(v))[:80] or "unknown"

def text(path):
    try:
        return pathlib.Path(path).read_text("utf-8",errors="replace")
    except Exception:
        return ""

def swap_bytes(pid):
    for line in text(f"/proc/{pid}/status").splitlines():
        if line.startswith("VmSwap:"):
            parts=line.split()
            return int(parts[1])*1024 if len(parts)>1 else 0
    return 0

procs={}
children={}
for entry in pathlib.Path("/proc").iterdir():
    if not entry.name.isdigit():
        continue
    pid=int(entry.name)
    raw=text(entry/"stat")
    if not raw:
        continue
    right=raw.rfind(")")
    if right < 0:
        continue
    rest=raw[right+2:].split()
    if len(rest)<22:
        continue
    try:
        ppid=int(rest[1])
        state=rest[0]
        ticks=int(rest[11])+int(rest[12])
        rss=int(rest[21])*page
    except Exception:
        continue
    comm=clean(raw[raw.find("(")+1:right])
    wchan=clean(text(entry/"wchan").strip())
    procs[pid]=(ppid,state,ticks,rss,swap_bytes(pid),comm,wchan)
    children.setdefault(ppid,[]).append(pid)

seen=set()
stack=[root]
while stack:
    parent=stack.pop()
    for child in children.get(parent,[]):
        if child not in seen:
            seen.add(child)
            stack.append(child)

for pid in [root]+sorted(seen):
    if pid not in procs:
        continue
    ppid,state,ticks,rss,swap,comm,wchan=procs[pid]
    role="MAIN" if pid==root else "CHILD"
    print(
        f"{tag}_RESIDENT_{role} pid={pid} ppid={ppid} comm={comm} "
        f"state={state} cpu_ticks={ticks} rss_bytes={rss} swap_bytes={swap} wchan={wchan}"
    )
PY
}

echo '--- PRE REPO ---'
HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
BRANCH=$(git -C "$APP" branch --show-current 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "PRE_HEAD=$HEAD"
echo "PRE_BRANCH=$BRANCH"
if [[ -z "$WORKTREE" ]]; then echo 'PRE_WORKTREE_CLEAN=YES'; else echo 'PRE_WORKTREE_CLEAN=NO'; fi
if [[ "$HEAD" != "$PRE" || "$BRANCH" != main || -n "$WORKTREE" ]]; then
  echo 'PROD390V1=STOP:repo_baseline_changed'
  exit 0
fi

echo '--- PRE SERVICES ---'
require_service RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS"
require_service CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"
require_service SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS"
require_service DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS"
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
if [[ "$META_ACTIVE" != active || "$META_RESULT" != success ]]; then
  echo 'PROD390V1=STOP:metadata_block_not_healthy'
  exit 0
fi

echo '--- PRE CONTINUITY ---'
PRE_STATE=$(read_state)
printf '%s\n' "$PRE_STATE" | sed 's/^/PRE_/'
PRE_CORE_EVENTS=$(printf '%s\n' "$PRE_STATE" | awk -F= '$1=="CORE_EVENTS"{print $2}')
PRE_CORE_MESSAGES=$(printf '%s\n' "$PRE_STATE" | awk -F= '$1=="CORE_MESSAGES"{print $2}')
PRE_CURSOR=$(printf '%s\n' "$PRE_STATE" | awk -F= '$1=="LOBBY_CURSOR"{print $2}')
PRE_OBS_UPDATED=$(printf '%s\n' "$PRE_STATE" | awk -F= '$1=="OBSERVER_UPDATED_AT"{print $2}')
PRE_OBHB_UPDATED=$(printf '%s\n' "$PRE_STATE" | awk -F= '$1=="OBSERVER_HEARTBEAT_UPDATED_AT"{print $2}')
if [[ "$PRE_CORE_EVENTS" != "$EXPECTED_CORE_EVENTS" || "$PRE_CORE_MESSAGES" != "$EXPECTED_CORE_MESSAGES" ]]; then
  echo 'PROD390V1=STOP:core_moved_again'
  exit 0
fi

pressure PRE
PRE_MEM=$("$APP_PY" - <<'PY'
import pathlib
for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
    if line.startswith("MemAvailable:"):
        print(int(line.split()[1])*1024)
        break
PY
)
echo "PRE_MEM_AVAILABLE_GATE=$PRE_MEM"
if [[ -z "$PRE_MEM" || "$PRE_MEM" -lt "$MIN_MEM_AVAILABLE_BYTES" ]]; then
  echo 'PROD390V1=STOP:mem_too_low_for_restart'
  exit 0
fi
process_tree PRE "$EXPECTED_RES_PID"

echo '--- TARGET FETCH / AUTHORITY ---'
if ! git -C "$APP" fetch --quiet origin main; then
  echo 'PROD390V1=STOP:fetch_failed'
  exit 0
fi
ORIGIN_MAIN=$(git -C "$APP" rev-parse origin/main 2>/dev/null || true)
echo "ORIGIN_MAIN=$ORIGIN_MAIN"
if [[ "$ORIGIN_MAIN" != "$TARGET" ]]; then
  echo 'PROD390V1=STOP:origin_main_moved'
  exit 0
fi
if ! git -C "$APP" merge-base --is-ancestor "$PRE" "$TARGET"; then
  echo 'PROD390V1=STOP:target_not_ff_descendant'
  exit 0
fi

EXPECTED_DIFF=$(cat <<'EOF'
packaging/oracle/README.md
packaging/oracle/block-technocore-metadata.sh
packaging/oracle/oci-cloud-agent-diagnostic.sh
src/flop_agent/observer_lobby_capture.py
src/flop_agent/observer_lobby_startup_hole_bridge.py
src/flop_agent/observer_resident_isolation.py
tests/test_metadata_imds_isolation.py
tests/test_observer_lobby_capture.py
tests/test_observer_lobby_startup_hole_bridge.py
tests/test_observer_resident_isolation.py
tests/test_oci_cloud_agent_diagnostic.py
EOF
)
ACTUAL_DIFF=$(git -C "$APP" diff --name-only "$PRE" "$TARGET" | sort)
if [[ "$ACTUAL_DIFF" != "$(printf '%s\n' "$EXPECTED_DIFF" | sort)" ]]; then
  echo 'PROD390V1=STOP:unexpected_target_diff'
  exit 0
fi
echo 'TARGET_DIFF=EXPECTED'

check_blob() {
  local rev=$1 path=$2 expected=$3 label=$4
  local actual
  actual=$(git -C "$APP" rev-parse "$rev:$path" 2>/dev/null || true)
  echo "BLOB_$label=$actual"
  if [[ "$actual" != "$expected" ]]; then
    echo "PROD390V1=STOP:blob_mismatch:$label"
    exit 0
  fi
}
check_blob "$PRE" src/flop_agent/observer_lobby_capture.py "$EXPECTED_PRE_CAPTURE_BLOB" PRE_CAPTURE
check_blob "$PRE" src/flop_agent/observer_lobby_startup_hole_bridge.py "$EXPECTED_PRE_BRIDGE_BLOB" PRE_BRIDGE
check_blob "$PRE" src/flop_agent/observer_resident_isolation.py "$EXPECTED_PRE_ISOLATION_BLOB" PRE_ISOLATION
check_blob "$TARGET" src/flop_agent/observer_lobby_capture.py "$EXPECTED_TARGET_CAPTURE_BLOB" TARGET_CAPTURE
check_blob "$TARGET" src/flop_agent/observer_lobby_startup_hole_bridge.py "$EXPECTED_TARGET_BRIDGE_BLOB" TARGET_BRIDGE
check_blob "$TARGET" src/flop_agent/observer_resident_isolation.py "$EXPECTED_TARGET_ISOLATION_BLOB" TARGET_ISOLATION

echo '--- FAST-FORWARD ---'
if ! git -C "$APP" merge --ff-only "$TARGET"; then
  echo 'PROD390V1=STOP:ff_failed'
  exit 0
fi
POST_FF_HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
POST_FF_WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "POST_FF_HEAD=$POST_FF_HEAD"
if [[ -z "$POST_FF_WORKTREE" ]]; then echo 'POST_FF_WORKTREE_CLEAN=YES'; else echo 'POST_FF_WORKTREE_CLEAN=NO'; fi
if [[ "$POST_FF_HEAD" != "$TARGET" || -n "$POST_FF_WORKTREE" ]]; then
  git -C "$APP" reset --hard "$PRE" >/dev/null 2>&1 || true
  echo 'PRE_RESTART_ROLLBACK=ATTEMPTED'
  echo 'PROD390V1=STOP:post_ff_repo_invalid'
  exit 0
fi

echo '--- TARGET LOCAL SMOKE ---'
if ! "$APP_PY" -m py_compile \
  "$APP/src/flop_agent/observer_lobby_capture.py" \
  "$APP/src/flop_agent/observer_lobby_startup_hole_bridge.py" \
  "$APP/src/flop_agent/observer_resident_isolation.py"; then
  git -C "$APP" reset --hard "$PRE" >/dev/null 2>&1 || true
  echo 'PRE_RESTART_ROLLBACK=COMPLETE'
  echo 'PROD390V1=STOP:py_compile_failed'
  exit 0
fi

if ! PYTHONPATH="$APP/src" "$APP_PY" - <<'PY'
from flop_agent import observer_lobby_capture as capture
from flop_agent import observer_lobby_startup_hole_bridge as bridge
from flop_agent import observer_resident_isolation as isolation

assert callable(capture.first_available_seq)
metrics=bridge._metrics({"metrics": {}})
assert "lobby_startup_bridge_local_suffix_handoffs" in metrics
assert "lobby_startup_bridge_avoided_unrecoverable_messages" in metrics
assert isolation._MIN_MEM_AVAILABLE_BYTES == 256 * 1024 * 1024
assert isolation._MAX_MEMORY_FULL_AVG10 == 5.0
assert isolation._MAX_IO_FULL_AVG10 == 10.0
print("TARGET_LOCAL_SMOKE=PASS")
print("PRESSURE_GUARD_CURRENT="+("ON" if isolation._maintenance_pressure_high() else "OFF"))
PY
then
  git -C "$APP" reset --hard "$PRE" >/dev/null 2>&1 || true
  echo 'PRE_RESTART_ROLLBACK=COMPLETE'
  echo 'PROD390V1=STOP:target_smoke_failed'
  exit 0
fi

# Re-check continuity immediately before the only service mutation.
JUST_BEFORE=$(read_state)
JB_EVENTS=$(printf '%s\n' "$JUST_BEFORE" | awk -F= '$1=="CORE_EVENTS"{print $2}')
JB_MESSAGES=$(printf '%s\n' "$JUST_BEFORE" | awk -F= '$1=="CORE_MESSAGES"{print $2}')
echo "JUST_BEFORE_CORE=$JB_EVENTS/$JB_MESSAGES"
if [[ "$JB_EVENTS" != "$EXPECTED_CORE_EVENTS" || "$JB_MESSAGES" != "$EXPECTED_CORE_MESSAGES" ]]; then
  git -C "$APP" reset --hard "$PRE" >/dev/null 2>&1 || true
  echo 'PRE_RESTART_ROLLBACK=COMPLETE'
  echo 'PROD390V1=STOP:core_moved_before_restart'
  exit 0
fi
require_service CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS"
require_service SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS"
require_service DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS"

echo '--- RESIDENT-ONLY RESTART ---'
if ! systemctl restart "$RES"; then
  echo 'PROD390V1=STOP:resident_restart_command_failed'
  echo 'REPO_REMAINS_TARGET=YES'
  exit 0
fi
echo 'RESIDENT_RESTART_COMMAND=PASS'

sleep 3

NEW_RES_PID=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
NEW_RES_NR=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
NEW_RES_ACTIVE=$(systemctl is-active "$RES" 2>/dev/null || true)
NEW_RES_RESULT=$(systemctl show "$RES" -p Result --value 2>/dev/null || true)
echo "POST_RESTART_RESIDENT ACTIVE=$NEW_RES_ACTIVE PID=$NEW_RES_PID NRESTARTS=$NEW_RES_NR RESULT=$NEW_RES_RESULT"
if [[ "$NEW_RES_ACTIVE" != active || -z "$NEW_RES_PID" || "$NEW_RES_PID" == 0 || "$NEW_RES_PID" == "$EXPECTED_RES_PID" ]]; then
  echo 'PROD390V1=STOP:resident_not_restarted_cleanly'
  echo 'REPO_REMAINS_TARGET=YES'
  exit 0
fi
if [[ "$NEW_RES_NR" != "$EXPECTED_RES_RESTARTS" || "$NEW_RES_RESULT" != success ]]; then
  echo 'PROD390V1=STOP:resident_restart_counter_or_result_changed'
  echo 'REPO_REMAINS_TARGET=YES'
  exit 0
fi

POST_PROGRESS=NO
for step in 1 2 3 4 5 6 7 8; do
  sleep 5
  SNAP=$(read_state)
  EVENTS=$(printf '%s\n' "$SNAP" | awk -F= '$1=="CORE_EVENTS"{print $2}')
  MESSAGES=$(printf '%s\n' "$SNAP" | awk -F= '$1=="CORE_MESSAGES"{print $2}')
  CURSOR=$(printf '%s\n' "$SNAP" | awk -F= '$1=="LOBBY_CURSOR"{print $2}')
  UPDATED=$(printf '%s\n' "$SNAP" | awk -F= '$1=="OBSERVER_UPDATED_AT"{print $2}')
  OBHB_UPDATED=$(printf '%s\n' "$SNAP" | awk -F= '$1=="OBSERVER_HEARTBEAT_UPDATED_AT"{print $2}')
  echo "POST_SAMPLE_$step CORE=$EVENTS/$MESSAGES LOBBY_CURSOR=$CURSOR OBSERVER_UPDATED_AT=$UPDATED OBSERVER_HEARTBEAT_UPDATED_AT=$OBHB_UPDATED"
  if [[ "$EVENTS" != "$EXPECTED_CORE_EVENTS" || "$MESSAGES" != "$EXPECTED_CORE_MESSAGES" ]]; then
    echo 'PROD390V1=STOP:core_moved_after_restart'
    echo 'REPO_REMAINS_TARGET=YES'
    exit 0
  fi
  ACTIVE=$(systemctl is-active "$RES" 2>/dev/null || true)
  PID=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
  NR=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
  if [[ "$ACTIVE" != active || "$PID" != "$NEW_RES_PID" || "$NR" != "$EXPECTED_RES_RESTARTS" ]]; then
    echo 'PROD390V1=STOP:resident_unstable_after_restart'
    echo 'REPO_REMAINS_TARGET=YES'
    exit 0
  fi
  CAP_PID=$(systemctl show "$CAP" -p MainPID --value 2>/dev/null || true)
  CAP_NR=$(systemctl show "$CAP" -p NRestarts --value 2>/dev/null || true)
  if [[ "$CAP_PID" != "$EXPECTED_CAP_PID" || "$CAP_NR" != "$EXPECTED_CAP_RESTARTS" ]]; then
    echo 'PROD390V1=STOP:capture_changed_after_restart'
    echo 'REPO_REMAINS_TARGET=YES'
    exit 0
  fi
  if [[ "$UPDATED" != "$PRE_OBS_UPDATED" || "$OBHB_UPDATED" != "$PRE_OBHB_UPDATED" || "$CURSOR" != "$PRE_CURSOR" ]]; then
    POST_PROGRESS=YES
  fi
done

echo '--- POST ACCEPTANCE ---'
FINAL_HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
FINAL_BRANCH=$(git -C "$APP" branch --show-current 2>/dev/null || true)
FINAL_WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "FINAL_HEAD=$FINAL_HEAD"
echo "FINAL_BRANCH=$FINAL_BRANCH"
if [[ -z "$FINAL_WORKTREE" ]]; then echo 'FINAL_WORKTREE_CLEAN=YES'; else echo 'FINAL_WORKTREE_CLEAN=NO'; fi

service_fields RESIDENT "$RES"
service_fields CAPTURE "$CAP"
service_fields SIGNER "$SIGN"
service_fields DISCORD "$DISC"
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"

FINAL_STATE=$(read_state)
printf '%s\n' "$FINAL_STATE" | sed 's/^/FINAL_/'
pressure POST
process_tree POST "$NEW_RES_PID"
echo "POST_PROGRESS=$POST_PROGRESS"

FINAL_EVENTS=$(printf '%s\n' "$FINAL_STATE" | awk -F= '$1=="CORE_EVENTS"{print $2}')
FINAL_MESSAGES=$(printf '%s\n' "$FINAL_STATE" | awk -F= '$1=="CORE_MESSAGES"{print $2}')
FINAL_CAP_PID=$(systemctl show "$CAP" -p MainPID --value 2>/dev/null || true)
FINAL_CAP_NR=$(systemctl show "$CAP" -p NRestarts --value 2>/dev/null || true)
FINAL_SIGN_PID=$(systemctl show "$SIGN" -p MainPID --value 2>/dev/null || true)
FINAL_SIGN_NR=$(systemctl show "$SIGN" -p NRestarts --value 2>/dev/null || true)
FINAL_DISC_PID=$(systemctl show "$DISC" -p MainPID --value 2>/dev/null || true)
FINAL_DISC_NR=$(systemctl show "$DISC" -p NRestarts --value 2>/dev/null || true)

if [[ "$FINAL_HEAD" != "$TARGET" || "$FINAL_BRANCH" != main || -n "$FINAL_WORKTREE" ]]; then
  echo 'PROD390V1=STOP:final_repo_invalid'
  exit 0
fi
if [[ "$FINAL_EVENTS" != "$EXPECTED_CORE_EVENTS" || "$FINAL_MESSAGES" != "$EXPECTED_CORE_MESSAGES" ]]; then
  echo 'PROD390V1=STOP:final_core_changed'
  exit 0
fi
if [[ "$FINAL_CAP_PID" != "$EXPECTED_CAP_PID" || "$FINAL_CAP_NR" != "$EXPECTED_CAP_RESTARTS" ]]; then
  echo 'PROD390V1=STOP:final_capture_changed'
  exit 0
fi
if [[ "$FINAL_SIGN_PID" != "$EXPECTED_SIGN_PID" || "$FINAL_SIGN_NR" != "$EXPECTED_SIGN_RESTARTS" ]]; then
  echo 'PROD390V1=STOP:final_signer_changed'
  exit 0
fi
if [[ "$FINAL_DISC_PID" != "$EXPECTED_DISC_PID" || "$FINAL_DISC_NR" != "$EXPECTED_DISC_RESTARTS" ]]; then
  echo 'PROD390V1=STOP:final_discord_changed'
  exit 0
fi
if [[ "$META_ACTIVE" != active || "$META_RESULT" != success ]]; then
  echo 'PROD390V1=STOP:final_metadata_block_changed'
  exit 0
fi
if [[ "$POST_PROGRESS" != YES ]]; then
  echo 'PROD390V1=STOP:no_observer_progress_after_restart'
  echo 'REPO_REMAINS_TARGET=YES'
  exit 0
fi

echo 'APPLICATION_REPO_FAST_FORWARD=YES'
echo 'RESIDENT_RESTART=YES_EXACTLY_ONCE'
echo 'CAPTURE_RESTART=NO'
echo 'SIGNER_RESTART=NO'
echo 'DISCORD_RESTART=NO'
echo 'METADATA_BLOCK_RESTART=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'TECHNOCORE_WRITE=NO'
echo 'SYNTHETIC_ACTIVITY=NO'
echo '=== PROD390V1=PASS ==='
echo 'DO_NOT_RERUN=YES'
exit 0
