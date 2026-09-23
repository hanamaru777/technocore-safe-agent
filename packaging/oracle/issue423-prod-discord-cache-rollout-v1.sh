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

PRE=077d1e478363751bf5b73d810326f95f3a36b7a3
TARGET=576d06dae3550ca7f32b3857d17ff79e911be0d0
EXPECTED_CORE_EVENTS=120
EXPECTED_CORE_MESSAGES=5650166

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIGN=technocore-safe-agent-signer.service
DISC=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service

EXPECTED_RES_PID=2243415
EXPECTED_RES_RESTARTS=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0
EXPECTED_SIGN_PID=1539554
EXPECTED_SIGN_RESTARTS=1
EXPECTED_DISC_PID=1957840
EXPECTED_DISC_RESTARTS=0

DK=src/flop_agent/discord_knowledge.py
DR=src/flop_agent/discord_tclk_review.py
OW=src/flop_agent/observer_state_writer_isolation.py
TW=src/flop_agent/tclk_watch.py

PRE_DK=840f3bb30427b358ad7a56ba6738becb7b872e9c
PRE_DR=5e8cb7fc701bdab779431eebc422f6a5159293eb
PRE_OW=bb9f19a0bdbb1cd24bac77360f3b63aae56a2ada
PRE_TW=bc4c2629edd95af73ae7c3d481826a12c1a7163a

TARGET_DK=5e5cf8f72931c351740add75aa1719fd436fa288
TARGET_DR=fcf2a5bb8bedbdef6dc922e9e805e741ee6e9d0f
TARGET_OW=18d70de61c84d0e8b59d0de296d7b65d6d747f32
TARGET_TW=734b60aff2bf2a4e46a025c9e6a9a4aad9e1b714

echo '=== ISSUE423 PROD DISCORD REVISION CACHE ROLLOUT V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

stop_pre() {
  echo "PROD423CACHEV1=STOP:$1"
  exit 0
}

if [[ $EUID -ne 0 ]]; then stop_pre not_root; fi
for cmd in git systemctl stat runuser timeout sleep cut seq awk; do
  command -v "$cmd" >/dev/null 2>&1 || stop_pre "missing_command:$cmd"
done
[[ -x "$APP_PY" && -f "$OBS" && -f "$OBHB" && -f "$RESHB" ]] || stop_pre required_path_missing

HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
BRANCH=$(git -C "$APP" branch --show-current 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "PRE_HEAD=$HEAD"
echo "PRE_BRANCH=$BRANCH"
if [[ -z "$WORKTREE" ]]; then echo 'PRE_WORKTREE_CLEAN=YES'; else echo 'PRE_WORKTREE_CLEAN=NO'; fi
[[ "$HEAD" == "$PRE" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_pre repo_baseline_changed

service_exact() {
  local label=$1 unit=$2 expected_pid=$3 expected_nr=$4
  local active sub pid nr result
  active=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result"
  [[ "$active" == active && "$sub" == running && "$pid" == "$expected_pid" && "$nr" == "$expected_nr" && "$result" == success ]]
}

echo '--- PRE SERVICE GATES ---'
service_exact RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS" || stop_pre resident_baseline_changed
service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS" || stop_pre capture_baseline_changed
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS" || stop_pre signer_baseline_changed
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS" || stop_pre discord_baseline_changed
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || stop_pre metadata_block_changed

BASE=$("$APP_PY" - "$OBS" "$OBHB" <<'PY'
import json,pathlib,sys
from datetime import UTC,datetime
obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
hb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
m=obs.get("metrics") or {}; c=obs.get("cursors") or {}
def age(v):
    try:
        d=datetime.fromisoformat(v)
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:return -1.0
print(f"{int(m.get('unrecoverable_core_gap_events',0) or 0)}|{int(m.get('unrecoverable_core_gap_messages',0) or 0)}|{int(c.get('lobby',0) or 0)}|{obs.get('updated_at','missing')}|{age(hb.get('updated_at')):.1f}")
PY
)
BASE_EVENTS=$(printf '%s' "$BASE"|cut -d'|' -f1)
BASE_MESSAGES=$(printf '%s' "$BASE"|cut -d'|' -f2)
BASE_CURSOR=$(printf '%s' "$BASE"|cut -d'|' -f3)
BASE_UPDATED=$(printf '%s' "$BASE"|cut -d'|' -f4)
BASE_OBS_HB_AGE=$(printf '%s' "$BASE"|cut -d'|' -f5)
echo "PRE_PROTECTED_CORE=$BASE_EVENTS/$BASE_MESSAGES"
echo "PRE_LOBBY_CURSOR=$BASE_CURSOR"
echo "PRE_OBSERVER_UPDATED_AT=$BASE_UPDATED"
echo "PRE_OBSERVER_HEARTBEAT_AGE=$BASE_OBS_HB_AGE"
[[ "$BASE_EVENTS" == "$EXPECTED_CORE_EVENTS" && "$BASE_MESSAGES" == "$EXPECTED_CORE_MESSAGES" ]] || stop_pre protected_core_changed

check_file() {
  local rel=$1 expected=$2 phase=$3
  local path="$APP/$rel" blob mode owner group
  blob=$(git -C "$APP" hash-object "$path" 2>/dev/null || true)
  mode=$(stat -c '%a' "$path" 2>/dev/null || true)
  owner=$(stat -c '%U' "$path" 2>/dev/null || true)
  group=$(stat -c '%G' "$path" 2>/dev/null || true)
  echo "$phase FILE=$rel mode=$mode owner=$owner group=$group blob=$blob"
  [[ "$blob" == "$expected" && "$mode" == 644 && "$owner" == root && "$group" == root ]]
}

echo '--- PRE FILE GATES ---'
check_file "$DK" "$PRE_DK" PRE || stop_pre discord_knowledge_changed
check_file "$DR" "$PRE_DR" PRE || stop_pre discord_review_changed
check_file "$OW" "$PRE_OW" PRE || stop_pre observer_writer_changed
check_file "$TW" "$PRE_TW" PRE || stop_pre tclk_watch_changed

echo '--- FETCH / EXACT TARGET ---'
git -C "$APP" fetch --no-tags origin main || stop_pre fetch_failed
REMOTE_MAIN=$(git -C "$APP" rev-parse origin/main 2>/dev/null || true)
echo "REMOTE_MAIN=$REMOTE_MAIN"
[[ "$REMOTE_MAIN" == "$TARGET" ]] || stop_pre remote_main_moved
git -C "$APP" merge-base --is-ancestor "$PRE" "$TARGET" || stop_pre target_not_descendant

echo '--- FAST-FORWARD TARGET ---'
git -C "$APP" merge --ff-only "$TARGET" || { echo 'PROD423CACHEV1=STOP:ff_only_failed'; exit 0; }
POST_HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
echo "POST_HEAD=$POST_HEAD"
[[ "$POST_HEAD" == "$TARGET" ]] || { echo 'PROD423CACHEV1=STOP:post_head_wrong'; echo 'TARGET_MAY_BE_PARTIALLY_APPLIED=YES'; exit 0; }

chmod 0644 "$APP/$DK" "$APP/$DR" "$APP/$OW" "$APP/$TW"

echo '--- POST FILE VERIFY ---'
check_file "$DK" "$TARGET_DK" POST || { echo 'PROD423CACHEV1=STOP:discord_knowledge_post_invalid'; exit 0; }
check_file "$DR" "$TARGET_DR" POST || { echo 'PROD423CACHEV1=STOP:discord_review_post_invalid'; exit 0; }
check_file "$OW" "$TARGET_OW" POST || { echo 'PROD423CACHEV1=STOP:observer_writer_post_invalid'; exit 0; }
check_file "$TW" "$TARGET_TW" POST || { echo 'PROD423CACHEV1=STOP:tclk_watch_post_invalid'; exit 0; }

POST_WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
if [[ -z "$POST_WORKTREE" ]]; then echo 'POST_WORKTREE_CLEAN=YES'; else echo 'POST_WORKTREE_CLEAN=NO'; fi
[[ -z "$POST_WORKTREE" ]] || { echo 'PROD423CACHEV1=STOP:worktree_dirty_after_deploy'; exit 0; }

echo '--- IMPORT SMOKE AS SERVICE USER ---'
if ! runuser -u technocore -- env FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" PYTHONDONTWRITEBYTECODE=1 "$APP_PY" - <<'PY'
from flop_agent import discord_knowledge, discord_tclk_review, observer_state_writer_isolation, tclk_watch
assert callable(discord_knowledge._periodic_tclk_state)
assert callable(tclk_watch.tclk_revision)
assert callable(observer_state_writer_isolation._serialize_snapshot)
print("IMPORT_SMOKE=PASS")
PY
then
  echo 'PROD423CACHEV1=STOP:import_smoke_failed'
  exit 0
fi

echo '--- RESTART RESIDENT ONLY ---'
timeout 120 systemctl restart "$RES"
RC=$?
echo "RESIDENT_RESTART_COMMAND_RC=$RC"
[[ "$RC" == 0 ]] || { echo 'PROD423CACHEV1=STOP:resident_restart_failed'; echo 'TARGET_REMAINS_DEPLOYED=YES'; exit 0; }

NEW_RES_PID=
for i in $(seq 1 30); do
  active=$(systemctl show "$RES" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$RES" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$RES" -p Result --value 2>/dev/null || true)
  echo "RES_START_$i ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result"
  if [[ "$active" == active && "$sub" == running && "$pid" =~ ^[1-9][0-9]*$ && "$pid" != "$EXPECTED_RES_PID" && "$nr" == 0 && "$result" == success ]]; then
    NEW_RES_PID=$pid
    break
  fi
  sleep 2
done
[[ -n "$NEW_RES_PID" ]] || { echo 'PROD423CACHEV1=STOP:resident_not_recovered'; echo 'TARGET_REMAINS_DEPLOYED=YES'; exit 0; }

echo '--- WAIT FOR NEW OBSERVER HEARTBEAT REVISION ---'
REVISION=
for i in $(seq 1 60); do
  REVISION=$("$APP_PY" - "$OBHB" <<'PY'
import json,pathlib,sys
try:
    value=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8")).get("tclk_revision")
    print(value if type(value) is int and value >= 0 else "")
except Exception:
    print("")
PY
)
  if [[ "$REVISION" =~ ^[0-9]+$ ]]; then
    echo "OBSERVER_TCLK_REVISION=$REVISION"
    break
  fi
  sleep 2
done
[[ "$REVISION" =~ ^[0-9]+$ ]] || { echo 'PROD423CACHEV1=STOP:tclk_revision_not_emitted'; echo 'TARGET_REMAINS_DEPLOYED=YES'; exit 0; }

echo '--- RESTART DISCORD ONLY ---'
timeout 120 systemctl restart "$DISC"
RC=$?
echo "DISCORD_RESTART_COMMAND_RC=$RC"
[[ "$RC" == 0 ]] || { echo 'PROD423CACHEV1=STOP:discord_restart_failed'; echo 'TARGET_REMAINS_DEPLOYED=YES'; exit 0; }

NEW_DISC_PID=
for i in $(seq 1 30); do
  active=$(systemctl show "$DISC" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$DISC" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$DISC" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$DISC" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$DISC" -p Result --value 2>/dev/null || true)
  echo "DISC_START_$i ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result"
  if [[ "$active" == active && "$sub" == running && "$pid" =~ ^[1-9][0-9]*$ && "$pid" != "$EXPECTED_DISC_PID" && "$nr" == 0 && "$result" == success ]]; then
    NEW_DISC_PID=$pid
    break
  fi
  sleep 2
done
[[ -n "$NEW_DISC_PID" ]] || { echo 'PROD423CACHEV1=STOP:discord_not_recovered'; echo 'TARGET_REMAINS_DEPLOYED=YES'; exit 0; }

echo '--- WARMUP 60S ---'
sleep 60

sample() {
  local label=$1
  echo "--- $label ---"
  "$APP_PY" - "$label" "$NEW_RES_PID" "$NEW_DISC_PID" "$OBS" "$OBHB" "$RESHB" <<'PY'
import json,pathlib,re,sys
from datetime import UTC,datetime
label,res_pid_s,disc_pid_s,obs_s,obhb_s,reshb_s=sys.argv[1:]
def age(v):
    try:
        d=datetime.fromisoformat(v)
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:return -1.0
def proc(pid):
    status={}
    try:
        for line in pathlib.Path(f"/proc/{pid}/status").read_text("utf-8").splitlines():
            if ":" in line:
                k,v=line.split(":",1);status[k]=v.strip()
    except OSError:
        return {"rss":-1,"swap":-1,"majflt":-1,"rbytes":-1,"wbytes":-1,"state":"MISSING"}
    rss=int(status.get("VmRSS","-1 kB").split()[0])*1024
    swap=int(status.get("VmSwap","-1 kB").split()[0])*1024
    state=status.get("State","MISSING").split()[0]
    try:majflt=int(pathlib.Path(f"/proc/{pid}/stat").read_text("utf-8").split()[11])
    except Exception:majflt=-1
    rbytes=wbytes=-1
    try:
        for line in pathlib.Path(f"/proc/{pid}/io").read_text("utf-8").splitlines():
            if line.startswith("read_bytes:"):rbytes=int(line.split(":",1)[1])
            elif line.startswith("write_bytes:"):wbytes=int(line.split(":",1)[1])
    except Exception:pass
    return {"rss":rss,"swap":swap,"majflt":majflt,"rbytes":rbytes,"wbytes":wbytes,"state":state}
obs=json.loads(pathlib.Path(obs_s).read_text("utf-8"))
obhb=json.loads(pathlib.Path(obhb_s).read_text("utf-8"))
reshb=json.loads(pathlib.Path(reshb_s).read_text("utf-8"))
m=obs.get("metrics") or {};c=obs.get("cursors") or {}
for name,pid_s in (("RESIDENT",res_pid_s),("DISCORD",disc_pid_s)):
    p=proc(int(pid_s))
    print(f"{label}_{name} STATE={p['state']} RSS_BYTES={p['rss']} SWAP_BYTES={p['swap']} MAJFLT={p['majflt']} READ_BYTES={p['rbytes']} WRITE_BYTES={p['wbytes']}")
print(f"{label}_PROTECTED_CORE={int(m.get('unrecoverable_core_gap_events',0) or 0)}/{int(m.get('unrecoverable_core_gap_messages',0) or 0)}")
print(f"{label}_LOBBY_CURSOR={int(c.get('lobby',0) or 0)}")
print(f"{label}_OBSERVER_UPDATED_AT={obs.get('updated_at','missing')}")
print(f"{label}_OBSERVER_HEARTBEAT_AGE={age(obhb.get('updated_at')):.1f}")
print(f"{label}_RESIDENT_HEARTBEAT_STATUS={reshb.get('status','missing')}")
print(f"{label}_RESIDENT_HEARTBEAT_AGE={age(reshb.get('updated_at')):.1f}")
rev=obhb.get("tclk_revision")
print(f"{label}_TCLK_REVISION={rev if type(rev) is int and rev >= 0 else 'MISSING'}")
for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
    if ":" not in line:continue
    k,v=line.split(":",1)
    if k in {"MemAvailable","SwapFree","AnonPages"}:
        print(f"{label}_MEM_{k.upper()}_BYTES={int(v.strip().split()[0])*1024}")
for kind in ("io","memory"):
    p=pathlib.Path(f"/proc/pressure/{kind}")
    if p.exists():
        for idx,line in enumerate(p.read_text("utf-8").splitlines()[:2],1):
            print(f"{label}_PSI_{kind.upper()}_{idx}={re.sub(r'[^A-Za-z0-9_.:/=-]','',line)[:160]}")
vm={}
for line in pathlib.Path("/proc/vmstat").read_text("utf-8").splitlines():
    parts=line.split()
    if len(parts)==2 and parts[0] in {"pgmajfault","pswpin","pswpout"}:vm[parts[0]]=int(parts[1])
for k in ("pgmajfault","pswpin","pswpout"):
    print(f"{label}_VM_{k.upper()}={vm.get(k,-1)}")
PY
}

sample B0
sleep 30
sample B30
sleep 30
sample B60

echo '--- FINAL ACCEPTANCE ---'
FINAL_RES_ACTIVE=$(systemctl show "$RES" -p ActiveState --value)
FINAL_RES_SUB=$(systemctl show "$RES" -p SubState --value)
FINAL_RES_PID=$(systemctl show "$RES" -p MainPID --value)
FINAL_RES_NR=$(systemctl show "$RES" -p NRestarts --value)
FINAL_RES_RESULT=$(systemctl show "$RES" -p Result --value)
FINAL_DISC_ACTIVE=$(systemctl show "$DISC" -p ActiveState --value)
FINAL_DISC_SUB=$(systemctl show "$DISC" -p SubState --value)
FINAL_DISC_PID=$(systemctl show "$DISC" -p MainPID --value)
FINAL_DISC_NR=$(systemctl show "$DISC" -p NRestarts --value)
FINAL_DISC_RESULT=$(systemctl show "$DISC" -p Result --value)
echo "FINAL_RESIDENT ACTIVE=$FINAL_RES_ACTIVE SUB=$FINAL_RES_SUB PID=$FINAL_RES_PID NRESTARTS=$FINAL_RES_NR RESULT=$FINAL_RES_RESULT"
echo "FINAL_DISCORD ACTIVE=$FINAL_DISC_ACTIVE SUB=$FINAL_DISC_SUB PID=$FINAL_DISC_PID NRESTARTS=$FINAL_DISC_NR RESULT=$FINAL_DISC_RESULT"
[[ "$FINAL_RES_ACTIVE" == active && "$FINAL_RES_SUB" == running && "$FINAL_RES_PID" == "$NEW_RES_PID" && "$FINAL_RES_NR" == 0 && "$FINAL_RES_RESULT" == success ]] || { echo 'PROD423CACHEV1=STOP:resident_unstable'; exit 0; }
[[ "$FINAL_DISC_ACTIVE" == active && "$FINAL_DISC_SUB" == running && "$FINAL_DISC_PID" == "$NEW_DISC_PID" && "$FINAL_DISC_NR" == 0 && "$FINAL_DISC_RESULT" == success ]] || { echo 'PROD423CACHEV1=STOP:discord_unstable'; exit 0; }

FINAL=$("$APP_PY" - "$OBS" "$OBHB" "$RESHB" "$BASE_CURSOR" "$BASE_UPDATED" <<'PY'
import json,pathlib,sys
from datetime import UTC,datetime
obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
obhb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
reshb=json.loads(pathlib.Path(sys.argv[3]).read_text("utf-8"))
base_cursor=int(sys.argv[4]);base_updated=sys.argv[5]
m=obs.get("metrics") or {};c=obs.get("cursors") or {}
def age(v):
    try:
        d=datetime.fromisoformat(v)
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:return -1.0
rev=obhb.get("tclk_revision")
print(f"{int(m.get('unrecoverable_core_gap_events',0) or 0)}|{int(m.get('unrecoverable_core_gap_messages',0) or 0)}|{int(c.get('lobby',0) or 0)}|{obs.get('updated_at','missing')}|{age(obhb.get('updated_at')):.1f}|{age(reshb.get('updated_at')):.1f}|{rev if type(rev) is int and rev >= 0 else -1}|{1 if obs.get('updated_at') != base_updated else 0}|{1 if int(c.get('lobby',0) or 0) >= base_cursor else 0}")
PY
)
F_EVENTS=$(printf '%s' "$FINAL"|cut -d'|' -f1)
F_MESSAGES=$(printf '%s' "$FINAL"|cut -d'|' -f2)
F_CURSOR=$(printf '%s' "$FINAL"|cut -d'|' -f3)
F_UPDATED=$(printf '%s' "$FINAL"|cut -d'|' -f4)
F_OBS_HB_AGE=$(printf '%s' "$FINAL"|cut -d'|' -f5)
F_RES_HB_AGE=$(printf '%s' "$FINAL"|cut -d'|' -f6)
F_REV=$(printf '%s' "$FINAL"|cut -d'|' -f7)
F_UPDATED_MOVED=$(printf '%s' "$FINAL"|cut -d'|' -f8)
F_CURSOR_OK=$(printf '%s' "$FINAL"|cut -d'|' -f9)
echo "FINAL_PROTECTED_CORE=$F_EVENTS/$F_MESSAGES"
echo "FINAL_LOBBY_CURSOR=$F_CURSOR"
echo "FINAL_OBSERVER_UPDATED_AT=$F_UPDATED"
echo "FINAL_OBSERVER_HEARTBEAT_AGE=$F_OBS_HB_AGE"
echo "FINAL_RESIDENT_HEARTBEAT_AGE=$F_RES_HB_AGE"
echo "FINAL_TCLK_REVISION=$F_REV"
echo "FINAL_OBSERVER_UPDATED_MOVED=$F_UPDATED_MOVED"
echo "FINAL_CURSOR_NONDECREASING=$F_CURSOR_OK"

[[ "$F_EVENTS" == "$EXPECTED_CORE_EVENTS" && "$F_MESSAGES" == "$EXPECTED_CORE_MESSAGES" ]] || { echo 'PROD423CACHEV1=STOP:protected_core_changed'; exit 0; }
[[ "$F_UPDATED_MOVED" == 1 && "$F_CURSOR_OK" == 1 && "$F_REV" =~ ^[0-9]+$ ]] || { echo 'PROD423CACHEV1=STOP:continuity_or_revision_invalid'; exit 0; }
if ! "$APP_PY" - "$F_OBS_HB_AGE" "$F_RES_HB_AGE" <<'PY'
import sys
obs=float(sys.argv[1]);res=float(sys.argv[2])
raise SystemExit(0 if 0 <= obs <= 180 and 0 <= res <= 120 else 1)
PY
then
  echo 'PROD423CACHEV1=STOP:heartbeat_not_fresh'
  exit 0
fi

service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS" || { echo 'PROD423CACHEV1=STOP:capture_changed'; exit 0; }
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS" || { echo 'PROD423CACHEV1=STOP:signer_changed'; exit 0; }
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "FINAL_METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || { echo 'PROD423CACHEV1=STOP:metadata_block_changed'; exit 0; }

echo 'SOURCE_ROLLOUT=PASS'
echo 'RESIDENT_RESTART=EXACTLY_ONCE'
echo 'DISCORD_RESTART=EXACTLY_ONCE'
echo 'CAPTURE_RESTART=NO'
echo 'SIGNER_RESTART=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'TECHNOCORE_WRITE=NO'
echo '=== PROD423_DISCORD_CACHE_ROLLOUT_V1=PASS ==='
echo 'DO_NOT_RERUN=YES'
exit 0
