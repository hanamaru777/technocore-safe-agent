#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
RES_HB=/var/lib/technocore-safe-agent/observer/resident-heartbeat.json
EXPECTED_HEAD=b8c63f865856d5004f8d310eb8ff4c31dbd7ffb0
EXPECTED_RESIDENT_PID=2256397
EXPECTED_CAPTURE_PID=2349223
EXPECTED_SIGNER_PID=2256324
EXPECTED_DISCORD_PID=2349270
EXPECTED_CORE_EVENTS=121
EXPECTED_CORE_MESSAGES=5650187
EXPECTED_BRIDGE_EVENTS=4
EXPECTED_BRIDGE_MESSAGES=567032

echo '=== PROD456 RESIDENT HEARTBEAT WATCH V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

stop_diag() {
  echo "PROD456V1=STOP:$1"
  echo 'DO_NOT_RERUN=YES'
  exit 0
}

on_error() {
  local rc=$?
  trap - ERR
  echo "PROD456V1=ERROR:rc_$rc"
  echo 'DO_NOT_RERUN=YES'
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_diag not_root
[[ -x "$PY" && -f "$OBS" && -f "$RES_HB" && -d "$APP/.git" ]] || stop_diag required_path_missing

OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_diag git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

service_snapshot() {
  local unit=$1
  printf '%s|%s|%s|%s|%s\n'     "$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p Result --value 2>/dev/null || true)"
}

runtime_snapshot() {
  "$PY" - "$OBS" "$RES_HB" "$EXPECTED_RESIDENT_PID" <<'PY'
import json
import pathlib
import sys
from datetime import UTC, datetime

obs_path = pathlib.Path(sys.argv[1])
hb_path = pathlib.Path(sys.argv[2])
resident_pid = int(sys.argv[3])

obs = json.loads(obs_path.read_text("utf-8"))
hb = json.loads(hb_path.read_text("utf-8"))
now = datetime.now(UTC)

def parse(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z","+00:00")).astimezone(UTC)
    except ValueError:
        return None

def age(value):
    stamp = parse(value)
    if stamp is None:
        return -1.0
    return (now - stamp).total_seconds()

m = obs.get("metrics") or {}
rs = hb.get("resident_status")
if not isinstance(rs, dict):
    rs = {}

mem_available_kb = -1
try:
    for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
        if line.startswith("MemAvailable:"):
            mem_available_kb = int(line.split()[1])
            break
except Exception:
    pass

def psi_full_avg10(kind):
    try:
        for line in pathlib.Path(f"/proc/pressure/{kind}").read_text("utf-8").splitlines():
            if not line.startswith("full "):
                continue
            for part in line.split()[1:]:
                if part.startswith("avg10="):
                    return float(part.split("=",1)[1])
    except Exception:
        pass
    return -1.0

children = []
children_path = pathlib.Path(f"/proc/{resident_pid}/task/{resident_pid}/children")
try:
    for raw in children_path.read_text("utf-8").split():
        pid = int(raw)
        state = "?"
        name = "?"
        try:
            state = pathlib.Path(f"/proc/{pid}/stat").read_text("utf-8").split()[2]
        except Exception:
            pass
        try:
            name = pathlib.Path(f"/proc/{pid}/comm").read_text("utf-8").strip()
        except Exception:
            pass
        children.append(f"{pid}:{state}:{name}")
except Exception:
    pass

print("|".join([
    str(int(m.get("unrecoverable_core_gap_events",0) or 0)),
    str(int(m.get("unrecoverable_core_gap_messages",0) or 0)),
    str(int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0)),
    str(int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0)),
    str(int((obs.get("cursors") or {}).get("lobby",0) or 0)),
    str((obs.get("health") or {}).get("current") or "unknown"),
    f"{age(obs.get('updated_at')):.1f}",
    str(hb.get("status") or "unknown"),
    str(hb.get("updated_at") or ""),
    f"{age(hb.get('updated_at')):.1f}",
    "true" if rs.get("read_only") is True else "false",
    str(((rs.get("health") or {}).get("current")) or "unknown"),
    str(rs.get("last_refresh_at") or ""),
    f"{age(rs.get('last_refresh_at')):.1f}",
    str(mem_available_kb),
    f"{psi_full_avg10('memory'):.2f}",
    f"{psi_full_avg10('io'):.2f}",
    ",".join(children) if children else "none",
]))
PY
}

echo '--- BASELINE ---'
HEAD=$(git_owner rev-parse HEAD 2>/dev/null || true)
BRANCH=$(git_owner branch --show-current 2>/dev/null || true)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "HEAD=$HEAD"
echo "BRANCH=$BRANCH"
[[ -z "$WORKTREE" ]] && echo 'WORKTREE_CLEAN=YES' || echo 'WORKTREE_CLEAN=NO'
[[ "$HEAD" == "$EXPECTED_HEAD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_diag repo_state_unexpected

RES_BASE=$(service_snapshot technocore-safe-agent-resident.service)
CAP_BASE=$(service_snapshot technocore-safe-agent-lobby-capture.service)
SIG_BASE=$(service_snapshot technocore-safe-agent-signer.service)
DIS_BASE=$(service_snapshot technocore-safe-agent-discord.service)
echo "SERVICE=RESIDENT SNAPSHOT=$RES_BASE"
echo "SERVICE=CAPTURE SNAPSHOT=$CAP_BASE"
echo "SERVICE=SIGNER SNAPSHOT=$SIG_BASE"
echo "SERVICE=DISCORD SNAPSHOT=$DIS_BASE"

[[ "$RES_BASE" == "active|running|$EXPECTED_RESIDENT_PID|0|success" ]] || stop_diag resident_baseline_changed
[[ "$CAP_BASE" == "active|running|$EXPECTED_CAPTURE_PID|0|success" ]] || stop_diag capture_baseline_changed
[[ "$SIG_BASE" == "active|running|$EXPECTED_SIGNER_PID|0|success" ]] || stop_diag signer_baseline_changed
[[ "$DIS_BASE" == "active|running|$EXPECTED_DISCORD_PID|0|success" ]] || stop_diag discord_baseline_changed

META_ACTIVE=$(systemctl show technocore-safe-agent-metadata-block.service -p ActiveState --value 2>/dev/null || true)
META_RESULT=$(systemctl show technocore-safe-agent-metadata-block.service -p Result --value 2>/dev/null || true)
echo "METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || stop_diag metadata_block_changed

FIRST_HB=''
LAST_HB=''
HB_ADVANCES=0
MAX_HB_AGE=0
START_CURSOR=''
LAST_CURSOR=''

sample() {
  local phase=$1 line ce cm be bm cursor obs_health obs_age hb_status hb_stamp hb_age ro resident_health last_refresh last_refresh_age mem_kb mem_psi io_psi children
  if ! line=$(runtime_snapshot); then
    stop_diag "${phase}_runtime_read_failed"
  fi
  IFS='|' read -r ce cm be bm cursor obs_health obs_age hb_status hb_stamp hb_age ro resident_health last_refresh last_refresh_age mem_kb mem_psi io_psi children <<<"$line"

  echo "SAMPLE=$phase CORE=$ce/$cm BRIDGE=$be/$bm LOBBY_CURSOR=$cursor OBS_HEALTH=$obs_health OBS_STATE_AGE=$obs_age RES_HB_STATUS=$hb_status RES_HB_AGE=$hb_age RESIDENT_HEALTH=$resident_health RESIDENT_LAST_REFRESH_AGE=$last_refresh_age MEM_AVAILABLE_KB=$mem_kb MEM_PSI_FULL_AVG10=$mem_psi IO_PSI_FULL_AVG10=$io_psi"
  echo "RESIDENT_CHILDREN=$children"
  echo "LIVENESS_SOURCE=resident-heartbeat.json:updated_at"
  echo "OBSERVER_STATE_UPDATED_AT_LIVENESS_GATE=NO"

  [[ "$ce" == "$EXPECTED_CORE_EVENTS" && "$cm" == "$EXPECTED_CORE_MESSAGES" ]] || stop_diag "${phase}_protected_core_changed"
  [[ "$be" == "$EXPECTED_BRIDGE_EVENTS" && "$bm" == "$EXPECTED_BRIDGE_MESSAGES" ]] || stop_diag "${phase}_startup_bridge_changed"
  [[ "$obs_health" == ok ]] || stop_diag "${phase}_observer_health_not_ok"
  [[ "$hb_status" == ok || "$hb_status" == pressure_paused ]] || stop_diag "${phase}_resident_heartbeat_status_bad"
  [[ "$ro" == true ]] || stop_diag "${phase}_resident_status_not_read_only"

  if [[ -z "$FIRST_HB" ]]; then
    FIRST_HB=$hb_stamp
    START_CURSOR=$cursor
  fi
  if [[ -n "$LAST_HB" && "$hb_stamp" != "$LAST_HB" ]]; then
    HB_ADVANCES=$((HB_ADVANCES+1))
  fi
  LAST_HB=$hb_stamp

  HB_AGE_INT=$("$PY" - "$hb_age" <<'PY'
import math, sys
v=float(sys.argv[1])
print(max(0, int(math.ceil(v))))
PY
)
  if (( HB_AGE_INT > MAX_HB_AGE )); then
    MAX_HB_AGE=$HB_AGE_INT
  fi

  if [[ -n "$LAST_CURSOR" && "$cursor" -lt "$LAST_CURSOR" ]]; then
    stop_diag "${phase}_lobby_cursor_regressed"
  fi
  LAST_CURSOR=$cursor
}

for phase in T0 T30 T60 T90 T120 T150 T180; do
  if [[ "$phase" != T0 ]]; then sleep 30; fi
  [[ "$(service_snapshot technocore-safe-agent-resident.service)" == "$RES_BASE" ]] || stop_diag "${phase}_resident_changed"
  [[ "$(service_snapshot technocore-safe-agent-lobby-capture.service)" == "$CAP_BASE" ]] || stop_diag "${phase}_capture_changed"
  [[ "$(service_snapshot technocore-safe-agent-signer.service)" == "$SIG_BASE" ]] || stop_diag "${phase}_signer_changed"
  [[ "$(service_snapshot technocore-safe-agent-discord.service)" == "$DIS_BASE" ]] || stop_diag "${phase}_discord_changed"
  sample "$phase"
done

echo "HEARTBEAT_ADVANCES=$HB_ADVANCES"
echo "MAX_HEARTBEAT_AGE_SECONDS=$MAX_HB_AGE"
echo "LOBBY_CURSOR_DELTA=$((LAST_CURSOR-START_CURSOR))"

CLASSIFICATION='UNCLASSIFIED'
if (( HB_ADVANCES >= 2 )); then
  CLASSIFICATION='SELF_RECOVERED_AND_ADVANCING'
elif (( HB_ADVANCES == 1 )); then
  CLASSIFICATION='INTERMITTENT_DELAY'
else
  CLASSIFICATION='PERSISTENT_STALE'
fi

echo "HEARTBEAT_CLASSIFICATION=$CLASSIFICATION"

echo 'GIT_MUTATION=NO'
echo 'NETWORK_PROBE=NO'
echo 'JOURNAL_READ=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'SYSTEMD_MUTATION=NO'
echo 'RUNNING_SERVICE_RESTART=NO'
echo 'PROCESS_SIGNAL=NO'
echo 'RAW_CMDLINE_ENV_READ=NO'
echo 'SIGNER_ACTION=NO'
echo 'SYNTHETIC_DISCORD_MESSAGE=NO'
echo 'TECHNOCORE_WRITE=NO'
echo 'FLOP_WRITE=NO'
echo 'X_WRITE=NO'
echo '=== PROD456_HEARTBEAT_WATCH=PASS ==='
echo 'DO_NOT_RERUN=YES'
