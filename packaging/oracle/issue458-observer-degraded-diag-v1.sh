#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
OBHB=/var/lib/technocore-safe-agent/observer/observer-heartbeat.json
RESHB=/var/lib/technocore-safe-agent/observer/resident-heartbeat.json
EXPECTED_HEAD=b8c63f865856d5004f8d310eb8ff4c31dbd7ffb0
EXPECTED_RESIDENT_PID=2256397
EXPECTED_CAPTURE_PID=2349223
EXPECTED_SIGNER_PID=2256324
EXPECTED_DISCORD_PID=2349270
EXPECTED_CORE_EVENTS=121
EXPECTED_CORE_MESSAGES=5650187
EXPECTED_BRIDGE_EVENTS=4
EXPECTED_BRIDGE_MESSAGES=567032

echo '=== PROD458 OBSERVER DEGRADED READ-ONLY DIAG V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

stop_diag() {
  echo "PROD458V1=STOP:$1"
  echo 'DO_NOT_RERUN=YES'
  exit 0
}

on_error() {
  local rc=$?
  trap - ERR
  echo "PROD458V1=ERROR:rc_$rc"
  echo 'DO_NOT_RERUN=YES'
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_diag not_root
[[ -x "$PY" && -f "$OBS" && -f "$OBHB" && -f "$RESHB" && -d "$APP/.git" ]] || stop_diag required_path_missing

OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_diag git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

service_snapshot() {
  local unit=$1
  printf '%s|%s|%s|%s|%s\n'     "$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p Result --value 2>/dev/null || true)"
}

runtime_snapshot() {
"$PY" - "$OBS" "$OBHB" "$RESHB" <<'PY'
import json, pathlib, sys
from datetime import UTC, datetime

obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
obhb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
reshb=json.loads(pathlib.Path(sys.argv[3]).read_text("utf-8"))
now=datetime.now(UTC)

def parse(v):
    if not isinstance(v,str) or not v:
        return None
    try: return datetime.fromisoformat(v.replace("Z","+00:00")).astimezone(UTC)
    except ValueError: return None
def age(v):
    d=parse(v)
    return -1.0 if d is None else (now-d).total_seconds()

m=obs.get("metrics") or {}
print("|".join([
    str(int(m.get("unrecoverable_core_gap_events",0) or 0)),
    str(int(m.get("unrecoverable_core_gap_messages",0) or 0)),
    str(int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0)),
    str(int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0)),
    str(int((obs.get("cursors") or {}).get("lobby",0) or 0)),
    str((obs.get("health") or {}).get("current") or "unknown"),
    f"{age(obs.get('updated_at')):.1f}",
    str(obhb.get("status") or "unknown"),
    f"{age(obhb.get('updated_at')):.1f}",
    str(reshb.get("status") or "unknown"),
    f"{age(reshb.get('updated_at')):.1f}",
]))
PY
}

dump_forensics() {
"$PY" - "$OBS" <<'PY'
import json, pathlib, sys
obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
health=obs.get("health") or {}
print("HEALTH_ROOMS_BEGIN")
for room,value in sorted((health.get("rooms") or {}).items()):
    if isinstance(value,dict):
        print(json.dumps({"room":room,**value},sort_keys=True,separators=(",",":")))
print("HEALTH_ROOMS_END")

print("RECENT_ERROR_HISTORY_BEGIN")
for row in (obs.get("error_history") or [])[-30:]:
    if isinstance(row,dict):
        print(json.dumps(row,sort_keys=True,separators=(",",":")))
print("RECENT_ERROR_HISTORY_END")

print("LAST_UNRECOVERABLE_GAP="+json.dumps(obs.get("last_unrecoverable_gap"),sort_keys=True,separators=(",",":")))
PY
}

pressure() {
"$PY" - <<'PY'
from pathlib import Path
mem=-1
for line in Path("/proc/meminfo").read_text().splitlines():
    if line.startswith("MemAvailable:"):
        mem=int(line.split()[1]); break
def psi(kind):
    try:
        for line in Path(f"/proc/pressure/{kind}").read_text().splitlines():
            if line.startswith("full "):
                for part in line.split()[1:]:
                    if part.startswith("avg10="):
                        return part.split("=",1)[1]
    except Exception:
        pass
    return "-1"
print(f"MEM_AVAILABLE_KB={mem} MEM_PSI_FULL_AVG10={psi('memory')} IO_PSI_FULL_AVG10={psi('io')}")
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

RES=$(service_snapshot technocore-safe-agent-resident.service)
CAP=$(service_snapshot technocore-safe-agent-lobby-capture.service)
SIG=$(service_snapshot technocore-safe-agent-signer.service)
DIS=$(service_snapshot technocore-safe-agent-discord.service)
echo "SERVICE=RESIDENT SNAPSHOT=$RES"
echo "SERVICE=CAPTURE SNAPSHOT=$CAP"
echo "SERVICE=SIGNER SNAPSHOT=$SIG"
echo "SERVICE=DISCORD SNAPSHOT=$DIS"
[[ "$RES" == "active|running|$EXPECTED_RESIDENT_PID|0|success" ]] || stop_diag resident_baseline_changed
[[ "$CAP" == "active|running|$EXPECTED_CAPTURE_PID|0|success" ]] || stop_diag capture_baseline_changed
[[ "$SIG" == "active|running|$EXPECTED_SIGNER_PID|0|success" ]] || stop_diag signer_baseline_changed
[[ "$DIS" == "active|running|$EXPECTED_DISCORD_PID|0|success" ]] || stop_diag discord_baseline_changed

LAST_CURSOR=''
for phase in T0 T30 T60 T90; do
  if [[ "$phase" != T0 ]]; then sleep 30; fi
  [[ "$(service_snapshot technocore-safe-agent-resident.service)" == "$RES" ]] || stop_diag "${phase}_resident_changed"
  [[ "$(service_snapshot technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_diag "${phase}_capture_changed"
  [[ "$(service_snapshot technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_diag "${phase}_signer_changed"
  [[ "$(service_snapshot technocore-safe-agent-discord.service)" == "$DIS" ]] || stop_diag "${phase}_discord_changed"

  line=$(runtime_snapshot) || stop_diag "${phase}_runtime_read_failed"
  IFS='|' read -r ce cm be bm cursor health obs_age obhb_status obhb_age reshb_status reshb_age <<<"$line"
  echo "SAMPLE=$phase CORE=$ce/$cm BRIDGE=$be/$bm LOBBY_CURSOR=$cursor OBS_HEALTH=$health OBS_STATE_AGE=$obs_age OBS_HB_STATUS=$obhb_status OBS_HB_AGE=$obhb_age RES_HB_STATUS=$reshb_status RES_HB_AGE=$reshb_age"
  pressure

  [[ "$ce" == "$EXPECTED_CORE_EVENTS" && "$cm" == "$EXPECTED_CORE_MESSAGES" ]] || stop_diag "${phase}_protected_core_changed"
  [[ "$be" == "$EXPECTED_BRIDGE_EVENTS" && "$bm" == "$EXPECTED_BRIDGE_MESSAGES" ]] || stop_diag "${phase}_startup_bridge_changed"
  if [[ -n "$LAST_CURSOR" && "$cursor" -lt "$LAST_CURSOR" ]]; then stop_diag "${phase}_lobby_cursor_regressed"; fi
  LAST_CURSOR=$cursor

  echo "FORENSICS_PHASE=$phase"
  dump_forensics
done

echo '--- BOUNDED RESIDENT JOURNAL ---'
journalctl -u technocore-safe-agent-resident.service   --since '2026-09-24 05:30:00 UTC'   --until '2026-09-24 05:40:00 UTC'   --no-pager -o short-iso 2>/dev/null   | grep -Ei 'error|fail|timeout|gap|recover|pressure|degrad|stopp|start|kill'   | tail -n 160 || true

echo '--- BOUNDED CAPTURE JOURNAL ---'
journalctl -u technocore-safe-agent-lobby-capture.service   --since '2026-09-24 05:30:00 UTC'   --until '2026-09-24 05:40:00 UTC'   --no-pager -o short-iso 2>/dev/null   | grep -Ei 'error|fail|timeout|gap|recover|pressure|degrad|stopp|start|kill|capacity'   | tail -n 160 || true

echo 'GIT_MUTATION=NO'
echo 'NETWORK_PROBE=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'SYSTEMD_MUTATION=NO'
echo 'RUNNING_SERVICE_RESTART=NO'
echo 'PROCESS_SIGNAL=NO'
echo 'SIGNER_ACTION=NO'
echo 'TECHNOCORE_WRITE=NO'
echo 'FLOP_WRITE=NO'
echo 'X_WRITE=NO'
echo '=== PROD458_OBSERVER_DEGRADED_DIAG=PASS ==='
echo 'DO_NOT_RERUN=YES'
