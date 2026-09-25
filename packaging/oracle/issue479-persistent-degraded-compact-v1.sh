#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
RESHB=/var/lib/technocore-safe-agent/observer/resident-heartbeat.json

EXPECTED_HEAD=9baa91be7267b22143c33a06df3c67e1074dba0d
RES_PID=2256397
CAP_PID=2405706
SIG_PID=2256324
DIS_PID=2438454
CORE_E=124
CORE_M=5651120
BRIDGE_E=7
BRIDGE_M=567965

stop_diag() {
  echo "PROD479V1=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 0
}

on_error() {
  local rc=$?
  trap - ERR
  echo "PROD479V1=ERROR:rc_$rc"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_diag not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" && -f "$RESHB" ]] || stop_diag required_path_missing

OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_diag git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

snap() {
  local unit=$1
  printf '%s|%s|%s|%s|%s\n' \
    "$(systemctl show "$unit" -p ActiveState --value)" \
    "$(systemctl show "$unit" -p SubState --value)" \
    "$(systemctl show "$unit" -p MainPID --value)" \
    "$(systemctl show "$unit" -p NRestarts --value)" \
    "$(systemctl show "$unit" -p Result --value)"
}

runtime() {
"$PY" - "$OBS" "$RESHB" <<'PY'
import json, pathlib, sys
from collections import Counter
from datetime import UTC, datetime, timedelta

obs=json.loads(pathlib.Path(sys.argv[1]).read_text('utf-8'))
hb=json.loads(pathlib.Path(sys.argv[2]).read_text('utf-8'))
now=datetime.now(UTC)
m=obs.get('metrics') or {}

def parse(v):
    try:
        return datetime.fromisoformat(str(v).replace('Z','+00:00')).astimezone(UTC)
    except Exception:
        return None

def age(v):
    d=parse(v)
    return -1.0 if d is None else max(0.0,(now-d).total_seconds())

rooms=[]
for room,value in sorted(((obs.get('health') or {}).get('rooms') or {}).items()):
    if isinstance(value,dict) and value.get('status') not in (None,'ok'):
        rooms.append(f"{room}:{value.get('status')}")

since=now-timedelta(minutes=15)
counts=Counter()
for row in obs.get('error_history') or []:
    if not isinstance(row,dict):
        continue
    at=parse(row.get('at'))
    if at is None or at < since:
        continue
    counts[(str(row.get('room')),str(row.get('kind')))] += 1
errors=','.join(
    f"{room}/{kind}:{count}"
    for (room,kind),count in counts.most_common(5)
) or 'none'

mem=-1
for line in pathlib.Path('/proc/meminfo').read_text('utf-8').splitlines():
    if line.startswith('MemAvailable:'):
        mem=int(line.split()[1])
        break

def psi(kind):
    try:
        for line in pathlib.Path(f'/proc/pressure/{kind}').read_text('utf-8').splitlines():
            if line.startswith('full '):
                for part in line.split()[1:]:
                    if part.startswith('avg10='):
                        return part.split('=',1)[1]
    except Exception:
        pass
    return '-1'

print('|'.join([
 str(int(m.get('unrecoverable_core_gap_events',0) or 0)),
 str(int(m.get('unrecoverable_core_gap_messages',0) or 0)),
 str(int(m.get('lobby_startup_bridge_unrecoverable_events',0) or 0)),
 str(int(m.get('lobby_startup_bridge_unrecoverable_messages',0) or 0)),
 str(int((obs.get('cursors') or {}).get('lobby',0) or 0)),
 str((obs.get('health') or {}).get('current') or 'unknown'),
 f"{age(obs.get('updated_at')):.1f}",
 str(hb.get('status') or 'unknown'),
 f"{age(hb.get('updated_at')):.1f}",
 ';'.join(rooms[:5]) if rooms else 'none',
 errors,
 str(mem),
 psi('memory'),
 psi('io'),
]))
PY
}

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$EXPECTED_HEAD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_diag repo_state_unexpected
echo "REPO=head:$HEAD branch:$BRANCH clean:YES"

RES=$(snap technocore-safe-agent-resident.service)
CAP=$(snap technocore-safe-agent-lobby-capture.service)
SIG=$(snap technocore-safe-agent-signer.service)
DIS=$(snap technocore-safe-agent-discord.service)
[[ "$RES" == "active|running|$RES_PID|0|success" ]] || stop_diag resident_changed
[[ "$CAP" == "active|running|$CAP_PID|0|success" ]] || stop_diag capture_changed
[[ "$SIG" == "active|running|$SIG_PID|0|success" ]] || stop_diag signer_changed
[[ "$DIS" == "active|running|$DIS_PID|0|success" ]] || stop_diag discord_changed
echo "SERVICES=resident:$RES_PID capture:$CAP_PID signer:$SIG_PID discord:$DIS_PID all:active_nr0"

START_CURSOR=''
LAST_CURSOR=''
DEGRADED_SAMPLES=0
OK_SAMPLES=0

for phase in T0 T60 T120; do
  [[ "$phase" == T0 ]] || sleep 60
  [[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || stop_diag "${phase}_resident_changed"
  [[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_diag "${phase}_capture_changed"
  [[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_diag "${phase}_signer_changed"
  [[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || stop_diag "${phase}_discord_changed"

  line=$(runtime) || stop_diag "${phase}_runtime_read_failed"
  IFS='|' read -r ce cm be bm cursor health obs_age hb_status hb_age rooms errors mem mempsi iopsi <<<"$line"

  [[ "$ce" == "$CORE_E" && "$cm" == "$CORE_M" ]] || stop_diag "${phase}_protected_core_changed"
  [[ "$be" == "$BRIDGE_E" && "$bm" == "$BRIDGE_M" ]] || stop_diag "${phase}_startup_bridge_changed"
  if [[ -n "$LAST_CURSOR" && "$cursor" -lt "$LAST_CURSOR" ]]; then stop_diag "${phase}_lobby_cursor_regressed"; fi

  [[ -n "$START_CURSOR" ]] || START_CURSOR=$cursor
  LAST_CURSOR=$cursor
  if [[ "$health" == ok ]]; then OK_SAMPLES=$((OK_SAMPLES+1)); else DEGRADED_SAMPLES=$((DEGRADED_SAMPLES+1)); fi

  echo "SAMPLE=$phase health:$health cursor:$cursor obs_age:${obs_age}s hb:$hb_status/${hb_age}s rooms:$rooms errors15m:$errors mem_kb:$mem psi_mem:$mempsi psi_io:$iopsi"
done

CURSOR_DELTA=$((LAST_CURSOR-START_CURSOR))
if (( OK_SAMPLES >= 1 && DEGRADED_SAMPLES >= 1 )); then
  CLASS=OSCILLATING_SELF_RECOVERY
elif (( OK_SAMPLES == 3 )); then
  CLASS=RECOVERED
else
  CLASS=PERSISTENT_DEGRADED
fi

echo "RESULT=classification:$CLASS lobby_cursor_delta:$CURSOR_DELTA core:$CORE_E/$CORE_M bridge:$BRIDGE_E/$BRIDGE_M"
echo "SAFETY=mutation:NO restart:NO sqlite:NO network:NO signer:NO external_write:NO"
echo "PROD479V1=PASS"
echo "DO_NOT_RERUN=YES"
