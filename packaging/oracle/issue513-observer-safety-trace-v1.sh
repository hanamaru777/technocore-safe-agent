#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json
OBHB=/var/lib/technocore-safe-agent/observer/observer-heartbeat.json
RESHB=/var/lib/technocore-safe-agent/observer/resident-heartbeat.json

EXPECTED_HEAD=a4016accdef7b1df591d68d1bcdc54c7a9de7320
RES_PID=2462149
CAP_PID=2462148
SIG_PID=2462068
DIS_PID=2560998
CORE_E=124
CORE_M=5651120
BRIDGE_E=7
BRIDGE_M=567965

stop_diag() {
  echo "PROD513V1=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "PROD513V1=ERROR:rc_$rc"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_diag not_root
[[ -x "$PY" && -f "$OBS" && -f "$SAFETY" && -f "$OBHB" && -f "$RESHB" && -d "$APP/.git" ]] || stop_diag required_path_missing

OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_diag git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

snap() {
  local unit=$1
  printf '%s|%s|%s|%s|%s' \
    "$(systemctl show "$unit" -p ActiveState --value)" \
    "$(systemctl show "$unit" -p SubState --value)" \
    "$(systemctl show "$unit" -p MainPID --value)" \
    "$(systemctl show "$unit" -p NRestarts --value)" \
    "$(systemctl show "$unit" -p Result --value)"
}

sample() {
  "$PY" - "$OBS" "$SAFETY" "$OBHB" "$RESHB" <<'PY'
import json, pathlib, re, sys
from datetime import UTC, datetime

obs_p,safe_p,obhb_p,reshb_p=map(pathlib.Path,sys.argv[1:5])
obs=json.loads(obs_p.read_text("utf-8"))
safe=json.loads(safe_p.read_text("utf-8"))
obhb=json.loads(obhb_p.read_text("utf-8"))
reshb=json.loads(reshb_p.read_text("utf-8"))
now=datetime.now(UTC)

def parse(v):
    if not isinstance(v,str) or not v:
        return None
    try:
        return datetime.fromisoformat(v.replace("Z","+00:00")).astimezone(UTC)
    except ValueError:
        return None

def age(v):
    d=parse(v)
    return -1 if d is None else int((now-d).total_seconds())

m=obs.get("metrics") or {}
health=obs.get("health") or {}
rooms=health.get("rooms") or {}
degraded=[]
for room,value in sorted(rooms.items()):
    if not isinstance(room,str) or not isinstance(value,dict):
        continue
    status=str(value.get("status") or value.get("health") or value.get("state") or "unknown")
    if status == "ok":
        continue
    err=value.get("last_error")
    if isinstance(err,dict):
        err=err.get("type") or err.get("error") or err.get("class")
    err=str(err or "")
    err=re.sub(r"[^A-Za-z0-9_.:-]","",err)[:40]
    room=re.sub(r"[^A-Za-z0-9_.:-]","",room)[:40]
    degraded.append(f"{room}:{status}:{err or '-'}")
degraded=",".join(degraded[:6]) or "none"

mem=-1
for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
    if line.startswith("MemAvailable:"):
        mem=int(line.split()[1]); break

def psi(kind):
    try:
        for line in pathlib.Path(f"/proc/pressure/{kind}").read_text().splitlines():
            if line.startswith("full "):
                for part in line.split()[1:]:
                    if part.startswith("avg10="):
                        return part.split("=",1)[1]
    except Exception:
        pass
    return "-1"

print(" ".join([
    f"CORE={int(m.get('unrecoverable_core_gap_events',0) or 0)}/{int(m.get('unrecoverable_core_gap_messages',0) or 0)}",
    f"BRIDGE={int(m.get('lobby_startup_bridge_unrecoverable_events',0) or 0)}/{int(m.get('lobby_startup_bridge_unrecoverable_messages',0) or 0)}",
    f"CURSOR={int((obs.get('cursors') or {}).get('lobby',0) or 0)}",
    f"OBS={health.get('current','unknown')}/{age(obs.get('updated_at'))}s",
    f"SAFE={safe.get('schema_version')}/{safe.get('health','unknown')}/{age(safe.get('updated_at'))}s/{safe.get('unrecoverable_core_gap_events')}/{safe.get('unrecoverable_core_gap_messages')}",
    f"OBHB={obhb.get('status','unknown')}/{age(obhb.get('updated_at'))}s",
    f"RESHB={reshb.get('status','unknown')}/{age(reshb.get('updated_at'))}s",
    f"DEGRADED={degraded}",
    f"MEM_KB={mem}",
    f"MPSI={psi('memory')}",
    f"IPSI={psi('io')}",
]))
PY
}

echo "=== PROD513 OBSERVER SAFETY TRACE ==="
HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] && CLEAN=YES || CLEAN=NO
echo "REPO=head:$HEAD branch:$BRANCH clean:$CLEAN"
[[ "$HEAD" == "$EXPECTED_HEAD" && "$BRANCH" == main && "$CLEAN" == YES ]] || stop_diag repo_baseline_changed

RES=$(snap technocore-safe-agent-resident.service)
CAP=$(snap technocore-safe-agent-lobby-capture.service)
SIG=$(snap technocore-safe-agent-signer.service)
DIS=$(snap technocore-safe-agent-discord.service)
echo "SERVICES=resident:$RES capture:$CAP signer:$SIG discord:$DIS"
[[ "$RES" == "active|running|$RES_PID|0|success" ]] || stop_diag resident_baseline_changed
[[ "$CAP" == "active|running|$CAP_PID|0|success" ]] || stop_diag capture_baseline_changed
[[ "$SIG" == "active|running|$SIG_PID|0|success" ]] || stop_diag signer_baseline_changed
[[ "$DIS" == "active|running|$DIS_PID|0|success" ]] || stop_diag discord_baseline_changed

LAST_CURSOR=''
for PHASE in T0 T30 T60; do
  [[ "$PHASE" == T0 ]] || sleep 30
  LINE=$(sample) || stop_diag "${PHASE}_sample_failed"
  echo "SAMPLE=$PHASE $LINE"
  CURSOR=$(printf '%s\n' "$LINE" | sed -n 's/.* CURSOR=\([0-9][0-9]*\).*/\1/p')
  CORE=$(printf '%s\n' "$LINE" | sed -n 's/^CORE=\([^ ]*\).*/\1/p')
  BRIDGE=$(printf '%s\n' "$LINE" | sed -n 's/.* BRIDGE=\([^ ]*\).*/\1/p')
  [[ "$CORE" == "$CORE_E/$CORE_M" ]] || stop_diag "${PHASE}_protected_core_changed"
  [[ "$BRIDGE" == "$BRIDGE_E/$BRIDGE_M" ]] || stop_diag "${PHASE}_startup_bridge_changed"
  if [[ -n "$LAST_CURSOR" && -n "$CURSOR" && "$CURSOR" -lt "$LAST_CURSOR" ]]; then
    stop_diag "${PHASE}_lobby_cursor_regressed"
  fi
  LAST_CURSOR=$CURSOR
  [[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || stop_diag "${PHASE}_resident_changed"
  [[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_diag "${PHASE}_capture_changed"
  [[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_diag "${PHASE}_signer_changed"
  [[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || stop_diag "${PHASE}_discord_changed"
done

echo "MUTATION=NONE RESTART=NONE NETWORK_PROBE=NONE SQLITE=NONE JOURNAL=NONE"
echo "PROD513V1=PASS"
echo "DO_NOT_RERUN=YES"