#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
RESHB=/var/lib/technocore-safe-agent/observer/resident-heartbeat.json
EXPECTED_HEAD=9baa91be7267b22143c33a06df3c67e1074dba0d
BASE_CORE_E=124
BASE_CORE_M=5651120
BASE_BRIDGE_E=7
BASE_BRIDGE_M=567965

stop_diag() {
  echo "PROD481V1=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 0
}

on_error() {
  local rc=$?
  trap - ERR
  echo "PROD481V1=ERROR:rc_$rc"
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
from datetime import UTC, datetime

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

for entry in "$RES" "$CAP" "$SIG" "$DIS"; do
  IFS='|' read -r a s p n r <<<"$entry"
  [[ "$a" == active && "$s" == running && "$p" != 0 && "$r" == success ]] || stop_diag service_not_ready
done

IFS='|' read -r _ _ RES_PID RES_NR _ <<<"$RES"
IFS='|' read -r _ _ CAP_PID CAP_NR _ <<<"$CAP"
IFS='|' read -r _ _ SIG_PID SIG_NR _ <<<"$SIG"
IFS='|' read -r _ _ DIS_PID DIS_NR _ <<<"$DIS"
echo "SERVICES=resident:$RES_PID/nr$RES_NR capture:$CAP_PID/nr$CAP_NR signer:$SIG_PID/nr$SIG_NR discord:$DIS_PID/nr$DIS_NR"

META_A=$(systemctl show technocore-safe-agent-metadata-block.service -p ActiveState --value)
META_R=$(systemctl show technocore-safe-agent-metadata-block.service -p Result --value)
[[ "$META_A" == active && "$META_R" == success ]] || stop_diag metadata_block_not_ready

MON_A=$(systemctl is-active technocore-safe-agent-airdrop-monitor.timer 2>/dev/null || true)
MON_E=$(systemctl is-enabled technocore-safe-agent-airdrop-monitor.timer 2>/dev/null || true)
NOT_A=$(systemctl is-active technocore-safe-agent-airdrop-notifier.timer 2>/dev/null || true)
NOT_E=$(systemctl is-enabled technocore-safe-agent-airdrop-notifier.timer 2>/dev/null || true)
[[ "$MON_A" == active && "$MON_E" == enabled ]] || stop_diag monitor_timer_not_ready
[[ "$NOT_A" == active && "$NOT_E" == enabled ]] || stop_diag notifier_timer_not_ready
echo "AUX=metadata:ok monitor:$MON_A/$MON_E notifier:$NOT_A/$NOT_E"

START_CURSOR=''
LAST_CURSOR=''
OK_SAMPLES=0
DEG_SAMPLES=0
MAX_HB_AGE=0
FINAL_HEALTH=unknown

for phase in T0 T60 T120; do
  [[ "$phase" == T0 ]] || sleep 60
  [[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || stop_diag "${phase}_resident_changed"
  [[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_diag "${phase}_capture_changed"
  [[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_diag "${phase}_signer_changed"
  [[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || stop_diag "${phase}_discord_changed"

  line=$(runtime) || stop_diag "${phase}_runtime_read_failed"
  IFS='|' read -r ce cm be bm cursor health obs_age hb_status hb_age <<<"$line"
  [[ -n "$START_CURSOR" ]] || START_CURSOR=$cursor
  if [[ -n "$LAST_CURSOR" && "$cursor" -lt "$LAST_CURSOR" ]]; then stop_diag "${phase}_lobby_cursor_regressed"; fi
  LAST_CURSOR=$cursor
  FINAL_HEALTH=$health
  if [[ "$health" == ok ]]; then OK_SAMPLES=$((OK_SAMPLES+1)); else DEG_SAMPLES=$((DEG_SAMPLES+1)); fi
  HB_INT=$($PY - "$hb_age" <<'PY'
import math,sys
print(max(0,int(math.ceil(float(sys.argv[1])))))
PY
)
  (( HB_INT > MAX_HB_AGE )) && MAX_HB_AGE=$HB_INT || true
  echo "SAMPLE=$phase core:$ce/$cm bridge:$be/$bm cursor:$cursor health:$health obs_age:${obs_age}s hb:$hb_status/${hb_age}s"
done

FINAL=$(runtime)
IFS='|' read -r CE CM BE BM _ _ _ HB_STATUS HB_AGE <<<"$FINAL"
CORE_DE=$((CE-BASE_CORE_E))
CORE_DM=$((CM-BASE_CORE_M))
BRIDGE_DE=$((BE-BASE_BRIDGE_E))
BRIDGE_DM=$((BM-BASE_BRIDGE_M))
CURSOR_DELTA=$((LAST_CURSOR-START_CURSOR))

if (( CORE_DE > 0 || CORE_DM > 0 || BRIDGE_DE > 0 || BRIDGE_DM > 0 )); then
  CLASS=REBOOT_RECOVERED_WITH_NEW_GAP
elif [[ "$FINAL_HEALTH" == ok && "$HB_STATUS" =~ ^(ok|pressure_paused)$ ]]; then
  CLASS=REBOOT_RECOVERED_STABLE
else
  CLASS=REBOOT_HEALTH_UNSTABLE
fi

echo "RESULT=$CLASS core:$CE/$CM delta:+$CORE_DE/+$CORE_DM bridge:$BE/$BM delta:+$BRIDGE_DE/+$BRIDGE_DM cursor_delta:$CURSOR_DELTA final_health:$FINAL_HEALTH hb:$HB_STATUS/${HB_AGE}s max_hb_age:${MAX_HB_AGE}s"
echo "SAFETY=mutation:NO restart:NO sqlite:NO network:NO journal:NO signer:NO external_write:NO"
echo "PROD481V1=PASS"
echo "DO_NOT_RERUN=YES"
