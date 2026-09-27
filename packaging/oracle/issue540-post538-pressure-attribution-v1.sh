#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json
PROBE=$APP/packaging/oracle/issue540_pressure_probe.py

EXPECTED_HEAD=58943a072eb0d752960e092970f06311344a8996
RES_PID=2462149
CAP_PID=2462148
SIG_PID=2462068
DIS_PID=2660066
CORE_E=143
CORE_M=5652707
BRIDGE_E=26
BRIDGE_M=569552

UNITS=(
  technocore-safe-agent-tclk-stager.service
  technocore-safe-agent-tclk-preparer.service
  technocore-safe-agent-tclk-lock-watcher.service
  technocore-safe-agent-tclk-work-watcher.service
  technocore-safe-agent-tclk-reveal-preparer.service
)
TIMERS=(
  technocore-safe-agent-tclk-stager.timer
  technocore-safe-agent-tclk-preparer.timer
  technocore-safe-agent-tclk-lock-watcher.timer
  technocore-safe-agent-tclk-work-watcher.timer
  technocore-safe-agent-tclk-reveal-preparer.timer
)

stop_diag() {
  echo "PROD540V1=STOP:$1"
  echo "MUTATION=NONE"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "PROD540V1=ERROR:rc_$rc"
  echo "MUTATION=NONE"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_diag not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" && -f "$SAFETY" && -f "$PROBE" ]] || stop_diag required_path_missing
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

counts() {
  "$PY" - "$OBS" <<'PY'
import json, pathlib, sys
o=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m=o.get("metrics") or {}
print("|".join(map(str,[
 int(m.get("unrecoverable_core_gap_events",0) or 0),
 int(m.get("unrecoverable_core_gap_messages",0) or 0),
 int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),
 int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0),
])))
PY
}

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$EXPECTED_HEAD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_diag repo_baseline_changed

RES=$(snap technocore-safe-agent-resident.service)
CAP=$(snap technocore-safe-agent-lobby-capture.service)
SIG=$(snap technocore-safe-agent-signer.service)
DIS=$(snap technocore-safe-agent-discord.service)
[[ "$RES" == "active|running|$RES_PID|0|success" ]] || stop_diag resident_baseline_changed
[[ "$CAP" == "active|running|$CAP_PID|0|success" ]] || stop_diag capture_baseline_changed
[[ "$SIG" == "active|running|$SIG_PID|0|success" ]] || stop_diag signer_baseline_changed
[[ "$DIS" == "active|running|$DIS_PID|0|success" ]] || stop_diag discord_baseline_changed

BASE_COUNTS="$CORE_E|$CORE_M|$BRIDGE_E|$BRIDGE_M"
[[ "$(counts)" == "$BASE_COUNTS" ]] || stop_diag protected_baseline_changed

for unit in "${UNITS[@]}"; do
  installed="/etc/systemd/system/$unit"
  [[ -f "$installed" ]] || stop_diag unit_missing
  cmp -s "$APP/packaging/oracle/$unit" "$installed" || stop_diag unit_not_target
  [[ "$(stat -c '%U:%G:%a' "$installed" 2>/dev/null || true)" == "root:root:644" ]] || stop_diag unit_meta_changed
  [[ "$(systemctl show "$unit" -p FragmentPath --value 2>/dev/null || true)" == "$installed" ]] || stop_diag fragment_changed
  cond=$(systemctl show "$unit" -p ExecCondition --value 2>/dev/null || true)
  [[ "$cond" == *tclk_timer_gate* ]] || stop_diag loaded_gate_missing
done

for timer in "${TIMERS[@]}"; do
  systemctl is-active --quiet "$timer" || stop_diag timer_not_active
  [[ "$(systemctl is-enabled "$timer" 2>/dev/null || true)" == enabled ]] || stop_diag timer_not_enabled
done

"$PY" "$PROBE" "$OBS" "$SAFETY" "$RES_PID" "$CAP_PID" "$SIG_PID" "$DIS_PID" "$CORE_E" "$CORE_M"

[[ "$(git_owner rev-parse HEAD)" == "$EXPECTED_HEAD" && "$(git_owner branch --show-current)" == main && -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_diag repo_changed_post
[[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || stop_diag resident_changed_post
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_diag capture_changed_post
[[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_diag signer_changed_post
[[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || stop_diag discord_changed_post
[[ "$(counts)" == "$BASE_COUNTS" ]] || stop_diag protected_changed_post

for unit in "${UNITS[@]}"; do
  cmp -s "$APP/packaging/oracle/$unit" "/etc/systemd/system/$unit" || stop_diag unit_changed_post
  cond=$(systemctl show "$unit" -p ExecCondition --value 2>/dev/null || true)
  [[ "$cond" == *tclk_timer_gate* ]] || stop_diag loaded_gate_changed_post
done
for timer in "${TIMERS[@]}"; do
  systemctl is-active --quiet "$timer" || stop_diag timer_changed_post
  [[ "$(systemctl is-enabled "$timer" 2>/dev/null || true)" == enabled ]] || stop_diag timer_enablement_changed_post
done


echo "PROD540V1=PASS"
echo "MUTATION=NONE"
echo "DO_NOT_RERUN=YES"
