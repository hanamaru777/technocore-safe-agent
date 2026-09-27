#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OLD=8a6053326fbd9986a1845ae7e2c0f0deb896af41
TARGET=2be06f6aa74f7e1b65032cfa4bfe99c3583e9562
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
WATCH_STATE=/var/lib/technocore-safe-agent/observer/close1-standalone-watch.json

OLD_TIMER=technocore-safe-agent-close1-discord-activation.timer
OLD_SERVICE=technocore-safe-agent-close1-discord-activation.service
NEW_SERVICE=technocore-safe-agent-close1-standalone-watch.service
NEW_TIMER=technocore-safe-agent-close1-standalone-watch.timer

SRC_SERVICE=$APP/packaging/oracle/technocore-safe-agent-close1-standalone-watch.service
SRC_TIMER=$APP/packaging/oracle/technocore-safe-agent-close1-standalone-watch.timer
DST_SERVICE=/etc/systemd/system/$NEW_SERVICE
DST_TIMER=/etc/systemd/system/$NEW_TIMER

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service

CORE_E=143
CORE_M=5652707
BRIDGE_E=26
BRIDGE_M=569552

SOURCE_UPDATED=NO
NEW_UNITS_INSTALLED=NO
OLD_TIMER_WAS_ENABLED=NO
OLD_TIMER_DISABLED=NO

stop_now() {
  echo "PROD569V1=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 0
}

OWNER=''
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

rollback_error() {
  local rc=$?
  trap - ERR
  systemctl disable --now "$NEW_TIMER" >/dev/null 2>&1 || true
  rm -f "$DST_SERVICE" "$DST_TIMER" || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [[ "$SOURCE_UPDATED" == YES && -n "$OWNER" ]]; then
    git_owner reset --hard "$OLD" >/dev/null 2>&1 || true
  fi
  if [[ "$OLD_TIMER_DISABLED" == YES && "$OLD_TIMER_WAS_ENABLED" == YES ]]; then
    systemctl enable --now "$OLD_TIMER" >/dev/null 2>&1 || true
  fi
  echo "PROD569V1=ERROR:rc_$rc"
  echo "ROLLBACK=source:$SOURCE_UPDATED units:$NEW_UNITS_INSTALLED old_timer:$OLD_TIMER_DISABLED"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap rollback_error ERR

snap() {
  local unit=$1
  printf '%s|%s|%s|%s|%s' \
    "$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p Result --value 2>/dev/null || true)"
}

require_running() {
  local label=$1 unit=$2 s a sub pid restarts result
  s=$(snap "$unit")
  IFS='|' read -r a sub pid restarts result <<<"$s"
  [[ "$a" == active && "$sub" == running && "$pid" != 0 && "$result" == success ]] || stop_now "${label}_not_running"
  printf '%s' "$s"
}

protected_ok() {
  "$PY" - "$OBS" "$CORE_E" "$CORE_M" "$BRIDGE_E" "$BRIDGE_M" <<'PY'
import json,pathlib,sys
o=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m=o.get("metrics") or {}
actual=(
    int(m.get("unrecoverable_core_gap_events",0) or 0),
    int(m.get("unrecoverable_core_gap_messages",0) or 0),
    int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),
    int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0),
)
expected=tuple(map(int,sys.argv[2:]))
raise SystemExit(0 if actual==expected else 1)
PY
}

[[ $EUID -eq 0 ]] || stop_now not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" ]] || stop_now required_path_missing
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_now git_owner_missing

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$OLD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_now repo_baseline_changed
protected_ok || stop_now protected_baseline_changed

if [[ "$(systemctl is-enabled "$OLD_TIMER" 2>/dev/null || true)" == enabled ]]; then
  OLD_TIMER_WAS_ENABLED=YES
fi
systemctl disable --now "$OLD_TIMER" >/dev/null 2>&1 || true
OLD_TIMER_DISABLED=YES

for _ in $(seq 1 100); do
  old_active=$(systemctl is-active "$OLD_SERVICE" 2>/dev/null || true)
  [[ "$old_active" != active && "$old_active" != activating ]] && break
  sleep 1
done
old_active=$(systemctl is-active "$OLD_SERVICE" 2>/dev/null || true)
[[ "$old_active" != active && "$old_active" != activating ]] || false

RES_PRE=$(require_running resident "$RES")
CAP_PRE=$(require_running capture "$CAP")
SIG_PRE=$(require_running signer "$SIG")
DIS_PRE=$(require_running discord "$DIS")
protected_ok || false

git_owner fetch --no-tags origin refs/heads/main
FETCHED=$(git_owner rev-parse FETCH_HEAD)
[[ "$FETCHED" == "$TARGET" ]] || false
git_owner merge --ff-only "$TARGET"
SOURCE_UPDATED=YES

[[ "$(git_owner rev-parse HEAD)" == "$TARGET" ]] || false
[[ "$(git_owner branch --show-current)" == main ]] || false
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || false

for f in \
  "$APP/src/flop_agent/close1_standalone_watch.py" \
  "$APP/src/flop_agent/close1_candidate_scanner.py" \
  "$SRC_SERVICE" \
  "$SRC_TIMER"
do
  [[ -f "$f" && "$(stat -c %a "$f")" == 644 ]] || false
done

runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$PY" - <<'PY'
from flop_agent import close1_standalone_watch as w
from flop_agent import close1_candidate_scanner as s
assert callable(w.run_once)
assert callable(s.fetch_candidate_scan)
assert "stable_shadow_leader" in open(s.__file__,encoding="utf-8").read()
PY

install -o root -g root -m 0644 "$SRC_SERVICE" "$DST_SERVICE"
install -o root -g root -m 0644 "$SRC_TIMER" "$DST_TIMER"
NEW_UNITS_INSTALLED=YES
systemctl daemon-reload
systemctl enable "$NEW_TIMER" >/dev/null

[[ "$(snap "$RES")" == "$RES_PRE" ]] || false
[[ "$(snap "$CAP")" == "$CAP_PRE" ]] || false
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || false
[[ "$(snap "$DIS")" == "$DIS_PRE" ]] || false
protected_ok || false

rm -f "$WATCH_STATE"
systemctl start "$NEW_SERVICE" || true

CLASSIFICATION=PRESSURE_SKIP_OR_NO_STATE
WATCH_DETAIL=none
if [[ -f "$WATCH_STATE" ]]; then
  WATCH_DETAIL=$("$PY" - "$WATCH_STATE" <<'PY'
import json,pathlib,sys
v=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
print(
    f"activated={str(v.get('activated')).lower()} "
    f"sweep={v.get('last_sweep')} "
    f"error={v.get('last_error')} "
    f"alert_at={v.get('last_alert_at')}"
)
PY
)
  if grep -q 'activated=true' <<<"$WATCH_DETAIL" && grep -q 'error=None' <<<"$WATCH_DETAIL"; then
    CLASSIFICATION=ACTIVE
  else
    CLASSIFICATION=INSTALLED_RETRYING
  fi
fi

systemctl start "$NEW_TIMER"
[[ "$(systemctl is-enabled "$NEW_TIMER")" == enabled ]] || false
[[ "$(systemctl is-active "$NEW_TIMER")" == active ]] || false
[[ "$(systemctl is-enabled "$OLD_TIMER" 2>/dev/null || true)" != enabled ]] || false
[[ "$(systemctl is-active "$OLD_TIMER" 2>/dev/null || true)" != active ]] || false

[[ "$(snap "$RES")" == "$RES_PRE" ]] || false
[[ "$(snap "$CAP")" == "$CAP_PRE" ]] || false
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || false
[[ "$(snap "$DIS")" == "$DIS_PRE" ]] || false
protected_ok || false

SOURCE_UPDATED=NO
OLD_TIMER_DISABLED=NO

echo "PROD569V1=PASS_STANDALONE_INSTALLED"
echo "SOURCE=$TARGET branch=main worktree=clean"
echo "STANDALONE_TIMER=active/enabled cadence=5m"
echo "OLD_DISCORD_ACTIVATION_TIMER=disabled/inactive"
echo "FIRST_RUN=$CLASSIFICATION $WATCH_DETAIL"
echo "LONG_RUNNING_SERVICES=UNCHANGED"
echo "TRADE=NO"
echo "DO_NOT_RERUN=YES"
