#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json

PRE=a4016accdef7b1df591d68d1bcdc54c7a9de7320
TARGET=58943a072eb0d752960e092970f06311344a8996

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

fail() {
  echo "PROD535V1=ERROR:$1"
  echo "MUTATION=NONE"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap 'fail rc_$?' ERR

[[ $EUID -eq 0 ]] || fail not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" ]] || fail required_path_missing
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || fail git_owner_missing
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

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] && CLEAN=YES || CLEAN=NO
echo "REPO=head:$HEAD branch:$BRANCH clean:$CLEAN expected_pre:$PRE"

echo "LONG_RUNNING=resident:$(snap technocore-safe-agent-resident.service) capture:$(snap technocore-safe-agent-lobby-capture.service) signer:$(snap technocore-safe-agent-signer.service) discord:$(snap technocore-safe-agent-discord.service)"

"$PY" - "$OBS" <<'PY'
import json, pathlib, sys
o=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m=o.get("metrics") or {}
print(
    "PROTECTED="
    f"core:{int(m.get('unrecoverable_core_gap_events',0) or 0)}/"
    f"{int(m.get('unrecoverable_core_gap_messages',0) or 0)} "
    f"bridge:{int(m.get('lobby_startup_bridge_unrecoverable_events',0) or 0)}/"
    f"{int(m.get('lobby_startup_bridge_unrecoverable_messages',0) or 0)}"
)
PY

TMPDIR=$(mktemp -d /tmp/prod535.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT
mkdir -p "$TMPDIR/pre" "$TMPDIR/target"

for unit in "${UNITS[@]}"; do
  installed="/etc/systemd/system/$unit"
  if [[ ! -f "$installed" ]]; then
    echo "UNIT=$unit disk:MISSING meta:NA loaded_gate:UNKNOWN fragment:UNKNOWN state:UNKNOWN"
    continue
  fi

  git_owner show "$PRE:packaging/oracle/$unit" > "$TMPDIR/pre/$unit"
  git_owner show "$TARGET:packaging/oracle/$unit" > "$TMPDIR/target/$unit"

  if cmp -s "$installed" "$TMPDIR/pre/$unit"; then
    disk=PRE
  elif cmp -s "$installed" "$TMPDIR/target/$unit"; then
    disk=TARGET
  else
    disk=OTHER
  fi

  meta=$(stat -c '%U:%G:%a' "$installed" 2>/dev/null || echo unknown)
  fragment=$(systemctl show "$unit" -p FragmentPath --value 2>/dev/null || true)
  cond=$(systemctl show "$unit" -p ExecCondition --value 2>/dev/null || true)
  [[ "$cond" == *tclk_timer_gate* ]] && gate=YES || gate=NO
  state=$(snap "$unit")
  echo "UNIT=$unit disk:$disk meta:$meta loaded_gate:$gate fragment:${fragment:-NONE} state:$state"
done

for timer in "${TIMERS[@]}"; do
  active=$(systemctl is-active "$timer" 2>/dev/null || true)
  enabled=$(systemctl is-enabled "$timer" 2>/dev/null || true)
  echo "TIMER=$timer active:${active:-UNKNOWN} enabled:${enabled:-UNKNOWN}"
done

echo "PROD535V1=PASS"
echo "MUTATION=NONE DAEMON_RELOAD=NONE SERVICE_ACTION=NONE SOURCE_ACTION=NONE"
echo "DO_NOT_RERUN=YES"