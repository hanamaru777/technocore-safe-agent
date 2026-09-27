#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OLD=498d332ff70cc6e5487982e27711097793a16c86
TARGET=8a6053326fbd9986a1845ae7e2c0f0deb896af41
ACTIVATOR=/usr/local/sbin/technocore-close1-discord-activate-if-safe
TIMER=technocore-safe-agent-close1-discord-activation.timer
MARKER=/var/lib/technocore-safe-agent/resident/close1-discord-runtime-activated.json
BLOCKED=/var/lib/technocore-safe-agent/resident/close1-discord-runtime-blocked.json
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service
RES_PID=2462149
CAP_PID=2708820
SIG_PID=2462068
DIS_PID=2660066
CORE_E=143
CORE_M=5652707
BRIDGE_E=26
BRIDGE_M=569552

TIMER_DISABLED=NO
SOURCE_UPDATED=NO
ACTIVATOR_PATCHED=NO
BACKUP=$(mktemp /tmp/prod564-activator.XXXXXX)
trap 'rm -f "$BACKUP"' EXIT

stop_now() {
  echo "PROD564V1=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 0
}

OWNER=''
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

rollback_error() {
  local rc=$?
  trap - ERR
  if [[ "$ACTIVATOR_PATCHED" == YES && -s "$BACKUP" ]]; then
    cp "$BACKUP" "$ACTIVATOR" || true
    chmod 0755 "$ACTIVATOR" || true
  fi
  if [[ "$SOURCE_UPDATED" == YES && -n "$OWNER" ]]; then
    git_owner reset --hard "$OLD" >/dev/null 2>&1 || true
  fi
  if [[ "$TIMER_DISABLED" == YES ]]; then
    systemctl enable --now "$TIMER" >/dev/null 2>&1 || true
  fi
  echo "PROD564V1=ERROR:rc_$rc"
  echo "ROLLBACK=activator:$ACTIVATOR_PATCHED source:$SOURCE_UPDATED timer:$TIMER_DISABLED"
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
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" && -f "$ACTIVATOR" ]] || stop_now required_path_missing
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_now git_owner_missing

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$OLD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_now repo_baseline_changed
[[ ! -e "$MARKER" ]] || stop_now old_runtime_already_activated
[[ ! -e "$BLOCKED" ]] || stop_now activation_already_blocked
[[ "$(systemctl is-enabled "$TIMER" 2>/dev/null || true)" == enabled ]] || stop_now timer_not_enabled
[[ "$(systemctl is-active "$TIMER" 2>/dev/null || true)" == active ]] || stop_now timer_not_active

[[ "$(snap "$RES")" == "active|running|$RES_PID|0|success" ]] || stop_now resident_baseline_changed
[[ "$(snap "$CAP")" == "active|running|$CAP_PID|0|success" ]] || stop_now capture_baseline_changed
[[ "$(snap "$SIG")" == "active|running|$SIG_PID|0|success" ]] || stop_now signer_baseline_changed
[[ "$(snap "$DIS")" == "active|running|$DIS_PID|0|success" ]] || stop_now discord_baseline_changed
protected_ok || stop_now protected_baseline_changed

OLD_LINE="EXPECTED_HEAD=$OLD"
TARGET_LINE="EXPECTED_HEAD=$TARGET"
[[ "$(grep -Fxc "$OLD_LINE" "$ACTIVATOR")" == 1 ]] || stop_now activator_old_pin_unexpected
[[ "$(grep -Fxc "$TARGET_LINE" "$ACTIVATOR")" == 0 ]] || stop_now activator_target_already_present
cp "$ACTIVATOR" "$BACKUP"

systemctl disable --now "$TIMER"
TIMER_DISABLED=YES
[[ "$(systemctl is-active "$TIMER" 2>/dev/null || true)" != active ]] || false

git_owner fetch --no-tags origin refs/heads/main
FETCHED=$(git_owner rev-parse FETCH_HEAD)
[[ "$FETCHED" == "$TARGET" ]] || false

git_owner merge --ff-only "$TARGET"
SOURCE_UPDATED=YES
[[ "$(git_owner rev-parse HEAD)" == "$TARGET" ]] || false
[[ "$(git_owner branch --show-current)" == main ]] || false
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || false

[[ "$(stat -c %a "$APP/src/flop_agent/close1_candidate_scanner.py")" == 644 ]] || false
[[ "$(stat -c %a "$APP/src/flop_agent/close1_discord_progress.py")" == 644 ]] || false

"$PY" - "$ACTIVATOR" "$OLD_LINE" "$TARGET_LINE" <<'PY'
import os,pathlib,sys,tempfile
path=pathlib.Path(sys.argv[1]);old=sys.argv[2];new=sys.argv[3]
text=path.read_text("utf-8")
if text.count(old)!=1 or new in text:
    raise SystemExit(1)
updated=text.replace(old,new,1)
with tempfile.NamedTemporaryFile("w",encoding="utf-8",dir=path.parent,prefix=f".{path.name}.",suffix=".tmp",delete=False) as h:
    tmp=h.name
    h.write(updated)
    h.flush()
    os.fsync(h.fileno())
os.replace(tmp,path)
os.chmod(path,0o755)
PY
ACTIVATOR_PATCHED=YES
[[ "$(grep -Fxc "$TARGET_LINE" "$ACTIVATOR")" == 1 ]] || false
[[ "$(grep -Fxc "$OLD_LINE" "$ACTIVATOR")" == 0 ]] || false

runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$PY" - <<'PY'
from flop_agent import close1_candidate_scanner as scanner
assert callable(scanner.fetch_candidate_scan)
assert "stable_shadow_leader" in open(scanner.__file__, encoding="utf-8").read()
PY

[[ ! -e "$MARKER" && ! -e "$BLOCKED" ]] || false
[[ "$(snap "$RES")" == "active|running|$RES_PID|0|success" ]] || false
[[ "$(snap "$CAP")" == "active|running|$CAP_PID|0|success" ]] || false
[[ "$(snap "$SIG")" == "active|running|$SIG_PID|0|success" ]] || false
[[ "$(snap "$DIS")" == "active|running|$DIS_PID|0|success" ]] || false
protected_ok

systemctl enable --now "$TIMER"
TIMER_DISABLED=NO
[[ "$(systemctl is-enabled "$TIMER")" == enabled ]] || false
[[ "$(systemctl is-active "$TIMER")" == active ]] || false

echo "PROD564V1=PASS_REPINNED"
echo "SOURCE=$TARGET branch=main worktree=clean"
echo "ACTIVATOR_EXPECTED_HEAD=$TARGET"
echo "TIMER=active/enabled cadence=5m"
echo "SERVICES_RESTARTED=NONE"
echo "SHADOW_LEADER_SCANNER=ON_DISK_READY"
echo "DO_NOT_RERUN=YES"
