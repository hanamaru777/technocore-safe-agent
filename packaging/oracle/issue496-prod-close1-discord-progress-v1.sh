#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json
PROGRESS=/var/lib/technocore-safe-agent/observer/close1-discord-progress.json

PRE=9baa91be7267b22143c33a06df3c67e1074dba0d
TARGET=a4016accdef7b1df591d68d1bcdc54c7a9de7320
RES_PID=2462149
CAP_PID=2462148
SIG_PID=2462068
DIS_PID=2462020
CORE_E=124
CORE_M=5651120
BRIDGE_E=7
BRIDGE_M=567965

stop_rollout() {
  echo "PROD496V1=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "PROD496V1=ERROR:rc_$rc"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_rollout not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" && -f "$SAFETY" ]] || stop_rollout required_path_missing

OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_rollout git_owner_missing
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

safety_gate() {
  "$PY" - "$SAFETY" "$CORE_E" "$CORE_M" <<'PY'
import json, pathlib, sys
from datetime import UTC, datetime
p=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
core_e,core_m=map(int,sys.argv[2:4])
if (
    p.get("schema_version") != 1
    or p.get("health") != "ok"
    or p.get("unrecoverable_core_gap_events") != core_e
    or p.get("unrecoverable_core_gap_messages") != core_m
):
    raise RuntimeError("observer_safety_not_ok")
stamp=datetime.fromisoformat(str(p.get("updated_at","")).replace("Z","+00:00"))
age=(datetime.now(UTC)-stamp).total_seconds()
if not 0 <= age <= 300:
    raise RuntimeError("observer_safety_stale")
print(int(age))
PY
}

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$PRE" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_rollout repo_baseline_changed

RES=$(snap technocore-safe-agent-resident.service)
CAP=$(snap technocore-safe-agent-lobby-capture.service)
SIG=$(snap technocore-safe-agent-signer.service)
DIS=$(snap technocore-safe-agent-discord.service)
[[ "$RES" == "active|running|$RES_PID|0|success" ]] || stop_rollout resident_baseline_changed
[[ "$CAP" == "active|running|$CAP_PID|0|success" ]] || stop_rollout capture_baseline_changed
[[ "$SIG" == "active|running|$SIG_PID|0|success" ]] || stop_rollout signer_baseline_changed
[[ "$DIS" == "active|running|$DIS_PID|0|success" ]] || stop_rollout discord_baseline_changed

BASE_COUNTS=$(counts)
[[ "$BASE_COUNTS" == "$CORE_E|$CORE_M|$BRIDGE_E|$BRIDGE_M" ]] || stop_rollout protected_baseline_changed
SAFETY_AGE=$(safety_gate) || stop_rollout observer_safety_not_ok

git_owner fetch --quiet --no-tags origin main
[[ "$(git_owner rev-parse FETCH_HEAD)" == "$TARGET" ]] || stop_rollout remote_main_moved
git_owner merge-base --is-ancestor "$PRE" "$TARGET" || stop_rollout target_not_ff

ACTUAL=$(git_owner diff --name-only "$PRE" "$TARGET" | LC_ALL=C sort | tr '\n' '|')
EXPECTED='src/flop_agent/close1_discord_progress.py|src/flop_agent/close_call.py|src/flop_agent/discord_control.py|src/flop_agent/public_record.py|tests/test_close1_discord_progress.py|tests/test_close_call.py|'
[[ "$ACTUAL" == "$EXPECTED" ]] || stop_rollout target_diff_unexpected

git_owner merge --quiet --ff-only "$TARGET"
[[ "$(git_owner rev-parse HEAD)" == "$TARGET" && "$(git_owner branch --show-current)" == main ]] || stop_rollout source_update_mismatch
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_rollout worktree_dirty_after_update

runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$PY" - <<'PY'
from flop_agent import close1_discord_progress as progress
from flop_agent import discord_control
assert progress.POLL_INTERVAL_SECONDS == 300
assert progress.STATUS_INTERVAL_SECONDS == 1800
assert callable(progress.periodic_notices)
assert callable(discord_control.close1_progress_worker)
PY

[[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || stop_rollout resident_changed_before_restart
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_rollout capture_changed_before_restart
[[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_rollout signer_changed_before_restart
[[ "$(counts)" == "$BASE_COUNTS" ]] || stop_rollout protected_changed_before_restart

rm -f "$PROGRESS"
systemctl restart technocore-safe-agent-discord.service

NEW_DIS=''
for _ in $(seq 1 20); do
  CUR=$(snap technocore-safe-agent-discord.service)
  IFS='|' read -r a s p n r <<<"$CUR"
  if [[ "$a" == active && "$s" == running && "$p" != 0 && "$p" != "$DIS_PID" && "$n" == 0 && "$r" == success ]]; then
    NEW_DIS=$p
    break
  fi
  sleep 1
done
[[ -n "$NEW_DIS" ]] || stop_rollout discord_restart_not_stable

PROGRESS_READY=NO
for _ in $(seq 1 20); do
  if [[ -f "$PROGRESS" ]] && "$PY" - "$PROGRESS" <<'PY'
import json, pathlib, sys
p=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
assert p.get("schema_version")==1
assert isinstance(p.get("last_attempt_at"), str) and p["last_attempt_at"]
PY
  then
    PROGRESS_READY=YES
    break
  fi
  sleep 1
done
[[ "$PROGRESS_READY" == YES ]] || stop_rollout close1_progress_state_not_started

[[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || stop_rollout resident_changed_after_restart
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_rollout capture_changed_after_restart
[[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_rollout signer_changed_after_restart
[[ "$(snap technocore-safe-agent-discord.service)" == "active|running|$NEW_DIS|0|success" ]] || stop_rollout discord_unstable
[[ "$(counts)" == "$BASE_COUNTS" ]] || stop_rollout protected_counts_changed
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_rollout worktree_dirty_post

echo "PROD496V1=PASS"
echo "HEAD=$TARGET"
echo "SERVICES=resident:$RES_PID capture:$CAP_PID signer:$SIG_PID discord:$NEW_DIS"
echo "PROTECTED=core:$CORE_E/$CORE_M bridge:$BRIDGE_E/$BRIDGE_M"
echo "OBSERVER_SAFETY_AGE_S=$SAFETY_AGE"
echo "CLOSE1_DISCORD_PROGRESS=STARTED"
echo "MUTATION=ff_source+discord_restart_once"
echo "OTHER_RESTARTS=NO"
echo "EXTERNAL_WRITE=NO"
echo "DO_NOT_RERUN=YES"
