#!/usr/bin/env bash
set -euo pipefail
umask 022

APP=/opt/technocore-safe-agent
APP_PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
PRE=041b830d3b0ffd17ef95f8d889922f20d3ac6631
TARGET=b8c63f865856d5004f8d310eb8ff4c31dbd7ffb0
EXPECTED_CORE_EVENTS=121
EXPECTED_CORE_MESSAGES=5650187
EXPECTED_BRIDGE_EVENTS=4
EXPECTED_BRIDGE_MESSAGES=567032
PRE_RESIDENT_PID=2256397
PRE_CAPTURE_PID=2256396
PRE_SIGNER_PID=2256324
PRE_DISCORD_PID=2277537

echo '=== PROD452 CAPTURE + DISCORD ROLLOUT V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

stop_rollout() {
  echo "PROD452V1=STOP:$1"
  echo 'DO_NOT_RERUN=YES'
  exit 0
}

[[ $EUID -eq 0 ]] || stop_rollout not_root
[[ -d "$APP/.git" && -x "$APP_PY" && -f "$OBS" ]] || stop_rollout required_path_missing
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_rollout git_owner_missing

git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

snapshot() {
  local unit=$1
  local active sub pid nr result
  active=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  printf '%s|%s|%s|%s|%s\n' "$active" "$sub" "$pid" "$nr" "$result"
}

state_line() {
  "$APP_PY" - "$OBS" <<'PY'
import json
import pathlib
import sys
from datetime import UTC, datetime

p = pathlib.Path(sys.argv[1])
o = json.loads(p.read_text('utf-8'))
m = o.get('metrics') or {}
updated = o.get('updated_at')
age = -1.0
if isinstance(updated, str):
    try:
        dt = datetime.fromisoformat(updated.replace('Z', '+00:00'))
        age = (datetime.now(UTC) - dt.astimezone(UTC)).total_seconds()
    except ValueError:
        pass
print('|'.join([
    str(int(m.get('unrecoverable_core_gap_events', 0) or 0)),
    str(int(m.get('unrecoverable_core_gap_messages', 0) or 0)),
    str(int(m.get('lobby_startup_bridge_unrecoverable_events', 0) or 0)),
    str(int(m.get('lobby_startup_bridge_unrecoverable_messages', 0) or 0)),
    str(int((o.get('cursors') or {}).get('lobby', 0) or 0)),
    str((o.get('health') or {}).get('current') or 'unknown'),
    f'{age:.1f}',
]))
PY
}

require_state() {
  local phase=$1 line ce cm be bm cursor health age
  line=$(state_line)
  IFS='|' read -r ce cm be bm cursor health age <<<"$line"
  echo "STATE=$phase CORE=$ce/$cm BRIDGE=$be/$bm LOBBY_CURSOR=$cursor HEALTH=$health AGE=$age"
  [[ "$ce" == "$EXPECTED_CORE_EVENTS" && "$cm" == "$EXPECTED_CORE_MESSAGES" ]] || stop_rollout "${phase}_protected_core_changed"
  [[ "$be" == "$EXPECTED_BRIDGE_EVENTS" && "$bm" == "$EXPECTED_BRIDGE_MESSAGES" ]] || stop_rollout "${phase}_startup_bridge_changed"
  "$APP_PY" - "$age" <<'PY' || exit 41
import sys
age=float(sys.argv[1])
raise SystemExit(0 if 0 <= age <= 120 else 1)
PY
  [[ $? -eq 0 ]] || stop_rollout "${phase}_observer_stale"
  printf '%s\n' "$cursor"
}

echo '--- PRE REPO / SERVICES ---'
HEAD=$(git_owner rev-parse HEAD 2>/dev/null || true)
BRANCH=$(git_owner branch --show-current 2>/dev/null || true)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "PRE_HEAD=$HEAD"
echo "PRE_BRANCH=$BRANCH"
[[ -z "$WORKTREE" ]] && echo 'PRE_WORKTREE_CLEAN=YES' || echo 'PRE_WORKTREE_CLEAN=NO'
[[ "$HEAD" == "$PRE" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_rollout repo_baseline_changed

RES_PRE=$(snapshot technocore-safe-agent-resident.service)
CAP_PRE=$(snapshot technocore-safe-agent-lobby-capture.service)
SIG_PRE=$(snapshot technocore-safe-agent-signer.service)
DIS_PRE=$(snapshot technocore-safe-agent-discord.service)
echo "PRE_SERVICE=RESIDENT SNAPSHOT=$RES_PRE"
echo "PRE_SERVICE=CAPTURE SNAPSHOT=$CAP_PRE"
echo "PRE_SERVICE=SIGNER SNAPSHOT=$SIG_PRE"
echo "PRE_SERVICE=DISCORD SNAPSHOT=$DIS_PRE"
[[ "$RES_PRE" == "active|running|$PRE_RESIDENT_PID|0|success" ]] || stop_rollout resident_baseline_changed
[[ "$CAP_PRE" == "active|running|$PRE_CAPTURE_PID|0|success" ]] || stop_rollout capture_baseline_changed
[[ "$SIG_PRE" == "active|running|$PRE_SIGNER_PID|0|success" ]] || stop_rollout signer_baseline_changed
[[ "$DIS_PRE" == "active|running|$PRE_DISCORD_PID|0|success" ]] || stop_rollout discord_baseline_changed

PRE_CURSOR=$(require_state PRE | tail -n1)

echo '--- FETCH / TARGET GATES ---'
git_owner fetch --no-tags origin main
REMOTE_MAIN=$(git_owner rev-parse FETCH_HEAD)
echo "REMOTE_MAIN=$REMOTE_MAIN"
[[ "$REMOTE_MAIN" == "$TARGET" ]] || stop_rollout remote_main_moved
git_owner merge-base --is-ancestor "$PRE" "$TARGET" || stop_rollout target_not_ff

ACTUAL_DIFF=$(git_owner diff --name-only "$PRE" "$TARGET" | LC_ALL=C sort | tr '\n' '|')
EXPECTED_DIFF='src/flop_agent/discord_outcome_scorecard.py|src/flop_agent/observer_lobby_capture.py|tests/test_discord_outcome_scorecard.py|tests/test_observer_lobby_capture.py|'
echo "TARGET_DIFF=$ACTUAL_DIFF"
[[ "$ACTUAL_DIFF" == "$EXPECTED_DIFF" ]] || stop_rollout target_diff_unexpected

echo '--- FAST-FORWARD SOURCE ---'
git_owner merge --ff-only "$TARGET"
POST_HEAD=$(git_owner rev-parse HEAD)
POST_BRANCH=$(git_owner branch --show-current)
POST_WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
echo "POST_HEAD=$POST_HEAD"
echo "POST_BRANCH=$POST_BRANCH"
[[ -z "$POST_WORKTREE" ]] && echo 'POST_WORKTREE_CLEAN=YES' || echo 'POST_WORKTREE_CLEAN=NO'
[[ "$POST_HEAD" == "$TARGET" && "$POST_BRANCH" == main && -z "$POST_WORKTREE" ]] || stop_rollout source_update_mismatch

for file in src/flop_agent/observer_lobby_capture.py src/flop_agent/discord_outcome_scorecard.py; do
  chmod 0644 "$APP/$file"
  meta=$(stat -c '%a|%U|%G' "$APP/$file")
  echo "SOURCE_FILE=$file META=$meta"
  [[ "$meta" == '644|root|root' ]] || stop_rollout source_mode_owner_mismatch
done

echo '--- IMPORT SMOKE ---'
runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$APP_PY" - <<'PY'
from flop_agent import observer_lobby_capture as capture
from flop_agent import discord_outcome_scorecard as score
assert capture.MAX_ROWS == 300_000
assert capture.MAX_PROTECTED_ROWS == 2_000_000
assert capture.MAX_PROTECTED_ROWS > capture.MAX_ROWS
assert callable(capture._prune)
assert callable(score._digest)
print('SOURCE_IMPORT_SMOKE=PASS')
PY

[[ "$(snapshot technocore-safe-agent-resident.service)" == "$RES_PRE" ]] || stop_rollout resident_changed_before_restart
[[ "$(snapshot technocore-safe-agent-signer.service)" == "$SIG_PRE" ]] || stop_rollout signer_changed_before_restart

echo '--- CAPTURE-ONLY RESTART ---'
systemctl restart technocore-safe-agent-lobby-capture.service
NEW_CAPTURE_PID=''
for _ in $(seq 1 30); do
  cap=$(snapshot technocore-safe-agent-lobby-capture.service)
  IFS='|' read -r a s p n r <<<"$cap"
  if [[ "$a" == active && "$s" == running && "$p" != 0 && "$p" != "$PRE_CAPTURE_PID" && "$n" == 0 && "$r" == success ]]; then
    NEW_CAPTURE_PID=$p
    break
  fi
  sleep 1
done
[[ -n "$NEW_CAPTURE_PID" ]] || stop_rollout capture_restart_not_stable
echo "NEW_CAPTURE_PID=$NEW_CAPTURE_PID"
sleep 10

[[ "$(snapshot technocore-safe-agent-resident.service)" == "$RES_PRE" ]] || stop_rollout resident_changed_after_capture_restart
[[ "$(snapshot technocore-safe-agent-signer.service)" == "$SIG_PRE" ]] || stop_rollout signer_changed_after_capture_restart

echo '--- DISCORD-ONLY RESTART ---'
systemctl restart technocore-safe-agent-discord.service
NEW_DISCORD_PID=''
for _ in $(seq 1 30); do
  dis=$(snapshot technocore-safe-agent-discord.service)
  IFS='|' read -r a s p n r <<<"$dis"
  if [[ "$a" == active && "$s" == running && "$p" != 0 && "$p" != "$PRE_DISCORD_PID" && "$n" == 0 && "$r" == success ]]; then
    NEW_DISCORD_PID=$p
    break
  fi
  sleep 1
done
[[ -n "$NEW_DISCORD_PID" ]] || stop_rollout discord_restart_not_stable
echo "NEW_DISCORD_PID=$NEW_DISCORD_PID"

echo '--- 120S ACCEPTANCE WATCH ---'
LAST_CURSOR=$PRE_CURSOR
for phase in T0 T30 T60 T90 T120; do
  if [[ "$phase" != T0 ]]; then sleep 30; fi
  [[ "$(snapshot technocore-safe-agent-resident.service)" == "$RES_PRE" ]] || stop_rollout "${phase}_resident_changed"
  [[ "$(snapshot technocore-safe-agent-signer.service)" == "$SIG_PRE" ]] || stop_rollout "${phase}_signer_changed"
  [[ "$(snapshot technocore-safe-agent-lobby-capture.service)" == "active|running|$NEW_CAPTURE_PID|0|success" ]] || stop_rollout "${phase}_capture_unstable"
  [[ "$(snapshot technocore-safe-agent-discord.service)" == "active|running|$NEW_DISCORD_PID|0|success" ]] || stop_rollout "${phase}_discord_unstable"
  CURSOR=$(require_state "$phase" | tail -n1)
  [[ "$CURSOR" -ge "$LAST_CURSOR" ]] || stop_rollout "${phase}_lobby_cursor_regressed"
  LAST_CURSOR=$CURSOR
done

[[ "$LAST_CURSOR" -gt "$PRE_CURSOR" ]] || stop_rollout lobby_cursor_not_advancing
FINAL_LINE=$(state_line)
IFS='|' read -r _ _ _ _ _ FINAL_HEALTH FINAL_AGE <<<"$FINAL_LINE"
[[ "$FINAL_HEALTH" == ok ]] || stop_rollout final_observer_not_ok

echo '--- FINAL AUXILIARY HEALTH ---'
echo "AIRDROP_MONITOR_TIMER_ACTIVE=$(systemctl is-active technocore-safe-agent-airdrop-monitor.timer 2>/dev/null || true)"
echo "AIRDROP_MONITOR_TIMER_ENABLED=$(systemctl is-enabled technocore-safe-agent-airdrop-monitor.timer 2>/dev/null || true)"
echo "AIRDROP_NOTIFIER_TIMER_ACTIVE=$(systemctl is-active technocore-safe-agent-airdrop-notifier.timer 2>/dev/null || true)"
echo "AIRDROP_NOTIFIER_TIMER_ENABLED=$(systemctl is-enabled technocore-safe-agent-airdrop-notifier.timer 2>/dev/null || true)"

echo 'CAPTURE_RESTARTS_AUTHORIZED=1'
echo 'DISCORD_RESTARTS_AUTHORIZED=1'
echo 'RESIDENT_RESTART=NO'
echo 'SIGNER_RESTART=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'SYNTHETIC_DISCORD_MESSAGE=NO'
echo 'TECHNOCORE_WRITE=NO'
echo 'FLOP_WRITE=NO'
echo 'X_WRITE=NO'
echo '=== PROD452_CAPTURE_DISCORD_ROLLOUT_V1=PASS ==='
echo 'DO_NOT_RERUN=YES'
