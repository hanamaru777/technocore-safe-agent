#!/usr/bin/env bash
# One-shot guarded Production rollout for Airdrop Action Inbox.
# Branch-only operational helper. DO NOT MERGE and DO NOT RERUN after any terminal result.
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
OBSERVER_STATE="$STATE/observer/observer-state.json"
AIRDROP_DIR="$STATE/airdrop-radar"
ACTION_STATE="$AIRDROP_DIR/action-inbox.json"
ACTION_LOCK="$AIRDROP_DIR/action-inbox.lock"

PRE=a114d4d414f20009088a6ca150044b0f75e52d26
TARGET=52f71d77fd79c8fb3cf3a53d94205ec7ec5888b7
CORE_EVENTS=117
CORE_MESSAGES=5083155

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service
MON_TIMER=technocore-safe-agent-airdrop-monitor.timer
NOT_TIMER=technocore-safe-agent-airdrop-notifier.timer
MON_SVC=technocore-safe-agent-airdrop-monitor.service
NOT_SVC=technocore-safe-agent-airdrop-notifier.service

stop() {
  local reason=$1
  trap - ERR
  echo "PROD329=STOP:$reason"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'stop unexpected_rc_$?' ERR

[[ $EUID -eq 0 ]] || stop run_as_root
[[ -d $APP/.git && -x $APP/.venv/bin/python ]] || stop production_checkout_or_venv_missing
[[ -f $OBSERVER_STATE ]] || stop observer_state_missing
[[ -d $AIRDROP_DIR ]] || stop airdrop_state_missing

OWNER=$(stat -c %U "$APP/.git") || stop git_owner_unreadable
[[ -n $OWNER ]] || stop git_owner_missing
git_owner() { sudo -u "$OWNER" git -C "$APP" "$@"; }
svc_value() { systemctl show "$1" -p "$2" --value; }

observer_snapshot() {
  sudo python3 - "$OBSERVER_STATE" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
d = json.loads(p.read_text("utf-8"))
m = d.get("metrics") or {}
print(
    d.get("health", {}).get("current", "missing"),
    m.get("unrecoverable_core_gap_events", "missing"),
    m.get("unrecoverable_core_gap_messages", "missing"),
)
PY
}

airdrop_snapshot() {
  sudo -u technocore env -i     PATH=/usr/bin:/bin     FLOP_STATE_DIR="$STATE"     PYTHONPATH="$APP/src"     "$APP/.venv/bin/python" - <<'PY'
from __future__ import annotations
import json
from datetime import UTC, datetime
from flop_agent import airdrop_ledger

base = airdrop_ledger.ledger_dir()
hb = json.loads((base / "monitor-heartbeat.json").read_text("utf-8"))
verified = airdrop_ledger.verify_ledger()
completed = hb.get("last_completed_at")
if not isinstance(completed, str):
    raise SystemExit("heartbeat_missing")
stamp = datetime.fromisoformat(completed.replace("Z", "+00:00"))
if stamp.tzinfo is None:
    raise SystemExit("heartbeat_timezone_missing")
age = max(0, int((datetime.now(UTC) - stamp.astimezone(UTC)).total_seconds()))
print(
    hb.get("outcome", "missing"),
    hb.get("radar_health", "missing"),
    age,
    verified.get("count", "missing"),
)
PY
}

common_gate() {
  local label=$1
  for svc in "$META" "$RES" "$CAP" "$SIG" "$DIS"; do
    systemctl is-active --quiet "$svc" || stop "$label:required_service_not_active:$svc"
  done
  systemctl is-active --quiet "$MON_TIMER" || stop "$label:monitor_timer_not_active"
  systemctl is-active --quiet "$NOT_TIMER" || stop "$label:notifier_timer_not_active"

  local health events messages
  read -r health events messages < <(observer_snapshot) || stop "$label:observer_state_unreadable"
  [[ $health == ok ]] || stop "$label:observer_health_not_ok:$health"
  [[ $events == "$CORE_EVENTS" && $messages == "$CORE_MESSAGES" ]] ||     stop "$label:protected_core_changed:$events/$messages"

  local outcome radar age ledger_count
  read -r outcome radar age ledger_count < <(airdrop_snapshot) || stop "$label:airdrop_state_unreadable"
  [[ $outcome == recorded ]] || stop "$label:monitor_outcome_not_recorded:$outcome"
  [[ $radar == ok || $radar == degraded ]] || stop "$label:radar_health_not_allowed:$radar"
  [[ $age =~ ^[0-9]+$ && $age -le 1800 ]] || stop "$label:heartbeat_stale:$age"
  [[ $ledger_count =~ ^[0-9]+$ ]] || stop "$label:ledger_count_invalid:$ledger_count"

  echo "PROD329_GATE=$label observer=$health core=$events/$messages radar=$radar heartbeat_age=$age ledger_count=$ledger_count"
}

cd "$APP"
[[ "$(git_owner symbolic-ref --short HEAD)" == main ]] || stop branch_not_main
[[ "$(git_owner rev-parse HEAD)" == "$PRE" ]] || stop "unexpected_production_head:$(git_owner rev-parse HEAD)"
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop dirty_worktree

[[ ! -e $ACTION_STATE ]] || stop action_inbox_state_preexists
[[ ! -e $ACTION_LOCK ]] || stop action_inbox_lock_preexists

declare -A PID_PRE RESTART_PRE
for svc in "$RES" "$CAP" "$SIG" "$DIS"; do
  PID_PRE["$svc"]=$(svc_value "$svc" MainPID)
  RESTART_PRE["$svc"]=$(svc_value "$svc" NRestarts)
  [[ ${PID_PRE[$svc]:-0} =~ ^[1-9][0-9]*$ ]] || stop "invalid_mainpid:$svc"
done

common_gate pre1
sleep 15
common_gate pre2

git_owner fetch --no-tags origin main
REMOTE=$(git_owner rev-parse origin/main)
[[ $REMOTE == "$TARGET" ]] || stop "origin_main_moved:expected=$TARGET:actual=$REMOTE"
git_owner merge-base --is-ancestor "$PRE" "$TARGET" || stop target_not_fast_forward
[[ "$(git_owner rev-list --count "$TARGET..$PRE")" == 0 ]] || stop target_behind_production

EXPECTED=$(cat <<'EOF' | LC_ALL=C sort
src/flop_agent/airdrop_approval.py
src/flop_agent/discord_control.py
src/flop_agent/discord_tclk_approval.py
tests/test_airdrop_approval.py
EOF
)
ACTUAL=$(git_owner diff --name-only "$PRE..$TARGET" | LC_ALL=C sort)
[[ $ACTUAL == "$EXPECTED" ]] || {
  echo "PROD329=STOP:changed_file_allowlist_mismatch" >&2
  echo "ACTUAL_CHANGED_PATHS:" >&2
  printf '%s
' "$ACTUAL" >&2
  echo "DO_NOT_RERUN=YES" >&2
  exit 1
}
for path in   src/flop_agent/airdrop_approval.py   src/flop_agent/discord_control.py   src/flop_agent/discord_tclk_approval.py; do
  git_owner cat-file -e "$TARGET:$path" || stop "target_missing_runtime_path:$path"
done

CUTOVER_STARTED=0
DONE=0
rollback() {
  local rc=$?
  trap - ERR
  if [[ $DONE -eq 0 && $CUTOVER_STARTED -eq 1 ]]; then
    set +e
    cd "$APP"
    git_owner reset --hard "$PRE" >/dev/null 2>&1
    systemctl restart "$DIS" >/dev/null 2>&1
    if [[ ! -e $ACTION_STATE ]]; then
      rm -f -- "$ACTION_LOCK"
    fi
    echo "PROD329_ROLLBACK=COMPLETE code=$PRE discord_restored=YES" >&2
  fi
  exit "$rc"
}
trap rollback EXIT

echo "PROD329_PREFLIGHT=PASS pre=$PRE target=$TARGET"

CUTOVER_STARTED=1
git_owner merge --ff-only "$TARGET" >/dev/null
[[ "$(git_owner rev-parse HEAD)" == "$TARGET" ]] || stop post_merge_head_mismatch

systemctl restart "$DIS"
for _ in $(seq 1 20); do
  systemctl is-active --quiet "$DIS" && break
  sleep 1
done
systemctl is-active --quiet "$DIS" || stop discord_not_active_after_restart

SMOKE=$(sudo -u technocore env -i   PATH=/usr/bin:/bin   FLOP_STATE_DIR="$STATE"   PYTHONPATH="$APP/src"   "$APP/.venv/bin/python" - <<'PY'
from flop_agent import discord_control
control = discord_control.Control({"1"}, "2")
result = control.command("1", "/airdrop-approvals", "2")
if result.get("ok") is not True:
    raise SystemExit("control_command_failed")
message = str(result.get("message") or "")
if "承認待ちはありません" not in message:
    raise SystemExit("unexpected_control_message")
print("PASS")
PY
) || stop local_action_inbox_smoke_failed
[[ $SMOKE == PASS ]] || stop local_action_inbox_smoke_unexpected

[[ ! -e $ACTION_STATE ]] || stop rollout_fabricated_action_request
[[ -f $ACTION_LOCK ]] || stop action_inbox_lock_not_created
[[ "$(stat -c %U "$ACTION_LOCK")" == technocore ]] || stop action_inbox_lock_owner_wrong
[[ "$(stat -c %a "$ACTION_LOCK")" == 640 ]] || stop action_inbox_lock_mode_wrong

for svc in "$RES" "$CAP" "$SIG"; do
  [[ "$(svc_value "$svc" MainPID)" == "${PID_PRE[$svc]}" ]] || stop "unexpected_pid_change:$svc"
  [[ "$(svc_value "$svc" NRestarts)" == "${RESTART_PRE[$svc]}" ]] || stop "unexpected_restart_change:$svc"
done
NEW_DIS_PID=$(svc_value "$DIS" MainPID)
NEW_DIS_NR=$(svc_value "$DIS" NRestarts)
[[ $NEW_DIS_PID =~ ^[1-9][0-9]*$ && $NEW_DIS_PID != "${PID_PRE[$DIS]}" ]] || stop discord_pid_not_changed
[[ $NEW_DIS_NR == "${RESTART_PRE[$DIS]}" ]] || stop discord_unexpected_auto_restart

common_gate post
[[ "$(svc_value "$MON_SVC" Result)" == success ]] || stop monitor_last_result_not_success
[[ "$(svc_value "$MON_SVC" ExecMainStatus)" == 0 ]] || stop monitor_last_exit_nonzero
[[ "$(svc_value "$NOT_SVC" Result)" == success ]] || stop notifier_last_result_not_success
[[ "$(svc_value "$NOT_SVC" ExecMainStatus)" == 0 ]] || stop notifier_last_exit_nonzero
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop final_dirty_worktree

read -r FINAL_HEALTH FINAL_EVENTS FINAL_MESSAGES < <(observer_snapshot)
read -r FINAL_OUTCOME FINAL_RADAR FINAL_AGE FINAL_LEDGER_COUNT < <(airdrop_snapshot)

DONE=1
trap - EXIT

printf '%s
'   "PROD329=PASS"   "PRE_SHA=$PRE"   "POST_SHA=$(git_owner rev-parse HEAD)"   "PROTECTED_CORE=$FINAL_EVENTS/$FINAL_MESSAGES OBSERVER_HEALTH=$FINAL_HEALTH"   "AIRDROP_MONITOR=$FINAL_OUTCOME RADAR_HEALTH=$FINAL_RADAR HEARTBEAT_AGE=$FINAL_AGE LEDGER_COUNT=$FINAL_LEDGER_COUNT"   "AIRDROP_TIMERS=$(systemctl is-active "$MON_TIMER")/$(systemctl is-active "$NOT_TIMER")"   "RESIDENT_PRESERVED=${PID_PRE[$RES]}/NRestarts=${RESTART_PRE[$RES]}"   "CAPTURE_PRESERVED=${PID_PRE[$CAP]}/NRestarts=${RESTART_PRE[$CAP]}"   "SIGNER_PRESERVED=${PID_PRE[$SIG]}/NRestarts=${RESTART_PRE[$SIG]}"   "DISCORD_RESTARTED=${PID_PRE[$DIS]}->$NEW_DIS_PID NRestarts=$NEW_DIS_NR"   "ACTION_INBOX_LOCAL_SMOKE=PASS pending=0 request_json=ABSENT lock_mode=640"   "FLOP_EXTERNAL_WRITE=NO X_WRITE=NO CLAIM=NO SPEND=NO SUBMIT=NO SIGNER_CALL=NO"   "DO_NOT_RERUN=YES"
