#!/usr/bin/env bash
# One-shot guarded Production rollout for FLOP Airdrop Staging Bridge.
# Branch-only operational helper. DO NOT MERGE. Any terminal result is DO_NOT_RERUN.
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
OBSERVER_STATE="$STATE/observer/observer-state.json"
AIRDROP_DIR="$STATE/airdrop-radar"
HEARTBEAT="$AIRDROP_DIR/monitor-heartbeat.json"
MON_CONFIG="$AIRDROP_DIR/monitor-config.json"
ACTION_STATE="$AIRDROP_DIR/action-inbox.json"
CANDIDATE_STATE="$AIRDROP_DIR/action-candidates.json"
CANDIDATE_LOCK="$AIRDROP_DIR/action-candidates.lock"

PRE=52f71d77fd79c8fb3cf3a53d94205ec7ec5888b7
TARGET=cd8e91d26f06c2de3a549f5e8c22a65bfc38711c
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
  echo "PROD333=STOP:$reason"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'stop unexpected_rc_$?' ERR

[[ $EUID -eq 0 ]] || stop run_as_root
[[ -d $APP/.git && -x $APP/.venv/bin/python ]] || stop production_checkout_or_venv_missing
[[ -f $OBSERVER_STATE && -f $HEARTBEAT ]] || stop production_state_missing

OWNER=$(stat -c %U "$APP/.git") || stop git_owner_unreadable
[[ -n $OWNER ]] || stop git_owner_missing
git_owner() { sudo -u "$OWNER" git -C "$APP" "$@"; }
svc_value() { systemctl show "$1" -p "$2" --value; }

observer_snapshot() {
  sudo python3 - "$OBSERVER_STATE" <<'PY'
import json, pathlib, sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m=d.get("metrics") or {}
print(
    (d.get("health") or {}).get("current","missing"),
    m.get("unrecoverable_core_gap_events","missing"),
    m.get("unrecoverable_core_gap_messages","missing"),
)
PY
}

airdrop_snapshot() {
  sudo -u technocore env -i     PATH=/usr/bin:/bin     FLOP_STATE_DIR="$STATE"     PYTHONPATH="$APP/src"     "$APP/.venv/bin/python" - <<'PY'
from __future__ import annotations
import json
from datetime import UTC, datetime
from flop_agent import airdrop_ledger

base=airdrop_ledger.ledger_dir()
hb=json.loads((base/"monitor-heartbeat.json").read_text("utf-8"))
verified=airdrop_ledger.verify_ledger()
completed=hb.get("last_completed_at")
if not isinstance(completed,str):
    raise SystemExit("heartbeat_missing")
stamp=datetime.fromisoformat(completed.replace("Z","+00:00"))
if stamp.tzinfo is None:
    raise SystemExit("heartbeat_timezone_missing")
age=max(0,int((datetime.now(UTC)-stamp.astimezone(UTC)).total_seconds()))
print(
    hb.get("outcome","missing"),
    hb.get("radar_health","missing"),
    age,
    verified.get("count","missing"),
    hb.get("staging_outcome","pre_feature"),
    hb.get("staged_approvals",0),
    hb.get("staging_error_type") or "none",
)
PY
}

action_pending_count() {
  sudo -u technocore env -i     PATH=/usr/bin:/bin     FLOP_STATE_DIR="$STATE"     PYTHONPATH="$APP/src"     "$APP/.venv/bin/python" - <<'PY'
from pathlib import Path
import json
from flop_agent import airdrop_approval
p=airdrop_approval.state_path()
if not p.exists():
    print(0)
else:
    d=json.loads(p.read_text("utf-8"))
    if d.get("schema_version") != 1 or not isinstance(d.get("requests"),dict):
        raise SystemExit("action_inbox_invalid")
    print(sum(
        1 for r in d["requests"].values()
        if isinstance(r,dict) and r.get("status") == "pending"
    ))
PY
}

common_gate() {
  local label=$1
  for svc in "$META" "$RES" "$CAP" "$SIG" "$DIS"; do
    systemctl is-active --quiet "$svc" || stop "$label:required_service_not_active:$svc"
  done
  [[ "$(systemctl is-active "$MON_TIMER")" == active ]] || stop "$label:monitor_timer_not_active"
  [[ "$(systemctl is-enabled "$MON_TIMER")" == enabled ]] || stop "$label:monitor_timer_not_enabled"
  [[ "$(systemctl is-active "$NOT_TIMER")" == active ]] || stop "$label:notifier_timer_not_active"
  [[ "$(systemctl is-enabled "$NOT_TIMER")" == enabled ]] || stop "$label:notifier_timer_not_enabled"

  local health events messages
  read -r health events messages < <(observer_snapshot) || stop "$label:observer_unreadable"
  [[ $health == ok ]] || stop "$label:observer_health_not_ok:$health"
  [[ $events == "$CORE_EVENTS" && $messages == "$CORE_MESSAGES" ]] ||     stop "$label:protected_core_changed:$events/$messages"

  local outcome radar age ledger_count staging staged staging_error
  read -r outcome radar age ledger_count staging staged staging_error < <(airdrop_snapshot) ||     stop "$label:airdrop_state_unreadable"
  [[ $outcome == recorded ]] || stop "$label:monitor_outcome_not_recorded:$outcome"
  [[ $radar == ok || $radar == degraded ]] || stop "$label:radar_health_not_allowed:$radar"
  [[ $age =~ ^[0-9]+$ && $age -le 1800 ]] || stop "$label:heartbeat_stale:$age"
  [[ $ledger_count =~ ^[0-9]+$ ]] || stop "$label:ledger_count_invalid:$ledger_count"
  echo "PROD333_GATE=$label observer=$health core=$events/$messages radar=$radar heartbeat_age=$age ledger_count=$ledger_count staging=$staging staged=$staged staging_error=$staging_error"
}

scan_wait_seconds() {
  sudo python3 - "$HEARTBEAT" "$MON_CONFIG" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from datetime import UTC, datetime
hb=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
cfg_path=pathlib.Path(sys.argv[2])
floor=300
if cfg_path.exists():
    cfg=json.loads(cfg_path.read_text("utf-8"))
    raw=cfg.get("minimum_scan_interval_seconds")
    if isinstance(raw,int) and raw >= 300:
        floor=raw
last=hb.get("last_attempt_at")
if not isinstance(last,str):
    print(0)
    raise SystemExit
stamp=datetime.fromisoformat(last.replace("Z","+00:00"))
if stamp.tzinfo is None:
    raise SystemExit("heartbeat_timezone_missing")
elapsed=(datetime.now(UTC)-stamp.astimezone(UTC)).total_seconds()
remaining=max(0,int(floor-elapsed)+2)
if remaining > floor+5:
    raise SystemExit("scan_wait_invalid")
print(remaining)
PY
}

cd "$APP"
[[ "$(git_owner symbolic-ref --short HEAD)" == main ]] || stop branch_not_main
[[ "$(git_owner rev-parse HEAD)" == "$PRE" ]] || stop "unexpected_production_head:$(git_owner rev-parse HEAD)"
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop dirty_worktree

[[ ! -e $CANDIDATE_STATE ]] || stop candidate_state_preexists
[[ ! -e $CANDIDATE_LOCK ]] || stop candidate_lock_preexists
[[ "$(action_pending_count)" == 0 ]] || stop action_inbox_pending_preexists

for svc in "$MON_SVC" "$NOT_SVC"; do
  [[ "$(svc_value "$svc" Result)" == success ]] || stop "oneshot_last_result_not_success:$svc"
  [[ "$(svc_value "$svc" ExecMainStatus)" == 0 ]] || stop "oneshot_last_exit_nonzero:$svc"
done

declare -A PID_PRE RESTART_PRE
for svc in "$RES" "$CAP" "$SIG" "$DIS"; do
  PID_PRE["$svc"]=$(svc_value "$svc" MainPID)
  RESTART_PRE["$svc"]=$(svc_value "$svc" NRestarts)
  [[ ${PID_PRE[$svc]:-0} =~ ^[1-9][0-9]*$ ]] || stop "invalid_mainpid:$svc"
done

common_gate pre1
sleep 10
common_gate pre2

git_owner fetch --no-tags origin main
REMOTE=$(git_owner rev-parse origin/main)
[[ $REMOTE == "$TARGET" ]] || stop "origin_main_moved:expected=$TARGET:actual=$REMOTE"
git_owner merge-base --is-ancestor "$PRE" "$TARGET" || stop target_not_fast_forward
[[ "$(git_owner rev-list --count "$TARGET..$PRE")" == 0 ]] || stop target_behind_production

EXPECTED=$(cat <<'EOF' | LC_ALL=C sort
src/flop_agent/airdrop_action_stager.py
src/flop_agent/airdrop_monitor.py
src/flop_agent/airdrop_notifier.py
tests/test_airdrop_action_stager.py
EOF
)
ACTUAL=$(git_owner diff --name-only "$PRE..$TARGET" | LC_ALL=C sort)
[[ $ACTUAL == "$EXPECTED" ]] || {
  echo "PROD333=STOP:changed_file_allowlist_mismatch" >&2
  echo "ACTUAL_CHANGED_PATHS:" >&2
  printf '%s\n' "$ACTUAL" >&2
  echo "DO_NOT_RERUN=YES" >&2
  exit 1
}

for path in   src/flop_agent/airdrop_action_stager.py   src/flop_agent/airdrop_monitor.py   src/flop_agent/airdrop_notifier.py; do
  git_owner cat-file -e "$TARGET:$path" || stop "target_missing_runtime_path:$path"
done

CUTOVER_STARTED=0
DONE=0
rollback() {
  local rc=$?
  trap - ERR
  if [[ $DONE -eq 0 && $CUTOVER_STARTED -eq 1 ]]; then
    set +e
    git_owner reset --hard "$PRE" >/dev/null 2>&1
    if [[ ! -e $CANDIDATE_STATE ]]; then
      rm -f -- "$CANDIDATE_LOCK"
    fi
    echo "PROD333_ROLLBACK=COMPLETE code=$PRE long_running_services_not_restarted=YES" >&2
  fi
  exit "$rc"
}
trap rollback EXIT

echo "PROD333_PREFLIGHT=PASS pre=$PRE target=$TARGET"

CUTOVER_STARTED=1
git_owner merge --ff-only "$TARGET" >/dev/null
[[ "$(git_owner rev-parse HEAD)" == "$TARGET" ]] || stop post_merge_head_mismatch

# Import-only smoke. No state write and no external action.
sudo -u technocore env -i   PATH=/usr/bin:/bin   FLOP_STATE_DIR="$STATE"   PYTHONPATH="$APP/src"   "$APP/.venv/bin/python" - <<'PY'
from flop_agent import airdrop_action_stager
assert airdrop_action_stager.AUTO_STAGE_KEYS == {
    "faucet": "faucet_status",
    "registration": "registration_status",
    "claim": "claim_status",
}
assert not airdrop_action_stager.store_path().exists()
print("STAGER_IMPORT_SMOKE=PASS")
PY

# Wait until the monitor's existing anti-spam floor permits a real cycle.
for _ in 1 2 3 4; do
  WAIT=$(scan_wait_seconds) || stop scan_floor_read_failed
  [[ $WAIT =~ ^[0-9]+$ ]] || stop scan_wait_not_numeric
  if [[ $WAIT -eq 0 ]]; then
    break
  fi
  sleep "$WAIT"
done
WAIT=$(scan_wait_seconds) || stop scan_floor_recheck_failed
[[ $WAIT -eq 0 ]] || stop "scan_floor_not_reached:$WAIT"

# Run one normal read-only Radar monitor cycle under the existing hardened unit.
systemctl is-active --quiet "$MON_SVC" && stop monitor_oneshot_already_running
systemctl start "$MON_SVC"
[[ "$(svc_value "$MON_SVC" Result)" == success ]] || stop monitor_oneshot_failed
[[ "$(svc_value "$MON_SVC" ExecMainStatus)" == 0 ]] || stop monitor_exit_nonzero

read -r POST_OUTCOME POST_RADAR POST_AGE POST_LEDGER POST_STAGING POST_STAGED POST_STAGING_ERROR < <(airdrop_snapshot)
[[ $POST_OUTCOME == recorded ]] || stop "post_monitor_outcome:$POST_OUTCOME"
[[ $POST_RADAR == ok || $POST_RADAR == degraded ]] || stop "post_radar_health:$POST_RADAR"
[[ $POST_STAGING == ok ]] || stop "post_staging_outcome:$POST_STAGING:$POST_STAGING_ERROR"
[[ $POST_STAGED == 0 ]] || stop "unexpected_staged_approvals:$POST_STAGED"
[[ ! -e $CANDIDATE_STATE ]] || stop unexpected_candidate_state_created
[[ -f $CANDIDATE_LOCK ]] || stop candidate_lock_not_created
[[ "$(stat -c %U "$CANDIDATE_LOCK")" == technocore ]] || stop candidate_lock_owner_wrong
[[ "$(stat -c %a "$CANDIDATE_LOCK")" == 640 ]] || stop candidate_lock_mode_wrong
[[ "$(action_pending_count)" == 0 ]] || stop unexpected_action_inbox_pending

for svc in "$RES" "$CAP" "$SIG" "$DIS"; do
  [[ "$(svc_value "$svc" MainPID)" == "${PID_PRE[$svc]}" ]] || stop "unexpected_pid_change:$svc"
  [[ "$(svc_value "$svc" NRestarts)" == "${RESTART_PRE[$svc]}" ]] || stop "unexpected_restart_change:$svc"
done

common_gate post
[[ "$(svc_value "$NOT_SVC" Result)" == success ]] || stop notifier_last_result_not_success
[[ "$(svc_value "$NOT_SVC" ExecMainStatus)" == 0 ]] || stop notifier_last_exit_nonzero
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop final_dirty_worktree

read -r FINAL_HEALTH FINAL_EVENTS FINAL_MESSAGES < <(observer_snapshot)

DONE=1
trap - EXIT

printf '%s\n'   "PROD333=PASS"   "PRE_SHA=$PRE"   "POST_SHA=$(git_owner rev-parse HEAD)"   "PROTECTED_CORE=$FINAL_EVENTS/$FINAL_MESSAGES OBSERVER_HEALTH=$FINAL_HEALTH"   "AIRDROP_MONITOR=$POST_OUTCOME RADAR_HEALTH=$POST_RADAR HEARTBEAT_AGE=$POST_AGE LEDGER_COUNT=$POST_LEDGER"   "STAGING_OUTCOME=$POST_STAGING STAGED_APPROVALS=$POST_STAGED STAGING_ERROR=$POST_STAGING_ERROR"   "ACTION_INBOX_PENDING=0 CANDIDATE_STATE=ABSENT CANDIDATE_LOCK=technocore/640"   "AIRDROP_TIMERS=$(systemctl is-active "$MON_TIMER")/$(systemctl is-active "$NOT_TIMER")"   "RESIDENT_PRESERVED=${PID_PRE[$RES]}/NRestarts=${RESTART_PRE[$RES]}"   "CAPTURE_PRESERVED=${PID_PRE[$CAP]}/NRestarts=${RESTART_PRE[$CAP]}"   "SIGNER_PRESERVED=${PID_PRE[$SIG]}/NRestarts=${RESTART_PRE[$SIG]}"   "DISCORD_PRESERVED=${PID_PRE[$DIS]}/NRestarts=${RESTART_PRE[$DIS]}"   "FLOP_EXTERNAL_WRITE=NO X_WRITE=NO REGISTRATION=NO FAUCET=NO CLAIM=NO SPEND=NO SUBMIT=NO SIGNER_CALL=NO"   "DO_NOT_RERUN=YES"
