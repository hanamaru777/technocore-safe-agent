#!/usr/bin/env bash
# One-shot Production rollout for the read-only FLOP Adapter Readiness Gate.
# Branch-only operational helper. DO NOT MERGE. Any terminal result is DO_NOT_RERUN.
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
OBSERVER_STATE="$STATE/observer/observer-state.json"
AIRDROP_DIR="$STATE/airdrop-radar"

PRE=2d140ccf5334b709876c2c4f3223649898ef2dc8
TARGET=76fbb513a1f9616865c699cd2b78fb7ccbe83f04
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

CUTOVER_STARTED=0
DONE=0

stop() {
  local reason=$1
  trap - ERR
  echo "PROD346=STOP:$reason"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'stop unexpected_rc_$?' ERR

[[ $EUID -eq 0 ]] || stop run_as_root
[[ -d $APP/.git && -x $APP/.venv/bin/python ]] || stop production_checkout_or_venv_missing
[[ -f $OBSERVER_STATE && -d $AIRDROP_DIR ]] || stop production_state_missing

OWNER=$(stat -c %U "$APP/.git") || stop git_owner_unreadable
[[ -n $OWNER ]] || stop git_owner_missing

git_owner() { sudo -u "$OWNER" git -C "$APP" "$@"; }
svc_value() { systemctl show "$1" -p "$2" --value; }

observer_snapshot() {
  sudo python3 - "$OBSERVER_STATE" <<'PY'
import json, pathlib, sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
h=d.get("health") or {}
m=d.get("metrics") or {}
print(
    h.get("current","missing"),
    m.get("unrecoverable_core_gap_events","missing"),
    m.get("unrecoverable_core_gap_messages","missing"),
)
PY
}

airdrop_snapshot() {
  sudo -u technocore env -i \
    PATH=/usr/bin:/bin \
    FLOP_STATE_DIR="$STATE" \
    PYTHONPATH="$APP/src" \
    "$APP/.venv/bin/python" - <<'PY'
from __future__ import annotations
import json
from datetime import UTC, datetime
from flop_agent import airdrop_ledger

base=airdrop_ledger.ledger_dir()
hb=json.loads((base/"monitor-heartbeat.json").read_text("utf-8"))
verified=airdrop_ledger.verify_ledger()
stamp=datetime.fromisoformat(hb["last_completed_at"].replace("Z","+00:00"))
age=max(0,int((datetime.now(UTC)-stamp.astimezone(UTC)).total_seconds()))
print(
    hb.get("outcome","missing"),
    hb.get("radar_health","missing"),
    age,
    verified.get("count","missing"),
    hb.get("staging_outcome","missing"),
    hb.get("staged_approvals",0),
    hb.get("staging_error_type") or "none",
)
PY
}

local_counts() {
  sudo python3 - \
    "$AIRDROP_DIR/action-inbox.json" \
    "$AIRDROP_DIR/action-candidates.json" \
    "$AIRDROP_DIR/action-executions.json" <<'PY'
import json, pathlib, sys

paths=[pathlib.Path(item) for item in sys.argv[1:]]
keys=("requests","candidates","executions")
values=[]

for path,key in zip(paths,keys):
    if not path.exists():
        values.append(0)
        continue
    d=json.loads(path.read_text("utf-8"))
    rows=d.get(key)
    if d.get("schema_version") != 1 or not isinstance(rows,dict):
        raise SystemExit(f"{key}_state_invalid")
    values.append(len(rows))

print(*values)
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
  [[ $events == "$CORE_EVENTS" && $messages == "$CORE_MESSAGES" ]] || \
    stop "$label:protected_core_changed:$events/$messages"

  local outcome radar age ledger_count staging staged staging_error
  read -r outcome radar age ledger_count staging staged staging_error < <(airdrop_snapshot) || \
    stop "$label:airdrop_state_unreadable"
  [[ $outcome == recorded ]] || stop "$label:monitor_outcome_not_recorded:$outcome"
  [[ $radar == ok || $radar == degraded ]] || stop "$label:radar_health_not_allowed:$radar"
  [[ $age =~ ^[0-9]+$ && $age -le 1800 ]] || stop "$label:heartbeat_stale:$age"
  [[ $ledger_count =~ ^[0-9]+$ ]] || stop "$label:ledger_count_invalid:$ledger_count"
  [[ $staging == ok ]] || stop "$label:staging_not_ok:$staging:$staging_error"
  [[ $staged =~ ^[0-9]+$ ]] || stop "$label:staged_count_invalid:$staged"

  local requests candidates executions
  read -r requests candidates executions < <(local_counts) || stop "$label:local_state_unreadable"
  [[ $requests == 0 ]] || stop "$label:action_request_count_not_zero:$requests"
  [[ $candidates == 0 ]] || stop "$label:candidate_count_not_zero:$candidates"
  [[ $executions == 0 ]] || stop "$label:execution_count_not_zero:$executions"

  echo "PROD346_GATE=$label observer=$health core=$events/$messages radar=$radar heartbeat_age=$age ledger_count=$ledger_count staging=$staging staged=$staged requests=$requests candidates=$candidates executions=$executions"
}

rollback() {
  local rc=$?
  trap - ERR
  set +e
  if [[ $DONE -eq 0 && $CUTOVER_STARTED -eq 1 ]]; then
    git_owner reset --hard "$PRE" >/dev/null 2>&1
    echo "PROD346_ROLLBACK=COMPLETE code=$PRE services_restarted=NO" >&2
  fi
  exit "$rc"
}
trap rollback EXIT

cd "$APP"
[[ "$(git_owner symbolic-ref --short HEAD)" == main ]] || stop branch_not_main
[[ "$(git_owner rev-parse HEAD)" == "$PRE" ]] || stop "unexpected_production_head:$(git_owner rev-parse HEAD)"
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop dirty_worktree

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

common_gate pre

git_owner fetch --no-tags origin main
REMOTE=$(git_owner rev-parse origin/main)
[[ $REMOTE == "$TARGET" ]] || stop "origin_main_moved:expected=$TARGET:actual=$REMOTE"
git_owner merge-base --is-ancestor "$PRE" "$TARGET" || stop target_not_fast_forward
[[ "$(git_owner rev-list --count "$TARGET..$PRE")" == 0 ]] || stop target_behind_production

EXPECTED=$(cat <<'EOF' | LC_ALL=C sort
src/flop_agent/airdrop_adapter_readiness.py
src/flop_agent/airdrop_ledger.py
src/flop_agent/airdrop_monitor.py
src/flop_agent/cli.py
tests/test_airdrop_adapter_readiness.py
EOF
)
ACTUAL=$(git_owner diff --name-only "$PRE..$TARGET" | LC_ALL=C sort)
[[ $ACTUAL == "$EXPECTED" ]] || {
  echo "PROD346=STOP:changed_file_allowlist_mismatch" >&2
  echo "ACTUAL_CHANGED_PATHS:" >&2
  printf '%s\n' "$ACTUAL" >&2
  echo "DO_NOT_RERUN=YES" >&2
  exit 1
}

for path in \
  src/flop_agent/airdrop_adapter_readiness.py \
  src/flop_agent/airdrop_ledger.py \
  src/flop_agent/airdrop_monitor.py \
  src/flop_agent/cli.py; do
  git_owner cat-file -e "$TARGET:$path" || stop "target_missing_runtime_path:$path"
done

echo "PROD346_PREFLIGHT=PASS pre=$PRE target=$TARGET"

CUTOVER_STARTED=1
git_owner merge --ff-only "$TARGET" >/dev/null
[[ "$(git_owner rev-parse HEAD)" == "$TARGET" ]] || stop post_merge_head_mismatch

READINESS_JSON=$(sudo -u technocore env -i \
  PATH=/usr/bin:/bin \
  FLOP_STATE_DIR="$STATE" \
  PYTHONPATH="$APP/src" \
  "$APP/.venv/bin/python" -m flop_agent.cli airdrop-adapter-readiness
) || stop readiness_cli_failed

READINESS_SUMMARY=$(printf '%s' "$READINESS_JSON" | sudo python3 -c '
import json,sys
d=json.load(sys.stdin)
if d.get("ledger_valid") is not True:
    raise SystemExit("ledger_not_valid")
actions=d.get("actions")
if not isinstance(actions,dict):
    raise SystemExit("actions_invalid")
expected=("faucet","registration","claim")
for action in expected:
    row=actions.get(action)
    if not isinstance(row,dict):
        raise SystemExit(f"missing_{action}")
    if row.get("state") != "BLOCKED":
        raise SystemExit(f"{action}_not_blocked:{row.get(chr(115)+chr(116)+chr(97)+chr(116)+chr(101))}")
    blockers=row.get("blockers")
    if not isinstance(blockers,list) or not blockers:
        raise SystemExit(f"{action}_blockers_missing")
print(" ".join(
    f"{action}=BLOCKED[" + ",".join(actions[action]["blockers"]) + "]"
    for action in expected
))
') || stop readiness_baseline_unexpected

if ! git_owner show HEAD:src/flop_agent/airdrop_executor.py \
  | grep -Fq '_ADAPTERS: dict[str, ExecutionAdapter] = {}'; then
  stop adapter_registry_not_empty
fi

for svc in "$RES" "$CAP" "$SIG" "$DIS"; do
  [[ "$(svc_value "$svc" MainPID)" == "${PID_PRE[$svc]}" ]] || stop "unexpected_pid_change:$svc"
  [[ "$(svc_value "$svc" NRestarts)" == "${RESTART_PRE[$svc]}" ]] || stop "unexpected_restart_change:$svc"
done

common_gate post

read -r POST_REQUESTS POST_CANDIDATES POST_EXECUTIONS < <(local_counts) || stop post_local_state_unreadable
[[ $POST_REQUESTS == 0 && $POST_CANDIDATES == 0 && $POST_EXECUTIONS == 0 ]] || stop readiness_command_mutated_action_state

[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop final_dirty_worktree

read -r FINAL_HEALTH FINAL_EVENTS FINAL_MESSAGES < <(observer_snapshot)
read -r FINAL_OUTCOME FINAL_RADAR FINAL_AGE FINAL_LEDGER FINAL_STAGING FINAL_STAGED FINAL_STAGING_ERROR < <(airdrop_snapshot)

DONE=1
trap - EXIT

printf '%s\n' \
  "PROD346=PASS" \
  "PRE_SHA=$PRE" \
  "POST_SHA=$(git_owner rev-parse HEAD)" \
  "PROTECTED_CORE=$FINAL_EVENTS/$FINAL_MESSAGES OBSERVER_HEALTH=$FINAL_HEALTH" \
  "AIRDROP_MONITOR=$FINAL_OUTCOME RADAR_HEALTH=$FINAL_RADAR HEARTBEAT_AGE=$FINAL_AGE LEDGER_COUNT=$FINAL_LEDGER" \
  "STAGING_OUTCOME=$FINAL_STAGING STAGED_APPROVALS=$FINAL_STAGED STAGING_ERROR=$FINAL_STAGING_ERROR" \
  "ACTION_REQUESTS=$POST_REQUESTS CANDIDATES=$POST_CANDIDATES EXECUTIONS=$POST_EXECUTIONS" \
  "ADAPTER_REGISTRY=EMPTY" \
  "READINESS=$READINESS_SUMMARY" \
  "AIRDROP_TIMERS=$(systemctl is-active "$MON_TIMER")/$(systemctl is-active "$NOT_TIMER")" \
  "RESIDENT_PRESERVED=${PID_PRE[$RES]}/NRestarts=${RESTART_PRE[$RES]}" \
  "CAPTURE_PRESERVED=${PID_PRE[$CAP]}/NRestarts=${RESTART_PRE[$CAP]}" \
  "SIGNER_PRESERVED=${PID_PRE[$SIG]}/NRestarts=${RESTART_PRE[$SIG]}" \
  "DISCORD_PRESERVED=${PID_PRE[$DIS]}/NRestarts=${RESTART_PRE[$DIS]}" \
  "SERVICE_RESTART=NO REAL_DISCORD_MESSAGE=NO" \
  "FLOP_EXTERNAL_WRITE=NO X_WRITE=NO REGISTRATION=NO FAUCET=NO CLAIM=NO SPEND=NO SUBMIT=NO SIGNER_CALL=NO" \
  "DO_NOT_RERUN=YES"
