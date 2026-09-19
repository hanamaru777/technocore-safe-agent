#!/usr/bin/env bash
# One-shot guarded Production rollout for Discord Airdrop Action Inbox buttons.
# Branch-only operational helper. DO NOT MERGE. Any terminal result is DO_NOT_RERUN.
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
OBSERVER_STATE="$STATE/observer/observer-state.json"
AIRDROP_DIR="$STATE/airdrop-radar"

PRE=cd8e91d26f06c2de3a549f5e8c22a65bfc38711c
TARGET=9e69f0e33f29c2e39bbda8b61e6a098480192ae5
CORE_EVENTS=117
CORE_MESSAGES=5083155
HEALTH_MAX_ATTEMPTS=12
HEALTH_SAMPLE_SECONDS=15
HEALTH_REQUIRED_CONSECUTIVE=2
OBSERVER_MAX_AGE_SECONDS=300

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service
MON_TIMER=technocore-safe-agent-airdrop-monitor.timer
NOT_TIMER=technocore-safe-agent-airdrop-notifier.timer
MON_SVC=technocore-safe-agent-airdrop-monitor.service
NOT_SVC=technocore-safe-agent-airdrop-notifier.service

SMOKE_DIR=""
CUTOVER_STARTED=0
DISCORD_RESTARTED=0
DONE=0

cleanup_smoke() {
  if [[ -n "$SMOKE_DIR" && -d "$SMOKE_DIR" ]]; then
    rm -rf -- "$SMOKE_DIR"
  fi
}
stop() {
  local reason=$1
  trap - ERR
  echo "PROD337B=STOP:$reason"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'stop unexpected_rc_$?' ERR

[[ $EUID -eq 0 ]] || stop run_as_root
[[ -d $APP/.git && -x $APP/.venv/bin/python ]] || stop production_checkout_or_venv_missing
[[ -f $OBSERVER_STATE && -d $AIRDROP_DIR ]] || stop production_state_missing

OWNER=$(stat -c %U "$APP/.git") || stop git_owner_unreadable
STATE_GROUP=$(stat -c %G "$STATE") || stop state_group_unreadable
[[ -n $OWNER && -n $STATE_GROUP ]] || stop owner_or_group_missing

git_owner() { sudo -u "$OWNER" git -C "$APP" "$@"; }
svc_value() { systemctl show "$1" -p "$2" --value; }

observer_snapshot() {
  sudo -u technocore env -i \
    PATH=/usr/bin:/bin \
    FLOP_STATE_DIR="$STATE" \
    PYTHONPATH="$APP/src" \
    "$APP/.venv/bin/python" - "$OBSERVER_STATE" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from datetime import UTC, datetime
from flop_agent import observer_resilience

d=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
health=d.get("health") or {}
rooms=health.get("rooms") or {}
m=d.get("metrics") or {}
stamp=d.get("updated_at")
age=-1
if isinstance(stamp,str):
    parsed=datetime.fromisoformat(stamp.replace("Z","+00:00"))
    if parsed.tzinfo is not None:
        age=max(0,int((datetime.now(UTC)-parsed.astimezone(UTC)).total_seconds()))
optional=set(observer_resilience.OPTIONAL_ROOMS)
nonoptional=[
    room for room,row in rooms.items()
    if isinstance(row,dict)
    and row.get("status")=="error"
    and room not in optional
]
optional_errors=[
    room for room,row in rooms.items()
    if isinstance(row,dict)
    and row.get("status")=="error"
    and room in optional
]
print(
    health.get("current","missing"),
    m.get("unrecoverable_core_gap_events","missing"),
    m.get("unrecoverable_core_gap_messages","missing"),
    age,
    len(nonoptional),
    len(optional_errors),
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
    hb.get("staging_outcome","missing"),
    hb.get("staged_approvals",0),
    hb.get("staging_error_type") or "none",
)
PY
}

action_counts() {
  sudo python3 - "$AIRDROP_DIR/action-inbox.json" "$AIRDROP_DIR/action-candidates.json" <<'PY'
import json, pathlib, sys
inbox=pathlib.Path(sys.argv[1])
candidates=pathlib.Path(sys.argv[2])

pending=0
total=0
if inbox.exists():
    d=json.loads(inbox.read_text("utf-8"))
    req=d.get("requests")
    if d.get("schema_version") != 1 or not isinstance(req,dict):
        raise SystemExit("action_inbox_invalid")
    total=len(req)
    pending=sum(
        1 for row in req.values()
        if isinstance(row,dict) and row.get("status") == "pending"
    )

candidate_count=0
if candidates.exists():
    d=json.loads(candidates.read_text("utf-8"))
    rows=d.get("candidates")
    if d.get("schema_version") != 1 or not isinstance(rows,dict):
        raise SystemExit("candidate_store_invalid")
    candidate_count=len(rows)

print(pending,total,candidate_count)
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

  local health events messages observer_age nonoptional_errors optional_errors
  read -r health events messages observer_age nonoptional_errors optional_errors < <(observer_snapshot) || stop "$label:observer_unreadable"
  [[ $events == "$CORE_EVENTS" && $messages == "$CORE_MESSAGES" ]] || stop "$label:protected_core_changed:$events/$messages"
  [[ $observer_age =~ ^[0-9]+$ && $observer_age -le $OBSERVER_MAX_AGE_SECONDS ]] || stop "$label:observer_state_stale:$observer_age"
  [[ $health == ok ]] || stop "$label:observer_health_not_ok:$health"
  [[ $nonoptional_errors == 0 ]] || stop "$label:nonoptional_room_errors:$nonoptional_errors"

  local outcome radar age ledger_count staging staged staging_error
  read -r outcome radar age ledger_count staging staged staging_error < <(airdrop_snapshot) ||     stop "$label:airdrop_state_unreadable"
  [[ $outcome == recorded ]] || stop "$label:monitor_outcome_not_recorded:$outcome"
  [[ $radar == ok || $radar == degraded ]] || stop "$label:radar_health_not_allowed:$radar"
  [[ $age =~ ^[0-9]+$ && $age -le 1800 ]] || stop "$label:heartbeat_stale:$age"
  [[ $ledger_count =~ ^[0-9]+$ ]] || stop "$label:ledger_count_invalid:$ledger_count"
  [[ $staging == ok ]] || stop "$label:staging_not_ok:$staging:$staging_error"
  [[ $staged =~ ^[0-9]+$ ]] || stop "$label:staged_count_invalid:$staged"

  local pending total candidates
  read -r pending total candidates < <(action_counts) || stop "$label:action_state_unreadable"
  [[ $pending == 0 ]] || stop "$label:pending_action_requests:$pending"
  [[ $candidates == 0 ]] || stop "$label:candidate_count_not_zero:$candidates"

  echo "PROD337B_GATE=$label observer=$health observer_age=$observer_age nonoptional_errors=$nonoptional_errors optional_errors=$optional_errors core=$events/$messages radar=$radar heartbeat_age=$age ledger_count=$ledger_count staging=$staging staged=$staged action_pending=$pending action_total=$total candidates=$candidates"
}

wait_for_stable_observer() {
  local label=$1
  local consecutive=0
  local attempt health events messages observer_age nonoptional_errors optional_errors
  for attempt in $(seq 1 "$HEALTH_MAX_ATTEMPTS"); do
    read -r health events messages observer_age nonoptional_errors optional_errors < <(observer_snapshot) || stop "$label:observer_unreadable"
    [[ $events == "$CORE_EVENTS" && $messages == "$CORE_MESSAGES" ]] || stop "$label:protected_core_changed:$events/$messages"
    if [[ $observer_age =~ ^[0-9]+$ && $observer_age -le $OBSERVER_MAX_AGE_SECONDS && $health == ok && $nonoptional_errors == 0 ]]; then
      consecutive=$((consecutive + 1))
    else
      consecutive=0
    fi
    echo "PROD337B_HEALTH_WAIT=$label attempt=$attempt observer=$health observer_age=$observer_age nonoptional_errors=$nonoptional_errors optional_errors=$optional_errors core=$events/$messages consecutive=$consecutive/$HEALTH_REQUIRED_CONSECUTIVE"
    if [[ $consecutive -ge $HEALTH_REQUIRED_CONSECUTIVE ]]; then
      return 0
    fi
    sleep "$HEALTH_SAMPLE_SECONDS"
  done
  stop "$label:observer_not_stably_ok"
}

rollback() {
  local rc=$?
  trap - ERR
  set +e
  cleanup_smoke
  if [[ $DONE -eq 0 && $CUTOVER_STARTED -eq 1 ]]; then
    git_owner reset --hard "$PRE" >/dev/null 2>&1
    if [[ $DISCORD_RESTARTED -eq 1 ]]; then
      systemctl restart "$DIS" >/dev/null 2>&1
      for _ in $(seq 1 20); do
        systemctl is-active --quiet "$DIS" && break
        sleep 1
      done
    fi
    echo "PROD337B_ROLLBACK=COMPLETE code=$PRE discord_restored=$DISCORD_RESTARTED" >&2
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

wait_for_stable_observer pre
common_gate pre_stable

git_owner fetch --no-tags origin main
REMOTE=$(git_owner rev-parse origin/main)
[[ $REMOTE == "$TARGET" ]] || stop "origin_main_moved:expected=$TARGET:actual=$REMOTE"
git_owner merge-base --is-ancestor "$PRE" "$TARGET" || stop target_not_fast_forward
[[ "$(git_owner rev-list --count "$TARGET..$PRE")" == 0 ]] || stop target_behind_production

EXPECTED=$(cat <<'EOF' | LC_ALL=C sort
src/flop_agent/airdrop_approval.py
src/flop_agent/discord_airdrop_actions.py
src/flop_agent/discord_control.py
src/flop_agent/discord_tclk_approval.py
tests/test_airdrop_approval.py
tests/test_discord_airdrop_actions.py
EOF
)
ACTUAL=$(git_owner diff --name-only "$PRE..$TARGET" | LC_ALL=C sort)
[[ $ACTUAL == "$EXPECTED" ]] || {
  echo "PROD337B=STOP:changed_file_allowlist_mismatch" >&2
  echo "ACTUAL_CHANGED_PATHS:" >&2
  printf '%s\n' "$ACTUAL" >&2
  echo "DO_NOT_RERUN=YES" >&2
  exit 1
}
for path in   src/flop_agent/airdrop_approval.py   src/flop_agent/discord_airdrop_actions.py   src/flop_agent/discord_control.py   src/flop_agent/discord_tclk_approval.py; do
  git_owner cat-file -e "$TARGET:$path" || stop "target_missing_runtime_path:$path"
done

echo "PROD337B_PREFLIGHT=PASS pre=$PRE target=$TARGET"

CUTOVER_STARTED=1
git_owner merge --ff-only "$TARGET" >/dev/null
[[ "$(git_owner rev-parse HEAD)" == "$TARGET" ]] || stop post_merge_head_mismatch

# Isolated local-only smoke: no Production Action Inbox state and no Discord network.
SMOKE_DIR=$(mktemp -d /tmp/prod337b-action-ui.XXXXXX)
chown technocore:"$STATE_GROUP" "$SMOKE_DIR"
chmod 0750 "$SMOKE_DIR"

SMOKE=$(sudo -u technocore env -i   PATH=/usr/bin:/bin   FLOP_STATE_DIR="$SMOKE_DIR"   PYTHONPATH="$APP/src"   "$APP/.venv/bin/python" - <<'PY'
from __future__ import annotations
import asyncio
from datetime import UTC, datetime, timedelta

import discord

from flop_agent import airdrop_approval, discord_airdrop_actions, discord_control

now=datetime.now(UTC)
row=airdrop_approval.stage_request(
    action_class="x_post",
    payload_sha256="a"*64,
    source_event_id="prod337b-local-smoke",
    summary="PROD337B isolated local-only UI smoke",
    cost_note="0 FLOP / no network / no external execution",
    reversible=False,
    expires_at=now+timedelta(hours=1),
    now=now,
)

specs=discord_airdrop_actions.button_specs(row)
assert [item["action"] for item in specs] == ["details","approve","reject"]
assert all(row["approval_digest"] not in item["custom_id"] for item in specs)
assert all(len(item["custom_id"]) <= 100 for item in specs)

async def build():
    return discord_control._airdrop_action_view(discord,row)

view=asyncio.run(build())
assert [item.label for item in view.children] == ["詳細","承認","拒否"]

detail=discord_airdrop_actions.handle_interaction(
    allowed_ids={"1"},
    expected_channel_id="2",
    user_id="1",
    channel_id="2",
    component_custom_id=discord_airdrop_actions.custom_id("details",row["request_id"]),
    now=now,
)
assert detail["edit_original"] is False
assert "exact candidate" in detail["message"]

approved=discord_airdrop_actions.handle_interaction(
    allowed_ids={"1"},
    expected_channel_id="2",
    user_id="1",
    channel_id="2",
    component_custom_id=discord_airdrop_actions.custom_id("approve",row["request_id"]),
    now=now,
)
assert approved["record"]["status"] == "approved"
assert approved["edit_original"] is True
assert "まだ署名・送信・Claim・支払いは実行していません" in approved["message"]

print("PASS")
PY
) || stop isolated_ui_smoke_failed
[[ $SMOKE == PASS ]] || stop isolated_ui_smoke_unexpected
cleanup_smoke
SMOKE_DIR=""

# Restart only the existing Discord gateway so it loads TARGET code.
systemctl restart "$DIS"
DISCORD_RESTARTED=1
for _ in $(seq 1 20); do
  systemctl is-active --quiet "$DIS" && break
  sleep 1
done
systemctl is-active --quiet "$DIS" || stop discord_not_active_after_restart

NEW_DIS_PID=$(svc_value "$DIS" MainPID)
NEW_DIS_NR=$(svc_value "$DIS" NRestarts)
[[ $NEW_DIS_PID =~ ^[1-9][0-9]*$ && $NEW_DIS_PID != "${PID_PRE[$DIS]}" ]] || stop discord_pid_not_changed
[[ $NEW_DIS_NR == "${RESTART_PRE[$DIS]}" ]] || stop discord_unexpected_auto_restart

# Stability window catches import/startup crash loops.
sleep 8
[[ "$(svc_value "$DIS" MainPID)" == "$NEW_DIS_PID" ]] || stop discord_pid_changed_during_stability_window
[[ "$(svc_value "$DIS" NRestarts)" == "$NEW_DIS_NR" ]] || stop discord_restarted_during_stability_window
systemctl is-active --quiet "$DIS" || stop discord_not_active_after_stability_window

for svc in "$RES" "$CAP" "$SIG"; do
  [[ "$(svc_value "$svc" MainPID)" == "${PID_PRE[$svc]}" ]] || stop "unexpected_pid_change:$svc"
  [[ "$(svc_value "$svc" NRestarts)" == "${RESTART_PRE[$svc]}" ]] || stop "unexpected_restart_change:$svc"
done

wait_for_stable_observer post
common_gate post_stable
[[ "$(svc_value "$MON_SVC" Result)" == success ]] || stop monitor_last_result_not_success
[[ "$(svc_value "$MON_SVC" ExecMainStatus)" == 0 ]] || stop monitor_last_exit_nonzero
[[ "$(svc_value "$NOT_SVC" Result)" == success ]] || stop notifier_last_result_not_success
[[ "$(svc_value "$NOT_SVC" ExecMainStatus)" == 0 ]] || stop notifier_last_exit_nonzero
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop final_dirty_worktree

read -r FINAL_HEALTH FINAL_EVENTS FINAL_MESSAGES FINAL_OBSERVER_AGE FINAL_NONOPTIONAL FINAL_OPTIONAL < <(observer_snapshot)
read -r FINAL_OUTCOME FINAL_RADAR FINAL_AGE FINAL_LEDGER FINAL_STAGING FINAL_STAGED FINAL_STAGING_ERROR < <(airdrop_snapshot)
read -r FINAL_PENDING FINAL_TOTAL FINAL_CANDIDATES < <(action_counts)

DONE=1
trap - EXIT

printf '%s\n'   "PROD337B=PASS"   "PRE_SHA=$PRE"   "POST_SHA=$(git_owner rev-parse HEAD)"   "PROTECTED_CORE=$FINAL_EVENTS/$FINAL_MESSAGES OBSERVER_HEALTH=$FINAL_HEALTH OBSERVER_AGE=$FINAL_OBSERVER_AGE NONOPTIONAL_ERRORS=$FINAL_NONOPTIONAL OPTIONAL_ERRORS=$FINAL_OPTIONAL"   "AIRDROP_MONITOR=$FINAL_OUTCOME RADAR_HEALTH=$FINAL_RADAR HEARTBEAT_AGE=$FINAL_AGE LEDGER_COUNT=$FINAL_LEDGER"   "STAGING_OUTCOME=$FINAL_STAGING STAGED_APPROVALS=$FINAL_STAGED STAGING_ERROR=$FINAL_STAGING_ERROR"   "ACTION_INBOX_PENDING=$FINAL_PENDING ACTION_REQUESTS=$FINAL_TOTAL CANDIDATES=$FINAL_CANDIDATES"   "AIRDROP_TIMERS=$(systemctl is-active "$MON_TIMER")/$(systemctl is-active "$NOT_TIMER")"   "RESIDENT_PRESERVED=${PID_PRE[$RES]}/NRestarts=${RESTART_PRE[$RES]}"   "CAPTURE_PRESERVED=${PID_PRE[$CAP]}/NRestarts=${RESTART_PRE[$CAP]}"   "SIGNER_PRESERVED=${PID_PRE[$SIG]}/NRestarts=${RESTART_PRE[$SIG]}"   "DISCORD_RESTARTED=${PID_PRE[$DIS]}->$NEW_DIS_PID NRestarts=$NEW_DIS_NR"   "ISOLATED_UI_SMOKE=PASS REAL_DISCORD_MESSAGE=NO"   "FLOP_EXTERNAL_WRITE=NO X_WRITE=NO REGISTRATION=NO FAUCET=NO CLAIM=NO SPEND=NO SUBMIT=NO SIGNER_CALL=NO"   "DO_NOT_RERUN=YES"
