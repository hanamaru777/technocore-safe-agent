#!/usr/bin/env bash
# One-shot Production rollout for tclk Note retry classification/backoff.
# Branch-only operational helper. DO NOT MERGE. Any terminal result is DO_NOT_RERUN.
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
OBSERVER_STATE="$STATE/observer/observer-state.json"
AIRDROP_DIR="$STATE/airdrop-radar"

PRE=3fd5ce445692cc2f94a574c012c080048f96d755
TARGET=b7bf27dbaa605971d340aa926fdffc17489c3afe
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
DISCORD_RESTARTED=0
DONE=0
SMOKE_DIR=""

cleanup_smoke() {
  if [[ -n "$SMOKE_DIR" && -d "$SMOKE_DIR" ]]; then
    rm -rf -- "$SMOKE_DIR"
  fi
}

stop() {
  local reason=$1
  trap - ERR
  echo "PROD354=STOP:$reason"
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

local_counts() {
  sudo python3 -     "$AIRDROP_DIR/action-inbox.json"     "$AIRDROP_DIR/action-candidates.json"     "$AIRDROP_DIR/action-executions.json" <<'PY'
import json, pathlib, sys
mapping=(
    ("requests", pathlib.Path(sys.argv[1])),
    ("candidates", pathlib.Path(sys.argv[2])),
    ("executions", pathlib.Path(sys.argv[3])),
)
counts=[]
for key,path in mapping:
    if not path.exists():
        counts.append(0)
        continue
    value=json.loads(path.read_text("utf-8"))
    rows=value.get(key)
    if not isinstance(rows,dict):
        raise SystemExit(f"{key}_state_invalid")
    counts.append(len(rows))
print(*counts)
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
  [[ "$(svc_value "$MON_SVC" Result)" == success ]] || stop "$label:monitor_last_result_not_success"
  [[ "$(svc_value "$MON_SVC" ExecMainStatus)" == 0 ]] || stop "$label:monitor_last_exit_nonzero"
  [[ "$(svc_value "$NOT_SVC" Result)" == success ]] || stop "$label:notifier_last_result_not_success"
  [[ "$(svc_value "$NOT_SVC" ExecMainStatus)" == 0 ]] || stop "$label:notifier_last_exit_nonzero"

  local health events messages
  read -r health events messages < <(observer_snapshot) || stop "$label:observer_unreadable"
  [[ $health == ok || $health == degraded ]] || stop "$label:observer_health_invalid:$health"
  [[ $events == "$CORE_EVENTS" && $messages == "$CORE_MESSAGES" ]] ||     stop "$label:protected_core_changed:$events/$messages"

  local requests candidates executions
  read -r requests candidates executions < <(local_counts) || stop "$label:local_state_unreadable"
  [[ $requests == 0 ]] || stop "$label:action_request_count_not_zero:$requests"
  [[ $candidates == 0 ]] || stop "$label:candidate_count_not_zero:$candidates"
  [[ $executions == 0 ]] || stop "$label:execution_count_not_zero:$executions"

  git_owner show HEAD:src/flop_agent/airdrop_executor.py     | grep -Fq '_ADAPTERS: dict[str, ExecutionAdapter] = {}'     || stop "$label:adapter_registry_not_empty"

  echo "PROD354_GATE=$label observer=$health core=$events/$messages requests=$requests candidates=$candidates executions=$executions"
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
      for _ in {1..30}; do
        systemctl is-active --quiet "$DIS" && break
        sleep 1
      done
    fi
    echo "PROD354_ROLLBACK=COMPLETE code=$PRE discord_reloaded=$DISCORD_RESTARTED" >&2
  fi
  exit "$rc"
}
trap rollback EXIT

cd "$APP"
[[ "$(git_owner symbolic-ref --short HEAD)" == main ]] || stop branch_not_main
[[ "$(git_owner rev-parse HEAD)" == "$PRE" ]] || stop "unexpected_production_head:$(git_owner rev-parse HEAD)"
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop dirty_worktree

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

EXPECTED=$(cat <<'EOF' | LC_ALL=C sort
src/flop_agent/discord_tclk_review.py
src/flop_agent/tclk_note_review.py
src/flop_agent/tclk_review_evidence.py
tests/test_tclk_auto_review_evidence.py
tests/test_tclk_note_review.py
EOF
)
ACTUAL=$(git_owner diff --name-only "$PRE..$TARGET" | LC_ALL=C sort)
[[ $ACTUAL == "$EXPECTED" ]] || {
  echo "PROD354=STOP:changed_file_allowlist_mismatch" >&2
  printf '%s\n' "$ACTUAL" >&2
  echo "DO_NOT_RERUN=YES" >&2
  exit 1
}

echo "PROD354_PREFLIGHT=PASS pre=$PRE target=$TARGET"

CUTOVER_STARTED=1
git_owner merge --ff-only "$TARGET" >/dev/null
[[ "$(git_owner rev-parse HEAD)" == "$TARGET" ]] || stop post_merge_head_mismatch

SMOKE_DIR=$(mktemp -d /tmp/prod354-tclk-note.XXXXXX)

SMOKE=$(sudo -u technocore env -i   PATH=/usr/bin:/bin   FLOP_STATE_DIR="$SMOKE_DIR"   PYTHONPATH="$APP/src"   "$APP/.venv/bin/python" - <<'PY'
from flop_agent import discord_tclk_review, tclk_note_review

NOW=2_000_000_000_000
item={
    "id":"0x"+"7"*64,
    "frame_type":"offer",
    "read_only":True,
    "accepted":False,
    "rail":"paper",
    "job_proto":"a2a",
    "job_id":"paper-safe-open",
    "expires_ms":NOW+900_000,
    "frame_sha256":"a"*64,
}

assert discord_tclk_review._retry_delay("full_spec_read_failed",1)==60
assert discord_tclk_review._retry_delay("full_spec_read_failed",2)==120
assert discord_tclk_review._retry_delay("full_spec_not_found",1)==300
assert discord_tclk_review._retry_delay("full_spec_not_found",2)==600
assert discord_tclk_review._retry_delay("unsupported_note_reference",1) is None

try:
    tclk_note_review.resolve_offer(
        item,
        reader=lambda _ns,_key: None,
        now_ms=NOW,
    )
except tclk_note_review.ResolutionError as error:
    assert str(error)=="full_spec_not_found"
else:
    raise AssertionError("missing Note unexpectedly resolved")

def timeout_reader(_ns,_key):
    raise TimeoutError("simulated")

try:
    tclk_note_review.resolve_offer(
        item,
        reader=timeout_reader,
        now_ms=NOW,
    )
except tclk_note_review.ResolutionError as error:
    assert str(error)=="full_spec_read_failed"
else:
    raise AssertionError("timeout unexpectedly resolved")

print("PASS")
PY
) || stop isolated_tclk_smoke_failed

[[ $SMOKE == PASS ]] || stop isolated_tclk_smoke_unexpected
cleanup_smoke
SMOKE_DIR=""

# Long-running non-Discord services must remain untouched before Discord reload.
for svc in "$RES" "$CAP" "$SIG"; do
  [[ "$(svc_value "$svc" MainPID)" == "${PID_PRE[$svc]}" ]] || stop "unexpected_pre_restart_pid_change:$svc"
  [[ "$(svc_value "$svc" NRestarts)" == "${RESTART_PRE[$svc]}" ]] || stop "unexpected_pre_restart_restart_change:$svc"
done

systemctl restart "$DIS"
DISCORD_RESTARTED=1

for _ in {1..30}; do
  if systemctl is-active --quiet "$DIS"; then
    break
  fi
  sleep 1
done
systemctl is-active --quiet "$DIS" || stop discord_not_active_after_restart
sleep 3
systemctl is-active --quiet "$DIS" || stop discord_failed_after_settle

DIS_POST=$(svc_value "$DIS" MainPID)
[[ $DIS_POST =~ ^[1-9][0-9]*$ ]] || stop discord_post_pid_invalid
[[ $DIS_POST != "${PID_PRE[$DIS]}" ]] || stop discord_pid_did_not_change
[[ "$(svc_value "$DIS" NRestarts)" == "${RESTART_PRE[$DIS]}" ]] || stop discord_restart_counter_changed

for svc in "$RES" "$CAP" "$SIG"; do
  [[ "$(svc_value "$svc" MainPID)" == "${PID_PRE[$svc]}" ]] || stop "unexpected_pid_change:$svc"
  [[ "$(svc_value "$svc" NRestarts)" == "${RESTART_PRE[$svc]}" ]] || stop "unexpected_restart_change:$svc"
done

common_gate post
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop final_dirty_worktree

read -r FINAL_HEALTH FINAL_EVENTS FINAL_MESSAGES < <(observer_snapshot)
read -r FINAL_REQUESTS FINAL_CANDIDATES FINAL_EXECUTIONS < <(local_counts)

DONE=1
trap - EXIT

printf '%s\n'   "PROD354=PASS"   "PRE_SHA=$PRE"   "POST_SHA=$(git_owner rev-parse HEAD)"   "PROTECTED_CORE=$FINAL_EVENTS/$FINAL_MESSAGES OBSERVER_HEALTH=$FINAL_HEALTH"   "ACTION_REQUESTS=$FINAL_REQUESTS CANDIDATES=$FINAL_CANDIDATES EXECUTIONS=$FINAL_EXECUTIONS"   "ADAPTER_REGISTRY=EMPTY"   "AIRDROP_TIMERS=$(systemctl is-active "$MON_TIMER")/$(systemctl is-active "$NOT_TIMER")"   "RESIDENT_PRESERVED=${PID_PRE[$RES]}/NRestarts=${RESTART_PRE[$RES]}"   "CAPTURE_PRESERVED=${PID_PRE[$CAP]}/NRestarts=${RESTART_PRE[$CAP]}"   "SIGNER_PRESERVED=${PID_PRE[$SIG]}/NRestarts=${RESTART_PRE[$SIG]}"   "DISCORD_RESTARTED=${PID_PRE[$DIS]}->$DIS_POST NRestarts=${RESTART_PRE[$DIS]}"   "ISOLATED_TCLK_NOTE_SMOKE=PASS"   "SYNTHETIC_TECHNOCORE_ACTIVITY=NO HELPER_DISCORD_MESSAGE=NO"   "TCLK_ACCEPT=NO TCLK_REVEAL=NO TCLK_VALUE=NO SIGNER_CALL=NO FLOP_EXTERNAL_WRITE=NO X_WRITE=NO"   "DO_NOT_RERUN=YES"
