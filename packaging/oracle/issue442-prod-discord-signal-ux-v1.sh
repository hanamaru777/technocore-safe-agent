#!/usr/bin/env bash
set -u
set -o pipefail
umask 022

APP=/opt/technocore-safe-agent
APP_PY=$APP/.venv/bin/python
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json

PRE=d8a9c2a43e1ba85f57e057ebf06a2a20da51bb20
TARGET=041b830d3b0ffd17ef95f8d889922f20d3ac6631
EXPECTED_CORE_EVENTS=120
EXPECTED_CORE_MESSAGES=5650166
MIN_SERVICE_AGE_SECONDS=300
POST_DISCORD_STABILITY_SECONDS=15

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIGN=technocore-safe-agent-signer.service
DISC=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service
MON_TIMER=technocore-safe-agent-airdrop-monitor.timer
MON_SERVICE=technocore-safe-agent-airdrop-monitor.service
NOT_TIMER=technocore-safe-agent-airdrop-notifier.timer
NOT_SERVICE=technocore-safe-agent-airdrop-notifier.service

echo '=== PROD442 DISCORD SIGNAL UX ROLLOUT V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

stop_pre() {
  echo "PROD442V1=STOP:$1"
  echo 'MUTATION_STARTED=NO'
  echo 'DO_NOT_RERUN=YES'
  exit 0
}

stop_post() {
  echo "PROD442V1=STOP:$1"
  echo 'MUTATION_STARTED=YES'
  echo 'TARGET_OR_DISCORD_STATE_MAY_HAVE_CHANGED=YES'
  echo 'DO_NOT_RERUN=YES'
  exit 0
}

if [[ $EUID -ne 0 ]]; then stop_pre not_root; fi
for cmd in git systemctl stat runuser cut sort sleep; do
  command -v "$cmd" >/dev/null 2>&1 || stop_pre "missing_command:$cmd"
done
[[ -x "$APP_PY" && -f "$OBS" && -d "$APP/.git" && -r /proc/uptime ]] || stop_pre required_path_missing

OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_pre git_owner_missing

git_owner() {
  runuser -u "$OWNER" -- git -C "$APP" "$@"
}

HEAD=$(git_owner rev-parse HEAD 2>/dev/null || true)
BRANCH=$(git_owner branch --show-current 2>/dev/null || true)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "PRE_HEAD=$HEAD"
echo "PRE_BRANCH=$BRANCH"
if [[ -z "$WORKTREE" ]]; then echo 'PRE_WORKTREE_CLEAN=YES'; else echo 'PRE_WORKTREE_CLEAN=NO'; fi
[[ "$HEAD" == "$PRE" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_pre repo_baseline_changed

UPTIME_SECONDS=$(cut -d. -f1 /proc/uptime)
[[ "$UPTIME_SECONDS" =~ ^[0-9]+$ ]] || stop_pre uptime_unreadable

service_identity() {
  local unit=$1
  local active sub pid nr result start_us
  active=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  start_us=$(systemctl show "$unit" -p ExecMainStartTimestampMonotonic --value 2>/dev/null || true)
  [[ "$active" == active && "$sub" == running && "$result" == success ]] || return 1
  [[ "$pid" =~ ^[1-9][0-9]*$ && "$nr" =~ ^[0-9]+$ && "$start_us" =~ ^[0-9]+$ ]] || return 1
  printf '%s|%s|%s|%s|%s|%s\n' "$active" "$sub" "$pid" "$nr" "$result" "$start_us"
}

capture_stable_service() {
  local label=$1 unit=$2 varname=$3
  local snap pid nr start_us age_s
  snap=$(service_identity "$unit") || stop_pre "${label,,}_not_healthy"
  pid=$(printf '%s' "$snap" | cut -d'|' -f3)
  nr=$(printf '%s' "$snap" | cut -d'|' -f4)
  start_us=$(printf '%s' "$snap" | cut -d'|' -f6)
  age_s=$(( UPTIME_SECONDS - (start_us / 1000000) ))
  echo "PRE_SERVICE=$label PID=$pid NRESTARTS=$nr AGE_SECONDS=$age_s SNAPSHOT=$snap"
  (( age_s >= MIN_SERVICE_AGE_SECONDS )) || stop_pre "${label,,}_not_stable_long_enough"
  printf -v "$varname" '%s' "$snap"
}

timer_gate() {
  local label=$1 unit=$2
  local active enabled
  active=$(systemctl is-active "$unit" 2>/dev/null || true)
  enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)
  echo "TIMER=$label ACTIVE=$active ENABLED=$enabled"
  [[ "$active" == active && "$enabled" == enabled ]]
}

oneshot_gate() {
  local label=$1 unit=$2
  local result rc
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  rc=$(systemctl show "$unit" -p ExecMainStatus --value 2>/dev/null || true)
  echo "ONESHOT=$label RESULT=$result EXEC_MAIN_STATUS=$rc"
  [[ "$result" == success && "$rc" == 0 ]]
}

protected_core() {
  "$APP_PY" - "$OBS" <<'PY'
import json, pathlib, sys
obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m=obs.get("metrics") or {}
print(f"{int(m.get('unrecoverable_core_gap_events',0) or 0)}|{int(m.get('unrecoverable_core_gap_messages',0) or 0)}")
PY
}

airdrop_health() {
  runuser -u technocore -- env FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" PYTHONDONTWRITEBYTECODE=1 "$APP_PY" - <<'PY'
from flop_agent import airdrop_monitor, airdrop_notifier
m=airdrop_monitor.monitor_status()
n=airdrop_notifier.status()
print(f"MONITOR_OUTCOME={m.get('outcome')}")
print(f"MONITOR_HEARTBEAT_STALE={m.get('heartbeat_stale')}")
print(f"RADAR_HEALTH={m.get('radar_health')}")
print(f"LEDGER_INTEGRITY={m.get('ledger_integrity_valid')}")
print(f"PENDING_ALERTS={int(m.get('pending_immediate_alerts',0))+int(m.get('pending_digest_alerts',0))}")
print(f"NOTIFIER_FAILURE_COUNT={n.get('failure_count')}")
print(f"NOTIFIER_BACKOFF_ACTIVE={n.get('backoff_active')}")
if m.get("outcome") != "recorded":
    raise SystemExit(11)
if m.get("heartbeat_stale") is not False:
    raise SystemExit(12)
if m.get("radar_health") not in {"ok","degraded"}:
    raise SystemExit(13)
if m.get("ledger_integrity_valid") is not True:
    raise SystemExit(14)
if int(n.get("failure_count",0) or 0) != 0:
    raise SystemExit(15)
if n.get("backoff_active") is not False:
    raise SystemExit(16)
PY
}

echo '--- PRE SERVICE / TIMER GATES ---'
capture_stable_service RESIDENT "$RES" PRE_RES
capture_stable_service CAPTURE "$CAP" PRE_CAP
capture_stable_service SIGNER "$SIGN" PRE_SIGN
capture_stable_service DISCORD "$DISC" PRE_DISC

PRE_DISC_PID=$(printf '%s' "$PRE_DISC" | cut -d'|' -f3)
PRE_DISC_NR=$(printf '%s' "$PRE_DISC" | cut -d'|' -f4)
PRE_DISC_START=$(printf '%s' "$PRE_DISC" | cut -d'|' -f6)

META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "PRE_METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || stop_pre metadata_block_not_healthy

timer_gate AIRDROP_MONITOR "$MON_TIMER" || stop_pre monitor_timer_not_active_enabled
timer_gate AIRDROP_NOTIFIER "$NOT_TIMER" || stop_pre notifier_timer_not_active_enabled
oneshot_gate AIRDROP_MONITOR "$MON_SERVICE" || stop_pre monitor_last_run_not_success
oneshot_gate AIRDROP_NOTIFIER "$NOT_SERVICE" || stop_pre notifier_last_run_not_success

CORE=$(protected_core)
CORE_EVENTS=$(printf '%s' "$CORE" | cut -d'|' -f1)
CORE_MESSAGES=$(printf '%s' "$CORE" | cut -d'|' -f2)
echo "PRE_PROTECTED_CORE=$CORE_EVENTS/$CORE_MESSAGES"
[[ "$CORE_EVENTS" == "$EXPECTED_CORE_EVENTS" && "$CORE_MESSAGES" == "$EXPECTED_CORE_MESSAGES" ]] || stop_pre protected_core_changed

echo '--- PRE AIRDROP LOCAL HEALTH ---'
airdrop_health || stop_pre airdrop_local_health_not_ok

echo '--- FETCH / TARGET GATES ---'
git_owner fetch --no-tags origin main || stop_pre fetch_failed
REMOTE_MAIN=$(git_owner rev-parse origin/main 2>/dev/null || true)
echo "REMOTE_MAIN=$REMOTE_MAIN"
[[ "$REMOTE_MAIN" == "$TARGET" ]] || stop_pre remote_main_moved
git_owner merge-base --is-ancestor "$PRE" "$TARGET" || stop_pre target_not_descendant

EXPECTED=$(printf '%s\n' \
  'src/flop_agent/airdrop_notifier.py' \
  'src/flop_agent/discord_control.py' \
  'src/flop_agent/discord_tclk_review.py' \
  'tests/test_airdrop_notifier.py' \
  'tests/test_discord_gap_notice_coalescing.py' \
  'tests/test_discord_signal_notifications.py' \
  'tests/test_tclk_auto_review_evidence.py' | sort)
ACTUAL=$(git_owner diff --name-only "$PRE" "$TARGET" | sort)
echo 'TARGET_DIFF_BEGIN'
printf '%s\n' "$ACTUAL"
echo 'TARGET_DIFF_END'
[[ "$ACTUAL" == "$EXPECTED" ]] || stop_pre target_diff_not_exact

echo '--- FAST-FORWARD SOURCE ---'
git_owner merge --ff-only "$TARGET" || stop_pre ff_only_failed

POST_HEAD=$(git_owner rev-parse HEAD 2>/dev/null || true)
POST_BRANCH=$(git_owner branch --show-current 2>/dev/null || true)
POST_WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "POST_HEAD=$POST_HEAD"
echo "POST_BRANCH=$POST_BRANCH"
if [[ -z "$POST_WORKTREE" ]]; then echo 'POST_WORKTREE_CLEAN=YES'; else echo 'POST_WORKTREE_CLEAN=NO'; fi
[[ "$POST_HEAD" == "$TARGET" && "$POST_BRANCH" == main && -z "$POST_WORKTREE" ]] || stop_post post_repo_state_invalid

for path in \
  "$APP/src/flop_agent/airdrop_notifier.py" \
  "$APP/src/flop_agent/discord_control.py" \
  "$APP/src/flop_agent/discord_tclk_review.py"
do
  mode=$(stat -c '%a' "$path" 2>/dev/null || true)
  fowner=$(stat -c '%U' "$path" 2>/dev/null || true)
  fgroup=$(stat -c '%G' "$path" 2>/dev/null || true)
  echo "SOURCE_FILE=$path MODE=$mode OWNER=$fowner GROUP=$fgroup"
  [[ "$mode" == 644 && "$fowner" == root && "$fgroup" == root ]] || stop_post source_permissions_invalid
done

echo '--- IMPORT / RENDER SMOKE ---'
if ! runuser -u technocore -- env FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" PYTHONDONTWRITEBYTECODE=1 "$APP_PY" - <<'PY'
from flop_agent import airdrop_notifier, discord_control, discord_tclk_review

message, selected = airdrop_notifier.render_digest([{
    "payload": {
        "event_id": "smoke-event-123456789",
        "severity": "MEDIUM",
        "key": "github_critical_repo_activity",
        "source": "github_org",
        "before": {"value": [{"name": "repo-a", "pushed_at": "2026-09-23T00:00:00Z", "default_branch": "main"}]},
        "after": {"value": [{"name": "repo-a", "pushed_at": "2026-09-23T01:00:00Z", "default_branch": "main"}]},
    }
}])
assert selected == ["smoke-event-123456789"]
assert "GitHub重要repo更新" in message
assert '{"' not in message

retry = discord_tclk_review._auto_failure_notice(
    {"id": "0x" + "a" * 64, "job_id": "smoke"},
    {"seconds_left": 600},
    "full_spec_not_found",
    retrying=True,
)
assert "操作不要" in retry
assert "full_spec_not_found" not in retry
assert "0x" + "a" * 64 not in retry

assert callable(discord_control._gap_breakdown)
print("DISCORD_UX_IMPORT_RENDER_SMOKE=PASS")
PY
then
  stop_post import_render_smoke_failed
fi

verify_preserved_service() {
  local label=$1 unit=$2 expected=$3
  local current
  current=$(service_identity "$unit") || stop_post "${label,,}_not_healthy"
  echo "PRESERVED_SERVICE=$label SNAPSHOT=$current"
  [[ "$current" == "$expected" ]] || stop_post "${label,,}_identity_changed"
}

echo '--- PRE-RESTART PRESERVATION CHECK ---'
verify_preserved_service RESIDENT "$RES" "$PRE_RES"
verify_preserved_service CAPTURE "$CAP" "$PRE_CAP"
verify_preserved_service SIGNER "$SIGN" "$PRE_SIGN"
current_disc=$(service_identity "$DISC") || stop_post discord_not_healthy_before_restart
[[ "$current_disc" == "$PRE_DISC" ]] || stop_post discord_changed_before_authorized_restart

echo '--- DISCORD-ONLY RESTART ---'
systemctl restart "$DISC" || stop_post discord_restart_command_failed

POST_DISC=""
for _ in $(seq 1 30); do
  POST_DISC=$(service_identity "$DISC" 2>/dev/null || true)
  if [[ -n "$POST_DISC" ]]; then
    break
  fi
  sleep 1
done
[[ -n "$POST_DISC" ]] || stop_post discord_did_not_recover

POST_DISC_PID=$(printf '%s' "$POST_DISC" | cut -d'|' -f3)
POST_DISC_NR=$(printf '%s' "$POST_DISC" | cut -d'|' -f4)
POST_DISC_START=$(printf '%s' "$POST_DISC" | cut -d'|' -f6)
echo "POST_DISCORD_SNAPSHOT=$POST_DISC"
[[ "$POST_DISC_PID" != "$PRE_DISC_PID" ]] || stop_post discord_pid_did_not_change
[[ "$POST_DISC_START" != "$PRE_DISC_START" ]] || stop_post discord_start_time_did_not_change
[[ "$POST_DISC_NR" == "$PRE_DISC_NR" ]] || stop_post discord_auto_restart_count_changed

sleep "$POST_DISCORD_STABILITY_SECONDS"
FINAL_DISC=$(service_identity "$DISC") || stop_post discord_not_stable
echo "FINAL_DISCORD_SNAPSHOT=$FINAL_DISC"
[[ "$FINAL_DISC" == "$POST_DISC" ]] || stop_post discord_identity_changed_after_restart

echo '--- FINAL PRESERVATION / HEALTH ---'
verify_preserved_service RESIDENT "$RES" "$PRE_RES"
verify_preserved_service CAPTURE "$CAP" "$PRE_CAP"
verify_preserved_service SIGNER "$SIGN" "$PRE_SIGN"

META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "FINAL_METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || stop_post metadata_block_changed

timer_gate AIRDROP_MONITOR "$MON_TIMER" || stop_post monitor_timer_changed
timer_gate AIRDROP_NOTIFIER "$NOT_TIMER" || stop_post notifier_timer_changed
oneshot_gate AIRDROP_MONITOR "$MON_SERVICE" || stop_post monitor_last_run_changed
oneshot_gate AIRDROP_NOTIFIER "$NOT_SERVICE" || stop_post notifier_last_run_changed

FINAL_CORE=$(protected_core)
FINAL_EVENTS=$(printf '%s' "$FINAL_CORE" | cut -d'|' -f1)
FINAL_MESSAGES=$(printf '%s' "$FINAL_CORE" | cut -d'|' -f2)
echo "FINAL_PROTECTED_CORE=$FINAL_EVENTS/$FINAL_MESSAGES"
[[ "$FINAL_EVENTS" == "$EXPECTED_CORE_EVENTS" && "$FINAL_MESSAGES" == "$EXPECTED_CORE_MESSAGES" ]] || stop_post protected_core_changed

echo '--- FINAL AIRDROP LOCAL HEALTH ---'
airdrop_health || stop_post final_airdrop_local_health_not_ok

echo 'AUTHORIZED_DISCORD_RESTARTS=1'
echo 'RESIDENT_RESTART=NO'
echo 'CAPTURE_RESTART=NO'
echo 'SIGNER_RESTART=NO'
echo 'METADATA_BLOCK_MUTATION=NO'
echo 'AIRDROP_TIMER_RESTART=NO'
echo 'PACKAGE_SYNC=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'SIGNER_ACTION=NO'
echo 'TECHNOCORE_WRITE=NO'
echo 'FLOP_WRITE=NO'
echo 'X_WRITE=NO'
echo 'SYNTHETIC_DISCORD_MESSAGE=NO'
echo '=== PROD442_DISCORD_SIGNAL_UX_V1=PASS ==='
echo 'DO_NOT_RERUN=YES'
exit 0
