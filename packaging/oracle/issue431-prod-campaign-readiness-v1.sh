#!/usr/bin/env bash
set -u
set -o pipefail
umask 022

APP=/opt/technocore-safe-agent
APP_PY=$APP/.venv/bin/python
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json

PRE=576d06dae3550ca7f32b3857d17ff79e911be0d0
TARGET=d8a9c2a43e1ba85f57e057ebf06a2a20da51bb20
EXPECTED_CORE_EVENTS=120
EXPECTED_CORE_MESSAGES=5650166

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIGN=technocore-safe-agent-signer.service
DISC=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service
MON_TIMER=technocore-safe-agent-airdrop-monitor.timer
MON_SERVICE=technocore-safe-agent-airdrop-monitor.service
NOT_TIMER=technocore-safe-agent-airdrop-notifier.timer
NOT_SERVICE=technocore-safe-agent-airdrop-notifier.service

EXPECTED_RES_PID=2251452
EXPECTED_RES_NR=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_NR=0
EXPECTED_SIGN_PID=1539554
EXPECTED_SIGN_NR=1
EXPECTED_DISC_PID=2251589
EXPECTED_DISC_NR=0

echo '=== PROD431 CAMPAIGN READINESS ROLLOUT V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

stop_pre() {
  echo "PROD431V1=STOP:$1"
  echo 'DO_NOT_RERUN=YES'
  exit 0
}

stop_post() {
  echo "PROD431V1=STOP:$1"
  echo 'TARGET_MAY_REMAIN_DEPLOYED=YES'
  echo 'DO_NOT_RERUN=YES'
  exit 0
}

if [[ $EUID -ne 0 ]]; then stop_pre not_root; fi
for cmd in git systemctl stat runuser cut sort diff; do
  command -v "$cmd" >/dev/null 2>&1 || stop_pre "missing_command:$cmd"
done
[[ -x "$APP_PY" && -f "$OBS" && -d "$APP/.git" ]] || stop_pre required_path_missing

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

service_exact() {
  local label=$1 unit=$2 expected_pid=$3 expected_nr=$4
  local active sub pid nr result
  active=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result"
  [[ "$active" == active && "$sub" == running && "$pid" == "$expected_pid" && "$nr" == "$expected_nr" && "$result" == success ]]
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

echo '--- PRE SERVICE / TIMER GATES ---'
service_exact RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_NR" || stop_pre resident_baseline_changed
service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_NR" || stop_pre capture_baseline_changed
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_NR" || stop_pre signer_baseline_changed
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_NR" || stop_pre discord_baseline_changed
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || stop_pre metadata_block_changed

timer_gate AIRDROP_MONITOR "$MON_TIMER" || stop_pre monitor_timer_not_active_enabled
timer_gate AIRDROP_NOTIFIER "$NOT_TIMER" || stop_pre notifier_timer_not_active_enabled
oneshot_gate AIRDROP_MONITOR "$MON_SERVICE" || stop_pre monitor_last_run_not_success
oneshot_gate AIRDROP_NOTIFIER "$NOT_SERVICE" || stop_pre notifier_last_run_not_success

CORE=$( "$APP_PY" - "$OBS" <<'PY'
import json, pathlib, sys
obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m=obs.get("metrics") or {}
print(f"{int(m.get('unrecoverable_core_gap_events',0) or 0)}|{int(m.get('unrecoverable_core_gap_messages',0) or 0)}")
PY
)
CORE_EVENTS=$(printf '%s' "$CORE" | cut -d'|' -f1)
CORE_MESSAGES=$(printf '%s' "$CORE" | cut -d'|' -f2)
echo "PRE_PROTECTED_CORE=$CORE_EVENTS/$CORE_MESSAGES"
[[ "$CORE_EVENTS" == "$EXPECTED_CORE_EVENTS" && "$CORE_MESSAGES" == "$EXPECTED_CORE_MESSAGES" ]] || stop_pre protected_core_changed

echo '--- PRE AIRDROP LOCAL HEALTH ---'
if ! runuser -u technocore -- env FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" PYTHONDONTWRITEBYTECODE=1 "$APP_PY" - <<'PY'
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
then
  stop_pre airdrop_local_health_not_ok
fi

echo '--- FETCH / TARGET GATES ---'
git_owner fetch --no-tags origin main || stop_pre fetch_failed
REMOTE_MAIN=$(git_owner rev-parse origin/main 2>/dev/null || true)
echo "REMOTE_MAIN=$REMOTE_MAIN"
[[ "$REMOTE_MAIN" == "$TARGET" ]] || stop_pre remote_main_moved
git_owner merge-base --is-ancestor "$PRE" "$TARGET" || stop_pre target_not_descendant

EXPECTED=$(printf '%s\n' \
  'docs/FIELD_REPORT_2026-09-23.md' \
  'src/flop_agent/airdrop_challenge.py' \
  'tests/test_airdrop_campaign_replay.py' | sort)
ACTUAL=$(git_owner diff --name-only "$PRE" "$TARGET" | sort)
echo 'TARGET_DIFF_BEGIN'
printf '%s\n' "$ACTUAL"
echo 'TARGET_DIFF_END'
[[ "$ACTUAL" == "$EXPECTED" ]] || stop_pre target_diff_not_exact

echo '--- FAST-FORWARD SOURCE ONLY ---'
git_owner merge --ff-only "$TARGET" || stop_pre ff_only_failed

POST_HEAD=$(git_owner rev-parse HEAD 2>/dev/null || true)
POST_BRANCH=$(git_owner branch --show-current 2>/dev/null || true)
POST_WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "POST_HEAD=$POST_HEAD"
echo "POST_BRANCH=$POST_BRANCH"
if [[ -z "$POST_WORKTREE" ]]; then echo 'POST_WORKTREE_CLEAN=YES'; else echo 'POST_WORKTREE_CLEAN=NO'; fi
[[ "$POST_HEAD" == "$TARGET" && "$POST_BRANCH" == main && -z "$POST_WORKTREE" ]] || stop_post post_repo_state_invalid

MODE=$(stat -c '%a' "$APP/src/flop_agent/airdrop_challenge.py" 2>/dev/null || true)
FOWNER=$(stat -c '%U' "$APP/src/flop_agent/airdrop_challenge.py" 2>/dev/null || true)
FGROUP=$(stat -c '%G' "$APP/src/flop_agent/airdrop_challenge.py" 2>/dev/null || true)
echo "CHALLENGE_SOURCE MODE=$MODE OWNER=$FOWNER GROUP=$FGROUP"
[[ "$MODE" == 644 && "$FOWNER" == root && "$FGROUP" == root ]] || stop_post challenge_source_permissions_invalid

echo '--- IMPORT SMOKE ---'
if ! runuser -u technocore -- env FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" PYTHONDONTWRITEBYTECODE=1 "$APP_PY" - <<'PY'
from flop_agent import airdrop_challenge
assert airdrop_challenge.DEFAULT_ARTIFACT_ATTEMPTS == 3
assert callable(airdrop_challenge._read_official_bytes)
print("CHALLENGE_IMPORT_SMOKE=PASS")
PY
then
  stop_post challenge_import_smoke_failed
fi

echo '--- POST SERVICE / TIMER GATES ---'
service_exact RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_NR" || stop_post resident_changed
service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_NR" || stop_post capture_changed
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_NR" || stop_post signer_changed
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_NR" || stop_post discord_changed
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "FINAL_METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || stop_post metadata_block_changed

timer_gate AIRDROP_MONITOR "$MON_TIMER" || stop_post monitor_timer_changed
timer_gate AIRDROP_NOTIFIER "$NOT_TIMER" || stop_post notifier_timer_changed
oneshot_gate AIRDROP_MONITOR "$MON_SERVICE" || stop_post monitor_last_run_changed
oneshot_gate AIRDROP_NOTIFIER "$NOT_SERVICE" || stop_post notifier_last_run_changed

FINAL_CORE=$( "$APP_PY" - "$OBS" <<'PY'
import json, pathlib, sys
obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m=obs.get("metrics") or {}
print(f"{int(m.get('unrecoverable_core_gap_events',0) or 0)}|{int(m.get('unrecoverable_core_gap_messages',0) or 0)}")
PY
)
FINAL_EVENTS=$(printf '%s' "$FINAL_CORE" | cut -d'|' -f1)
FINAL_MESSAGES=$(printf '%s' "$FINAL_CORE" | cut -d'|' -f2)
echo "FINAL_PROTECTED_CORE=$FINAL_EVENTS/$FINAL_MESSAGES"
[[ "$FINAL_EVENTS" == "$EXPECTED_CORE_EVENTS" && "$FINAL_MESSAGES" == "$EXPECTED_CORE_MESSAGES" ]] || stop_post protected_core_changed

echo '--- FINAL AIRDROP LOCAL HEALTH ---'
if ! runuser -u technocore -- env FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" PYTHONDONTWRITEBYTECODE=1 "$APP_PY" - <<'PY'
from flop_agent import airdrop_monitor, airdrop_notifier
m=airdrop_monitor.monitor_status()
n=airdrop_notifier.status()
print(f"FINAL_MONITOR_OUTCOME={m.get('outcome')}")
print(f"FINAL_MONITOR_HEARTBEAT_STALE={m.get('heartbeat_stale')}")
print(f"FINAL_RADAR_HEALTH={m.get('radar_health')}")
print(f"FINAL_LEDGER_INTEGRITY={m.get('ledger_integrity_valid')}")
print(f"FINAL_PENDING_ALERTS={int(m.get('pending_immediate_alerts',0))+int(m.get('pending_digest_alerts',0))}")
print(f"FINAL_NOTIFIER_FAILURE_COUNT={n.get('failure_count')}")
print(f"FINAL_NOTIFIER_BACKOFF_ACTIVE={n.get('backoff_active')}")
if m.get("outcome") != "recorded":
    raise SystemExit(21)
if m.get("heartbeat_stale") is not False:
    raise SystemExit(22)
if m.get("radar_health") not in {"ok","degraded"}:
    raise SystemExit(23)
if m.get("ledger_integrity_valid") is not True:
    raise SystemExit(24)
if int(n.get("failure_count",0) or 0) != 0:
    raise SystemExit(25)
if n.get("backoff_active") is not False:
    raise SystemExit(26)
PY
then
  stop_post final_airdrop_local_health_not_ok
fi

echo 'RUNNING_SERVICE_RESTART=NO'
echo 'SYSTEMD_MUTATION=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'TECHNOCORE_WRITE=NO'
echo 'FLOP_WRITE=NO'
echo 'X_WRITE=NO'
echo '=== PROD431_CAMPAIGN_READINESS_ROLLOUT_V1=PASS ==='
echo 'DO_NOT_RERUN=YES'
exit 0
