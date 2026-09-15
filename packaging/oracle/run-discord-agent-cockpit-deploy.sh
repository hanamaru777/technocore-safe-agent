#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  trap - ERR
  echo "DISCORD_COCKPIT_DEPLOY=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'fail unexpected_rc_$?' ERR

REPO=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
PRE=11c527796d468beb268a1da1538be3a03cb88c33
TARGET=51d058b45a66259074eb8cb22dda49b4cb26aea8
RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service
OBS="$STATE/observer/observer-state.json"
SAFETY="$STATE/observer-safety.json"

cd "$REPO"
OWNER=$(stat -c %U .git) || fail git_owner_unreadable
gitx() { sudo -u "$OWNER" git -C "$REPO" "$@"; }
pid() { systemctl show "$1" -p MainPID --value; }
restarts() { systemctl show "$1" -p NRestarts --value; }

snapshot() {
  timeout 8s python3 - "$OBS" "$SAFETY" <<'PY'
import json, sys
from datetime import UTC, datetime

obs_path, safety_path = sys.argv[1:]
def load(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)
def age(value):
    if not value:
        return 999999.0
    stamp = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return (datetime.now(UTC) - stamp.astimezone(UTC)).total_seconds()
obs = load(obs_path)
safety = load(safety_path)
m = obs.get('metrics') or {}
h = obs.get('health') or {}
print(
    h.get('current'),
    m.get('unrecoverable_core_gap_events'),
    m.get('unrecoverable_core_gap_messages'),
    round(age(obs.get('updated_at')), 1),
    safety.get('health'),
    safety.get('unrecoverable_core_gap_events'),
    safety.get('unrecoverable_core_gap_messages'),
    round(age(safety.get('updated_at')), 1),
)
PY
}

echo '=== DISCORD AGENT COCKPIT DEPLOY PRECHECK ==='
echo "UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "GIT_OWNER=$OWNER"
[[ "$(gitx symbolic-ref --short -q HEAD)" == main ]] || fail branch_not_main
[[ "$(gitx rev-parse HEAD)" == "$PRE" ]] || fail unexpected_pre_head
[[ -z "$(gitx status --porcelain=v1 --untracked-files=all)" ]] || fail dirty_tree
for svc in "$RES" "$CAP" "$SIG" "$DIS"; do
  systemctl is-active --quiet "$svc" || fail "service_not_active:$svc"
done

PRE_VALUES=$(snapshot) || fail pre_snapshot_unavailable
read -r PRE_HEALTH PRE_CE PRE_CM PRE_OBS_AGE PRE_SAFE_HEALTH PRE_SE PRE_SM PRE_SAFE_AGE <<< "$PRE_VALUES"
[[ "$PRE_CE" == 117 && "$PRE_CM" == 5083155 ]] || fail "P0_pre_observer_core_changed:$PRE_CE/$PRE_CM"
[[ "$PRE_SE" == 117 && "$PRE_SM" == 5083155 ]] || fail "P0_pre_safety_core_changed:$PRE_SE/$PRE_SM"
[[ "$PRE_SAFE_HEALTH" == ok || "$PRE_SAFE_HEALTH" == degraded ]] || fail safety_health_not_allowed
python3 - "$PRE_SAFE_AGE" <<'PY' || fail safety_stale
import sys
age=float(sys.argv[1])
raise SystemExit(0 if 0 <= age <= 300 else 1)
PY
echo "PRE_HEALTH=$PRE_HEALTH"
echo "PRE_CORE=$PRE_CE/$PRE_CM"
echo "PRE_SAFETY=$PRE_SAFE_HEALTH age=$PRE_SAFE_AGE"

RES_PID_BEFORE=$(pid "$RES"); RES_NR_BEFORE=$(restarts "$RES")
CAP_PID_BEFORE=$(pid "$CAP"); CAP_NR_BEFORE=$(restarts "$CAP")
SIG_PID_BEFORE=$(pid "$SIG"); SIG_NR_BEFORE=$(restarts "$SIG")
DIS_PID_BEFORE=$(pid "$DIS"); DIS_NR_BEFORE=$(restarts "$DIS")

timeout 30s sudo -u "$OWNER" git -C "$REPO" fetch --no-tags origin \
  refs/heads/main:refs/remotes/origin/main || fail origin_main_fetch_failed
[[ "$(gitx rev-parse refs/remotes/origin/main)" == "$TARGET" ]] || fail origin_main_not_target
[[ "$(gitx merge-base "$PRE" "$TARGET")" == "$PRE" ]] || fail target_not_descendant

ACTUAL=$(gitx diff --name-only "$PRE" "$TARGET" | LC_ALL=C sort)
EXPECTED=$(printf '%s\n' \
  src/flop_agent/discord_agent_activity.py \
  src/flop_agent/discord_health_coalescing.py \
  src/flop_agent/sonnet_nonbinding_policy.py \
  tests/test_discord_agent_activity.py \
  tests/test_sonnet_nonbinding_policy.py | LC_ALL=C sort)
[[ "$ACTUAL" == "$EXPECTED" ]] || fail unexpected_target_delta
echo 'DISCORD_COCKPIT_PREFLIGHT=PASS'

# Only two Production mutations: ff-only source update and Discord-only restart.
# Do not touch signer-private state or synthesize/backfill shared activity records.
gitx merge --ff-only "$TARGET" || fail fast_forward_failed
[[ "$(gitx rev-parse HEAD)" == "$TARGET" ]] || fail head_after_fast_forward
systemctl restart "$DIS" || fail discord_restart_failed
for _ in $(seq 1 20); do
  systemctl is-active --quiet "$DIS" && break
  sleep 1
done
systemctl is-active --quiet "$DIS" || fail discord_not_active
sleep 3

DIS_PID_AFTER=$(pid "$DIS"); DIS_NR_AFTER=$(restarts "$DIS")
[[ "$DIS_PID_AFTER" =~ ^[1-9][0-9]*$ ]] || fail discord_pid_invalid
[[ "$DIS_PID_AFTER" != "$DIS_PID_BEFORE" ]] || fail discord_pid_unchanged
[[ "$(pid "$RES")" == "$RES_PID_BEFORE" && "$(restarts "$RES")" == "$RES_NR_BEFORE" ]] || fail resident_changed
[[ "$(pid "$CAP")" == "$CAP_PID_BEFORE" && "$(restarts "$CAP")" == "$CAP_NR_BEFORE" ]] || fail capture_changed
[[ "$(pid "$SIG")" == "$SIG_PID_BEFORE" && "$(restarts "$SIG")" == "$SIG_NR_BEFORE" ]] || fail signer_changed

POST_VALUES=$(snapshot) || fail post_snapshot_unavailable
read -r POST_HEALTH POST_CE POST_CM POST_OBS_AGE POST_SAFE_HEALTH POST_SE POST_SM POST_SAFE_AGE <<< "$POST_VALUES"
[[ "$POST_CE" == 117 && "$POST_CM" == 5083155 ]] || fail "P0_post_observer_core_changed:$POST_CE/$POST_CM"
[[ "$POST_SE" == 117 && "$POST_SM" == 5083155 ]] || fail "P0_post_safety_core_changed:$POST_SE/$POST_SM"
[[ -z "$(gitx status --porcelain=v1 --untracked-files=all)" ]] || fail final_dirty_tree

trap - ERR
echo 'DISCORD_COCKPIT_DEPLOY=PASS'
echo "HEAD=$TARGET"
echo "POST_HEALTH=$POST_HEALTH"
echo "PROTECTED_CORE=$POST_CE/$POST_CM"
echo "DISCORD_RESTARTED=$DIS_PID_BEFORE->$DIS_PID_AFTER/NRestarts=$DIS_NR_AFTER"
echo "RESIDENT_PRESERVED=$RES_PID_BEFORE/NRestarts=$RES_NR_BEFORE"
echo "CAPTURE_PRESERVED=$CAP_PID_BEFORE/NRestarts=$CAP_NR_BEFORE"
echo "SIGNER_PRESERVED=$SIG_PID_BEFORE/NRestarts=$SIG_NR_BEFORE"
echo 'DO_NOT_RERUN=YES'
