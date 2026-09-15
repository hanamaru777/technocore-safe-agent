#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  trap - ERR
  echo "PROD225_REPAIR=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'fail unexpected_rc_$?' ERR

REPO=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
PRE=362dddadb669d4e126fe00c37da4a3f57cecbdbc
TARGET=11c527796d468beb268a1da1538be3a03cb88c33

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service
OBS="$STATE/observer/observer-state.json"
RESHB="$STATE/resident-heartbeat.json"

cd "$REPO"
OWNER=$(stat -c %U .git) || fail git_owner_unreadable
gitx() { sudo -u "$OWNER" git -C "$REPO" "$@"; }
pid() { systemctl show "$1" -p MainPID --value; }
restarts() { systemctl show "$1" -p NRestarts --value; }

snapshot() {
  timeout 8s python3 - "$OBS" "$RESHB" <<'PY'
import json, sys
from datetime import UTC, datetime

obs_path, resident_path = sys.argv[1:]

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
res = load(resident_path)
m = obs.get('metrics') or {}
c = obs.get('cursors') or {}
h = obs.get('health') or {}
print(
    h.get('current'),
    m.get('unrecoverable_core_gap_events'),
    m.get('unrecoverable_core_gap_messages'),
    c.get('lobby'),
    c.get('events'),
    round(age(obs.get('updated_at')), 1),
    res.get('status'),
    round(age(res.get('updated_at')), 1),
)
PY
}

echo '=== PROD225 REPAIR PRECHECK ==='
echo "UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "GIT_OWNER=$OWNER"

[[ "$(gitx symbolic-ref --short -q HEAD)" == main ]] || fail branch_not_main
[[ "$(gitx rev-parse HEAD)" == "$PRE" ]] || fail unexpected_pre_head
[[ -z "$(gitx status --porcelain=v1 --untracked-files=all)" ]] || fail dirty_tree

for svc in "$RES" "$CAP" "$SIG" "$DIS"; do
  systemctl is-active --quiet "$svc" || fail "service_not_active:$svc"
done

read -r PRE_HEALTH PRE_CE PRE_CM PRE_LOBBY PRE_EVENTS PRE_OBS_AGE PRE_RES_STATUS PRE_RES_AGE < <(snapshot) \
  || fail pre_snapshot_unavailable
[[ "$PRE_CE" == 117 && "$PRE_CM" == 5083155 ]] \
  || fail "P0_pre_core_changed:$PRE_CE/$PRE_CM"

echo "PRE_HEALTH=$PRE_HEALTH"
echo "PRE_CORE=$PRE_CE/$PRE_CM"
echo "PRE_LOBBY=$PRE_LOBBY"
echo "PRE_EVENTS=$PRE_EVENTS"
echo "PRE_OBSERVER_AGE_SEC=$PRE_OBS_AGE"
echo "PRE_RESIDENT_HEARTBEAT=$PRE_RES_STATUS age=$PRE_RES_AGE"

RES_PID_BEFORE=$(pid "$RES"); RES_NR_BEFORE=$(restarts "$RES")
CAP_PID_BEFORE=$(pid "$CAP"); CAP_NR_BEFORE=$(restarts "$CAP")
SIG_PID_BEFORE=$(pid "$SIG"); SIG_NR_BEFORE=$(restarts "$SIG")
DIS_PID_BEFORE=$(pid "$DIS"); DIS_NR_BEFORE=$(restarts "$DIS")

# Repair mode deliberately does not require Observer health=ok before deploying
# the reviewed fix for the unhealthy Observer. It requires only unchanged core,
# exact source/target, a clean tree, and preservation of unrelated services.
timeout 30s sudo -u "$OWNER" git -C "$REPO" fetch --no-tags origin \
  refs/heads/main:refs/remotes/origin/main \
  || fail origin_main_fetch_failed
[[ "$(gitx rev-parse refs/remotes/origin/main)" == "$TARGET" ]] || fail origin_main_not_target
[[ "$(gitx rev-list --count "$PRE..$TARGET")" == 1 ]] || fail target_not_one_commit_ahead
[[ "$(gitx rev-list --count "$TARGET..$PRE")" == 0 ]] || fail target_diverged

ACTUAL=$(gitx diff --name-only "$PRE" "$TARGET" | LC_ALL=C sort)
EXPECTED=$(printf '%s\n' \
  src/flop_agent/observer_lobby_startup_local_liveness.py \
  tests/test_observer_lobby_startup_local_liveness.py | LC_ALL=C sort)
[[ "$ACTUAL" == "$EXPECTED" ]] || fail unexpected_target_delta

echo 'PROD225_REPAIR_PREFLIGHT=PASS'

# The only Production mutations in this helper are the reviewed ff-only update
# and a Resident-only restart needed to load it.
gitx merge --ff-only "$TARGET" || fail fast_forward_failed
[[ "$(gitx rev-parse HEAD)" == "$TARGET" ]] || fail head_after_fast_forward
systemctl restart "$RES" || fail resident_restart_failed

for _ in $(seq 1 20); do
  systemctl is-active --quiet "$RES" && break
  sleep 1
done
systemctl is-active --quiet "$RES" || fail resident_not_active

RES_PID_AFTER=$(pid "$RES"); RES_NR_AFTER=$(restarts "$RES")
[[ "$RES_PID_AFTER" =~ ^[1-9][0-9]*$ ]] || fail resident_pid_invalid
[[ "$RES_PID_AFTER" != "$RES_PID_BEFORE" ]] || fail resident_pid_unchanged

[[ "$(pid "$CAP")" == "$CAP_PID_BEFORE" && "$(restarts "$CAP")" == "$CAP_NR_BEFORE" ]] \
  || fail capture_changed
[[ "$(pid "$SIG")" == "$SIG_PID_BEFORE" && "$(restarts "$SIG")" == "$SIG_NR_BEFORE" ]] \
  || fail signer_changed
[[ "$(pid "$DIS")" == "$DIS_PID_BEFORE" && "$(restarts "$DIS")" == "$DIS_NR_BEFORE" ]] \
  || fail discord_changed

# Do not require global health=ok here: upstream events transport may still be
# degraded independently. Require the repaired Resident to resume producing fresh
# state while the protected core stays exact.
RECOVERED=0
for I in $(seq 1 30); do
  if VALUES=$(snapshot 2>/dev/null); then
    read -r POST_HEALTH POST_CE POST_CM POST_LOBBY POST_EVENTS POST_OBS_AGE POST_RES_STATUS POST_RES_AGE <<< "$VALUES"
    [[ "$POST_CE" == 117 && "$POST_CM" == 5083155 ]] \
      || fail "P0_post_core_changed:$POST_CE/$POST_CM"
    if (( I % 5 == 0 )); then
      echo "RECOVERY_SAMPLE=$I health=$POST_HEALTH core=$POST_CE/$POST_CM lobby=$POST_LOBBY events=$POST_EVENTS obs_age=$POST_OBS_AGE resident=$POST_RES_STATUS resident_age=$POST_RES_AGE"
    fi
    if [[ "$POST_RES_STATUS" == ok ]] && python3 - "$POST_OBS_AGE" "$POST_RES_AGE" <<'PY'
import sys
obs_age, resident_age = map(float, sys.argv[1:])
raise SystemExit(0 if 0 <= obs_age <= 120 and 0 <= resident_age <= 120 else 1)
PY
    then
      RECOVERED=1
      break
    fi
  fi
  sleep 5
done
[[ "$RECOVERED" == 1 ]] || fail resident_state_not_fresh_after_repair

[[ -z "$(gitx status --porcelain=v1 --untracked-files=all)" ]] || fail final_dirty_tree
[[ "$(pid "$CAP")" == "$CAP_PID_BEFORE" && "$(restarts "$CAP")" == "$CAP_NR_BEFORE" ]] \
  || fail final_capture_changed
[[ "$(pid "$SIG")" == "$SIG_PID_BEFORE" && "$(restarts "$SIG")" == "$SIG_NR_BEFORE" ]] \
  || fail final_signer_changed
[[ "$(pid "$DIS")" == "$DIS_PID_BEFORE" && "$(restarts "$DIS")" == "$DIS_NR_BEFORE" ]] \
  || fail final_discord_changed

trap - ERR
echo 'PROD225_REPAIR=PASS'
echo "HEAD=$TARGET"
echo "POST_HEALTH=$POST_HEALTH"
echo "PROTECTED_CORE=$POST_CE/$POST_CM"
echo "POST_LOBBY=$POST_LOBBY"
echo "POST_EVENTS=$POST_EVENTS"
echo "RESIDENT_RESTARTED=$RES_PID_BEFORE->$RES_PID_AFTER/NRestarts=$RES_NR_AFTER"
echo "CAPTURE_PRESERVED=$CAP_PID_BEFORE/NRestarts=$CAP_NR_BEFORE"
echo "SIGNER_PRESERVED=$SIG_PID_BEFORE/NRestarts=$SIG_NR_BEFORE"
echo "DISCORD_PRESERVED=$DIS_PID_BEFORE/NRestarts=$DIS_NR_BEFORE"
echo 'DO_NOT_RERUN=YES'
