#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  trap - ERR
  echo "DISCORD_SCORECARD_DEPLOY=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'fail unexpected_rc_$?' ERR

REPO=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
PRE=51d058b45a66259074eb8cb22dda49b4cb26aea8
TARGET=baf5a3e1d5d36a24b28cf9fa7dfa2dd41ccdf20f
RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service
SAFETY="$STATE/observer-safety.json"

cd "$REPO"
OWNER=$(stat -c %U .git) || fail git_owner_unreadable
gitx() { sudo -u "$OWNER" git -C "$REPO" "$@"; }
pid() { systemctl show "$1" -p MainPID --value; }
restarts() { systemctl show "$1" -p NRestarts --value; }

[[ "$(gitx symbolic-ref --short -q HEAD)" == main ]] || fail branch_not_main
[[ "$(gitx rev-parse HEAD)" == "$PRE" ]] || fail unexpected_pre_head
[[ -z "$(gitx status --porcelain=v1 --untracked-files=all)" ]] || fail dirty_tree
for svc in "$RES" "$CAP" "$SIG" "$DIS"; do
  systemctl is-active --quiet "$svc" || fail "service_not_active:$svc"
done

read -r HEALTH AGE EVENTS MESSAGES < <(
  timeout 5s python3 - "$SAFETY" <<'PY'
import datetime, json, sys
with open(sys.argv[1], encoding="utf-8") as f: d=json.load(f)
t=datetime.datetime.fromisoformat(d["updated_at"].replace("Z", "+00:00"))
if t.tzinfo is None: t=t.replace(tzinfo=datetime.timezone.utc)
age=(datetime.datetime.now(datetime.timezone.utc)-t.astimezone(datetime.timezone.utc)).total_seconds()
print(d["health"], round(age,3), d["unrecoverable_core_gap_events"], d["unrecoverable_core_gap_messages"])
PY
) || fail safety_snapshot_unavailable
[[ "$HEALTH" == ok || "$HEALTH" == degraded ]] || fail safety_health_not_allowed
python3 - "$AGE" <<'PY' || fail safety_stale
import sys
age=float(sys.argv[1])
raise SystemExit(0 if 0 <= age <= 300 else 1)
PY
[[ "$EVENTS" == 117 && "$MESSAGES" == 5083155 ]] || fail "P0_core_changed:$EVENTS/$MESSAGES"
echo "DISCORD_SCORECARD_PREFLIGHT=PASS health=$HEALTH age=$AGE core=$EVENTS/$MESSAGES"

RES_PID=$(pid "$RES"); RES_NR=$(restarts "$RES")
CAP_PID=$(pid "$CAP"); CAP_NR=$(restarts "$CAP")
SIG_PID=$(pid "$SIG"); SIG_NR=$(restarts "$SIG")
DIS_PID_BEFORE=$(pid "$DIS"); DIS_NR_BEFORE=$(restarts "$DIS")

timeout 30s sudo -u "$OWNER" git -C "$REPO" fetch --no-tags origin \
  refs/heads/main:refs/remotes/origin/main || fail origin_main_fetch_failed
[[ "$(gitx rev-parse refs/remotes/origin/main)" == "$TARGET" ]] || fail origin_main_not_target
[[ "$(gitx merge-base "$PRE" "$TARGET")" == "$PRE" ]] || fail target_not_descendant
ACTUAL=$(gitx diff --name-only "$PRE" "$TARGET" | LC_ALL=C sort)
EXPECTED=$(printf '%s\n' \
  src/flop_agent/discord_health_coalescing.py \
  src/flop_agent/discord_sonnet_outcome_overlay.py \
  tests/test_discord_sonnet_outcome_overlay.py | LC_ALL=C sort)
[[ "$ACTUAL" == "$EXPECTED" ]] || fail unexpected_target_delta

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
[[ "$(pid "$RES")" == "$RES_PID" && "$(restarts "$RES")" == "$RES_NR" ]] || fail resident_changed
[[ "$(pid "$CAP")" == "$CAP_PID" && "$(restarts "$CAP")" == "$CAP_NR" ]] || fail capture_changed
[[ "$(pid "$SIG")" == "$SIG_PID" && "$(restarts "$SIG")" == "$SIG_NR" ]] || fail signer_changed
[[ -z "$(gitx status --porcelain=v1 --untracked-files=all)" ]] || fail final_dirty_tree

read -r POST_EVENTS POST_MESSAGES < <(
  timeout 5s python3 - "$SAFETY" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f: d=json.load(f)
print(d["unrecoverable_core_gap_events"], d["unrecoverable_core_gap_messages"])
PY
) || fail post_safety_unavailable
[[ "$POST_EVENTS" == 117 && "$POST_MESSAGES" == 5083155 ]] || fail "P0_post_core_changed:$POST_EVENTS/$POST_MESSAGES"

trap - ERR
echo 'DISCORD_SCORECARD_DEPLOY=PASS'
echo "HEAD=$TARGET"
echo "PROTECTED_CORE=$POST_EVENTS/$POST_MESSAGES"
echo "DISCORD_RESTARTED=$DIS_PID_BEFORE->$DIS_PID_AFTER/NRestarts=$DIS_NR_AFTER"
echo "RESIDENT_PRESERVED=$RES_PID/NRestarts=$RES_NR"
echo "CAPTURE_PRESERVED=$CAP_PID/NRestarts=$CAP_NR"
echo "SIGNER_PRESERVED=$SIG_PID/NRestarts=$SIG_NR"
echo 'DO_NOT_RERUN=YES'
