#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json

PRE=d80a84aa04e1759e182e2cc16e6473d65b09eaef
TARGET=9baa91be7267b22143c33a06df3c67e1074dba0d
RES_PID=2256397
CAP_PID=2405706
SIG_PID=2256324
DIS_PID=2382118
CORE_E=124
CORE_M=5651120
BRIDGE_E=7
BRIDGE_M=567965

stop_rollout() {
  echo "PROD476V1=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "PROD476V1=ERROR:rc_$rc"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_rollout not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" ]] || stop_rollout required_path_missing
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_rollout git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

snap() {
  local unit=$1
  printf '%s|%s|%s|%s|%s\n'     "$(systemctl show "$unit" -p ActiveState --value)"     "$(systemctl show "$unit" -p SubState --value)"     "$(systemctl show "$unit" -p MainPID --value)"     "$(systemctl show "$unit" -p NRestarts --value)"     "$(systemctl show "$unit" -p Result --value)"
}

counts() {
  "$PY" - "$OBS" <<'PY'
import json, pathlib, sys
o=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m=o.get("metrics") or {}
print("|".join(map(str,[
 int(m.get("unrecoverable_core_gap_events",0) or 0),
 int(m.get("unrecoverable_core_gap_messages",0) or 0),
 int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),
 int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0),
])))
PY
}

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$PRE" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_rollout repo_baseline_changed

RES=$(snap technocore-safe-agent-resident.service)
CAP=$(snap technocore-safe-agent-lobby-capture.service)
SIG=$(snap technocore-safe-agent-signer.service)
DIS=$(snap technocore-safe-agent-discord.service)
[[ "$RES" == "active|running|$RES_PID|0|success" ]] || stop_rollout resident_baseline_changed
[[ "$CAP" == "active|running|$CAP_PID|0|success" ]] || stop_rollout capture_baseline_changed
[[ "$SIG" == "active|running|$SIG_PID|0|success" ]] || stop_rollout signer_baseline_changed
[[ "$DIS" == "active|running|$DIS_PID|0|success" ]] || stop_rollout discord_baseline_changed

BASE_COUNTS=$(counts)
[[ "$BASE_COUNTS" == "$CORE_E|$CORE_M|$BRIDGE_E|$BRIDGE_M" ]] || stop_rollout protected_baseline_changed

git_owner fetch --quiet --no-tags origin main
[[ "$(git_owner rev-parse FETCH_HEAD)" == "$TARGET" ]] || stop_rollout remote_main_moved
git_owner merge-base --is-ancestor "$PRE" "$TARGET" || stop_rollout target_not_ff

ACTUAL=$(git_owner diff --name-only "$PRE" "$TARGET" | LC_ALL=C sort | tr '\n' '|')
EXPECTED='src/flop_agent/discord_outcome_scorecard.py|tests/test_discord_outcome_scorecard.py|'
[[ "$ACTUAL" == "$EXPECTED" ]] || stop_rollout target_diff_unexpected

git_owner merge --quiet --ff-only "$TARGET"
[[ "$(git_owner rev-parse HEAD)" == "$TARGET" && "$(git_owner branch --show-current)" == main ]] || stop_rollout source_update_mismatch
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_rollout worktree_dirty_after_update

runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$PY" - <<'PY'
from flop_agent import discord_outcome_scorecard as score
assert callable(score._digest)
PY

[[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || stop_rollout resident_changed_before_restart
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_rollout capture_changed_before_restart
[[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_rollout signer_changed_before_restart

systemctl restart technocore-safe-agent-discord.service
NEW_DIS=''
for _ in $(seq 1 20); do
  CUR=$(snap technocore-safe-agent-discord.service)
  IFS='|' read -r a s p n r <<<"$CUR"
  if [[ "$a" == active && "$s" == running && "$p" != 0 && "$p" != "$DIS_PID" && "$n" == 0 && "$r" == success ]]; then
    NEW_DIS=$p
    break
  fi
  sleep 1
done
[[ -n "$NEW_DIS" ]] || stop_rollout discord_restart_not_stable
sleep 8

[[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || stop_rollout resident_changed_after_restart
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_rollout capture_changed_after_restart
[[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_rollout signer_changed_after_restart
[[ "$(snap technocore-safe-agent-discord.service)" == "active|running|$NEW_DIS|0|success" ]] || stop_rollout discord_unstable
[[ "$(counts)" == "$BASE_COUNTS" ]] || stop_rollout protected_counts_changed

echo "PROD476V1=PASS"
echo "HEAD=$TARGET"
echo "SERVICES=resident:$RES_PID capture:$CAP_PID signer:$SIG_PID discord:$NEW_DIS"
echo "PROTECTED=core:$CORE_E/$CORE_M bridge:$BRIDGE_E/$BRIDGE_M"
echo "SOURCE=6h_digest_health_severity_live"
echo "MUTATION=ff_source+discord_restart_once"
echo "OTHER_RESTARTS=NO"
echo "EXTERNAL_WRITE=NO"
echo "DO_NOT_RERUN=YES"
