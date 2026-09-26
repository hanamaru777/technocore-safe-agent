#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json
PROGRESS=/var/lib/technocore-safe-agent/observer/close1-discord-progress.json

PRE=a4016accdef7b1df591d68d1bcdc54c7a9de7320
TARGET=ebea19c35cd60aac930f43fe7eaaf69be68a250f
RES_PID=2462149
CAP_PID=2462148
SIG_PID=2462068
DIS_PID=2560998
CORE_E=143
CORE_M=5652707
BRIDGE_E=26
BRIDGE_M=569552

stop_rollout() {
  echo "PROD519V1=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "PROD519V1=ERROR:rc_$rc"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_rollout not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" && -f "$SAFETY" && -f "$PROGRESS" ]] || stop_rollout required_path_missing
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_rollout git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

snap() {
  local unit=$1
  printf '%s|%s|%s|%s|%s' \
    "$(systemctl show "$unit" -p ActiveState --value)" \
    "$(systemctl show "$unit" -p SubState --value)" \
    "$(systemctl show "$unit" -p MainPID --value)" \
    "$(systemctl show "$unit" -p NRestarts --value)" \
    "$(systemctl show "$unit" -p Result --value)"
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

obs_fields() {
  "$PY" - "$OBS" <<'PY'
import json, pathlib, sys
o=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
print("|".join([
 str(o.get("updated_at") or ""),
 str((o.get("health") or {}).get("current") or ""),
 str(int((o.get("cursors") or {}).get("lobby",0) or 0)),
]))
PY
}

progress_fields() {
  "$PY" - "$PROGRESS" <<'PY'
import json, pathlib, sys
p=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
assert p.get("schema_version")==1
attempt=p.get("last_attempt_at")
assert isinstance(attempt,str) and attempt
success=p.get("last_success_at")
failures=int(p.get("failure_count",0) or 0)
sweep=p.get("last_sweep")
print("|".join([attempt,success if isinstance(success,str) else "",str(failures),str(sweep if sweep is not None else "")]))
PY
}

safe_sample() {
  "$PY" - "$OBS" "$SAFETY" "$CORE_E" "$CORE_M" <<'PY'
import json, pathlib, sys
from datetime import UTC, datetime
obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
safe=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
ce,cm=map(int,sys.argv[3:5])
now=datetime.now(UTC)
def age(value):
    stamp=datetime.fromisoformat(str(value).replace("Z","+00:00")).astimezone(UTC)
    return (now-stamp).total_seconds()
if (obs.get("health") or {}).get("current")!="ok": raise SystemExit(1)
if not 0 <= age(obs.get("updated_at")) <= 300: raise SystemExit(1)
if safe.get("schema_version")!=1 or safe.get("health")!="ok": raise SystemExit(1)
if safe.get("unrecoverable_core_gap_events")!=ce or safe.get("unrecoverable_core_gap_messages")!=cm: raise SystemExit(1)
if not 0 <= age(safe.get("updated_at")) <= 300: raise SystemExit(1)
mem=None
for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
    if line.startswith("MemAvailable:"): mem=int(line.split()[1])*1024; break
if mem is None or mem < 256*1024*1024: raise SystemExit(1)
def psi(kind):
    for line in pathlib.Path(f"/proc/pressure/{kind}").read_text().splitlines():
        if line.startswith("full "):
            for part in line.split()[1:]:
                if part.startswith("avg10="): return float(part.split("=",1)[1])
    return 0.0
mpsi=psi("memory"); ipsi=psi("io")
if mpsi>5.0 or ipsi>10.0: raise SystemExit(1)
print(f"mem_mb:{mem//1024//1024} mpsi:{mpsi:.2f} ipsi:{ipsi:.2f}")
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
BASE_COUNTS="$CORE_E|$CORE_M|$BRIDGE_E|$BRIDGE_M"
[[ "$(counts)" == "$BASE_COUNTS" ]] || stop_rollout protected_baseline_changed

SAFE_STREAK=0
SAFE_LINE=""
for _ in $(seq 1 40); do
  [[ "$(git_owner rev-parse HEAD)" == "$PRE" && -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_rollout repo_changed_during_safe_wait
  [[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || stop_rollout resident_changed_during_safe_wait
  [[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_rollout capture_changed_during_safe_wait
  [[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_rollout signer_changed_during_safe_wait
  [[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || stop_rollout discord_changed_during_safe_wait
  [[ "$(counts)" == "$BASE_COUNTS" ]] || stop_rollout protected_changed_during_safe_wait
  if SAFE_LINE=$(safe_sample 2>/dev/null); then
    SAFE_STREAK=$((SAFE_STREAK+1))
    if (( SAFE_STREAK >= 5 )); then break; fi
  else
    SAFE_STREAK=0
  fi
  sleep 15
done
(( SAFE_STREAK >= 5 )) || stop_rollout no_safe_restart_window

PRE_OBS=$(obs_fields) || stop_rollout observer_state_unreadable
IFS='|' read -r OBS_UPDATED_BEFORE OBS_HEALTH_BEFORE LOBBY_BEFORE <<<"$PRE_OBS"
[[ "$OBS_HEALTH_BEFORE" == ok ]] || stop_rollout observer_not_ok_after_safe_wait
PROGRESS_BEFORE=$(progress_fields) || stop_rollout close1_progress_state_unreadable
IFS='|' read -r ATTEMPT_BEFORE SUCCESS_BEFORE FAILURES_BEFORE SWEEP_BEFORE <<<"$PROGRESS_BEFORE"

git_owner fetch --quiet --no-tags origin main
[[ "$(git_owner rev-parse FETCH_HEAD)" == "$TARGET" ]] || stop_rollout remote_main_moved
git_owner merge-base --is-ancestor "$PRE" "$TARGET" || stop_rollout target_not_ff
ACTUAL=$(git_owner diff --name-only "$PRE" "$TARGET" | LC_ALL=C sort | tr '\n' '|')
EXPECTED='src/flop_agent/close1_candidate_scanner.py|src/flop_agent/close1_discord_progress.py|src/flop_agent/close1_strategy.py|src/flop_agent/close_call.py|src/flop_agent/discord_control.py|src/flop_agent/observer_lobby_startup_hole_bridge.py|tests/test_close1_candidate_scanner.py|tests/test_close1_discord_progress.py|tests/test_close1_strategy.py|tests/test_close_call.py|tests/test_observer_lobby_startup_hole_bridge.py|'
[[ "$ACTUAL" == "$EXPECTED" ]] || stop_rollout target_diff_unexpected

git_owner merge --quiet --ff-only "$TARGET"
[[ "$(git_owner rev-parse HEAD)" == "$TARGET" && "$(git_owner branch --show-current)" == main ]] || stop_rollout source_update_mismatch
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_rollout worktree_dirty_after_update

runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$PY" - <<'PY'
from flop_agent import close1_candidate_scanner as scanner
from flop_agent import close1_discord_progress as progress
from flop_agent import discord_control
from flop_agent import observer_lobby_startup_hole_bridge as bridge
assert callable(scanner.fetch_candidate_scan)
assert callable(progress.periodic_notices)
assert callable(discord_control._close1_progress_once)
assert callable(discord_control.close1_progress_worker)
assert bridge.LOCAL_RECOVERY_GRACE_SECONDS == 8.5
assert bridge.LOCAL_RECOVERY_POLL_SECONDS == 1.0
assert callable(bridge._wait_for_local_resume)
PY

[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_rollout capture_changed_before_resident_restart
[[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_rollout signer_changed_before_resident_restart
[[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || stop_rollout discord_changed_before_resident_restart
[[ "$(counts)" == "$BASE_COUNTS" ]] || stop_rollout protected_changed_before_resident_restart

systemctl restart technocore-safe-agent-resident.service
NEW_RES=""
for _ in $(seq 1 30); do
  CUR=$(snap technocore-safe-agent-resident.service)
  IFS='|' read -r a s p n r <<<"$CUR"
  if [[ "$a" == active && "$s" == running && "$p" != 0 && "$p" != "$RES_PID" && "$n" == 0 && "$r" == success ]]; then NEW_RES=$p; break; fi
  sleep 1
done
[[ -n "$NEW_RES" ]] || stop_rollout resident_restart_not_stable

RES_ACCEPTED=NO
POST_SAFE=""
for _ in $(seq 1 60); do
  [[ "$(snap technocore-safe-agent-resident.service)" == "active|running|$NEW_RES|0|success" ]] || stop_rollout resident_unstable_after_restart
  [[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_rollout capture_changed_after_resident_restart
  [[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_rollout signer_changed_after_resident_restart
  [[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || stop_rollout discord_changed_before_its_restart
  [[ "$(counts)" == "$BASE_COUNTS" ]] || stop_rollout protected_changed_after_resident_restart
  CUR_OBS=$(obs_fields) || stop_rollout observer_state_unreadable_after_resident
  IFS='|' read -r OBS_UPDATED_AFTER OBS_HEALTH_AFTER LOBBY_AFTER <<<"$CUR_OBS"
  if [[ "$OBS_UPDATED_AFTER" != "$OBS_UPDATED_BEFORE" && "$OBS_HEALTH_AFTER" == ok && "$LOBBY_AFTER" -ge "$LOBBY_BEFORE" ]]; then
    if POST_SAFE=$(safe_sample 2>/dev/null); then RES_ACCEPTED=YES; break; fi
  fi
  sleep 10
done
[[ "$RES_ACCEPTED" == YES ]] || stop_rollout resident_observer_not_accepted

systemctl restart technocore-safe-agent-discord.service
NEW_DIS=""
for _ in $(seq 1 30); do
  CUR=$(snap technocore-safe-agent-discord.service)
  IFS='|' read -r a s p n r <<<"$CUR"
  if [[ "$a" == active && "$s" == running && "$p" != 0 && "$p" != "$DIS_PID" && "$n" == 0 && "$r" == success ]]; then NEW_DIS=$p; break; fi
  sleep 1
done
[[ -n "$NEW_DIS" ]] || stop_rollout discord_restart_not_stable

ADVANCED=NO
PROGRESS_AFTER="$PROGRESS_BEFORE"
for _ in $(seq 1 18); do
  [[ "$(snap technocore-safe-agent-resident.service)" == "active|running|$NEW_RES|0|success" ]] || stop_rollout resident_changed_during_discord_wait
  [[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_rollout capture_changed_during_discord_wait
  [[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_rollout signer_changed_during_discord_wait
  [[ "$(snap technocore-safe-agent-discord.service)" == "active|running|$NEW_DIS|0|success" ]] || stop_rollout discord_unstable_during_progress_wait
  [[ "$(counts)" == "$BASE_COUNTS" ]] || stop_rollout protected_changed_during_discord_wait
  PROGRESS_AFTER=$(progress_fields) || stop_rollout close1_progress_state_unreadable_after_restart
  IFS='|' read -r ATTEMPT_AFTER SUCCESS_AFTER FAILURES_AFTER SWEEP_AFTER <<<"$PROGRESS_AFTER"
  if [[ "$ATTEMPT_AFTER" != "$ATTEMPT_BEFORE" ]]; then ADVANCED=YES; break; fi
  sleep 10
done
[[ "$ADVANCED" == YES ]] || stop_rollout close1_worker_did_not_advance

[[ "$(git_owner rev-parse HEAD)" == "$TARGET" && -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_rollout repo_postcondition_failed
[[ "$(counts)" == "$BASE_COUNTS" ]] || stop_rollout protected_counts_changed_post
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_rollout capture_changed_post
[[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_rollout signer_changed_post

echo "PROD519V1=PASS"
echo "HEAD=$TARGET"
echo "SERVICES=resident:$NEW_RES capture:$CAP_PID signer:$SIG_PID discord:$NEW_DIS"
echo "PROTECTED=core:$CORE_E/$CORE_M bridge:$BRIDGE_E/$BRIDGE_M"
echo "SAFE_WINDOW=$SAFE_LINE"
echo "POST_RESIDENT_SAFE=$POST_SAFE lobby:$LOBBY_BEFORE->$LOBBY_AFTER"
echo "PROGRESS_ADVANCED=YES before:$ATTEMPT_BEFORE after:$ATTEMPT_AFTER"
echo "PROGRESS_POST=failure_count:$FAILURES_AFTER last_success:$SUCCESS_AFTER sweep:$SWEEP_AFTER"
echo "BRIDGE_FIX=LOADED DISCORD_INTELLIGENCE=LOADED SELF_HEALING_WORKER=LOADED"
echo "MUTATION=ff_source+resident_restart_once+discord_restart_once"
echo "CAPTURE_RESTART=NO SIGNER_RESTART=NO TECHNOCORE_POST=NO TRADE=NO"
echo "DO_NOT_RERUN=YES"