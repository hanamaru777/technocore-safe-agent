#!/usr/bin/env bash
set -u
set -o pipefail
umask 022

APP=/opt/technocore-safe-agent
APP_PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
EXPECTED_PROD_HEAD=041b830d3b0ffd17ef95f8d889922f20d3ac6631

echo '=== PROD445 CORE121 PATH ATTRIBUTION V2 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

stop_diag() {
  echo "DIAG445V2=STOP:$1"
  echo 'MUTATION=NO'
  echo 'DO_NOT_RERUN=YES'
  exit 0
}

if [[ $EUID -ne 0 ]]; then stop_diag not_root; fi
[[ -x "$APP_PY" && -f "$OBS" && -d "$APP/.git" ]] || stop_diag required_path_missing

OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_diag git_owner_missing

git_owner() {
  runuser -u "$OWNER" -- git -C "$APP" "$@"
}

HEAD=$(git_owner rev-parse HEAD 2>/dev/null || true)
BRANCH=$(git_owner branch --show-current 2>/dev/null || true)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all 2>/dev/null || true)

echo "REPO_HEAD=$HEAD"
echo "REPO_BRANCH=$BRANCH"
if [[ -z "$WORKTREE" ]]; then echo 'REPO_WORKTREE_CLEAN=YES'; else echo 'REPO_WORKTREE_CLEAN=NO'; fi
[[ "$HEAD" == "$EXPECTED_PROD_HEAD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_diag repo_state_unexpected

for unit in \
  technocore-safe-agent-resident.service \
  technocore-safe-agent-lobby-capture.service \
  technocore-safe-agent-signer.service \
  technocore-safe-agent-discord.service
do
  echo "SERVICE=$unit ACTIVE=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true) SUB=$(systemctl show "$unit" -p SubState --value 2>/dev/null || true) PID=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true) NRESTARTS=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true) RESULT=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)"
done

"$APP_PY" - "$OBS" <<'PY'
import json
import pathlib
import sys

BASE_CORE_EVENTS = 120
BASE_CORE_MESSAGES = 5_650_166
BASE_BRIDGE_EVENTS = 3
BASE_BRIDGE_MESSAGES = 567_011

obs = json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m = obs.get("metrics") or {}

core_events = int(m.get("unrecoverable_core_gap_events", 0) or 0)
core_messages = int(m.get("unrecoverable_core_gap_messages", 0) or 0)
bridge_events = int(m.get("lobby_startup_bridge_unrecoverable_events", 0) or 0)
bridge_messages = int(m.get("lobby_startup_bridge_unrecoverable_messages", 0) or 0)

core_delta_events = core_events - BASE_CORE_EVENTS
core_delta_messages = core_messages - BASE_CORE_MESSAGES
bridge_delta_events = bridge_events - BASE_BRIDGE_EVENTS
bridge_delta_messages = bridge_messages - BASE_BRIDGE_MESSAGES

print(f"CORE_CURRENT={core_events}/{core_messages}")
print(f"CORE_DELTA_FROM_444={core_delta_events}/{core_delta_messages}")
print(f"STARTUP_BRIDGE_CURRENT={bridge_events}/{bridge_messages}")
print(f"STARTUP_BRIDGE_DELTA_FROM_409={bridge_delta_events}/{bridge_delta_messages}")
print(
    "STARTUP_BRIDGE_EXACTLY_EXPLAINS_POST_BASELINE_CORE="
    + (
        "YES"
        if (
            core_delta_events == bridge_delta_events
            and core_delta_messages == bridge_delta_messages
        )
        else "NO"
    )
)

keys = (
    "lobby_startup_bridge_attempts",
    "lobby_startup_bridge_successes",
    "lobby_startup_bridge_messages",
    "lobby_startup_bridge_failures",
    "lobby_startup_bridge_bytes",
    "lobby_startup_bridge_unrecoverable_events",
    "lobby_startup_bridge_unrecoverable_messages",
    "lobby_startup_bridge_local_suffix_handoffs",
    "lobby_startup_bridge_avoided_unrecoverable_messages",
    "lobby_startup_spool_attempts",
    "lobby_startup_spool_recoveries",
    "lobby_startup_spool_messages",
    "lobby_spool_recovery_events",
    "lobby_spool_recovered_messages",
    "lobby_spool_partial_recovery_messages",
    "lobby_spool_catchup_waits",
    "lobby_spool_catchup_successes",
    "lobby_spool_catchup_timeouts",
)
for key in keys:
    print(f"METRIC_{key.upper()}={int(m.get(key, 0) or 0)}")

last = obs.get("last_unrecoverable_gap")
print("LAST_UNRECOVERABLE_GAP=" + json.dumps(last, sort_keys=True, separators=(",", ":")))
print(f"LOBBY_CURSOR={int((obs.get('cursors') or {}).get('lobby', 0) or 0)}")
print(f"OBSERVER_HEALTH={((obs.get('health') or {}).get('current'))}")
PY

echo 'GIT_MUTATION=NO'
echo 'NETWORK_PROBE=NO'
echo 'JOURNAL_READ=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'SYSTEMD_MUTATION=NO'
echo 'RUNNING_SERVICE_RESTART=NO'
echo 'SIGNER_ACTION=NO'
echo 'TECHNOCORE_WRITE=NO'
echo 'FLOP_WRITE=NO'
echo 'X_WRITE=NO'
echo '=== DIAG445V2_READ_ONLY_ATTRIBUTION=PASS ==='
echo 'DO_NOT_RERUN=YES'
