#!/usr/bin/env bash
# One-shot Production rollout for FLOP Airdrop Radar monitor + Discord notifier.
# Never restarts Resident, Lobby Capture, Signer, Discord Gateway, or Metadata Block.
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
SOURCE_ENV=/etc/technocore-safe-agent/env
NOTIFIER_ENV=/etc/technocore-safe-agent/airdrop-notifier.env
OBSERVER_STATE="$STATE/observer/observer-state.json"

PRE_EXPECTED=b8dc6ef0b1ac689f1c45a0fb1451800c75dd5c1f
CORE_EVENTS_EXPECTED=117
CORE_MESSAGES_EXPECTED=5083155
TARGET=${1:-}

MONITOR_SERVICE=technocore-safe-agent-airdrop-monitor.service
MONITOR_TIMER=technocore-safe-agent-airdrop-monitor.timer
NOTIFIER_SERVICE=technocore-safe-agent-airdrop-notifier.service
NOTIFIER_TIMER=technocore-safe-agent-airdrop-notifier.timer

MONITOR_SERVICE_FILE=/etc/systemd/system/$MONITOR_SERVICE
MONITOR_TIMER_FILE=/etc/systemd/system/$MONITOR_TIMER
NOTIFIER_SERVICE_FILE=/etc/systemd/system/$NOTIFIER_SERVICE
NOTIFIER_TIMER_FILE=/etc/systemd/system/$NOTIFIER_TIMER

EXISTING_SERVICES=(
  technocore-safe-agent-resident.service
  technocore-safe-agent-lobby-capture.service
  technocore-safe-agent-signer.service
  technocore-safe-agent-discord.service
  technocore-safe-agent-metadata-block.service
)
LONG_RUNNING_SERVICES=(
  technocore-safe-agent-resident.service
  technocore-safe-agent-lobby-capture.service
  technocore-safe-agent-signer.service
  technocore-safe-agent-discord.service
)

stop() {
  local reason=$1
  trap - ERR
  echo "AIRDROP_PROD_DEPLOY=STOP:$reason"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'stop unexpected_rc_$?' ERR

[[ $EUID -eq 0 ]] || stop run_as_root
[[ $TARGET =~ ^[0-9a-f]{40}$ ]] || stop exact_target_sha_required
[[ -d $APP/.git && -x $APP/.venv/bin/python ]] || stop production_checkout_or_venv_missing
OWNER=$(stat -c %U "$APP/.git")
[[ -n $OWNER ]] || stop production_checkout_owner_missing
git_owner() {
  sudo -u "$OWNER" git "$@"
}
[[ -f $OBSERVER_STATE ]] || stop observer_state_missing
[[ -r $SOURCE_ENV ]] || stop discord_source_env_unreadable

for path in \
  "$MONITOR_SERVICE_FILE" "$MONITOR_TIMER_FILE" \
  "$NOTIFIER_SERVICE_FILE" "$NOTIFIER_TIMER_FILE" \
  "$NOTIFIER_ENV"; do
  [[ ! -e $path ]] || stop "airdrop_install_artifact_already_exists:$path"
done
[[ ! -e $STATE/airdrop-radar ]] || stop airdrop_state_already_exists_review_required

cd "$APP"
[[ -z $(git_owner status --porcelain) ]] || stop production_worktree_not_clean
PRE=$(git_owner rev-parse HEAD)
[[ $PRE == "$PRE_EXPECTED" ]] || stop "unexpected_production_head:$PRE"

for svc in "${EXISTING_SERVICES[@]}"; do
  systemctl is-active --quiet "$svc" || stop "required_service_not_active:$svc"
done

service_value() {
  systemctl show "$1" -p "$2" --value
}
declare -A PID_PRE RESTARTS_PRE
for svc in "${LONG_RUNNING_SERVICES[@]}"; do
  PID_PRE["$svc"]=$(service_value "$svc" MainPID)
  RESTARTS_PRE["$svc"]=$(service_value "$svc" NRestarts)
  [[ ${PID_PRE[$svc]:-0} -gt 0 ]] || stop "invalid_mainpid:$svc"
done

read -r HEALTH_PRE EVENTS_PRE MESSAGES_PRE < <(
  python3 - "$OBSERVER_STATE" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
metrics = data.get("metrics", {})
print(
    data.get("health", {}).get("current", "missing"),
    metrics.get("unrecoverable_core_gap_events", "missing"),
    metrics.get("unrecoverable_core_gap_messages", "missing"),
)
PY
)
[[ $HEALTH_PRE == ok || $HEALTH_PRE == degraded ]] || stop "observer_health_not_allowed:$HEALTH_PRE"
[[ $EVENTS_PRE == "$CORE_EVENTS_EXPECTED" && $MESSAGES_PRE == "$CORE_MESSAGES_EXPECTED" ]] || \
  stop "P0_core_changed_before:$EVENTS_PRE/$MESSAGES_PRE"

ENV_TMP=$(mktemp /tmp/airdrop-notifier-env.XXXXXX)
cleanup_tmp() { rm -f "$ENV_TMP"; }
trap cleanup_tmp EXIT

python3 - "$SOURCE_ENV" "$ENV_TMP" <<'PY'
from __future__ import annotations
import os, pathlib, re, sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
wanted = {}
seen = set()

for number, raw in enumerate(source.read_text("utf-8").splitlines(), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if "=" not in line:
        raise SystemExit(f"invalid env line {number}")
    key, value = line.split("=", 1)
    key = key.strip()
    value = value.strip()
    if key in seen:
        raise SystemExit(f"duplicate env key: {key}")
    seen.add(key)
    if key not in {"DISCORD_BOT_TOKEN", "DISCORD_CHANNEL_ID"}:
        continue
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    wanted[key] = value

token = wanted.get("DISCORD_BOT_TOKEN", "")
channel = wanted.get("DISCORD_CHANNEL_ID", "")
if not (20 <= len(token) <= 256) or re.search(r"\s", token):
    raise SystemExit("DISCORD_BOT_TOKEN missing or malformed")
if not channel.isdecimal() or not (10 <= len(channel) <= 30):
    raise SystemExit("DISCORD_CHANNEL_ID missing or malformed")

target.write_text(
    f"DISCORD_BOT_TOKEN={token}\nDISCORD_CHANNEL_ID={channel}\n",
    encoding="utf-8",
)
os.chmod(target, 0o600)
PY

git_owner fetch --no-tags origin main
REMOTE=$(git_owner rev-parse origin/main)
[[ $REMOTE == "$TARGET" ]] || stop "origin_main_moved:expected=$TARGET:actual=$REMOTE"
git_owner merge-base --is-ancestor "$PRE" "$TARGET" || stop target_not_fast_forward_from_production

EXPECTED_PATHS=$(cat <<'EOF' | sort
packaging/oracle/airdrop-monitor.service
packaging/oracle/airdrop-monitor.timer
packaging/oracle/airdrop-notifier.service
packaging/oracle/airdrop-notifier.timer
packaging/oracle/deploy-airdrop-production-v1.sh
src/flop_agent/airdrop_challenge.py
src/flop_agent/airdrop_ledger.py
src/flop_agent/airdrop_monitor.py
src/flop_agent/airdrop_notifier.py
src/flop_agent/airdrop_radar.py
src/flop_agent/cli.py
src/flop_agent/core.py
tests/test_airdrop_challenge.py
tests/test_airdrop_ledger.py
tests/test_airdrop_monitor.py
tests/test_airdrop_notifier.py
tests/test_airdrop_packaging.py
tests/test_airdrop_radar.py
tests/test_security.py
EOF
)
ACTUAL_PATHS=$(git_owner diff --name-only "$PRE..$TARGET" | sort)
[[ $ACTUAL_PATHS == "$EXPECTED_PATHS" ]] || {
  echo "AIRDROP_PROD_DEPLOY=STOP:changed_file_allowlist_mismatch" >&2
  echo "ACTUAL_CHANGED_PATHS:" >&2
  printf '%s\n' "$ACTUAL_PATHS" >&2
  echo "DO_NOT_RERUN=YES" >&2
  exit 1
}

for path in \
  packaging/oracle/airdrop-monitor.service \
  packaging/oracle/airdrop-monitor.timer \
  packaging/oracle/airdrop-notifier.service \
  packaging/oracle/airdrop-notifier.timer \
  packaging/oracle/deploy-airdrop-production-v1.sh; do
  git_owner cat-file -e "$TARGET:$path" || stop "target_missing_required_path:$path"
done

CUTOVER_STARTED=0
DONE=0
rollback() {
  local rc=$?
  trap - ERR
  if [[ $DONE -eq 0 && $CUTOVER_STARTED -eq 1 ]]; then
    set +e
    systemctl disable --now "$MONITOR_TIMER" "$NOTIFIER_TIMER" >/dev/null 2>&1
    systemctl stop "$MONITOR_SERVICE" "$NOTIFIER_SERVICE" >/dev/null 2>&1
    rm -f \
      "$MONITOR_SERVICE_FILE" "$MONITOR_TIMER_FILE" \
      "$NOTIFIER_SERVICE_FILE" "$NOTIFIER_TIMER_FILE" \
      "$NOTIFIER_ENV"
    systemctl daemon-reload >/dev/null 2>&1
    rm -rf -- "$STATE/airdrop-radar"
    cd "$APP"
    git_owner reset --hard "$PRE" >/dev/null 2>&1
    echo "AIRDROP_PROD_ROLLBACK=COMPLETE existing_services_not_restarted=YES" >&2
  fi
  cleanup_tmp
  exit "$rc"
}
trap rollback EXIT

CUTOVER_STARTED=1
git_owner merge --ff-only "$TARGET" >/dev/null
[[ $(git_owner rev-parse HEAD) == "$TARGET" ]] || stop post_merge_head_mismatch

install -o root -g root -m 0600 "$ENV_TMP" "$NOTIFIER_ENV"
install -o root -g root -m 0644 "$APP/packaging/oracle/airdrop-monitor.service" "$MONITOR_SERVICE_FILE"
install -o root -g root -m 0644 "$APP/packaging/oracle/airdrop-monitor.timer" "$MONITOR_TIMER_FILE"
install -o root -g root -m 0644 "$APP/packaging/oracle/airdrop-notifier.service" "$NOTIFIER_SERVICE_FILE"
install -o root -g root -m 0644 "$APP/packaging/oracle/airdrop-notifier.timer" "$NOTIFIER_TIMER_FILE"
systemctl daemon-reload

systemctl start "$MONITOR_SERVICE"
[[ $(service_value "$MONITOR_SERVICE" Result) == success ]] || stop monitor_oneshot_failed
[[ $(service_value "$MONITOR_SERVICE" ExecMainStatus) == 0 ]] || stop monitor_exit_nonzero

read -r MONITOR_OUTCOME RADAR_HEALTH LEDGER_OK SNAPSHOT_ID < <(
  sudo -u technocore env -i \
    PATH=/usr/bin:/bin \
    FLOP_STATE_DIR="$STATE" \
    PYTHONPATH="$APP/src" \
    "$APP/.venv/bin/python" - <<'PY'
from flop_agent import airdrop_monitor
s = airdrop_monitor.monitor_status()
print(
    s.get("outcome", "missing"),
    s.get("radar_health", "missing"),
    str(bool(s.get("ledger_integrity_valid"))).lower(),
    s.get("snapshot_id") or "missing",
)
PY
)
[[ $MONITOR_OUTCOME == recorded ]] || stop "monitor_baseline_not_recorded:$MONITOR_OUTCOME"
[[ $RADAR_HEALTH == ok || $RADAR_HEALTH == degraded ]] || stop "radar_health_not_allowed:$RADAR_HEALTH"
[[ $LEDGER_OK == true ]] || stop ledger_integrity_not_valid
[[ $SNAPSHOT_ID != missing ]] || stop snapshot_id_missing

SMOKE_ID="production-notifier-smoke-${TARGET:0:12}"
sudo -u technocore env -i \
  PATH=/usr/bin:/bin \
  FLOP_STATE_DIR="$STATE" \
  PYTHONPATH="$APP/src" \
  "$APP/.venv/bin/python" - "$SMOKE_ID" <<'PY'
from __future__ import annotations
import sys
from datetime import UTC, datetime
from flop_agent import airdrop_monitor

event_id = sys.argv[1]
now = datetime.now(UTC).isoformat()
payload = {
    "event_id": event_id,
    "severity": "HIGH",
    "type": "PRODUCTION_SMOKE_TEST",
    "key": "production_notifier_smoke_test",
    "route": "immediate",
    "source": "local_deploy_helper",
    "source_url": None,
    "authority": "local_smoke_test",
    "tier": None,
    "source_version": None,
    "before": "pending",
    "after": "delivery_test",
    "deadline": None,
    "deadline_gate": None,
    "safe_next_step": "No action required. Synthetic Production notifier delivery test only.",
}
with airdrop_monitor._alert_lock():
    state = airdrop_monitor._load_alerts()
    pending = [
        row for row in state.get("events", {}).values()
        if isinstance(row, dict) and row.get("delivery_state") == "pending"
    ]
    if pending:
        raise SystemExit("unexpected pending alerts before smoke test")
    if event_id in state.get("events", {}):
        raise SystemExit("smoke event already exists")
    state["events"][event_id] = {
        "event_id": event_id,
        "first_queued_at": now,
        "last_seen": now,
        "route": "immediate",
        "delivery_state": "pending",
        "payload": payload,
    }
    state["updated_at"] = now
    airdrop_monitor._atomic_json_write(
        airdrop_monitor._path(airdrop_monitor.ALERTS_NAME),
        state,
    )
PY

systemctl start "$NOTIFIER_SERVICE"
[[ $(service_value "$NOTIFIER_SERVICE" Result) == success ]] || stop notifier_oneshot_failed
[[ $(service_value "$NOTIFIER_SERVICE" ExecMainStatus) == 0 ]] || stop notifier_exit_nonzero

read -r SMOKE_STATE SMOKE_TRANSPORT SMOKE_RECEIPT < <(
  sudo -u technocore env -i \
    PATH=/usr/bin:/bin \
    FLOP_STATE_DIR="$STATE" \
    PYTHONPATH="$APP/src" \
    "$APP/.venv/bin/python" - "$SMOKE_ID" <<'PY'
import sys
from flop_agent import airdrop_monitor
row = airdrop_monitor.alert_delivery_status(sys.argv[1])
print(
    row.get("delivery_state", "missing"),
    row.get("delivery_transport", "missing"),
    row.get("delivery_receipt", "missing"),
)
PY
)
[[ $SMOKE_STATE == delivered && $SMOKE_TRANSPORT == discord ]] || stop "discord_smoke_not_delivered:$SMOKE_STATE/$SMOKE_TRANSPORT"
[[ $SMOKE_RECEIPT =~ ^[0-9]+$ ]] || stop discord_smoke_receipt_invalid

systemctl enable --now "$MONITOR_TIMER" "$NOTIFIER_TIMER" >/dev/null
systemctl is-active --quiet "$MONITOR_TIMER" || stop monitor_timer_not_active
systemctl is-active --quiet "$NOTIFIER_TIMER" || stop notifier_timer_not_active

for svc in "${EXISTING_SERVICES[@]}"; do
  systemctl is-active --quiet "$svc" || stop "existing_service_not_active_after:$svc"
done
for svc in "${LONG_RUNNING_SERVICES[@]}"; do
  pid_post=$(service_value "$svc" MainPID)
  restarts_post=$(service_value "$svc" NRestarts)
  [[ $pid_post == "${PID_PRE[$svc]}" ]] || stop "existing_service_pid_changed:$svc"
  [[ $restarts_post == "${RESTARTS_PRE[$svc]}" ]] || stop "existing_service_restarts_changed:$svc"
done

read -r HEALTH_POST EVENTS_POST MESSAGES_POST < <(
  python3 - "$OBSERVER_STATE" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
metrics = data.get("metrics", {})
print(
    data.get("health", {}).get("current", "missing"),
    metrics.get("unrecoverable_core_gap_events", "missing"),
    metrics.get("unrecoverable_core_gap_messages", "missing"),
)
PY
)
[[ $EVENTS_POST == "$CORE_EVENTS_EXPECTED" && $MESSAGES_POST == "$CORE_MESSAGES_EXPECTED" ]] || \
  stop "P0_core_changed_after:$EVENTS_POST/$MESSAGES_POST"
[[ $HEALTH_POST == ok || $HEALTH_POST == degraded ]] || stop "observer_health_not_allowed_after:$HEALTH_POST"
[[ -z $(git_owner status --porcelain) ]] || stop post_deploy_worktree_not_clean

DONE=1
trap - EXIT
cleanup_tmp

printf '%s\n' \
  "AIRDROP_PROD_DEPLOY=PASS" \
  "PRE_SHA=$PRE" \
  "POST_SHA=$(git_owner rev-parse HEAD)" \
  "PROTECTED_CORE=$EVENTS_POST/$MESSAGES_POST OBSERVER_HEALTH=$HEALTH_POST" \
  "EXISTING_SERVICES_UNCHANGED=YES" \
  "MONITOR_OUTCOME=$MONITOR_OUTCOME RADAR_HEALTH=$RADAR_HEALTH LEDGER_INTEGRITY=$LEDGER_OK" \
  "MONITOR_TIMER=$(systemctl is-active "$MONITOR_TIMER") NOTIFIER_TIMER=$(systemctl is-active "$NOTIFIER_TIMER")" \
  "DISCORD_SMOKE=DELIVERED receipt=$SMOKE_RECEIPT" \
  "NOTIFIER_ENV=DEDICATED_DISCORD_KEYS_ONLY" \
  "FLOP_EXTERNAL_WRITE=NO SIGNER_RESTART=NO RESIDENT_RESTART=NO DISCORD_GATEWAY_RESTART=NO" \
  "DO_NOT_RERUN=YES"
