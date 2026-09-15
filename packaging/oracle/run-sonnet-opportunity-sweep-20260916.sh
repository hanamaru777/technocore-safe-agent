#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  trap - ERR
  echo "SONNET_SWEEP=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'fail unexpected_rc_$?' ERR

REPO=/opt/technocore-safe-agent
REF=refs/remotes/origin/sonnet-opportunity-sweep-helper
PROD_HEAD=51d058b45a66259074eb8cb22dda49b4cb26aea8
MODULE_BLOB=3cd14419e2bfa386834920b1c521ac89d8030e23
MODULE=/run/sonnet_opportunity_sweep_20260916.py
LAUNCHER=/run/sonnet_opportunity_sweep_20260916_launcher.py
UNIT=/run/systemd/system/technocore-safe-agent-sonnet-opportunity-sweep.service
UNIT_NAME=technocore-safe-agent-sonnet-opportunity-sweep.service
STATE=/var/lib/technocore-safe-agent/signer/sonnet-2-opportunity-sweep-20260916.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json

cleanup() {
  rm -f "$UNIT" "$MODULE" "$LAUNCHER"
  systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$REPO"
OWNER=$(stat -c %U .git) || fail git_owner_unreadable
GIT=(sudo -u "$OWNER" git -C "$REPO")

[[ "$("${GIT[@]}" symbolic-ref --short -q HEAD)" == main ]] || fail branch_not_main
[[ "$("${GIT[@]}" rev-parse HEAD)" == "$PROD_HEAD" ]] || fail unexpected_head
[[ -z "$("${GIT[@]}" status --porcelain=v1 --untracked-files=all)" ]] || fail dirty_tree
[[ "$("${GIT[@]}" rev-parse "$REF:src/flop_agent/sonnet_opportunity_sweep_20260916.py")" == "$MODULE_BLOB" ]] || fail module_blob_mismatch
[[ ! -e "$STATE" ]] || fail state_already_exists

for svc in \
  technocore-safe-agent-resident.service \
  technocore-safe-agent-lobby-capture.service \
  technocore-safe-agent-signer.service \
  technocore-safe-agent-discord.service; do
  systemctl is-active --quiet "$svc" || fail "service_not_active:$svc"
done

read -r HEALTH AGE EVENTS MESSAGES < <(
  timeout 5s python3 - "$SAFETY" <<'PY'
import datetime, json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d=json.load(f)
t=datetime.datetime.fromisoformat(d["updated_at"].replace("Z", "+00:00"))
if t.tzinfo is None:
    t=t.replace(tzinfo=datetime.timezone.utc)
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
echo "SONNET_SWEEP_PREFLIGHT=PASS health=$HEALTH age=$AGE core=$EVENTS/$MESSAGES"

RES_PID=$(systemctl show technocore-safe-agent-resident.service -p MainPID --value)
RES_NR=$(systemctl show technocore-safe-agent-resident.service -p NRestarts --value)
CAP_PID=$(systemctl show technocore-safe-agent-lobby-capture.service -p MainPID --value)
CAP_NR=$(systemctl show technocore-safe-agent-lobby-capture.service -p NRestarts --value)
SIG_PID=$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)
SIG_NR=$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)
DIS_PID=$(systemctl show technocore-safe-agent-discord.service -p MainPID --value)
DIS_NR=$(systemctl show technocore-safe-agent-discord.service -p NRestarts --value)

"${GIT[@]}" show "$REF:src/flop_agent/sonnet_opportunity_sweep_20260916.py" > "$MODULE"
chmod 0444 "$MODULE"
cat > "$LAUNCHER" <<'PY'
import importlib.util
import sys

name = "flop_agent.sonnet_opportunity_sweep_20260916"
spec = importlib.util.spec_from_file_location(name, "/run/sonnet_opportunity_sweep_20260916.py")
if spec is None or spec.loader is None:
    raise SystemExit("loader_unavailable")
module = importlib.util.module_from_spec(spec)
sys.modules[name] = module
spec.loader.exec_module(module)
module.main()
PY
chmod 0444 "$LAUNCHER"

cat > "$UNIT" <<'UNIT'
[Unit]
Description=Fixed non-binding Sonnet-2 opportunity sweep (magnatsv + luxion status)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=technocore-signer
Group=technocore-signer
SupplementaryGroups=technocore-autopilot
WorkingDirectory=/opt/technocore-safe-agent
EnvironmentFile=/etc/technocore-safe-agent/signer.env
Environment=FLOP_STATE_DIR=/var/lib/technocore-safe-agent
Environment=PYTHONPATH=/opt/technocore-safe-agent/src
Environment=UV_CACHE_DIR=/var/lib/technocore-safe-agent/signer/uv-cache
ExecStart=/opt/technocore-safe-agent/.venv/bin/python /run/sonnet_opportunity_sweep_20260916_launcher.py
TimeoutStartSec=240s
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectKernelLogs=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadOnlyPaths=/run/sonnet_opportunity_sweep_20260916.py /run/sonnet_opportunity_sweep_20260916_launcher.py
ReadWritePaths=/var/lib/technocore-safe-agent/signer /var/lib/technocore-safe-agent/nonces.json
UNIT

systemctl daemon-reload
systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true
if ! timeout 250s systemctl start "$UNIT_NAME"; then
  echo 'SONNET_SWEEP=FAIL:oneshot'
  if [[ -f "$STATE" ]]; then
    timeout 5s python3 - "$STATE" <<'PY' || true
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f: d=json.load(f)
    for key, item in d.get("items", {}).items():
        print(f"FAIL_ITEM={key} STATE={item.get('state')} ATTEMPTED={'YES' if item.get('attempted_at') else 'NO'} SEQ={item.get('seq')} TS={item.get('ts')}")
except Exception as e:
    print("FAIL_STATE_READ=" + type(e).__name__)
PY
  else
    echo 'FAIL_STATE=ABSENT'
  fi
  journalctl -u "$UNIT_NAME" -n 20 --no-pager -o cat || true
  echo 'DO_NOT_RERUN=YES'
  exit 1
fi

[[ -f "$STATE" ]] || fail no_state_after_oneshot
timeout 5s python3 - "$STATE" <<'PY' || fail post_state_invalid
import json, sys
with open(sys.argv[1], encoding="utf-8") as f: d=json.load(f)
assert d.get("schema_version") == 1
items=d.get("items")
assert isinstance(items, dict) and set(items) == {"magnatsv", "luxion-1"}
for key in ("magnatsv", "luxion-1"):
    item=items[key]
    assert item.get("state") == "posted"
    assert isinstance(item.get("seq"), int) and item["seq"] >= 0
    assert isinstance(item.get("ts"), str) and item["ts"]
    print(f"ITEM={key} STATE=posted REQUEST_ID={item.get('request_id')} SEQ={item.get('seq')} TS={item.get('ts')}")
PY

[[ "$(systemctl show technocore-safe-agent-resident.service -p MainPID --value)" == "$RES_PID" ]] || fail resident_pid_changed
[[ "$(systemctl show technocore-safe-agent-resident.service -p NRestarts --value)" == "$RES_NR" ]] || fail resident_restarts_changed
[[ "$(systemctl show technocore-safe-agent-lobby-capture.service -p MainPID --value)" == "$CAP_PID" ]] || fail capture_pid_changed
[[ "$(systemctl show technocore-safe-agent-lobby-capture.service -p NRestarts --value)" == "$CAP_NR" ]] || fail capture_restarts_changed
[[ "$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)" == "$SIG_PID" ]] || fail signer_pid_changed
[[ "$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)" == "$SIG_NR" ]] || fail signer_restarts_changed
[[ "$(systemctl show technocore-safe-agent-discord.service -p MainPID --value)" == "$DIS_PID" ]] || fail discord_pid_changed
[[ "$(systemctl show technocore-safe-agent-discord.service -p NRestarts --value)" == "$DIS_NR" ]] || fail discord_restarts_changed
[[ "$("${GIT[@]}" rev-parse HEAD)" == "$PROD_HEAD" ]] || fail repo_head_changed
[[ -z "$("${GIT[@]}" status --porcelain=v1 --untracked-files=all)" ]] || fail final_dirty_tree

read -r POST_EVENTS POST_MESSAGES < <(
  timeout 5s python3 - "$SAFETY" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f: d=json.load(f)
print(d["unrecoverable_core_gap_events"], d["unrecoverable_core_gap_messages"])
PY
) || fail post_safety_unavailable
[[ "$POST_EVENTS" == 117 && "$POST_MESSAGES" == 5083155 ]] || fail "P0_post_core_changed:$POST_EVENTS/$POST_MESSAGES"

trap - ERR
echo 'SONNET_SWEEP=PASS'
echo "PROTECTED_CORE=$POST_EVENTS/$POST_MESSAGES"
echo "RESIDENT_PRESERVED=$RES_PID/NRestarts=$RES_NR"
echo "CAPTURE_PRESERVED=$CAP_PID/NRestarts=$CAP_NR"
echo "SIGNER_PRESERVED=$SIG_PID/NRestarts=$SIG_NR"
echo "DISCORD_PRESERVED=$DIS_PID/NRestarts=$DIS_NR"
echo 'DO_NOT_RERUN=YES'
