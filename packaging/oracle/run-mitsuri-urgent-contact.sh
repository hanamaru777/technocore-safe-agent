#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  trap - ERR
  echo "MITSURI_URGENT=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'fail unexpected_rc_$?' ERR

REPO=/opt/technocore-safe-agent
REF=refs/remotes/origin/mitsuri-urgent-contact-helper
PROD_HEAD=11c527796d468beb268a1da1538be3a03cb88c33
MODULE_BLOB=8f4ebcebba3caed449dad6ec5091145746914ceb
MODULE=/run/sonnet_mitsuri_urgent_contact.py
LAUNCHER=/run/sonnet_mitsuri_urgent_launcher.py
UNIT=/run/systemd/system/technocore-safe-agent-sonnet-mitsuri-urgent.service
UNIT_NAME=technocore-safe-agent-sonnet-mitsuri-urgent.service
STATE=/var/lib/technocore-safe-agent/signer/sonnet-2-mitsuri-live-contact.json
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
[[ "$("${GIT[@]}" rev-parse "$REF:src/flop_agent/sonnet_mitsuri_urgent_contact.py")" == "$MODULE_BLOB" ]] || fail module_blob_mismatch
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
with open(sys.argv[1], encoding='utf-8') as f:
    d=json.load(f)
t=datetime.datetime.fromisoformat(d['updated_at'].replace('Z','+00:00'))
if t.tzinfo is None:
    t=t.replace(tzinfo=datetime.timezone.utc)
age=(datetime.datetime.now(datetime.timezone.utc)-t.astimezone(datetime.timezone.utc)).total_seconds()
print(d['health'], round(age,3), d['unrecoverable_core_gap_events'], d['unrecoverable_core_gap_messages'])
PY
) || fail safety_snapshot_unavailable
[[ "$HEALTH" == ok || "$HEALTH" == degraded ]] || fail safety_health_not_allowed
python3 - "$AGE" <<'PY' || fail safety_stale
import sys
age=float(sys.argv[1])
raise SystemExit(0 if 0 <= age <= 900 else 1)
PY
[[ "$EVENTS" == 117 && "$MESSAGES" == 5083155 ]] || fail "P0_core_changed:$EVENTS/$MESSAGES"
echo "MITSURI_URGENT_PREFLIGHT=PASS health=$HEALTH age=$AGE core=$EVENTS/$MESSAGES"

RES_PID=$(systemctl show technocore-safe-agent-resident.service -p MainPID --value)
RES_NR=$(systemctl show technocore-safe-agent-resident.service -p NRestarts --value)
CAP_PID=$(systemctl show technocore-safe-agent-lobby-capture.service -p MainPID --value)
CAP_NR=$(systemctl show technocore-safe-agent-lobby-capture.service -p NRestarts --value)
SIG_PID=$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)
SIG_NR=$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)
DIS_PID=$(systemctl show technocore-safe-agent-discord.service -p MainPID --value)
DIS_NR=$(systemctl show technocore-safe-agent-discord.service -p NRestarts --value)

"${GIT[@]}" show "$REF:src/flop_agent/sonnet_mitsuri_urgent_contact.py" > "$MODULE"
chmod 0444 "$MODULE"
cat > "$LAUNCHER" <<'PY'
import importlib.util, sys
spec=importlib.util.spec_from_file_location('flop_agent.sonnet_mitsuri_urgent_contact','/run/sonnet_mitsuri_urgent_contact.py')
if spec is None or spec.loader is None:
    raise SystemExit('loader_unavailable')
module=importlib.util.module_from_spec(spec)
sys.modules['flop_agent.sonnet_mitsuri_urgent_contact']=module
spec.loader.exec_module(module)
module.main()
PY
chmod 0444 "$LAUNCHER"

cat > "$UNIT" <<'UNIT'
[Unit]
Description=Approved urgent non-binding Mitsuri Agent contact
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
ExecStart=/opt/technocore-safe-agent/.venv/bin/python /run/sonnet_mitsuri_urgent_launcher.py
TimeoutStartSec=45s
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
IPAddressDeny=169.254.169.254
ReadOnlyPaths=/run/sonnet_mitsuri_urgent_contact.py /run/sonnet_mitsuri_urgent_launcher.py
ReadWritePaths=/var/lib/technocore-safe-agent/signer /var/lib/technocore-safe-agent/nonces.json
UNIT

systemctl daemon-reload
systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true
if ! timeout 55s systemctl start "$UNIT_NAME"; then
  echo 'MITSURI_URGENT=FAIL:oneshot'
  timeout 5s python3 - "$STATE" <<'PY' || true
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as f: d=json.load(f)
    print('FAIL_STATE=' + str(d.get('state')))
    print('FAIL_ATTEMPTED=' + ('YES' if d.get('attempted_at') else 'NO'))
    print('FAIL_SEQ=' + str(d.get('seq')))
    print('FAIL_TS=' + str(d.get('ts')))
except Exception as e:
    print('FAIL_STATE_READ=' + type(e).__name__)
PY
  journalctl -u "$UNIT_NAME" -n 12 --no-pager -o cat || true
  echo 'DO_NOT_RERUN=YES'
  exit 1
fi

read -r APP_STATE REQUEST_ID SEQ TS < <(
  timeout 5s python3 - "$STATE" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as f: d=json.load(f)
print(d.get('state'), d.get('request_id'), d.get('seq'), d.get('ts'))
PY
) || fail post_state_unreadable

echo "CONTACT_STATE=$APP_STATE"
echo "REQUEST_ID=$REQUEST_ID"
echo "SEQ=$SEQ"
echo "TS=$TS"
[[ "$APP_STATE" == posted ]] || fail contact_not_posted
[[ "$REQUEST_ID" == maru-mitsuri-live-20260915-1 ]] || fail request_id_mismatch
[[ "$SEQ" =~ ^[0-9]+$ ]] || fail missing_seq
[[ "$TS" != None && -n "$TS" ]] || fail missing_ts

[[ "$(systemctl show technocore-safe-agent-resident.service -p MainPID --value)" == "$RES_PID" ]] || fail resident_pid_changed
[[ "$(systemctl show technocore-safe-agent-resident.service -p NRestarts --value)" == "$RES_NR" ]] || fail resident_restarts_changed
[[ "$(systemctl show technocore-safe-agent-lobby-capture.service -p MainPID --value)" == "$CAP_PID" ]] || fail capture_pid_changed
[[ "$(systemctl show technocore-safe-agent-lobby-capture.service -p NRestarts --value)" == "$CAP_NR" ]] || fail capture_restarts_changed
[[ "$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)" == "$SIG_PID" ]] || fail signer_pid_changed
[[ "$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)" == "$SIG_NR" ]] || fail signer_restarts_changed
[[ "$(systemctl show technocore-safe-agent-discord.service -p MainPID --value)" == "$DIS_PID" ]] || fail discord_pid_changed
[[ "$(systemctl show technocore-safe-agent-discord.service -p NRestarts --value)" == "$DIS_NR" ]] || fail discord_restarts_changed
[[ "$("${GIT[@]}" rev-parse HEAD)" == "$PROD_HEAD" ]] || fail repo_head_changed

read -r POST_EVENTS POST_MESSAGES < <(
  timeout 5s python3 - "$SAFETY" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as f: d=json.load(f)
print(d['unrecoverable_core_gap_events'], d['unrecoverable_core_gap_messages'])
PY
) || fail post_safety_unavailable
[[ "$POST_EVENTS" == 117 && "$POST_MESSAGES" == 5083155 ]] || fail "P0_post_core_changed:$POST_EVENTS/$POST_MESSAGES"

trap - ERR
echo 'MITSURI_URGENT=PASS'
echo "PROTECTED_CORE=$POST_EVENTS/$POST_MESSAGES"
echo "RESIDENT_PRESERVED=$RES_PID/NRestarts=$RES_NR"
echo "CAPTURE_PRESERVED=$CAP_PID/NRestarts=$CAP_NR"
echo "SIGNER_PRESERVED=$SIG_PID/NRestarts=$SIG_NR"
echo "DISCORD_PRESERVED=$DIS_PID/NRestarts=$DIS_NR"
echo 'DO_NOT_RERUN=YES'
