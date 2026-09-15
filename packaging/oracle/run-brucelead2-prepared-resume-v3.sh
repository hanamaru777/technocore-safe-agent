#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  trap - ERR
  echo "BRUCELEAD2_V3=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'fail unexpected_rc_$?' ERR

REPO=/opt/technocore-safe-agent
REF=refs/remotes/origin/brucelead2-prepared-resume-v3-helper
PROD_HEAD=11c527796d468beb268a1da1538be3a03cb88c33
LANE_BLOB=e3292675bb6b952cdd2ec6fc963a29479c8dbc7f
V3_BLOB=c6ca669ab841942ca141a7d8e903d3e845905f04
LANE=/run/sonnet_brucelead2_application.py
V3=/run/sonnet_brucelead2_prepared_resume_v3.py
LAUNCHER=/run/sonnet_brucelead2_v3_launcher.py
UNIT=/run/systemd/system/technocore-safe-agent-sonnet-brucelead2-v3.service
UNIT_NAME=technocore-safe-agent-sonnet-brucelead2-v3.service
STATE=/var/lib/technocore-safe-agent/signer/sonnet-2-brucelead2-application.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json

cleanup() {
  rm -f "$UNIT" "$LANE" "$V3" "$LAUNCHER"
  systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$REPO"
OWNER=$(stat -c %U .git) || fail git_owner_unreadable
GIT=(sudo -u "$OWNER" git -C "$REPO")

[[ "$("${GIT[@]}" symbolic-ref --short -q HEAD)" == main ]] || fail branch_not_main
[[ "$("${GIT[@]}" rev-parse HEAD)" == "$PROD_HEAD" ]] || fail unexpected_head
[[ -z "$("${GIT[@]}" status --porcelain=v1 --untracked-files=all)" ]] || fail dirty_tree
[[ "$("${GIT[@]}" rev-parse "$REF:src/flop_agent/sonnet_brucelead2_application.py")" == "$LANE_BLOB" ]] || fail lane_blob_mismatch
[[ "$("${GIT[@]}" rev-parse "$REF:src/flop_agent/sonnet_brucelead2_prepared_resume_v3.py")" == "$V3_BLOB" ]] || fail v3_blob_mismatch

for svc in \
  technocore-safe-agent-resident.service \
  technocore-safe-agent-lobby-capture.service \
  technocore-safe-agent-signer.service \
  technocore-safe-agent-discord.service; do
  systemctl is-active --quiet "$svc" || fail "service_not_active:$svc"
done

[[ -f "$STATE" ]] || fail prepared_state_missing
read -r APP_STATE REQUEST_ID NONCE ATTEMPTED SEQ TS POSTED STATE_AGE < <(
  timeout 5s python3 - "$STATE" <<'PY'
import datetime, json, os, sys
p=sys.argv[1]
with open(p, encoding='utf-8') as f:
    d=json.load(f)
age=(datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromtimestamp(os.stat(p).st_mtime, datetime.timezone.utc)).total_seconds()
print(
    d.get('state'), d.get('request_id'), d.get('nonce'), d.get('attempted_at'),
    d.get('seq'), d.get('ts'), 'yes' if d.get('posted_record') is not None else 'no',
    round(age,3),
)
PY
) || fail prepared_state_unreadable
[[ "$APP_STATE" == prepared ]] || fail "state_not_prepared:$APP_STATE"
[[ "$REQUEST_ID" == maru-brucelead2-apply-20260915-1 ]] || fail request_id_mismatch
[[ "$NONCE" =~ ^[0-9]+$ ]] || fail nonce_missing
[[ "$ATTEMPTED" == None && "$SEQ" == None && "$TS" == None && "$POSTED" == no ]] || fail post_evidence_present
python3 - "$STATE_AGE" <<'PY' || fail prepared_state_stale
import sys
age=float(sys.argv[1])
raise SystemExit(0 if 0 <= age <= 3600 else 1)
PY

echo "PREPARED_STATE=PASS age=$STATE_AGE nonce_present=yes attempted=no"

read -r SAFETY_HEALTH SAFETY_AGE SAFETY_EVENTS SAFETY_MESSAGES < <(
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
[[ "$SAFETY_HEALTH" == ok || "$SAFETY_HEALTH" == degraded ]] || fail safety_health_not_allowed
python3 - "$SAFETY_AGE" <<'PY' || fail safety_stale
import sys
age=float(sys.argv[1])
raise SystemExit(0 if 0 <= age <= 300 else 1)
PY
[[ "$SAFETY_EVENTS" == 117 && "$SAFETY_MESSAGES" == 5083155 ]] || fail "P0_core_changed:$SAFETY_EVENTS/$SAFETY_MESSAGES"

echo "BRUCELEAD2_V3_PREFLIGHT=PASS health=$SAFETY_HEALTH age=$SAFETY_AGE core=$SAFETY_EVENTS/$SAFETY_MESSAGES"

RES_PID_BEFORE=$(systemctl show technocore-safe-agent-resident.service -p MainPID --value)
RES_NR_BEFORE=$(systemctl show technocore-safe-agent-resident.service -p NRestarts --value)
CAP_PID_BEFORE=$(systemctl show technocore-safe-agent-lobby-capture.service -p MainPID --value)
CAP_NR_BEFORE=$(systemctl show technocore-safe-agent-lobby-capture.service -p NRestarts --value)
SIG_PID_BEFORE=$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)
SIG_NR_BEFORE=$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)
DIS_PID_BEFORE=$(systemctl show technocore-safe-agent-discord.service -p MainPID --value)
DIS_NR_BEFORE=$(systemctl show technocore-safe-agent-discord.service -p NRestarts --value)

"${GIT[@]}" show "$REF:src/flop_agent/sonnet_brucelead2_application.py" > "$LANE"
"${GIT[@]}" show "$REF:src/flop_agent/sonnet_brucelead2_prepared_resume_v3.py" > "$V3"
chmod 0444 "$LANE" "$V3"
cat > "$LAUNCHER" <<'PY'
import importlib.util
import sys
import flop_agent


def load(name, path):
    spec=importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit('loader_unavailable')
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    spec.loader.exec_module(module)
    return module

load('flop_agent.sonnet_brucelead2_application', '/run/sonnet_brucelead2_application.py')
v3=load('flop_agent.sonnet_brucelead2_prepared_resume_v3', '/run/sonnet_brucelead2_prepared_resume_v3.py')
v3.main()
PY
chmod 0444 "$LAUNCHER"

cat > "$UNIT" <<'UNIT'
[Unit]
Description=Approved BRUCELEAD-2 prepared-state non-binding resume v3
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
ExecStart=/opt/technocore-safe-agent/.venv/bin/python /run/sonnet_brucelead2_v3_launcher.py
TimeoutStartSec=60s
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
ReadOnlyPaths=/run/sonnet_brucelead2_application.py /run/sonnet_brucelead2_prepared_resume_v3.py /run/sonnet_brucelead2_v3_launcher.py
ReadWritePaths=/var/lib/technocore-safe-agent/signer /var/lib/technocore-safe-agent/nonces.json
UNIT

systemctl daemon-reload
systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true
if ! timeout 70s systemctl start "$UNIT_NAME"; then
  echo 'BRUCELEAD2_V3=FAIL:oneshot'
  timeout 5s python3 - "$STATE" <<'PY' || true
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as f:
        d=json.load(f)
    print('FAIL_STATE=' + str(d.get('state')))
    print('FAIL_ATTEMPTED=' + ('YES' if d.get('attempted_at') else 'NO'))
    print('FAIL_SEQ=' + str(d.get('seq')))
    print('FAIL_TS=' + str(d.get('ts')))
    print('FAIL_POSTED_RECORD=' + ('YES' if d.get('posted_record') else 'NO'))
except Exception as e:
    print('FAIL_STATE_READ_ERROR=' + type(e).__name__)
PY
  journalctl -u "$UNIT_NAME" -n 12 --no-pager -o cat || true
  echo 'DO_NOT_RERUN=YES'
  exit 1
fi

read -r APP_STATE REQUEST_ID SEQ TS < <(timeout 5s python3 - "$STATE" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
    d=json.load(f)
print(d.get('state'), d.get('request_id'), d.get('seq'), d.get('ts'))
PY
) || fail post_state_unreadable

echo "APPLICATION_STATE=$APP_STATE"
echo "REQUEST_ID=$REQUEST_ID"
echo "SEQ=$SEQ"
echo "TS=$TS"
[[ "$APP_STATE" == posted ]] || fail application_not_posted
[[ "$REQUEST_ID" == maru-brucelead2-apply-20260915-1 ]] || fail post_request_id_mismatch
[[ "$SEQ" =~ ^[0-9]+$ ]] || fail missing_seq
[[ "$TS" != None && -n "$TS" ]] || fail missing_ts

[[ "$(systemctl show technocore-safe-agent-resident.service -p MainPID --value)" == "$RES_PID_BEFORE" ]] || fail resident_pid_changed
[[ "$(systemctl show technocore-safe-agent-resident.service -p NRestarts --value)" == "$RES_NR_BEFORE" ]] || fail resident_restarts_changed
[[ "$(systemctl show technocore-safe-agent-lobby-capture.service -p MainPID --value)" == "$CAP_PID_BEFORE" ]] || fail capture_pid_changed
[[ "$(systemctl show technocore-safe-agent-lobby-capture.service -p NRestarts --value)" == "$CAP_NR_BEFORE" ]] || fail capture_restarts_changed
[[ "$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)" == "$SIG_PID_BEFORE" ]] || fail signer_pid_changed
[[ "$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)" == "$SIG_NR_BEFORE" ]] || fail signer_restarts_changed
[[ "$(systemctl show technocore-safe-agent-discord.service -p MainPID --value)" == "$DIS_PID_BEFORE" ]] || fail discord_pid_changed
[[ "$(systemctl show technocore-safe-agent-discord.service -p NRestarts --value)" == "$DIS_NR_BEFORE" ]] || fail discord_restarts_changed
[[ "$("${GIT[@]}" rev-parse HEAD)" == "$PROD_HEAD" ]] || fail repo_head_changed
[[ -z "$("${GIT[@]}" status --porcelain=v1 --untracked-files=all)" ]] || fail final_dirty_tree

read -r POST_HEALTH POST_AGE POST_EVENTS POST_MESSAGES < <(
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
) || fail post_safety_unavailable
[[ "$POST_EVENTS" == 117 && "$POST_MESSAGES" == 5083155 ]] || fail "P0_post_core_changed:$POST_EVENTS/$POST_MESSAGES"

trap - ERR
echo 'BRUCELEAD2_V3=PASS'
echo "PROTECTED_CORE=$POST_EVENTS/$POST_MESSAGES"
echo "RESIDENT_PRESERVED=$RES_PID_BEFORE/NRestarts=$RES_NR_BEFORE"
echo "CAPTURE_PRESERVED=$CAP_PID_BEFORE/NRestarts=$CAP_NR_BEFORE"
echo "SIGNER_PRESERVED=$SIG_PID_BEFORE/NRestarts=$SIG_NR_BEFORE"
echo "DISCORD_PRESERVED=$DIS_PID_BEFORE/NRestarts=$DIS_NR_BEFORE"
echo 'DO_NOT_RERUN=YES'
