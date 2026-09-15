#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  trap - ERR
  echo "MITSURI_RESUME=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'fail unexpected_rc_$?' ERR

REPO=/opt/technocore-safe-agent
REF=refs/remotes/origin/mitsuri-urgent-resume-helper
PROD_HEAD=11c527796d468beb268a1da1538be3a03cb88c33
BASE_BLOB=8f4ebcebba3caed449dad6ec5091145746914ceb
RESUME_BLOB=ac86869ccd29ed2af8b1862d202e40e30a89e3c9
BASE_MODULE=/run/sonnet_mitsuri_urgent_contact.py
RESUME_MODULE=/run/sonnet_mitsuri_urgent_resume.py
LAUNCHER=/run/sonnet_mitsuri_urgent_resume_launcher.py
UNIT=/run/systemd/system/technocore-safe-agent-sonnet-mitsuri-resume.service
UNIT_NAME=technocore-safe-agent-sonnet-mitsuri-resume.service
STATE=/var/lib/technocore-safe-agent/signer/sonnet-2-mitsuri-live-contact.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json

cleanup() {
  rm -f "$UNIT" "$BASE_MODULE" "$RESUME_MODULE" "$LAUNCHER"
  systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$REPO"
OWNER=$(stat -c %U .git) || fail git_owner_unreadable
GIT=(sudo -u "$OWNER" git -C "$REPO")

[[ "$("${GIT[@]}" symbolic-ref --short -q HEAD)" == main ]] || fail branch_not_main
[[ "$("${GIT[@]}" rev-parse HEAD)" == "$PROD_HEAD" ]] || fail unexpected_head
[[ -z "$("${GIT[@]}" status --porcelain=v1 --untracked-files=all)" ]] || fail dirty_tree
[[ "$("${GIT[@]}" rev-parse "$REF:src/flop_agent/sonnet_mitsuri_urgent_contact.py")" == "$BASE_BLOB" ]] || fail base_blob_mismatch
[[ "$("${GIT[@]}" rev-parse "$REF:src/flop_agent/sonnet_mitsuri_urgent_resume.py")" == "$RESUME_BLOB" ]] || fail resume_blob_mismatch

# Exact durable boundary from the failed pre-POST attempt. No blind write retry.
timeout 5s python3 - "$STATE" <<'PY' || fail prepared_state_not_exact
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
    d=json.load(f)
ok=(
    d.get('state') == 'prepared'
    and d.get('request_id') == 'maru-mitsuri-live-20260915-1'
    and isinstance(d.get('nonce'), str) and d.get('nonce').isdigit()
    and d.get('attempted_at') is None
    and d.get('seq') is None
    and d.get('ts') is None
    and d.get('posted_record') is None
    and isinstance(d.get('payload'), dict)
    and d['payload'].get('no_live_roster_consent') is True
    and d['payload'].get('target_did') == 'did:key:z6MkrjMTaN3kDvff5kdE6BhNxgErLdpz58kmsipP3PuHwoct'
)
raise SystemExit(0 if ok else 1)
PY

echo 'MITSURI_PREPARED_STATE=PASS attempted=NO post=NO'

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
with open(sys.argv[1], encoding='utf-8') as f: d=json.load(f)
t=datetime.datetime.fromisoformat(d['updated_at'].replace('Z','+00:00'))
if t.tzinfo is None: t=t.replace(tzinfo=datetime.timezone.utc)
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
echo "MITSURI_RESUME_PREFLIGHT=PASS health=$HEALTH age=$AGE core=$EVENTS/$MESSAGES"

RES_PID=$(systemctl show technocore-safe-agent-resident.service -p MainPID --value)
RES_NR=$(systemctl show technocore-safe-agent-resident.service -p NRestarts --value)
CAP_PID=$(systemctl show technocore-safe-agent-lobby-capture.service -p MainPID --value)
CAP_NR=$(systemctl show technocore-safe-agent-lobby-capture.service -p NRestarts --value)
SIG_PID=$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)
SIG_NR=$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)
DIS_PID=$(systemctl show technocore-safe-agent-discord.service -p MainPID --value)
DIS_NR=$(systemctl show technocore-safe-agent-discord.service -p NRestarts --value)

"${GIT[@]}" show "$REF:src/flop_agent/sonnet_mitsuri_urgent_contact.py" > "$BASE_MODULE"
"${GIT[@]}" show "$REF:src/flop_agent/sonnet_mitsuri_urgent_resume.py" > "$RESUME_MODULE"
chmod 0444 "$BASE_MODULE" "$RESUME_MODULE"

cat > "$LAUNCHER" <<'PY'
import importlib.util, sys

def load(name, path):
    spec=importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None: raise SystemExit('loader_unavailable')
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    spec.loader.exec_module(module)
    return module

load('flop_agent.sonnet_mitsuri_urgent_contact','/run/sonnet_mitsuri_urgent_contact.py')
module=load('flop_agent.sonnet_mitsuri_urgent_resume','/run/sonnet_mitsuri_urgent_resume.py')
module.main()
PY
chmod 0444 "$LAUNCHER"

cat > "$UNIT" <<'UNIT'
[Unit]
Description=Resume exact prepared non-binding Mitsuri Agent contact
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
ExecStart=/opt/technocore-safe-agent/.venv/bin/python /run/sonnet_mitsuri_urgent_resume_launcher.py
TimeoutStartSec=130s
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
ReadOnlyPaths=/run/sonnet_mitsuri_urgent_contact.py /run/sonnet_mitsuri_urgent_resume.py /run/sonnet_mitsuri_urgent_resume_launcher.py
ReadWritePaths=/var/lib/technocore-safe-agent/signer /var/lib/technocore-safe-agent/nonces.json
UNIT

systemctl daemon-reload
systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true
if ! timeout 140s systemctl start "$UNIT_NAME"; then
  echo 'MITSURI_RESUME=FAIL:oneshot'
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
  journalctl -u "$UNIT_NAME" -n 14 --no-pager -o cat || true
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
echo 'MITSURI_RESUME=PASS'
echo "PROTECTED_CORE=$POST_EVENTS/$POST_MESSAGES"
echo "RESIDENT_PRESERVED=$RES_PID/NRestarts=$RES_NR"
echo "CAPTURE_PRESERVED=$CAP_PID/NRestarts=$CAP_NR"
echo "SIGNER_PRESERVED=$SIG_PID/NRestarts=$SIG_NR"
echo "DISCORD_PRESERVED=$DIS_PID/NRestarts=$DIS_NR"
echo 'DO_NOT_RERUN=YES'
