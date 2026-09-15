#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  trap - ERR
  echo "MITSURI_FAST=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'fail unexpected_rc_$?' ERR

REPO=/opt/technocore-safe-agent
REF=refs/remotes/origin/mitsuri-fast-contact-helper
PROD_HEAD=362dddadb669d4e126fe00c37da4a3f57cecbdbc
LANE_BLOB=e4bb73ed338144034f768cdd9257359f27d09fdb
FAST_BLOB=6bdc191a594c10df120a9bb9cd5313f03a37dbd0

LANE=/run/sonnet_mitsuri_contact.py
FAST=/run/sonnet_mitsuri_contact_fast.py
UNIT=/run/systemd/system/technocore-safe-agent-sonnet-mitsuri-fast.service
UNIT_NAME=technocore-safe-agent-sonnet-mitsuri-fast.service
STATE=/var/lib/technocore-safe-agent/signer/sonnet-2-mitsuri-contact.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json

cleanup() {
  rm -f "$UNIT" "$LANE" "$FAST"
  systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$REPO"
OWNER=$(stat -c %U .git) || fail git_owner_unreadable
GIT=(sudo -u "$OWNER" git -C "$REPO")

[[ "$("${GIT[@]}" rev-parse HEAD)" == "$PROD_HEAD" ]] || fail unexpected_head
[[ -z "$("${GIT[@]}" status --porcelain=v1 --untracked-files=all)" ]] || fail dirty_tree
[[ "$("${GIT[@]}" rev-parse "$REF:src/flop_agent/sonnet_mitsuri_contact.py")" == "$LANE_BLOB" ]] || fail lane_blob_mismatch
[[ "$("${GIT[@]}" rev-parse "$REF:src/flop_agent/sonnet_mitsuri_contact_fast.py")" == "$FAST_BLOB" ]] || fail fast_blob_mismatch

systemctl is-active --quiet technocore-safe-agent-resident.service || fail resident_inactive
systemctl is-active --quiet technocore-safe-agent-lobby-capture.service || fail capture_inactive
systemctl is-active --quiet technocore-safe-agent-signer.service || fail signer_inactive

# This exact successor is permitted only because the prior timed-out export
# bootstrap left no durable contact state at all. If a state exists now, stop:
# it may represent a later sign/POST attempt and must be reconciled separately.
[[ ! -e "$STATE" ]] || fail state_already_exists

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
raise SystemExit(0 if 0 <= age <= 900 else 1)
PY
[[ "$SAFETY_EVENTS" == 117 && "$SAFETY_MESSAGES" == 5083155 ]] \
  || fail "P0_core_changed:$SAFETY_EVENTS/$SAFETY_MESSAGES"

echo "MITSURI_FAST_PREFLIGHT=PASS health=$SAFETY_HEALTH age=$SAFETY_AGE core=$SAFETY_EVENTS/$SAFETY_MESSAGES"

SIGNER_PID_BEFORE=$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)
SIGNER_NR_BEFORE=$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)
RES_PID_BEFORE=$(systemctl show technocore-safe-agent-resident.service -p MainPID --value)
CAP_PID_BEFORE=$(systemctl show technocore-safe-agent-lobby-capture.service -p MainPID --value)

"${GIT[@]}" show "$REF:src/flop_agent/sonnet_mitsuri_contact.py" > "$LANE"
"${GIT[@]}" show "$REF:src/flop_agent/sonnet_mitsuri_contact_fast.py" > "$FAST"
chmod 0444 "$LANE" "$FAST"

cat > "$UNIT" <<'UNIT'
[Unit]
Description=Approved fixed non-binding Mitsuri Sonnet contact fast path v2
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
Environment=PYTHONPATH=/run:/opt/technocore-safe-agent/src
Environment=UV_CACHE_DIR=/var/lib/technocore-safe-agent/signer/uv-cache
ExecStart=/opt/technocore-safe-agent/.venv/bin/python /run/sonnet_mitsuri_contact_fast.py
TimeoutStartSec=75s
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
ReadOnlyPaths=/run/sonnet_mitsuri_contact.py /run/sonnet_mitsuri_contact_fast.py
ReadWritePaths=/var/lib/technocore-safe-agent/signer /var/lib/technocore-safe-agent/nonces.json
UNIT

systemctl daemon-reload
systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true
if ! systemctl start "$UNIT_NAME"; then
  echo 'MITSURI_FAST=FAIL:oneshot'
  journalctl -u "$UNIT_NAME" -n 12 --no-pager -o cat || true
  if [[ -f "$STATE" ]]; then
    python3 - "$STATE" <<'PY' || true
import json, sys
try:
    d=json.load(open(sys.argv[1], encoding='utf-8'))
    print('FAIL_STATE=' + str(d.get('state')))
    print('FAIL_REQUEST_ID=' + str(d.get('request_id')))
    print('FAIL_SEQ=' + str(d.get('seq')))
    print('FAIL_TS=' + str(d.get('ts')))
except Exception as e:
    print('FAIL_STATE_READ=' + type(e).__name__)
PY
  else
    echo 'FAIL_STATE=ABSENT'
  fi
  echo 'DO_NOT_RERUN=YES'
  exit 1
fi

[[ -f "$STATE" ]] || fail no_state_after_oneshot
read -r CONTACT_STATE REQUEST_ID SEQ TS < <(python3 - "$STATE" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
    d=json.load(f)
print(d.get('state'), d.get('request_id'), d.get('seq'), d.get('ts'))
PY
)

echo "CONTACT_STATE=$CONTACT_STATE"
echo "REQUEST_ID=$REQUEST_ID"
echo "SEQ=$SEQ"
echo "TS=$TS"
[[ "$CONTACT_STATE" == posted ]] || fail contact_not_posted
[[ "$REQUEST_ID" == maru-mitsuri-contact-20260915-1 ]] || fail request_id_mismatch
[[ "$SEQ" =~ ^[0-9]+$ ]] || fail missing_seq
[[ "$TS" != None && -n "$TS" ]] || fail missing_ts

[[ "$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)" == "$SIGNER_PID_BEFORE" ]] || fail signer_pid_changed
[[ "$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)" == "$SIGNER_NR_BEFORE" ]] || fail signer_restarts_changed
[[ "$(systemctl show technocore-safe-agent-resident.service -p MainPID --value)" == "$RES_PID_BEFORE" ]] || fail resident_changed
[[ "$(systemctl show technocore-safe-agent-lobby-capture.service -p MainPID --value)" == "$CAP_PID_BEFORE" ]] || fail capture_changed

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
[[ "$POST_EVENTS" == 117 && "$POST_MESSAGES" == 5083155 ]] \
  || fail "P0_post_core_changed:$POST_EVENTS/$POST_MESSAGES"

trap - ERR
echo 'MITSURI_FAST=PASS'
echo "PROTECTED_CORE=$POST_EVENTS/$POST_MESSAGES"
echo "SIGNER_PRESERVED=$SIGNER_PID_BEFORE/NRestarts=$SIGNER_NR_BEFORE"
echo "RESIDENT_PRESERVED=$RES_PID_BEFORE"
echo "CAPTURE_PRESERVED=$CAP_PID_BEFORE"
echo 'DO_NOT_RERUN=YES'
