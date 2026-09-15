#!/usr/bin/env bash
set -euo pipefail

REPO=/opt/technocore-safe-agent
REF=refs/remotes/origin/mitsuri-contact-helper
PROD_HEAD=11c527796d468beb268a1da1538be3a03cb88c33
LANE_BLOB=5abdc71904a31cea79c9e06032f5841a5e89cf2d
BOOTSTRAP_BLOB=869c23970d5e55a012795e5c0e54890fa910259d
LANE=/run/sonnet_mitsuri_contact.py
BOOTSTRAP=/run/sonnet-mitsuri-contact-v2.py
UNIT=/run/systemd/system/technocore-safe-agent-sonnet-mitsuri-contact.service
UNIT_NAME=technocore-safe-agent-sonnet-mitsuri-contact.service
STATE=/var/lib/technocore-safe-agent/signer/sonnet-2-mitsuri-contact.json

cleanup() {
  rm -f "$UNIT" "$LANE" "$BOOTSTRAP"
  systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$REPO"
OWNER=$(stat -c %U .git)
GIT=(sudo -u "$OWNER" git -C "$REPO")

[[ "$("${GIT[@]}" rev-parse HEAD)" == "$PROD_HEAD" ]] || { echo 'MITSURI=STOP:unexpected_head'; exit 1; }
[[ -z "$("${GIT[@]}" status --porcelain=v1 --untracked-files=all)" ]] || { echo 'MITSURI=STOP:dirty_tree'; exit 1; }
[[ "$("${GIT[@]}" rev-parse "$REF:src/flop_agent/sonnet_mitsuri_contact.py")" == "$LANE_BLOB" ]] || { echo 'MITSURI=STOP:lane_blob_mismatch'; exit 1; }
[[ "$("${GIT[@]}" rev-parse "$REF:src/flop_agent/sonnet_mitsuri_contact_v2.py")" == "$BOOTSTRAP_BLOB" ]] || { echo 'MITSURI=STOP:bootstrap_blob_mismatch'; exit 1; }

systemctl is-active --quiet technocore-safe-agent-resident.service || { echo 'MITSURI=STOP:resident_inactive'; exit 1; }
systemctl is-active --quiet technocore-safe-agent-lobby-capture.service || { echo 'MITSURI=STOP:capture_inactive'; exit 1; }
systemctl is-active --quiet technocore-safe-agent-signer.service || { echo 'MITSURI=STOP:signer_inactive'; exit 1; }

read -r HEALTH CORE_EVENTS CORE_MESSAGES < <(python3 - <<'PY'
import json
p='/var/lib/technocore-safe-agent/observer/observer-state.json'
d=json.load(open(p))
m=d.get('metrics',{})
print((d.get('health') or {}).get('current'),m.get('unrecoverable_core_gap_events'),m.get('unrecoverable_core_gap_messages'))
PY
)
[[ "$HEALTH" == ok ]] || { echo 'MITSURI=STOP:observer_health_not_ok'; exit 1; }
[[ "$CORE_EVENTS" == 117 && "$CORE_MESSAGES" == 5083155 ]] || { echo "MITSURI=STOP:core_changed:$CORE_EVENTS/$CORE_MESSAGES"; exit 1; }

read -r SAFETY_HEALTH SAFETY_AGE SAFETY_EVENTS SAFETY_MESSAGES < <(python3 - <<'PY'
import datetime, json
p='/var/lib/technocore-safe-agent/observer-safety.json'
d=json.load(open(p))
t=datetime.datetime.fromisoformat(d['updated_at'].replace('Z','+00:00'))
age=(datetime.datetime.now(datetime.timezone.utc)-t).total_seconds()
print(d['health'], round(age,3), d['unrecoverable_core_gap_events'], d['unrecoverable_core_gap_messages'])
PY
)
[[ "$SAFETY_HEALTH" == ok ]] || { echo 'MITSURI=STOP:signer_safety_not_ok'; exit 1; }
python3 - "$SAFETY_AGE" <<'PY' || { echo 'MITSURI=STOP:signer_safety_stale'; exit 1; }
import sys
age=float(sys.argv[1])
raise SystemExit(0 if 0 <= age <= 300 else 1)
PY
[[ "$SAFETY_EVENTS" == 117 && "$SAFETY_MESSAGES" == 5083155 ]] || { echo "MITSURI=STOP:signer_safety_core_changed:$SAFETY_EVENTS/$SAFETY_MESSAGES"; exit 1; }

[[ ! -e "$STATE" ]] || { echo 'MITSURI=STOP:state_already_exists'; echo 'DO_NOT_RERUN=YES'; exit 1; }

SIGNER_PID_BEFORE=$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)
SIGNER_RESTARTS_BEFORE=$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)

"${GIT[@]}" show "$REF:src/flop_agent/sonnet_mitsuri_contact.py" > "$LANE"
"${GIT[@]}" show "$REF:src/flop_agent/sonnet_mitsuri_contact_v2.py" > "$BOOTSTRAP"
chmod 0444 "$LANE" "$BOOTSTRAP"

cat > "$UNIT" <<'UNIT'
[Unit]
Description=Approved one-shot non-binding Sonnet-2 Mitsuri contact
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
ExecStart=/opt/technocore-safe-agent/.venv/bin/python /run/sonnet-mitsuri-contact-v2.py
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
ReadOnlyPaths=/run/sonnet_mitsuri_contact.py /run/sonnet-mitsuri-contact-v2.py
ReadWritePaths=/var/lib/technocore-safe-agent/signer /var/lib/technocore-safe-agent/nonces.json
UNIT

systemctl daemon-reload
systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true
if ! systemctl start "$UNIT_NAME"; then
  echo 'MITSURI=FAIL:oneshot'
  journalctl -u "$UNIT_NAME" -n 8 --no-pager -o cat || true
  echo 'DO_NOT_RERUN=YES'
  exit 1
fi

[[ -f "$STATE" ]] || { echo 'MITSURI=STOP:no_state_after_oneshot'; echo 'DO_NOT_RERUN=YES'; exit 1; }
read -r CONTACT_STATE REQUEST_ID SEQ TS < <(python3 - "$STATE" <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
print(d.get('state'), d.get('request_id'), d.get('seq'), d.get('ts'))
PY
)
echo "CONTACT_STATE=$CONTACT_STATE"
echo "REQUEST_ID=$REQUEST_ID"
echo "SEQ=$SEQ"
echo "TS=$TS"
[[ "$CONTACT_STATE" == posted ]] || { echo 'MITSURI=STOP:contact_not_posted'; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$REQUEST_ID" == maru-mitsuri-contact-20260915-1 ]] || { echo 'MITSURI=STOP:request_id_mismatch'; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$SEQ" =~ ^[0-9]+$ ]] || { echo 'MITSURI=STOP:missing_seq'; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$TS" != None && -n "$TS" ]] || { echo 'MITSURI=STOP:missing_ts'; echo 'DO_NOT_RERUN=YES'; exit 1; }

read -r HEALTH CORE_EVENTS CORE_MESSAGES < <(python3 - <<'PY'
import json
p='/var/lib/technocore-safe-agent/observer/observer-state.json'
d=json.load(open(p))
m=d.get('metrics',{})
print((d.get('health') or {}).get('current'),m.get('unrecoverable_core_gap_events'),m.get('unrecoverable_core_gap_messages'))
PY
)
SIGNER_PID_AFTER=$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)
SIGNER_RESTARTS_AFTER=$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)

[[ "$HEALTH" == ok ]] || { echo 'MITSURI=FAIL:post_health'; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$CORE_EVENTS" == 117 && "$CORE_MESSAGES" == 5083155 ]] || { echo "MITSURI=P0:core_changed:$CORE_EVENTS/$CORE_MESSAGES"; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$SIGNER_PID_AFTER" == "$SIGNER_PID_BEFORE" && "$SIGNER_RESTARTS_AFTER" == "$SIGNER_RESTARTS_BEFORE" ]] || { echo 'MITSURI=FAIL:signer_changed'; echo 'DO_NOT_RERUN=YES'; exit 1; }

echo 'MITSURI=PASS'
echo "PROTECTED_CORE=$CORE_EVENTS/$CORE_MESSAGES"
echo "SIGNER_PRESERVED=$SIGNER_PID_AFTER/NRestarts=$SIGNER_RESTARTS_AFTER"
echo 'DO_NOT_RERUN=YES'
