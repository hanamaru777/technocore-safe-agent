#!/usr/bin/env bash
set -euo pipefail

REPO=/opt/technocore-safe-agent
REF=refs/remotes/origin/hrnb-reply-helper
PROD_HEAD=362dddadb669d4e126fe00c37da4a3f57cecbdbc
MODULE_BLOB=1ca114d8b719c5d56a7d5c8f8d5f96e768fe350e
MODULE=/run/sonnet-hrnb-reply.py
UNIT=/run/systemd/system/technocore-safe-agent-sonnet-hrnb-reply.service
UNIT_NAME=technocore-safe-agent-sonnet-hrnb-reply.service
STATE=/var/lib/technocore-safe-agent/signer/sonnet-2-hrnb-reply.json

cleanup() {
  rm -f "$UNIT" "$MODULE"
  systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$REPO"
OWNER=$(stat -c %U .git)
GIT=(sudo -u "$OWNER" git -C "$REPO")

[[ "$("${GIT[@]}" rev-parse HEAD)" == "$PROD_HEAD" ]] || { echo 'HRNB=STOP:unexpected_head'; exit 1; }
[[ -z "$("${GIT[@]}" status --porcelain=v1 --untracked-files=all)" ]] || { echo 'HRNB=STOP:dirty_tree'; exit 1; }
[[ "$("${GIT[@]}" rev-parse "$REF:src/flop_agent/sonnet_hrnb_reply.py")" == "$MODULE_BLOB" ]] || { echo 'HRNB=STOP:helper_blob_mismatch'; exit 1; }

systemctl is-active --quiet technocore-safe-agent-resident.service || { echo 'HRNB=STOP:resident_inactive'; exit 1; }
systemctl is-active --quiet technocore-safe-agent-lobby-capture.service || { echo 'HRNB=STOP:capture_inactive'; exit 1; }
systemctl is-active --quiet technocore-safe-agent-signer.service || { echo 'HRNB=STOP:signer_inactive'; exit 1; }

read -r HEALTH CORE_EVENTS CORE_MESSAGES < <(python3 - <<'PY'
import json
p='/var/lib/technocore-safe-agent/observer/observer-state.json'
d=json.load(open(p))
m=d.get('metrics',{})
print((d.get('health') or {}).get('current'),m.get('unrecoverable_core_gap_events'),m.get('unrecoverable_core_gap_messages'))
PY
)
[[ "$HEALTH" == ok ]] || { echo 'HRNB=STOP:health_not_ok'; exit 1; }
[[ "$CORE_EVENTS" == 117 && "$CORE_MESSAGES" == 5083155 ]] || { echo "HRNB=STOP:core_changed:$CORE_EVENTS/$CORE_MESSAGES"; exit 1; }

SIGNER_PID_BEFORE=$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)
SIGNER_RESTARTS_BEFORE=$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)

"${GIT[@]}" show "$REF:src/flop_agent/sonnet_hrnb_reply.py" > "$MODULE"
chmod 0444 "$MODULE"

cat > "$UNIT" <<'UNIT'
[Unit]
Description=Approved one-shot non-binding Sonnet-2 hrnb reply
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
ExecStart=/opt/technocore-safe-agent/.venv/bin/python /run/sonnet-hrnb-reply.py
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
ReadOnlyPaths=/run/sonnet-hrnb-reply.py
ReadWritePaths=/var/lib/technocore-safe-agent/signer /var/lib/technocore-safe-agent/nonces.json
UNIT

systemctl daemon-reload
systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true
if ! systemctl start "$UNIT_NAME"; then
  echo 'HRNB=FAIL:oneshot'
  journalctl -u "$UNIT_NAME" -n 8 --no-pager -o cat || true
  echo 'DO_NOT_RERUN=YES'
  exit 1
fi

read -r REPLY_STATE REQUEST_ID SEQ TS < <(python3 - "$STATE" <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
print(d.get('state'), d.get('request_id'), d.get('seq'), d.get('ts'))
PY
)
echo "REPLY_STATE=$REPLY_STATE"
echo "REQUEST_ID=$REQUEST_ID"
echo "SEQ=$SEQ"
echo "TS=$TS"
[[ "$REPLY_STATE" == posted ]] || { echo 'HRNB=STOP:reply_not_posted'; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$REQUEST_ID" == maru-hrnb-reply-20260915-1 ]] || { echo 'HRNB=STOP:request_id_mismatch'; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$SEQ" =~ ^[0-9]+$ ]] || { echo 'HRNB=STOP:missing_seq'; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$TS" != None && -n "$TS" ]] || { echo 'HRNB=STOP:missing_ts'; echo 'DO_NOT_RERUN=YES'; exit 1; }

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

[[ "$HEALTH" == ok ]] || { echo 'HRNB=FAIL:post_health'; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$CORE_EVENTS" == 117 && "$CORE_MESSAGES" == 5083155 ]] || { echo "HRNB=P0:core_changed:$CORE_EVENTS/$CORE_MESSAGES"; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$SIGNER_PID_AFTER" == "$SIGNER_PID_BEFORE" && "$SIGNER_RESTARTS_AFTER" == "$SIGNER_RESTARTS_BEFORE" ]] || { echo 'HRNB=FAIL:signer_changed'; echo 'DO_NOT_RERUN=YES'; exit 1; }

echo 'HRNB=PASS'
echo "PROTECTED_CORE=$CORE_EVENTS/$CORE_MESSAGES"
echo "SIGNER_PRESERVED=$SIGNER_PID_AFTER/NRestarts=$SIGNER_RESTARTS_AFTER"
echo 'DO_NOT_RERUN=YES'
