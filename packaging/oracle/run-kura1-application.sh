#!/usr/bin/env bash
set -euo pipefail

REPO=/opt/technocore-safe-agent
REF=refs/remotes/origin/kura1-application-helper
PROD_HEAD=362dddadb669d4e126fe00c37da4a3f57cecbdbc
MODULE_BLOB=f2ab714f85bc147aef737dcfb109844bca147916
MODULE=/run/sonnet-kura1-application.py
UNIT=/run/systemd/system/technocore-safe-agent-sonnet-kura1-application.service
UNIT_NAME=technocore-safe-agent-sonnet-kura1-application.service
APP_STATE=/var/lib/technocore-safe-agent/signer/sonnet-2-kura1-application.json

cleanup() {
  rm -f "$UNIT" "$MODULE"
  systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$REPO"
OWNER=$(stat -c %U .git)
GIT=(sudo -u "$OWNER" git -C "$REPO")

[[ "$("${GIT[@]}" rev-parse HEAD)" == "$PROD_HEAD" ]] || { echo 'KURA1=STOP:unexpected_head'; exit 1; }
[[ -z "$("${GIT[@]}" status --porcelain=v1 --untracked-files=all)" ]] || { echo 'KURA1=STOP:dirty_tree'; exit 1; }
[[ "$("${GIT[@]}" rev-parse "$REF:src/flop_agent/sonnet_kura1_application.py")" == "$MODULE_BLOB" ]] || { echo 'KURA1=STOP:helper_blob_mismatch'; exit 1; }

systemctl is-active --quiet technocore-safe-agent-resident.service || { echo 'KURA1=STOP:resident_inactive'; exit 1; }
systemctl is-active --quiet technocore-safe-agent-lobby-capture.service || { echo 'KURA1=STOP:capture_inactive'; exit 1; }
systemctl is-active --quiet technocore-safe-agent-signer.service || { echo 'KURA1=STOP:signer_inactive'; exit 1; }

read -r HEALTH CORE_EVENTS CORE_MESSAGES < <(python3 - <<'PY'
import json
p='/var/lib/technocore-safe-agent/observer/observer-state.json'
d=json.load(open(p))
m=d.get('metrics',{})
print((d.get('health') or {}).get('current'),m.get('unrecoverable_core_gap_events'),m.get('unrecoverable_core_gap_messages'))
PY
)
[[ "$HEALTH" == ok ]] || { echo 'KURA1=STOP:health_not_ok'; exit 1; }
[[ "$CORE_EVENTS" == 117 && "$CORE_MESSAGES" == 5083155 ]] || { echo "KURA1=STOP:core_changed:$CORE_EVENTS/$CORE_MESSAGES"; exit 1; }

SIGNER_PID_BEFORE=$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)
SIGNER_RESTARTS_BEFORE=$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)

"${GIT[@]}" show "$REF:src/flop_agent/sonnet_kura1_application.py" > "$MODULE"
chmod 0444 "$MODULE"

cat > "$UNIT" <<'UNIT'
[Unit]
Description=Approved one-shot non-binding Sonnet-2 kura1 application
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
ExecStart=/opt/technocore-safe-agent/.venv/bin/python /run/sonnet-kura1-application.py
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
ReadOnlyPaths=/run/sonnet-kura1-application.py
ReadWritePaths=/var/lib/technocore-safe-agent/signer /var/lib/technocore-safe-agent/nonces.json
UNIT

systemctl daemon-reload
systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true
if ! systemctl start "$UNIT_NAME"; then
  echo 'KURA1=FAIL:oneshot'
  journalctl -u "$UNIT_NAME" -n 8 --no-pager -o cat || true
  echo 'DO_NOT_RERUN=YES'
  exit 1
fi

read -r APPLICATION_STATE REQUEST_ID SEQ TS < <(python3 - "$APP_STATE" <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
print(d.get('state'), d.get('request_id'), d.get('seq'), d.get('ts'))
PY
)
echo "APPLICATION_STATE=$APPLICATION_STATE"
echo "REQUEST_ID=$REQUEST_ID"
echo "SEQ=$SEQ"
echo "TS=$TS"
[[ "$APPLICATION_STATE" == posted ]] || { echo 'KURA1=STOP:application_not_posted'; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$REQUEST_ID" == maru-kura1-apply-20260915-1 ]] || { echo 'KURA1=STOP:request_id_mismatch'; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$SEQ" =~ ^[0-9]+$ ]] || { echo 'KURA1=STOP:missing_seq'; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$TS" != None && -n "$TS" ]] || { echo 'KURA1=STOP:missing_ts'; echo 'DO_NOT_RERUN=YES'; exit 1; }

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

[[ "$HEALTH" == ok ]] || { echo 'KURA1=FAIL:post_health'; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$CORE_EVENTS" == 117 && "$CORE_MESSAGES" == 5083155 ]] || { echo "KURA1=P0:core_changed:$CORE_EVENTS/$CORE_MESSAGES"; echo 'DO_NOT_RERUN=YES'; exit 1; }
[[ "$SIGNER_PID_AFTER" == "$SIGNER_PID_BEFORE" && "$SIGNER_RESTARTS_AFTER" == "$SIGNER_RESTARTS_BEFORE" ]] || { echo 'KURA1=FAIL:signer_changed'; echo 'DO_NOT_RERUN=YES'; exit 1; }

echo 'KURA1=PASS'
echo "PROTECTED_CORE=$CORE_EVENTS/$CORE_MESSAGES"
echo "SIGNER_PRESERVED=$SIGNER_PID_AFTER/NRestarts=$SIGNER_RESTARTS_AFTER"
echo 'DO_NOT_RERUN=YES'
