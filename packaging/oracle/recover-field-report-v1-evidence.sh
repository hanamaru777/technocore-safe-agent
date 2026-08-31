#!/usr/bin/env bash
set -euo pipefail

app=/opt/technocore-safe-agent
state=/var/lib/technocore-safe-agent
signer_service=technocore-safe-agent-signer.service
recovery_service=technocore-safe-agent-contribution2-recovery.service
recovery_unit=/etc/systemd/system/$recovery_service
python="$app/.venv/bin/python"

cd "$app"

as_technocore() {
  runuser -u technocore -- env \
    FLOP_STATE_DIR="$state" \
    PYTHONPATH="$app/src" \
    "$python" -m flop_agent.cli "$@"
}

cleanup() {
  rm -f "$recovery_unit" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl start "$signer_service" >/dev/null 2>&1 || true
  as_technocore autopilot-resume >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Freeze autonomous writes while the signer identity is borrowed for local-only
# deterministic signature reconstruction.
as_technocore autopilot-pause >/dev/null
runuser -u technocore -- env \
  FLOP_STATE_DIR="$state" \
  PYTHONPATH="$app/src" \
  "$python" -c 'from flop_agent import autopilot; s=autopilot.status(); raise SystemExit(0 if s["queued"] == 0 else 20)'

systemctl stop "$signer_service"
install -d -o technocore-signer -g technocore-signer -m 0700 "$state/contributions"
install -d -o technocore-signer -g technocore-signer -m 0700 "$state/signer/uv-cache"
install -o root -g root -m 0644 "$app/packaging/oracle/technocore-safe-agent-contribution2-recovery.service" "$recovery_unit"
systemctl daemon-reload

if ! systemctl start "$recovery_service"; then
  journalctl -u "$recovery_service" -n 100 --no-pager
  exit 1
fi
journalctl -u "$recovery_service" -n 100 --no-pager
