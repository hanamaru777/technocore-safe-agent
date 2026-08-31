#!/usr/bin/env bash
# One-time guarded publisher for the explicitly approved Contribution #2 field report.
set -euo pipefail

app=/opt/technocore-safe-agent
state=/var/lib/technocore-safe-agent
signer_service=technocore-safe-agent-signer.service
signer_env=/etc/technocore-safe-agent/signer.env
python="$app/.venv/bin/python"

cd "$app"

as_technocore() {
  runuser -u technocore -- env \
    FLOP_STATE_DIR="$state" \
    PYTHONPATH="$app/src" \
    "$python" -m flop_agent.cli "$@"
}

cleanup() {
  systemctl start "$signer_service" >/dev/null 2>&1 || true
  as_technocore autopilot-resume >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Freeze creation of new autonomous intents before touching the signer.
as_technocore autopilot-pause >/dev/null

# Refuse to interrupt any already-queued autonomous work.
runuser -u technocore -- env \
  FLOP_STATE_DIR="$state" \
  PYTHONPATH="$app/src" \
  "$python" -c 'from flop_agent import autopilot; s=autopilot.status(); raise SystemExit(0 if s["queued"] == 0 else 20)'

# The queue is empty and cannot refill while paused, so the signer is idle-safe to stop.
systemctl stop "$signer_service"

# Create only the dedicated one-time public-evidence state directory. The parent state
# directory is intentionally not group-writable.
install -d -o technocore-signer -g technocore-signer -m 0700 "$state/contributions"
install -d -o technocore-signer -g technocore-signer -m 0700 "$state/signer/uv-cache"

# Load only the existing signer service environment; never print it.
set -a
# shellcheck disable=SC1090
. "$signer_env"
set +a

runuser -u technocore-signer -- env \
  FLOP_STATE_DIR="$state" \
  PYTHONPATH="$app/src" \
  UV_CACHE_DIR="$state/signer/uv-cache" \
  TECHNOCORE_SIGNER_EXPECTED_DID="$TECHNOCORE_SIGNER_EXPECTED_DID" \
  OCI_VAULT_SECRET_OCID="$OCI_VAULT_SECRET_OCID" \
  PATH="/usr/local/bin:/usr/bin:/bin" \
  "$python" "$app/scripts/publish_field_report_v1.py"

# cleanup trap restores signer + autopilot before exit.
