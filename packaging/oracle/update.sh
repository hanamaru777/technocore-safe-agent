#!/usr/bin/env bash
# Fetch, fast-forward and preflight before restarting only active services.
set -euo pipefail
app=/opt/technocore-safe-agent
cd "$app"
git diff --quiet && git diff --cached --quiet || { echo "Refusing update with local changes." >&2; exit 1; }
git fetch origin main
git merge-base --is-ancestor HEAD origin/main || { echo "Local HEAD cannot fast-forward to origin/main." >&2; exit 1; }
git merge --ff-only origin/main
extras=(--group dev)
[[ -e /etc/systemd/system/technocore-safe-agent-discord.service ]] && extras+=(--extra discord)
[[ -e /etc/systemd/system/technocore-safe-agent-signer.service ]] && extras+=(--extra oracle-signer)
uv sync --frozen "${extras[@]}"
PYTHONPATH="$app/src" uv run --project "$app" pytest -q
PYTHONPATH="$app/src" uv run --project "$app" python -m flop_agent.cli secret-scan
PYTHONPATH="$app/src" uv run --project "$app" python -m flop_agent.cli doctor
for service in technocore-safe-agent-resident.service technocore-safe-agent-discord.service technocore-safe-agent-signer.service; do
  systemctl is-active --quiet "$service" && systemctl try-restart "$service"
done
