#!/usr/bin/env bash
# Fetch, fast-forward and preflight before restarting only active services.
set -euo pipefail
app=/opt/technocore-safe-agent
cd "$app"
git diff --quiet && git diff --cached --quiet || { echo "Refusing update with local changes." >&2; exit 1; }
git fetch origin main
git merge-base --is-ancestor HEAD origin/main || { echo "Local HEAD cannot fast-forward to origin/main." >&2; exit 1; }
git merge --ff-only origin/main
if systemctl is-active --quiet technocore-safe-agent-discord.service; then uv sync --frozen --group dev --extra discord; else uv sync --frozen --group dev; fi
PYTHONPATH="$app/src" uv run --project "$app" pytest -q
PYTHONPATH="$app/src" uv run --project "$app" python -m flop_agent.cli secret-scan
PYTHONPATH="$app/src" uv run --project "$app" python -m flop_agent.cli doctor
systemctl try-restart technocore-safe-agent-resident.service
systemctl try-restart technocore-safe-agent-discord.service
