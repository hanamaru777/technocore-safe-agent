#!/usr/bin/env bash
set -euo pipefail
cd /opt/technocore-safe-agent
git pull --ff-only
systemctl restart technocore-safe-agent-resident.service
