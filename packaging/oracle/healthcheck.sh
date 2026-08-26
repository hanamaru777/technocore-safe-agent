#!/usr/bin/env bash
set -euo pipefail
systemctl is-active --quiet technocore-safe-agent-resident.service
