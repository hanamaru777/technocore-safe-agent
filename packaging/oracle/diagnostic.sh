#!/usr/bin/env bash
# Read-only, lightweight diagnostics. It never parses observer/resident state.
set -euo pipefail
state=${FLOP_STATE_DIR:-/var/lib/technocore-safe-agent}
for path in "$state/observer/observer-state.json" "$state/observer/resident-state.json"; do
  [[ -e $path ]] && stat --printf '%n bytes=%s\n' "$path" || printf '%s missing\n' "$path"
done
for unit in technocore-safe-agent-resident.service technocore-safe-agent-discord.service technocore-safe-agent-signer.service; do
  printf '%s ' "$unit"
  systemctl show "$unit" --property=ActiveState,MemoryCurrent,NRestarts,MainPID --no-page || true
  pid=$(systemctl show "$unit" --property=MainPID --value --no-page 2>/dev/null || true)
  [[ $pid =~ ^[1-9][0-9]*$ ]] && ps -o rss= -p "$pid" | awk '{print "rss_kib=" $1}' || true
done
python3 - "$state" <<'PY'
import json, sys
from datetime import UTC, datetime
from pathlib import Path
for name in ("observer-heartbeat.json", "resident-heartbeat.json"):
    path = Path(sys.argv[1]) / "observer" / name
    try:
        data = json.loads(path.read_text("utf-8")); age = (datetime.now(UTC) - datetime.fromisoformat(data["updated_at"])).total_seconds()
        print(f"{name} status={data.get('status')} age_seconds={age:.0f}")
    except (OSError, ValueError, KeyError, json.JSONDecodeError): print(f"{name} unavailable")
PY
