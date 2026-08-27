#!/usr/bin/env bash
set -euo pipefail
state=${FLOP_STATE_DIR:-/var/lib/technocore-safe-agent}
systemctl is-active --quiet technocore-safe-agent-resident.service
python3 - "$state" <<'PY'
import json, sys
from datetime import UTC, datetime
from pathlib import Path
root = Path(sys.argv[1]); observer = root / "observer" / "observer-state.json"; resident = root / "observer" / "resident-state.json"
for path in (observer, resident):
    if not path.is_file(): raise SystemExit(f"missing state: {path}")
data = json.loads(observer.read_text("utf-8")); health = data.get("health", {})
if health.get("current") != "ok": raise SystemExit("observer health is not ok")
last = json.loads(resident.read_text("utf-8")).get("daemon", {}).get("last_refresh_at")
if not last: raise SystemExit("resident has not refreshed")
age = (datetime.now(UTC) - datetime.fromisoformat(last)).total_seconds()
if age > 300: raise SystemExit(f"resident refresh is stale: {age:.0f}s")
print("resident healthcheck ok")
PY
