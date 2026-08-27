#!/usr/bin/env bash
set -euo pipefail
state=${FLOP_STATE_DIR:-/var/lib/technocore-safe-agent}
systemctl is-active --quiet technocore-safe-agent-metadata-block.service || { echo "metadata isolation is not active" >&2; exit 1; }
systemctl is-active --quiet technocore-safe-agent-resident.service
python3 - "$state" <<'PY'
import json, sys
from datetime import UTC, datetime
from pathlib import Path
root = Path(sys.argv[1]) / "observer"
observer, resident = root / "observer-heartbeat.json", root / "resident-heartbeat.json"
for path in (observer, resident):
    if not path.is_file(): raise SystemExit(f"missing heartbeat: {path}")
    data = json.loads(path.read_text("utf-8"))
    if set(data) < {"schema_version", "updated_at", "status"} or data.get("schema_version") != 1 or data.get("status") != "ok": raise SystemExit(f"heartbeat is not ok: {path.name}")
    age = (datetime.now(UTC) - datetime.fromisoformat(data["updated_at"])).total_seconds()
    if age > 300: raise SystemExit(f"heartbeat is stale: {path.name} {age:.0f}s")
if not json.loads(resident.read_text("utf-8")).get("last_refresh_at"): raise SystemExit("resident has not refreshed")
print("resident healthcheck ok")
PY
if systemctl is-active --quiet technocore-safe-agent-signer.service; then
python3 - "$state" <<'PY'
import json, sys
from datetime import UTC, datetime
from pathlib import Path
path = Path(sys.argv[1]) / "signer" / "signer-health.json"
if not path.is_file(): raise SystemExit(f"missing signer health: {path}")
data = json.loads(path.read_text("utf-8"))
required = {"schema_version", "last_cycle_at", "last_success_at", "last_error_code", "consecutive_failures", "status"}
if set(data) != required or data.get("schema_version") != 1: raise SystemExit("invalid signer health")
if data.get("status") != "ok" or not data.get("last_cycle_at") or not data.get("last_success_at"): raise SystemExit("signer health is not ok")
age = (datetime.now(UTC) - datetime.fromisoformat(data["last_cycle_at"])).total_seconds()
if age > 120: raise SystemExit(f"signer cycle is stale: {age:.0f}s")
print("signer healthcheck ok")
PY
fi
