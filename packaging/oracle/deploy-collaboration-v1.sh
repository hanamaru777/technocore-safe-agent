#!/usr/bin/env bash
# Selective Collaboration Pipeline v1 cutover for the existing Oracle VM.
# Intentionally pauses Autopilot, fast-forwards to one caller-pinned main SHA,
# restarts Discord only, and verifies Resident/Signer process continuity.
set -euo pipefail

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
UNIT=/etc/systemd/system/technocore-safe-agent-discord.service
DISCORD=technocore-safe-agent-discord.service
RESIDENT=technocore-safe-agent-resident.service
SIGNER=technocore-safe-agent-signer.service
OUTBOX="$STATE/autopilot/autopilot-outbox.json"
FIRST_CONTACT_INTENT=dce534babcc3e50d7e5e
TARGET=${1:-}

[[ $EUID -eq 0 ]] || { echo 'FAIL: run as root (sudo).' >&2; exit 2; }
[[ $TARGET =~ ^[0-9a-f]{40}$ ]] || { echo 'FAIL: pass the exact 40-hex reviewed main SHA.' >&2; exit 2; }
[[ -d $APP/.git && -x $APP/.venv/bin/python ]] || { echo 'FAIL: production checkout/venv missing.' >&2; exit 2; }
[[ -f $UNIT ]] || { echo 'FAIL: installed Discord unit missing.' >&2; exit 2; }

cd "$APP"
git diff --quiet && git diff --cached --quiet || { echo 'FAIL: local checkout has changes.' >&2; exit 2; }
PRE=$(git rev-parse HEAD)

service_value() { systemctl show "$1" -p "$2" --value; }
SIGNER_PID_PRE=$(service_value "$SIGNER" MainPID)
SIGNER_RESTARTS_PRE=$(service_value "$SIGNER" NRestarts)
RESIDENT_PID_PRE=$(service_value "$RESIDENT" MainPID)
RESIDENT_RESTARTS_PRE=$(service_value "$RESIDENT" NRestarts)
[[ ${SIGNER_PID_PRE:-0} -gt 0 && ${RESIDENT_PID_PRE:-0} -gt 0 ]] || { echo 'FAIL: Resident/Signer must already be active.' >&2; exit 2; }

# Freeze the write-producing planner before taking the deploy-state snapshot.
sudo -u technocore env FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" \
  "$APP/.venv/bin/python" -m flop_agent.cli autopilot-pause >/dev/null

read -r QUEUED_PRE RECEIPTS_PRE OUTBOX_HASH_PRE < <(
  "$APP/.venv/bin/python" - "$OUTBOX" <<'PY'
import hashlib, json, pathlib, sys
p = pathlib.Path(sys.argv[1])
raw = p.read_bytes()
data = json.loads(raw)
outbox = data.get('outbox', {})
queued = sum(isinstance(v, dict) and v.get('status', 'queued') == 'queued' for v in outbox.values())
receipts = len(data.get('receipts', {}))
print(queued, receipts, hashlib.sha256(raw).hexdigest())
PY
)
[[ $QUEUED_PRE -eq 0 ]] || { echo "FAIL: queue is not empty after pause ($QUEUED_PRE)." >&2; exit 3; }

# Pin both the remote tip and the exact changed-file surface. This prevents a
# later unrelated main change from silently riding this production cutover.
git fetch origin main
REMOTE=$(git rev-parse origin/main)
[[ $REMOTE == "$TARGET" ]] || { echo "FAIL: origin/main moved; expected $TARGET got $REMOTE." >&2; exit 3; }
git merge-base --is-ancestor "$PRE" "$TARGET" || { echo 'FAIL: production HEAD cannot fast-forward to reviewed target.' >&2; exit 3; }

ALLOWED_RE='^(docs/collaboration-pipeline-v1\.md|packaging/oracle/discord\.service|packaging/oracle/deploy-collaboration-v1\.sh|src/flop_agent/collaboration\.py|src/flop_agent/collaboration_hardening\.py|src/flop_agent/discord_collaboration\.py|tests/test_collaboration_pipeline\.py|tests/test_collaboration_hardening\.py|tests/test_collaboration_deploy_static\.py)$'
BAD_PATHS=$(git diff --name-only "$PRE..$TARGET" | grep -Ev "$ALLOWED_RE" || true)
[[ -z $BAD_PATHS ]] || { echo 'FAIL: target contains non-collaboration files:' >&2; echo "$BAD_PATHS" >&2; exit 3; }

UNIT_BACKUP=$(mktemp /tmp/technocore-discord-unit.XXXXXX)
cp -a "$UNIT" "$UNIT_BACKUP"
CUTOVER_STARTED=0
DONE=0
rollback() {
  rc=$?
  if [[ $DONE -eq 0 && $CUTOVER_STARTED -eq 1 ]]; then
    set +e
    cd "$APP"
    git reset --hard "$PRE" >/dev/null 2>&1
    cp -a "$UNIT_BACKUP" "$UNIT"
    systemctl daemon-reload
    systemctl restart "$DISCORD"
    echo 'ROLLBACK: attempted Discord-only rollback; Autopilot remains paused.' >&2
  fi
  rm -f "$UNIT_BACKUP"
  exit "$rc"
}
trap rollback EXIT

CUTOVER_STARTED=1
git merge --ff-only "$TARGET" >/dev/null
install -o root -g root -m 0644 "$APP/packaging/oracle/discord.service" "$UNIT"
systemctl daemon-reload
DEPLOY_STARTED_AT=$(date --iso-8601=seconds)
systemctl restart "$DISCORD"
sleep 4
systemctl is-active --quiet "$DISCORD" || { echo 'FAIL: Discord service is not active.' >&2; exit 4; }

SIGNER_PID_POST=$(service_value "$SIGNER" MainPID)
SIGNER_RESTARTS_POST=$(service_value "$SIGNER" NRestarts)
RESIDENT_PID_POST=$(service_value "$RESIDENT" MainPID)
RESIDENT_RESTARTS_POST=$(service_value "$RESIDENT" NRestarts)
[[ $SIGNER_PID_POST == "$SIGNER_PID_PRE" && $SIGNER_RESTARTS_POST == "$SIGNER_RESTARTS_PRE" ]] || { echo 'FAIL: Signer PID/restarts changed.' >&2; exit 4; }
[[ $RESIDENT_PID_POST == "$RESIDENT_PID_PRE" && $RESIDENT_RESTARTS_POST == "$RESIDENT_RESTARTS_PRE" ]] || { echo 'FAIL: Resident PID/restarts changed.' >&2; exit 4; }

read -r QUEUED_POST RECEIPTS_POST OUTBOX_HASH_POST < <(
  "$APP/.venv/bin/python" - "$OUTBOX" <<'PY'
import hashlib, json, pathlib, sys
p = pathlib.Path(sys.argv[1])
raw = p.read_bytes()
data = json.loads(raw)
outbox = data.get('outbox', {})
queued = sum(isinstance(v, dict) and v.get('status', 'queued') == 'queued' for v in outbox.values())
receipts = len(data.get('receipts', {}))
print(queued, receipts, hashlib.sha256(raw).hexdigest())
PY
)
[[ $QUEUED_POST -eq 0 && $RECEIPTS_POST -eq $RECEIPTS_PRE && $OUTBOX_HASH_POST == "$OUTBOX_HASH_PRE" ]] || { echo 'FAIL: Autopilot queue/receipt state changed during cutover.' >&2; exit 4; }

# Local-only reconciliation: no Technocore POST, no Signer call, no tclk accept.
COLLAB_JSON=$(sudo -u technocore env FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" \
  "$APP/.venv/bin/python" - "$FIRST_CONTACT_INTENT" <<'PY'
import json, sys, time
from flop_agent import collaboration, collaboration_hardening, discord_collaboration

collaboration_hardening.install()
intent_id = sys.argv[1]
start = time.perf_counter()
rows = collaboration.records(include_tclk=False)
reconcile_seconds = time.perf_counter() - start
first = next((r for r in rows if r.get('first_contact_intent_id') == intent_id), None)
if not first or first.get('stage') != 'contacted':
    raise SystemExit('first acknowledged contact did not reconstruct as contacted')
start = time.perf_counter()
message = discord_collaboration._list_message()
list_seconds = time.perf_counter() - start
if reconcile_seconds > 5 or list_seconds > 5:
    raise SystemExit(f'collaboration read path too slow: reconcile={reconcile_seconds:.3f}s list={list_seconds:.3f}s')
metrics = collaboration.metrics()
print(json.dumps({
    'first_contact_stage': first.get('stage'),
    'first_contact_id': first.get('id'),
    'records': metrics.get('total'),
    'contacted': metrics.get('contacted'),
    'replied': metrics.get('replied'),
    'task_candidates': metrics.get('task_candidate'),
    'human_review': metrics.get('human_review'),
    'reconcile_seconds': round(reconcile_seconds, 3),
    'list_seconds': round(list_seconds, 3),
    'list_chars': len(message),
}, separators=(',', ':')))
PY
)

LAG_LINES=$(journalctl -u "$DISCORD" --since "$DEPLOY_STARTED_AT" --no-pager 2>/dev/null | grep -Eci 'heartbeat blocked|websocket[^ ]*.*behind' || true)
[[ $LAG_LINES -eq 0 ]] || { echo "FAIL: Discord gateway lag markers detected ($LAG_LINES)." >&2; exit 4; }

DONE=1
trap - EXIT
rm -f "$UNIT_BACKUP"

printf '%s\n' \
  'COLLAB_DEPLOY=PASS' \
  "PRE_SHA=$PRE" \
  "POST_SHA=$(git rev-parse HEAD)" \
  "AUTOPILOT_PAUSED=true QUEUE=$QUEUED_POST RECEIPTS=$RECEIPTS_POST" \
  "RESIDENT_PID=$RESIDENT_PID_POST NRESTARTS=$RESIDENT_RESTARTS_POST" \
  "SIGNER_PID=$SIGNER_PID_POST NRESTARTS=$SIGNER_RESTARTS_POST" \
  "DISCORD=$(systemctl is-active "$DISCORD") GATEWAY_LAG_MARKERS=$LAG_LINES" \
  "COLLAB=$COLLAB_JSON" \
  'NEXT=keep Autopilot paused; PM reviews this compact PASS before resume.'
