#!/usr/bin/env bash
set -euo pipefail

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
DISCORD=technocore-safe-agent-discord.service
RESIDENT=technocore-safe-agent-resident.service
SIGNER=technocore-safe-agent-signer.service
DISCORD_UNIT=/etc/systemd/system/technocore-safe-agent-discord.service
OUTBOX="$STATE/autopilot/autopilot-outbox.json"
AUTOPILOT_AUDIT="$STATE/autopilot/autopilot-audit.jsonl"
OBSERVER_STATE="$STATE/observer/observer-state.json"
PRE_EXPECTED=3d90733d046dc24bef374e649893fe88e9003b49
TARGET=${1:-}

[[ $EUID -eq 0 ]] || { echo 'FAIL: run as root.' >&2; exit 2; }
[[ $TARGET =~ ^[0-9a-f]{40}$ ]] || { echo 'FAIL: exact target SHA required.' >&2; exit 2; }
[[ -d $APP/.git && -x $APP/.venv/bin/python ]] || { echo 'FAIL: production checkout/venv missing.' >&2; exit 2; }
[[ -f $DISCORD_UNIT && -f $OUTBOX && -f $OBSERVER_STATE ]] || { echo 'FAIL: production unit/state missing.' >&2; exit 2; }

cd "$APP"
[[ -z $(git status --porcelain) ]] || { echo 'FAIL: production worktree is not clean.' >&2; exit 2; }
PRE=$(git rev-parse HEAD)
[[ $PRE == "$PRE_EXPECTED" ]] || { echo "FAIL: PRE SHA drifted; expected $PRE_EXPECTED got $PRE." >&2; exit 3; }

service_value() { systemctl show "$1" -p "$2" --value; }
for unit in "$RESIDENT" "$DISCORD" "$SIGNER"; do
  systemctl is-active --quiet "$unit" || { echo "FAIL: $unit is not active before deploy." >&2; exit 3; }
done
SIGNER_PID_PRE=$(service_value "$SIGNER" MainPID)
SIGNER_RESTARTS_PRE=$(service_value "$SIGNER" NRestarts)
[[ ${SIGNER_PID_PRE:-0} -gt 0 ]] || { echo 'FAIL: Signer PID invalid.' >&2; exit 3; }

# Keep the already-paused write planner paused. This is local state only.
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
print(queued, len(data.get('receipts', {})), hashlib.sha256(raw).hexdigest())
PY
)
[[ $QUEUED_PRE -eq 0 ]] || { echo "FAIL: queue is not empty ($QUEUED_PRE)." >&2; exit 3; }
[[ $RECEIPTS_PRE -eq 2 ]] || { echo "FAIL: receipts drifted; expected 2 got $RECEIPTS_PRE." >&2; exit 3; }
read -r GAPS_PRE MISSING_PRE < <(
  "$APP/.venv/bin/python" - "$OBSERVER_STATE" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text('utf-8'))
metrics = data.get('metrics', {})
print(int(metrics.get('message_gaps', 0)), int(metrics.get('estimated_missing_messages', 0)))
PY
)

git fetch origin main
REMOTE=$(git rev-parse origin/main)
[[ $REMOTE == "$TARGET" ]] || { echo "FAIL: origin/main moved; expected $TARGET got $REMOTE." >&2; exit 3; }
git merge-base --is-ancestor "$PRE" "$TARGET" || { echo 'FAIL: target is not a fast-forward descendant of PRE.' >&2; exit 3; }

EXPECTED_PATHS=$(cat <<'EOF' | sort
SOURCES.md
docs/source-backed-onboarding-v1.md
knowledge/registry-v1.json
packaging/oracle/discord.service
packaging/oracle/deploy-source-backed-v1.sh
src/flop_agent/discord_knowledge.py
src/flop_agent/knowledge.py
src/flop_agent/knowledge_guard.py
src/flop_agent/resident_daemon.py
tests/test_collaboration_hardening.py
tests/test_source_backed_deploy_static.py
tests/test_source_backed_discord.py
tests/test_source_backed_knowledge.py
EOF
)
ACTUAL_PATHS=$(git diff --name-only "$PRE..$TARGET" | sort)
[[ $ACTUAL_PATHS == "$EXPECTED_PATHS" ]] || {
  echo 'FAIL: exact #61 changed-file allowlist mismatch.' >&2
  echo 'ACTUAL:' >&2
  printf '%s\n' "$ACTUAL_PATHS" >&2
  exit 3
}

UNIT_BACKUP=$(mktemp /tmp/technocore-discord-unit.XXXXXX)
cp -a "$DISCORD_UNIT" "$UNIT_BACKUP"
CUTOVER_STARTED=0
DONE=0
rollback() {
  rc=$?
  if [[ $DONE -eq 0 && $CUTOVER_STARTED -eq 1 ]]; then
    set +e
    cd "$APP"
    git reset --hard "$PRE" >/dev/null 2>&1
    cp -a "$UNIT_BACKUP" "$DISCORD_UNIT"
    systemctl daemon-reload
    systemctl restart "$RESIDENT"
    systemctl restart "$DISCORD"
    echo 'ROLLBACK: PRE code restored; Resident+Discord restarted; Signer untouched; Autopilot remains paused.' >&2
  fi
  rm -f "$UNIT_BACKUP"
  exit "$rc"
}
trap rollback EXIT

CUTOVER_STARTED=1
git merge --ff-only "$TARGET" >/dev/null
[[ $(git rev-parse HEAD) == "$TARGET" ]] || { echo 'FAIL: POST SHA mismatch.' >&2; exit 4; }
install -o root -g root -m 0644 "$APP/packaging/oracle/discord.service" "$DISCORD_UNIT"
systemctl daemon-reload
DEPLOY_STARTED_AT=$(date --iso-8601=seconds)
systemctl restart "$RESIDENT"
systemctl restart "$DISCORD"
sleep 8
for unit in "$RESIDENT" "$DISCORD" "$SIGNER"; do
  systemctl is-active --quiet "$unit" || { echo "FAIL: $unit is not active after deploy." >&2; exit 4; }
done

SIGNER_PID_POST=$(service_value "$SIGNER" MainPID)
SIGNER_RESTARTS_POST=$(service_value "$SIGNER" NRestarts)
[[ $SIGNER_PID_POST == "$SIGNER_PID_PRE" && $SIGNER_RESTARTS_POST == "$SIGNER_RESTARTS_PRE" ]] || {
  echo 'FAIL: Signer PID/NRestarts changed.' >&2; exit 4;
}
RESIDENT_PID_POST=$(service_value "$RESIDENT" MainPID)
DISCORD_PID_POST=$(service_value "$DISCORD" MainPID)
[[ ${RESIDENT_PID_POST:-0} -gt 0 && ${DISCORD_PID_POST:-0} -gt 0 ]] || { echo 'FAIL: Resident/Discord PID invalid.' >&2; exit 4; }

ACCEPT_JSON=$(sudo -u technocore env FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" \
  "$APP/.venv/bin/python" - <<'PY'
import json
from flop_agent import discord_knowledge, knowledge, resident

summary = knowledge.summary()
assert summary['topics'] == 7
assert summary['verified'] == 7
assert summary['signable'] == 6
assert summary['stale'] == []

tclk = knowledge.topic_status('tclk_alpha')
assert tclk['verified'] is True and tclk['signable'] is False
assert 'no real value' in knowledge.preview('tclk_alpha').lower()

for text in (
    'What is the current reward timing?',
    'When is the FLOP TGE?',
    'What is the airdrop snapshot date?',
):
    info = knowledge.candidate_knowledge({'context': {'excerpt': text}, 'signals': {}})
    assert info['topic'] is None
    assert info['reason'] == 'unsupported_current_or_reward_fact'

control = discord_knowledge.Control({'acceptance'}, 'acceptance-channel')
knowledge_list = control.command('acceptance', '/knowledge', 'acceptance-channel')
assert knowledge_list['ok'] is True
assert 'verified 7/7' in knowledge_list['message']
assert 'signed-ready 6' in knowledge_list['message']

nonce_detail = control.command('acceptance', '/knowledge nonce', 'acceptance-channel')
assert nonce_detail['ok'] is True
assert 'state: verified' in nonce_detail['message']
assert 'exact answer preview:' in nonce_detail['message']

tclk_detail = control.command('acceptance', '/knowledge tclk_alpha', 'acceptance-channel')
assert tclk_detail['ok'] is True
assert 'mode: read-only' in tclk_detail['message']
assert 'no real value' in tclk_detail['message'].lower()

synthetic = {
    'candidate_id': 'acceptance-local-only',
    'did': 'did:key:z6MkAcceptanceOnly',
    'fingerprint': 'acceptance000000',
    'room': 'lobby',
    'seq': 1,
    'category': 'specific_question',
    'status': 'pending',
    'context': {'excerpt': 'Is PaperRail in tclk alpha moving real value?', 'untrusted': True},
    'signals': {},
}
original_candidate = resident.candidate
resident.candidate = lambda _candidate_id: {'untrusted_data': True, 'candidate': synthetic}
try:
    candidate_detail = control.command('acceptance', '/candidate acceptance-local-only', 'acceptance-channel')
finally:
    resident.candidate = original_candidate
assert candidate_detail['ok'] is True
assert 'Knowledge: tclk_alpha | verified | read-only' in candidate_detail['message']
assert 'tclk-readme-5cc4ab93' in candidate_detail['message']

collab = control.command('acceptance', '/collab', 'acceptance-channel')
assert collab['ok'] is True
assert 'FLOP Collaboration Pipeline' in collab['message']

status = control.command('acceptance', '/status', 'acceptance-channel')
assert status['ok'] is True
assert 'FLOP Agent' in status['message']

print(json.dumps({
    'knowledge_topics': summary['topics'],
    'verified': summary['verified'],
    'signed_ready': summary['signable'],
    'tclk_mode': 'read-only',
    'unsupported_current_reward_tge_snapshot': 'fail-closed',
    'candidate_provenance': 'ok',
    'collab_command': 'ok',
    'status_command': 'ok',
}, separators=(',', ':')))
PY
)

read -r QUEUED_POST RECEIPTS_POST OUTBOX_HASH_POST < <(
  "$APP/.venv/bin/python" - "$OUTBOX" <<'PY'
import hashlib, json, pathlib, sys
p = pathlib.Path(sys.argv[1])
raw = p.read_bytes()
data = json.loads(raw)
outbox = data.get('outbox', {})
queued = sum(isinstance(v, dict) and v.get('status', 'queued') == 'queued' for v in outbox.values())
print(queued, len(data.get('receipts', {})), hashlib.sha256(raw).hexdigest())
PY
)
[[ $QUEUED_POST -eq 0 && $RECEIPTS_POST -eq $RECEIPTS_PRE && $OUTBOX_HASH_POST == "$OUTBOX_HASH_PRE" ]] || {
  echo 'FAIL: Autopilot queue/receipt/outbox state changed during cutover.' >&2; exit 4;
}

AUDIT_SIZE_PRE=0
[[ -f $AUTOPILOT_AUDIT ]] && AUDIT_SIZE_PRE=$(stat -c %s "$AUTOPILOT_AUDIT")
CPU_JSON=$("$APP/.venv/bin/python" - "$RESIDENT_PID_POST" "$DISCORD_PID_POST" <<'PY'
import json, os, pathlib, sys, time
pids = {'resident': int(sys.argv[1]), 'discord': int(sys.argv[2])}
hz = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
def ticks(pid):
    fields = pathlib.Path(f'/proc/{pid}/stat').read_text().split()
    return int(fields[13]) + int(fields[14])
start_ticks = {name: ticks(pid) for name, pid in pids.items()}
start = time.monotonic()
time.sleep(30)
elapsed = time.monotonic() - start
end_ticks = {name: ticks(pid) for name, pid in pids.items()}
pct = {name: round((end_ticks[name]-start_ticks[name]) / hz / elapsed * 100, 1) for name in pids}
pct['combined'] = round(pct['resident'] + pct['discord'], 1)
print(json.dumps(pct, separators=(',', ':')))
PY
)
AUDIT_SIZE_POST=0
[[ -f $AUTOPILOT_AUDIT ]] && AUDIT_SIZE_POST=$(stat -c %s "$AUTOPILOT_AUDIT")
AUDIT_GROWTH=$((AUDIT_SIZE_POST - AUDIT_SIZE_PRE))
[[ $AUDIT_GROWTH -le 4096 ]] || { echo "FAIL: autopilot audit grew unexpectedly while paused ($AUDIT_GROWTH bytes)." >&2; exit 4; }

COMBINED_CPU=$("$APP/.venv/bin/python" - "$CPU_JSON" <<'PY'
import json, sys
print(json.loads(sys.argv[1])['combined'])
PY
)
"$APP/.venv/bin/python" - "$COMBINED_CPU" <<'PY'
import sys
if float(sys.argv[1]) > 120.0:
    raise SystemExit('combined Resident+Discord CPU exceeded 120% over 30s')
PY

LAG_LINES=$(journalctl -u "$DISCORD" --since "$DEPLOY_STARTED_AT" --no-pager 2>/dev/null | grep -Eci 'heartbeat blocked|websocket[^ ]*.*behind' || true)
[[ $LAG_LINES -eq 0 ]] || { echo "FAIL: Discord gateway lag markers detected ($LAG_LINES)." >&2; exit 4; }

read -r OBS_HEALTH GAPS_POST MISSING_POST < <(
  "$APP/.venv/bin/python" - "$OBSERVER_STATE" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text('utf-8'))
metrics = data.get('metrics', {})
print(str(data.get('health', {}).get('current', 'unknown')), int(metrics.get('message_gaps', 0)), int(metrics.get('estimated_missing_messages', 0)))
PY
)
[[ $OBS_HEALTH == ok ]] || { echo "FAIL: Observer health is $OBS_HEALTH." >&2; exit 4; }
[[ $GAPS_POST -eq $GAPS_PRE && $MISSING_POST -eq $MISSING_PRE ]] || {
  echo "FAIL: new Observer gap regression detected: gaps $GAPS_PRE->$GAPS_POST missing $MISSING_PRE->$MISSING_POST." >&2; exit 4;
}
RESIDENT_PID_FINAL=$(service_value "$RESIDENT" MainPID)
DISCORD_PID_FINAL=$(service_value "$DISCORD" MainPID)
[[ $RESIDENT_PID_FINAL == "$RESIDENT_PID_POST" && $DISCORD_PID_FINAL == "$DISCORD_PID_POST" ]] || {
  echo 'FAIL: Resident/Discord restarted unexpectedly during acceptance.' >&2; exit 4;
}

SIGNER_PID_FINAL=$(service_value "$SIGNER" MainPID)
SIGNER_RESTARTS_FINAL=$(service_value "$SIGNER" NRestarts)
[[ $SIGNER_PID_FINAL == "$SIGNER_PID_PRE" && $SIGNER_RESTARTS_FINAL == "$SIGNER_RESTARTS_PRE" ]] || {
  echo 'FAIL: Signer changed during acceptance window.' >&2; exit 4;
}
for unit in "$RESIDENT" "$DISCORD" "$SIGNER"; do
  systemctl is-active --quiet "$unit" || { echo "FAIL: $unit not active at final gate." >&2; exit 4; }
done
[[ -z $(git status --porcelain) ]] || { echo 'FAIL: post-deploy worktree is not clean.' >&2; exit 4; }

DONE=1
trap - EXIT
rm -f "$UNIT_BACKUP"
printf '%s\n' \
  'KNOWLEDGE_DEPLOY=PASS' \
  "PRE_SHA=$PRE" \
  "POST_SHA=$(git rev-parse HEAD)" \
  "AUTOPILOT_PAUSED=true QUEUE=$QUEUED_POST RECEIPTS=$RECEIPTS_POST" \
  "SIGNER_PID=$SIGNER_PID_FINAL NRESTARTS=$SIGNER_RESTARTS_FINAL" \
  "RESIDENT_PID=$RESIDENT_PID_POST DISCORD_PID=$DISCORD_PID_POST" \
  "ACCEPT=$ACCEPT_JSON" \
  "CPU_30S=$CPU_JSON AUTOPILOT_AUDIT_GROWTH=$AUDIT_GROWTH" \
  "OBSERVER_HEALTH=$OBS_HEALTH GAPS=$GAPS_POST MISSING=$MISSING_POST" \
  "DISCORD=$(systemctl is-active "$DISCORD") RESIDENT=$(systemctl is-active "$RESIDENT") GATEWAY_LAG_MARKERS=$LAG_LINES" \
  'NEXT=keep Autopilot paused; PM reviews this PASS before any resume or Phase C.'
