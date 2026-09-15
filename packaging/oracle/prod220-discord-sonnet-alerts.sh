#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  trap - ERR
  echo "PROD220=FAIL:$1"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'fail unexpected_rc_$?' ERR

REPO=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
PRE=96bd571b137f67e4ffb744491a757d18c7850a3d
TARGET=362dddadb669d4e126fe00c37da4a3f57cecbdbc

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
DIS=technocore-safe-agent-discord.service
SIG=technocore-safe-agent-signer.service
META=technocore-safe-agent-metadata-block.service

OLD3="$STATE/signer/sonnet-2-discovery-invites.json"
PRI="$STATE/signer/sonnet-2-discovery-priority-invites.json"
TEAM="$STATE/signer/sonnet-2-team-request-maru73s2.json"
MURPHY="$STATE/signer/sonnet-2-discovery-murphy.json"
OBS="$STATE/observer/observer-state.json"
CAPDB="$STATE/observer/lobby-capture-service.sqlite3"
WATCH="$STATE/observer/discord-sonnet-alerts.json"

[[ -d "$REPO/.git" ]] || fail repo_missing
cd "$REPO"
OWNER=$(stat -c %U .git) || fail git_owner_unreadable
gitx() { sudo -u "$OWNER" git -C "$REPO" "$@"; }

core_exact() {
  sudo python3 - "$OBS" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)
m = d.get("metrics") or {}
print(f"{m.get('unrecoverable_core_gap_events')}/{m.get('unrecoverable_core_gap_messages')}")
PY
}

capture_ok() {
  sudo python3 - "$CAPDB" <<'PY'
import sqlite3, sys
from datetime import UTC, datetime
p = sys.argv[1]
conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=2)
try:
    meta = {str(k): str(v) for k, v in conn.execute("select key,value from meta")}
finally:
    conn.close()
if meta.get("last_error") not in (None, ""):
    raise SystemExit(2)
last = meta.get("last_success_at")
if not last:
    raise SystemExit(3)
stamp = datetime.fromisoformat(last.replace("Z", "+00:00"))
if stamp.tzinfo is None:
    stamp = stamp.replace(tzinfo=UTC)
age = (datetime.now(UTC) - stamp.astimezone(UTC)).total_seconds()
if age < -5 or age > 120:
    raise SystemExit(4)
print(f"age_seconds={age:.1f}")
PY
}

health_gate() {
  sudo env FLOP_STATE_DIR="$STATE" bash "$REPO/packaging/oracle/healthcheck.sh" >/dev/null \
    || fail "$1_healthcheck"
  local core
  core=$(core_exact) || fail "$1_core_read"
  [[ "$core" == "117/5083155" ]] || fail "$1_core_$core"
  capture_ok >/dev/null || fail "$1_capture"
}

pid() { systemctl show "$1" -p MainPID --value; }
restarts() { systemctl show "$1" -p NRestarts --value; }
hash() { sudo sha256sum "$1" | awk '{print $1}'; }

# Exact pre-state.
[[ "$(gitx symbolic-ref --short HEAD)" == main ]] || fail branch_not_main
[[ "$(gitx rev-parse HEAD)" == "$PRE" ]] || fail unexpected_pre_head
[[ -z "$(gitx status --porcelain=v1 --untracked-files=all)" ]] || fail dirty_tree

for svc in "$META" "$RES" "$CAP" "$DIS" "$SIG"; do
  systemctl is-active --quiet "$svc" || fail "service_not_active:$svc"
done
for svc in \
  technocore-safe-agent-sonnet-registration.service \
  technocore-safe-agent-sonnet-invites.service \
  technocore-safe-agent-sonnet-priority-invites.service \
  technocore-safe-agent-sonnet-team-request.service \
  technocore-safe-agent-sonnet-murphy-invite.service
do
  [[ "$(systemctl is-active "$svc" 2>/dev/null || true)" != active ]] || fail "write_unit_active:$svc"
done

for path in "$OLD3" "$PRI" "$TEAM"; do sudo test -f "$path" || fail "state_missing:$(basename "$path")"; done
sudo test ! -e "$MURPHY" || fail murphy_state_present
sudo test ! -e "$WATCH" || fail watcher_state_preexists

# Require a stable healthy window, not a lucky single sample during a flap.
health_gate pre1
sleep 20
health_gate pre2

# Pin GitHub main and the exact deploy delta.
gitx fetch --prune origin refs/heads/main:refs/remotes/origin/main
[[ "$(gitx rev-parse refs/remotes/origin/main)" == "$TARGET" ]] || fail origin_main_not_target
[[ "$(gitx rev-list --count "$PRE..$TARGET")" == 1 ]] || fail target_not_one_ahead
[[ "$(gitx rev-list --count "$TARGET..$PRE")" == 0 ]] || fail target_diverged
ACTUAL=$(gitx diff --name-only "$PRE" "$TARGET" | LC_ALL=C sort)
EXPECTED=$(printf '%s\n' \
  src/flop_agent/discord_sonnet_alerts.py \
  src/flop_agent/discord_tclk_approval.py \
  tests/test_discord_sonnet_alerts.py | LC_ALL=C sort)
[[ "$ACTUAL" == "$EXPECTED" ]] || fail unexpected_delta

OLD3_HASH=$(hash "$OLD3")
PRI_HASH=$(hash "$PRI")
TEAM_HASH=$(hash "$TEAM")
RES_PID=$(pid "$RES"); RES_NR=$(restarts "$RES")
CAP_PID=$(pid "$CAP"); CAP_NR=$(restarts "$CAP")
DIS_PID=$(pid "$DIS")
SIG_PID=$(pid "$SIG"); SIG_NR=$(restarts "$SIG")

echo "PROD220_PREFLIGHT=PASS core=117/5083155"

# Mutation: ff-only repository update + Discord restart only.
gitx merge --ff-only "$TARGET"
[[ "$(gitx rev-parse HEAD)" == "$TARGET" ]] || fail head_after_ff
sudo systemctl restart "$DIS"
for _ in $(seq 1 20); do systemctl is-active --quiet "$DIS" && break; sleep 1; done
systemctl is-active --quiet "$DIS" || fail discord_not_active

# The watcher must at least create valid durable state. Individual upstream sources
# may be temporarily unavailable; source failure isolation/backoff is part of #219.
for _ in $(seq 1 45); do sudo test -f "$WATCH" && break; sleep 2; done
sudo test -f "$WATCH" || fail watcher_state_not_created
WATCH_SUMMARY=$(sudo python3 - "$WATCH" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)
if d.get("schema_version") != 6: raise SystemExit(2)
if not isinstance(d.get("github"), dict): raise SystemExit(3)
if not isinstance(d.get("rooms"), dict): raise SystemExit(4)
if not isinstance(d.get("pending"), list) or len(d["pending"]) > 32: raise SystemExit(5)
gh = sum(isinstance(v, dict) and v.get("initialized") is True for v in d["github"].values())
rooms = sum(isinstance(v, dict) and v.get("initialized") is True for v in d["rooms"].values())
print(f"schema=6 github={gh}/3 rooms={rooms}/2 pending={len(d['pending'])} failures={d.get('failures')}")
PY
) || fail watcher_state_invalid

# Safety invariants after restart.
[[ "$(pid "$RES")" == "$RES_PID" && "$(restarts "$RES")" == "$RES_NR" ]] || fail resident_changed
[[ "$(pid "$CAP")" == "$CAP_PID" && "$(restarts "$CAP")" == "$CAP_NR" ]] || fail capture_changed
[[ "$(pid "$SIG")" == "$SIG_PID" && "$(restarts "$SIG")" == "$SIG_NR" ]] || fail signer_changed
NEW_DIS_PID=$(pid "$DIS")
[[ "$NEW_DIS_PID" =~ ^[1-9][0-9]*$ && "$NEW_DIS_PID" != "$DIS_PID" ]] || fail discord_not_restarted
[[ "$(hash "$OLD3")" == "$OLD3_HASH" ]] || fail old_invites_changed
[[ "$(hash "$PRI")" == "$PRI_HASH" ]] || fail priority_invites_changed
[[ "$(hash "$TEAM")" == "$TEAM_HASH" ]] || fail team_request_changed
sudo test ! -e "$MURPHY" || fail murphy_state_created
health_gate post
[[ -z "$(gitx status --porcelain=v1 --untracked-files=all)" ]] || fail final_dirty_tree

trap - ERR
echo "PROD220=PASS"
echo "HEAD=$TARGET"
echo "HEALTH=ok"
echo "PROTECTED_CORE=117/5083155"
echo "WATCHER_STATE=$WATCH_SUMMARY"
echo "RESIDENT_PRESERVED=$RES_PID/NRestarts=$RES_NR"
echo "CAPTURE_PRESERVED=$CAP_PID/NRestarts=$CAP_NR"
echo "SIGNER_PRESERVED=$SIG_PID/NRestarts=$SIG_NR"
echo "DISCORD_RESTARTED=$DIS_PID->$NEW_DIS_PID"
echo "SIGNED_SONNET_STATE_PRESERVED=YES"
echo "DO_NOT_RERUN=YES"
