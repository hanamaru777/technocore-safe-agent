#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OLD=8f747f8f58de09f29d70bcc25d63b7f882a4ccaa
TARGET=2bd368a3a114bf9b0906370150159062ddbe3ace
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
WATCH_STATE=/var/lib/technocore-safe-agent/observer/close1-standalone-watch.json

WATCH_SERVICE=technocore-safe-agent-close1-standalone-watch.service
WATCH_TIMER=technocore-safe-agent-close1-standalone-watch.timer
OLD_TIMER=technocore-safe-agent-close1-discord-activation.timer

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service

CORE_E=143
CORE_M=5652707
BRIDGE_E=26
BRIDGE_M=569552

OWNER=''
SOURCE_UPDATED=NO
TIMER_STOPPED=NO
COMMITTED=NO

git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

snap() {
  local unit=$1
  printf '%s|%s|%s|%s|%s' \
    "$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p Result --value 2>/dev/null || true)"
}

protected_ok() {
  "$PY" - "$OBS" "$CORE_E" "$CORE_M" "$BRIDGE_E" "$BRIDGE_M" <<'PY'
import json,pathlib,sys
o=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m=o.get("metrics") or {}
actual=(
    int(m.get("unrecoverable_core_gap_events",0) or 0),
    int(m.get("unrecoverable_core_gap_messages",0) or 0),
    int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),
    int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0),
)
expected=tuple(map(int,sys.argv[2:]))
raise SystemExit(0 if actual==expected else 1)
PY
}

restore_timer() {
  if [[ "$TIMER_STOPPED" == YES ]]; then
    systemctl start "$WATCH_TIMER" >/dev/null 2>&1 || true
    TIMER_STOPPED=NO
  fi
}

stop_now() {
  local reason=$1
  restore_timer
  echo "PROD597V1=STOP:$reason"
  echo "DO_NOT_RERUN=YES"
  exit 0
}

rollback_error() {
  local rc=$?
  trap - ERR
  if [[ "$COMMITTED" != YES && "$SOURCE_UPDATED" == YES && -n "$OWNER" ]]; then
    git_owner reset --hard "$OLD" >/dev/null 2>&1 || true
  fi
  restore_timer
  echo "PROD597V1=ERROR:rc_$rc"
  echo "ROLLBACK=source:$SOURCE_UPDATED timer:restored"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap rollback_error ERR

require_running() {
  local label=$1 unit=$2 s a sub pid restarts result
  s=$(snap "$unit")
  IFS='|' read -r a sub pid restarts result <<<"$s"
  [[ "$a" == active && "$sub" == running && "$pid" != 0 && "$result" == success ]] \
    || stop_now "${label}_not_running"
  printf '%s' "$s"
}

[[ $EUID -eq 0 ]] || stop_now not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" ]] || stop_now required_path_missing
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_now git_owner_missing

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$OLD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_now repo_baseline_changed

[[ "$(systemctl is-enabled "$WATCH_TIMER" 2>/dev/null || true)" == enabled ]] || stop_now watcher_timer_not_enabled
[[ "$(systemctl is-active "$WATCH_TIMER" 2>/dev/null || true)" == active ]] || stop_now watcher_timer_not_active
[[ "$(systemctl is-enabled "$OLD_TIMER" 2>/dev/null || true)" != enabled ]] || stop_now old_activation_timer_enabled
[[ "$(systemctl is-active "$OLD_TIMER" 2>/dev/null || true)" != active ]] || stop_now old_activation_timer_active

RES_PRE=$(require_running resident "$RES")
CAP_PRE=$(require_running capture "$CAP")
SIG_PRE=$(require_running signer "$SIG")
DIS_PRE=$(require_running discord "$DIS")
protected_ok || stop_now protected_baseline_changed

systemctl stop "$WATCH_TIMER"
TIMER_STOPPED=YES
for _ in $(seq 1 60); do
  active=$(systemctl is-active "$WATCH_SERVICE" 2>/dev/null || true)
  [[ "$active" != active && "$active" != activating ]] && break
  sleep 1
done
active=$(systemctl is-active "$WATCH_SERVICE" 2>/dev/null || true)
[[ "$active" != active && "$active" != activating ]] || stop_now watcher_oneshot_still_active

git_owner fetch --no-tags origin refs/heads/main
FETCHED=$(git_owner rev-parse FETCH_HEAD)
[[ "$FETCHED" == "$TARGET" ]] || false
git_owner merge --ff-only "$TARGET"
SOURCE_UPDATED=YES

[[ "$(git_owner rev-parse HEAD)" == "$TARGET" ]] || false
[[ "$(git_owner branch --show-current)" == main ]] || false
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || false

for f in \
  "$APP/src/flop_agent/close1_standalone_watch.py" \
  "$APP/tests/test_close1_standalone_watch.py"
do
  [[ -f "$f" && "$(stat -c %a "$f")" == 644 ]] || false
done

runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$PY" - <<'PY'
from decimal import Decimal
from types import SimpleNamespace
from flop_agent import close1_standalone_watch as w

assert callable(w._large_flows)
assert callable(w._flow_alerted_qty)
assert callable(w._flow_signals)
assert w.FLOW_SHOCK_QTY == 40
assert w.FLOW_SHOCK_IMPROVEMENT == 20

migrated=w._flow_alerted_qty({
    "last_flow_key":"did:key:legacy:buy",
    "last_flow_qty":"43.21",
})
assert migrated == {"did:key:legacy:buy": Decimal("43.21")}

flows=tuple(
    SimpleNamespace(
        taker=f"did:key:test{i}",
        taker_side="buy",
        qty=Decimal("40")+Decimal(i),
    )
    for i in range(4)
)
rows=w._large_flows(SimpleNamespace(recent_flows=flows))
assert len(rows) == 3
assert [row.qty for row in rows] == [Decimal("40"),Decimal("41"),Decimal("42")]
PY

[[ "$(snap "$RES")" == "$RES_PRE" ]] || false
[[ "$(snap "$CAP")" == "$CAP_PRE" ]] || false
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || false
[[ "$(snap "$DIS")" == "$DIS_PRE" ]] || false
protected_ok || false

FLOW_SCAN=$(runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$PY" - <<'PY' 2>&1 || true
from flop_agent import close1_candidate_scanner as s
from flop_agent import close1_standalone_watch as w
try:
    r=s.fetch_candidate_scan(
        our_did=w.OWNER_DID,
        available_cash=w.AVAILABLE_CASH,
        current_position=w.CURRENT_POSITION,
    )
except Exception as e:
    print(f"error={type(e).__name__}:{e}")
else:
    rows=w._large_flows(r)
    if not rows:
        print(f"ok sweep={r.sweep} gate={r.strategy_gate} large_flows=0")
    else:
        parts=[]
        for idx,flow in enumerate(rows,1):
            parts.append(
                f"#{idx}:{flow.taker_side}:{flow.qty}:trades={flow.trades}:taker={flow.taker}"
            )
        print(f"ok sweep={r.sweep} gate={r.strategy_gate} large_flows={len(rows)} " + " ".join(parts))
PY
)

BEFORE_SUCCESS=''
if [[ -f "$WATCH_STATE" ]]; then
  BEFORE_SUCCESS=$("$PY" - "$WATCH_STATE" <<'PY'
import json,pathlib,sys
try:
    v=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
except Exception:
    v={}
print(v.get("last_success_at") or "")
PY
)
fi

systemctl start "$WATCH_SERVICE" || true

AFTER_SUCCESS=''
WATCH_DETAIL='state_missing'
if [[ -f "$WATCH_STATE" ]]; then
  readarray -t WATCH_INFO < <("$PY" - "$WATCH_STATE" <<'PY'
import json,pathlib,sys
v=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
print(v.get("last_success_at") or "")
mapping=v.get("flow_alerted_qty")
if isinstance(mapping,dict):
    flowmap=",".join(f"{k}={mapping[k]}" for k in sorted(mapping))
else:
    flowmap="invalid"
print(
    f"activated={str(v.get('activated')).lower()} "
    f"sweep={v.get('last_sweep')} "
    f"error={v.get('last_error')} "
    f"candidate={v.get('last_candidate_trade_id')} "
    f"flow_map={flowmap}"
)
PY
)
  AFTER_SUCCESS=${WATCH_INFO[0]:-}
  WATCH_DETAIL=${WATCH_INFO[1]:-state_invalid}
fi

WATCH_RESULT=$(systemctl show "$WATCH_SERVICE" -p Result --value 2>/dev/null || true)
if [[ -n "$AFTER_SUCCESS" && "$AFTER_SUCCESS" != "$BEFORE_SUCCESS" ]]; then
  CLASSIFICATION=ACTIVE_MULTI_FLOW
elif grep -q 'error=None' <<<"$WATCH_DETAIL"; then
  CLASSIFICATION=PRESSURE_SKIP_OR_NO_NEW_SWEEP
else
  CLASSIFICATION=RETRYING
fi

[[ "$(snap "$RES")" == "$RES_PRE" ]] || false
[[ "$(snap "$CAP")" == "$CAP_PRE" ]] || false
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || false
[[ "$(snap "$DIS")" == "$DIS_PRE" ]] || false
protected_ok || false
[[ "$(systemctl is-enabled "$OLD_TIMER" 2>/dev/null || true)" != enabled ]] || false
[[ "$(systemctl is-active "$OLD_TIMER" 2>/dev/null || true)" != active ]] || false

systemctl start "$WATCH_TIMER"
TIMER_STOPPED=NO
[[ "$(systemctl is-enabled "$WATCH_TIMER" 2>/dev/null || true)" == enabled ]] || false
[[ "$(systemctl is-active "$WATCH_TIMER" 2>/dev/null || true)" == active ]] || false

COMMITTED=YES
SOURCE_UPDATED=NO

echo "PROD597V1=PASS_MULTI_FLOW_DEPLOYED"
echo "SOURCE=$TARGET branch=main worktree=clean"
echo "STANDALONE_TIMER=active/enabled cadence=5m"
echo "FLOW_SCAN=$FLOW_SCAN"
echo "FIRST_RUN=$CLASSIFICATION service_result=$WATCH_RESULT $WATCH_DETAIL"
echo "LONG_RUNNING_SERVICES=UNCHANGED"
echo "LEGACY_DISCORD_PROCESS_RESTARTED=NO"
echo "TRADE=NO"
echo "DO_NOT_RERUN=YES"
