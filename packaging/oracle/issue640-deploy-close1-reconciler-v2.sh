#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OLD=2092ee877cd2bf5656e9265308736419716405e0
TARGET=facf67e8b8565dd311fabcea1920dc14dd2088f0
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
WATCH_STATE=/var/lib/technocore-safe-agent/observer/close1-standalone-watch.json
ACCOUNT_STATE=/var/lib/technocore-safe-agent/observer/close1-own-account.json

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
SOURCE_MODE=''

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
  echo "PROD640V2=STOP:$reason"
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
  echo "PROD640V2=ERROR:rc_$rc"
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
[[ "$BRANCH" == main && -z "$WORKTREE" ]] || stop_now repo_baseline_changed
if [[ "$HEAD" == "$OLD" ]]; then
  SOURCE_MODE=old_needs_update
elif [[ "$HEAD" == "$TARGET" ]]; then
  SOURCE_MODE=target_already_present
else
  stop_now repo_baseline_changed
fi

[[ "$(systemctl is-enabled "$WATCH_TIMER" 2>/dev/null || true)" == enabled ]] || stop_now watcher_timer_not_enabled
[[ "$(systemctl is-active "$WATCH_TIMER" 2>/dev/null || true)" == active ]] || stop_now watcher_timer_not_active
[[ "$(systemctl is-enabled "$OLD_TIMER" 2>/dev/null || true)" != enabled ]] || stop_now old_activation_timer_enabled
[[ "$(systemctl is-active "$OLD_TIMER" 2>/dev/null || true)" != active ]] || stop_now old_activation_timer_active

RES_PRE=$(require_running resident "$RES")
CAP_PRE=$(require_running capture "$CAP")
SIG_PRE=$(require_running signer "$SIG")
DIS_PRE=$(require_running discord "$DIS")
protected_ok || stop_now protected_baseline_changed
[[ ! -e "$ACCOUNT_STATE" ]] || stop_now unexpected_account_state_present

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
if [[ "$SOURCE_MODE" == old_needs_update ]]; then
  git_owner merge --ff-only "$TARGET"
  SOURCE_UPDATED=YES
else
  [[ "$(git_owner rev-parse HEAD)" == "$TARGET" ]] || false
fi

[[ "$(git_owner rev-parse HEAD)" == "$TARGET" ]] || false
[[ "$(git_owner branch --show-current)" == main ]] || false
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || false
[[ "$(stat -c %a "$APP/src/flop_agent/close1_standalone_watch.py")" == 644 ]] || false
[[ "$(stat -c %a "$APP/src/flop_agent/close1_account_reconciliation.py")" == 644 ]] || false
[[ "$(stat -c %a "$APP/src/flop_agent/close1_two_stage_planner.py")" == 644 ]] || false

runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$PY" - <<'PY'
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory
import inspect

from flop_agent import close1_account_reconciliation as a
from flop_agent import close1_candidate_scanner as s
from flop_agent import close1_two_stage_planner as p

assert a.SCHEMA_VERSION == 2
flat = a.checkpoint_ledger()
assert flat["status"] == "flat_confirmed"
assert a.scanner_account(flat) == ("10000", "0")
assert flat["position"] == "0" and flat["cumulative_fees"] == "0"

with TemporaryDirectory() as tmp:
    original = a.resident.resident_dir
    a.resident.resident_dir = lambda: Path(tmp)
    try:
        first = a.mark_pending("probe-trade", search_start_sweep=200, now="2026-10-01T00:00:00+00:00")
        assert first["status"] == "own_state_pending"
        same = a.mark_pending("probe-trade", search_start_sweep=201, now="2026-10-01T00:00:01+00:00")
        assert same == first
        try:
            a.mark_pending("probe-second", search_start_sweep=200)
        except RuntimeError as e:
            assert str(e) == "close1_pending_binding_inflight"
        else:
            raise AssertionError("second distinct pending binding was not blocked")
    finally:
        a.resident.resident_dir = original

source = inspect.getsource(p._nearest_stage2_victory)
assert "def tighten(" in source
assert "while " not in source
leaders = [
    s.LeaderView(
        did=f"leader-{index}", score=Decimal("100"), position=Decimal("0"),
        stable=True, reason="stable"
    )
    for index in range(3)
]
def solve(leader_set):
    return p._nearest_stage2_victory(
        realised_score=Decimal("0"), side="buy", qty=Decimal("10"),
        entry_price=Decimal("100"), entry_fee=Decimal("10"),
        current_mark=Decimal("100"), leaders=leader_set,
        price_floor=Decimal("0.01"), price_ceiling=Decimal("200"),
    )
assert solve(leaders[:1]) is None
result = solve(leaders)
assert result is not None
assert result[0] == Decimal("113.50")
PY


[[ "$(snap "$RES")" == "$RES_PRE" ]] || false
[[ "$(snap "$CAP")" == "$CAP_PRE" ]] || false
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || false
[[ "$(snap "$DIS")" == "$DIS_PRE" ]] || false
protected_ok || false

WATCH_SCAN=$(runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$PY" - <<'PY' 2>&1 || true
from flop_agent import close1_account_reconciliation as a
from flop_agent import close1_candidate_scanner as s
from flop_agent import close1_standalone_watch as w
try:
    ledger=a.reconcile_pending(owner_did=w.OWNER_DID)
    available_cash,current_position=a.scanner_account(ledger)
    r=s.fetch_candidate_scan(
        our_did=w.OWNER_DID,
        available_cash=available_cash,
        current_position=current_position,
    )
except Exception as e:
    print(f"error={type(e).__name__}:{e}")
else:
    opp=w._best_opportunity(r)
    if opp is None:
        print(
            f"ok sweep={r.sweep} gate={r.strategy_gate} "
            f"prize_target={r.flat_target_score} victory_target={r.victory_target_score} best=none"
        )
    else:
        kind,c=opp
        print(
            f"ok sweep={r.sweep} gate={r.strategy_gate} "
            f"prize_target={r.flat_target_score} victory_target={r.victory_target_score} "
            f"best={w._opportunity_key(kind,c)} "
            f"dynamic_victory_move={c.dynamic_victory_move_percent} "
            f"dynamic_victory_price={c.dynamic_victory_price}"
        )
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
print(
    f"activated={str(v.get('activated')).lower()} "
    f"sweep={v.get('last_sweep')} "
    f"error={v.get('last_error')} "
    f"fallback_baseline={v.get('last_fallback_watch_move')} "
    f"candidate={v.get('last_candidate_trade_id')}"
)
PY
)
  AFTER_SUCCESS=${WATCH_INFO[0]:-}
  WATCH_DETAIL=${WATCH_INFO[1]:-state_invalid}
fi

WATCH_RESULT=$(systemctl show "$WATCH_SERVICE" -p Result --value 2>/dev/null || true)
if [[ -n "$AFTER_SUCCESS" && "$AFTER_SUCCESS" != "$BEFORE_SUCCESS" ]]; then
  CLASSIFICATION=ACTIVE_WATCH_BAND
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
[[ ! -e "$ACCOUNT_STATE" ]] || false
[[ "$(systemctl is-enabled "$OLD_TIMER" 2>/dev/null || true)" != enabled ]] || false
[[ "$(systemctl is-active "$OLD_TIMER" 2>/dev/null || true)" != active ]] || false

systemctl start "$WATCH_TIMER"
TIMER_STOPPED=NO
[[ "$(systemctl is-enabled "$WATCH_TIMER" 2>/dev/null || true)" == enabled ]] || false
[[ "$(systemctl is-active "$WATCH_TIMER" 2>/dev/null || true)" == active ]] || false

COMMITTED=YES
SOURCE_UPDATED=NO

echo "PROD640V2=PASS_RECONCILER_DEPLOYED"
echo "SOURCE=$TARGET branch=main worktree=clean"
echo "STANDALONE_TIMER=active/enabled cadence=5m"
echo "WATCH_SCAN=$WATCH_SCAN"
echo "FIRST_RUN=$CLASSIFICATION service_result=$WATCH_RESULT $WATCH_DETAIL"
echo "LONG_RUNNING_SERVICES=UNCHANGED"
echo "LEGACY_DISCORD_PROCESS_RESTARTED=NO"
echo "TRADE=NO"
echo "DO_NOT_RERUN=YES"
