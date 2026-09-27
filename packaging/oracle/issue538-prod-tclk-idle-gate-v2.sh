#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json

PRE=a4016accdef7b1df591d68d1bcdc54c7a9de7320
TARGET=58943a072eb0d752960e092970f06311344a8996
RES_PID=2462149
CAP_PID=2462148
SIG_PID=2462068
DIS_PID=2660066
CORE_E=143
CORE_M=5652707
BRIDGE_E=26
BRIDGE_M=569552

UNITS=(
  technocore-safe-agent-tclk-stager.service
  technocore-safe-agent-tclk-preparer.service
  technocore-safe-agent-tclk-lock-watcher.service
  technocore-safe-agent-tclk-work-watcher.service
  technocore-safe-agent-tclk-reveal-preparer.service
)
TIMERS=(
  technocore-safe-agent-tclk-stager.timer
  technocore-safe-agent-tclk-preparer.timer
  technocore-safe-agent-tclk-lock-watcher.timer
  technocore-safe-agent-tclk-work-watcher.timer
  technocore-safe-agent-tclk-reveal-preparer.timer
)
MODES=(stager preparer lock work reveal)
USERS=(technocore technocore-signer technocore technocore technocore-signer)

TMPDIR=''
TIMERS_PAUSED=NO
UNIT_WRITES_STARTED=NO
SOURCE_UPDATED=NO
DAEMON_RELOADED=NO
TIMERS_RESTORED=NO
STEP=init

snap() {
  local unit=$1
  printf '%s|%s|%s|%s|%s' \
    "$(systemctl show "$unit" -p ActiveState --value)" \
    "$(systemctl show "$unit" -p SubState --value)" \
    "$(systemctl show "$unit" -p MainPID --value)" \
    "$(systemctl show "$unit" -p NRestarts --value)" \
    "$(systemctl show "$unit" -p Result --value)"
}

counts() {
  "$PY" - "$OBS" <<'PY'
import json, pathlib, sys
o=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m=o.get("metrics") or {}
print("|".join(map(str,[
 int(m.get("unrecoverable_core_gap_events",0) or 0),
 int(m.get("unrecoverable_core_gap_messages",0) or 0),
 int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),
 int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0),
])))
PY
}

restore_old_units() {
  [[ "$UNIT_WRITES_STARTED" == YES ]] || return 0
  [[ -n "$TMPDIR" && -d "$TMPDIR/old-units" ]] || return 1
  local unit
  for unit in "${UNITS[@]}"; do
    install -o root -g root -m 0644 "$TMPDIR/old-units/$unit" "/etc/systemd/system/$unit" || return 1
  done
  UNIT_WRITES_STARTED=NO
}

restore_old_source() {
  [[ "$SOURCE_UPDATED" == YES ]] || return 0
  [[ "$DAEMON_RELOADED" != YES ]] || return 1
  [[ "$(git_owner rev-parse HEAD)" == "$TARGET" ]] || return 1
  [[ "$(git_owner branch --show-current)" == main ]] || return 1
  [[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || return 1
  git_owner reset --hard "$PRE" >/dev/null
  SOURCE_UPDATED=NO
}

restore_timers() {
  [[ "$TIMERS_PAUSED" == YES ]] || return 0
  systemctl start "${TIMERS[@]}" || return 1
  local timer
  for timer in "${TIMERS[@]}"; do
    systemctl is-active --quiet "$timer" || return 1
    [[ "$(systemctl is-enabled "$timer" 2>/dev/null || true)" == enabled ]] || return 1
  done
  TIMERS_PAUSED=NO
  TIMERS_RESTORED=YES
}

finish_stop() {
  local reason=$1
  local unit_restore=NONE
  local source_restore=NONE
  local timer_restore=NONE
  if [[ "$UNIT_WRITES_STARTED" == YES && "$DAEMON_RELOADED" != YES ]]; then
    if restore_old_units; then unit_restore=YES; else unit_restore=FAILED; fi
  fi
  if [[ "$SOURCE_UPDATED" == YES && "$DAEMON_RELOADED" != YES ]]; then
    if restore_old_source; then source_restore=YES; else source_restore=FAILED; fi
  fi
  if [[ "$TIMERS_PAUSED" == YES ]]; then
    if restore_timers; then timer_restore=YES; else timer_restore=FAILED; fi
  elif [[ "$TIMERS_RESTORED" == YES ]]; then
    timer_restore=ALREADY
  fi
  echo "PROD538V1=STOP:$reason step:$STEP"
  echo "SOURCE_UPDATED=$SOURCE_UPDATED SOURCE_RESTORE=$source_restore UNIT_RESTORE=$unit_restore TIMER_RESTORE=$timer_restore"
  echo "DO_NOT_RERUN=YES"
  exit 0
}

on_error() {
  local rc=$?
  local failed_cmd="${BASH_COMMAND:-unknown}"
  local failed_line="${BASH_LINENO[0]:-0}"
  trap - ERR
  local unit_restore=NONE
  local source_restore=NONE
  local timer_restore=NONE
  if [[ "$UNIT_WRITES_STARTED" == YES && "$DAEMON_RELOADED" != YES ]]; then
    if restore_old_units; then unit_restore=YES; else unit_restore=FAILED; fi
  fi
  if [[ "$SOURCE_UPDATED" == YES && "$DAEMON_RELOADED" != YES ]]; then
    if restore_old_source; then source_restore=YES; else source_restore=FAILED; fi
  fi
  if [[ "$TIMERS_PAUSED" == YES ]]; then
    if restore_timers; then timer_restore=YES; else timer_restore=FAILED; fi
  elif [[ "$TIMERS_RESTORED" == YES ]]; then
    timer_restore=ALREADY
  fi
  echo "PROD538V1=ERROR:rc_$rc step:$STEP line:$failed_line"
  printf 'ERROR_COMMAND=%q\n' "$failed_cmd"
  echo "SOURCE_UPDATED=$SOURCE_UPDATED SOURCE_RESTORE=$source_restore UNIT_RESTORE=$unit_restore TIMER_RESTORE=$timer_restore"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

STEP=preflight
[[ $EUID -eq 0 ]] || finish_stop not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" ]] || finish_stop required_path_missing
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || finish_stop git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$PRE" && "$BRANCH" == main && -z "$WORKTREE" ]] || finish_stop repo_baseline_changed

RES=$(snap technocore-safe-agent-resident.service)
CAP=$(snap technocore-safe-agent-lobby-capture.service)
SIG=$(snap technocore-safe-agent-signer.service)
DIS=$(snap technocore-safe-agent-discord.service)
[[ "$RES" == "active|running|$RES_PID|0|success" ]] || finish_stop resident_baseline_changed
[[ "$CAP" == "active|running|$CAP_PID|0|success" ]] || finish_stop capture_baseline_changed
[[ "$SIG" == "active|running|$SIG_PID|0|success" ]] || finish_stop signer_baseline_changed
[[ "$DIS" == "active|running|$DIS_PID|0|success" ]] || finish_stop discord_baseline_changed

BASE_COUNTS="$CORE_E|$CORE_M|$BRIDGE_E|$BRIDGE_M"
[[ "$(counts)" == "$BASE_COUNTS" ]] || finish_stop protected_baseline_changed

TMPDIR=$(mktemp -d /tmp/prod538.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT
chmod 0755 "$TMPDIR"
mkdir -p "$TMPDIR/old-units" "$TMPDIR/target-units"

STEP=fetch_target
git_owner fetch --quiet --no-tags origin main
[[ "$(git_owner rev-parse FETCH_HEAD)" == "$TARGET" ]] || finish_stop remote_main_moved
git_owner merge-base --is-ancestor "$PRE" "$TARGET" || finish_stop target_not_ff

ACTUAL=$(git_owner diff --name-only "$PRE" "$TARGET" | LC_ALL=C sort | tr '\n' '|')
EXPECTED='packaging/oracle/technocore-safe-agent-tclk-lock-watcher.service|packaging/oracle/technocore-safe-agent-tclk-preparer.service|packaging/oracle/technocore-safe-agent-tclk-reveal-preparer.service|packaging/oracle/technocore-safe-agent-tclk-stager.service|packaging/oracle/technocore-safe-agent-tclk-work-watcher.service|src/flop_agent/close1_candidate_scanner.py|src/flop_agent/close1_discord_progress.py|src/flop_agent/close1_strategy.py|src/flop_agent/close_call.py|src/flop_agent/discord_control.py|src/flop_agent/observer_lobby_startup_hole_bridge.py|src/flop_agent/tclk_pilot.py|src/flop_agent/tclk_timer_gate.py|tests/test_close1_candidate_scanner.py|tests/test_close1_discord_progress.py|tests/test_close1_strategy.py|tests/test_close_call.py|tests/test_observer_lobby_startup_hole_bridge.py|tests/test_tclk_pilot_prepare.py|tests/test_tclk_timer_gate.py|'
[[ "$ACTUAL" == "$EXPECTED" ]] || finish_stop target_diff_unexpected

STEP=stage_reference_units
for i in "${!UNITS[@]}"; do
  unit="${UNITS[$i]}"
  installed="/etc/systemd/system/$unit"
  [[ -f "$installed" ]] || finish_stop "installed_unit_missing_$i"
  meta=$(stat -c '%U:%G:%a' "$installed" 2>/dev/null || true)
  [[ "$meta" == "root:root:644" ]] || finish_stop "installed_unit_meta_changed_$i"
  fragment=$(systemctl show "$unit" -p FragmentPath --value 2>/dev/null || true)
  [[ "$fragment" == "$installed" ]] || finish_stop "loaded_fragment_changed_$i"
  cond=$(systemctl show "$unit" -p ExecCondition --value 2>/dev/null || true)
  [[ "$cond" != *tclk_timer_gate* ]] || finish_stop "loaded_gate_changed_$i"
  git_owner show "$PRE:packaging/oracle/$unit" > "$TMPDIR/old-units/$unit"
  cmp -s "$TMPDIR/old-units/$unit" "$installed" || finish_stop "installed_unit_not_pre_$i"
  git_owner show "$TARGET:packaging/oracle/$unit" > "$TMPDIR/target-units/$unit"
done
git_owner show "$TARGET:src/flop_agent/tclk_timer_gate.py" > "$TMPDIR/tclk_timer_gate.py"
chmod 0644 "$TMPDIR/tclk_timer_gate.py"

STEP=verify_timers_pre
for timer in "${TIMERS[@]}"; do
  systemctl is-active --quiet "$timer" || finish_stop timer_not_active_before
  [[ "$(systemctl is-enabled "$timer" 2>/dev/null || true)" == enabled ]] || finish_stop timer_not_enabled_before
done

STEP=pause_timers
systemctl stop "${TIMERS[@]}"
TIMERS_PAUSED=YES

STEP=quiesce_oneshots
ALL_IDLE=NO
for _ in $(seq 1 90); do
  busy=0
  for unit in "${UNITS[@]}"; do
    active=$(systemctl show "$unit" -p ActiveState --value)
    [[ "$active" == inactive || "$active" == failed ]] || busy=1
  done
  if (( busy == 0 )); then ALL_IDLE=YES; break; fi
  sleep 1
done
[[ "$ALL_IDLE" == YES ]] || finish_stop tclk_oneshots_did_not_quiesce

STEP=pre_activation_gate
for i in "${!MODES[@]}"; do
  mode="${MODES[$i]}"
  user="${USERS[$i]}"
  if runuser -u "$user" -- env FLOP_STATE_DIR="$STATE" "$PY" "$TMPDIR/tclk_timer_gate.py" "$mode"; then
    rc=0
  else
    rc=$?
  fi
  [[ "$rc" == 1 ]] || finish_stop "target_gate_not_idle_${mode}_rc_${rc}"
done

STEP=revalidate_before_unit_write
[[ "$(git_owner rev-parse HEAD)" == "$PRE" && -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || finish_stop repo_changed_before_unit_stage
[[ "$(counts)" == "$BASE_COUNTS" ]] || finish_stop protected_changed_before_unit_stage
[[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || finish_stop resident_changed_before_unit_stage
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || finish_stop capture_changed_before_unit_stage
[[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || finish_stop signer_changed_before_unit_stage
[[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || finish_stop discord_changed_before_unit_stage

STEP=install_target_units
UNIT_WRITES_STARTED=YES
for unit in "${UNITS[@]}"; do
  install -o root -g root -m 0644 "$TMPDIR/target-units/$unit" "/etc/systemd/system/$unit"
done

STEP=source_fast_forward
git_owner merge --quiet --ff-only "$TARGET"
SOURCE_UPDATED=YES
[[ "$(git_owner rev-parse HEAD)" == "$TARGET" && "$(git_owner branch --show-current)" == main ]] || finish_stop source_update_mismatch
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || finish_stop worktree_dirty_after_update

STEP=import_smoke
runuser -u technocore -- env FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" "$PY" - <<'PY'
from flop_agent import tclk_timer_gate, tclk_pilot
assert callable(tclk_timer_gate.should_run)
assert callable(tclk_pilot.stage_pending)
PY

STEP=daemon_reload
systemctl daemon-reload
DAEMON_RELOADED=YES

STEP=verify_target_units
for unit in "${UNITS[@]}"; do
  cmp -s "$APP/packaging/oracle/$unit" "/etc/systemd/system/$unit" || finish_stop unit_install_mismatch
done

STEP=restore_timers_target
systemctl start "${TIMERS[@]}"
TIMERS_PAUSED=NO
TIMERS_RESTORED=YES
for timer in "${TIMERS[@]}"; do
  systemctl is-active --quiet "$timer" || finish_stop timer_not_active_after
  [[ "$(systemctl is-enabled "$timer" 2>/dev/null || true)" == enabled ]] || finish_stop timer_not_enabled_after
done

STEP=verify_long_running_post
[[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || finish_stop resident_changed_after_activation
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || finish_stop capture_changed_after_activation
[[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || finish_stop signer_changed_after_activation
[[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || finish_stop discord_changed_after_activation
[[ "$(counts)" == "$BASE_COUNTS" ]] || finish_stop protected_changed_after_activation

STEP=pressure_observation
"$PY" - "$RES_PID" "$CAP_PID" "$SIG_PID" "$DIS_PID" <<'PY'
import collections, os, pathlib, sys, time

long_running=set(map(int,sys.argv[1:5]))
self_pid=os.getpid()
labels=(
 "technocore-safe-agent-tclk-stager.service",
 "technocore-safe-agent-tclk-preparer.service",
 "technocore-safe-agent-tclk-lock-watcher.service",
 "technocore-safe-agent-tclk-work-watcher.service",
 "technocore-safe-agent-tclk-reveal-preparer.service",
)

def text(path):
    try: return pathlib.Path(path).read_text("utf-8")
    except Exception: return ""

def rss(pid):
    value=0
    for line in text(f"/proc/{pid}/status").splitlines():
        if line.startswith("VmRSS:"):
            try: value=int(line.split()[1])
            except Exception: pass
            break
    return value

def label(pid):
    for line in text(f"/proc/{pid}/cgroup").splitlines():
        if line.startswith("0::"):
            parts=[p for p in line[3:].strip().split("/") if p]
            for part in reversed(parts):
                if part.endswith(".service"):
                    return part
    return ""

def psi(kind):
    for line in text(f"/proc/pressure/{kind}").splitlines():
        if line.startswith("full "):
            for field in line.split()[1:]:
                if field.startswith("avg10="):
                    try: return float(field.split("=",1)[1])
                    except Exception: return -1.0
    return -1.0

def vmstat():
    wanted={"pswpin","pswpout","pgmajfault"}
    out={k:0 for k in wanted}
    for line in text("/proc/vmstat").splitlines():
        parts=line.split()
        if len(parts)==2 and parts[0] in wanted:
            try: out[parts[0]]=int(parts[1])
            except Exception: pass
    return out

def mem_mb():
    for line in text("/proc/meminfo").splitlines():
        if line.startswith("MemAvailable:"):
            try: return int(line.split()[1])//1024
            except Exception: return -1
    return -1

stats={name:{"samples":0,"peak":0,"pids":set()} for name in labels}
t0=vmstat(); mem0=mem_mb(); mpsi0=psi("memory"); ipsi0=psi("io")
for sample in range(76):
    current=collections.defaultdict(list)
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid=int(entry.name)
        if pid==self_pid or pid in long_running:
            continue
        name=label(pid)
        if name in stats:
            current[name].append(pid)
    for name,pids in current.items():
        rec=stats[name]
        rec["samples"]+=1
        rec["pids"].update(pids)
        rec["peak"]=max(rec["peak"],sum(rss(pid) for pid in pids))
    if sample < 75:
        time.sleep(1)

t1=vmstat(); mem1=mem_mb(); mpsi1=psi("memory"); ipsi1=psi("io")
print(f"PRESSURE=mem_mb:{mem0}->{mem1} memory_full:{mpsi0:.2f}->{mpsi1:.2f} io_full:{ipsi0:.2f}->{ipsi1:.2f}")
print("VMSTAT_DELTA="+" ".join(f"{k}:{t1[k]-t0[k]}" for k in ("pswpin","pswpout","pgmajfault")))
for name in labels:
    rec=stats[name]
    print(f"TCLK_GROUP={name} active_samples:{rec['samples']}/76 peak_rss_mb:{rec['peak']/1024:.1f} unique_pids:{len(rec['pids'])}")
PY

STEP=post_activation_gate
POST_GATE=()
for i in "${!MODES[@]}"; do
  mode="${MODES[$i]}"
  user="${USERS[$i]}"
  if runuser -u "$user" -- env FLOP_STATE_DIR="$STATE" PYTHONPATH="$APP/src" "$PY" -m flop_agent.tclk_timer_gate "$mode"; then
    rc=0
  else
    rc=$?
  fi
  [[ "$rc" == 0 || "$rc" == 1 ]] || finish_stop "post_gate_unexpected_${mode}_rc_${rc}"
  POST_GATE+=("$mode:$rc")
done

STEP=final_postconditions
[[ "$(git_owner rev-parse HEAD)" == "$TARGET" && -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || finish_stop repo_postcondition_failed
[[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || finish_stop resident_changed_post
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || finish_stop capture_changed_post
[[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || finish_stop signer_changed_post
[[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || finish_stop discord_changed_post
[[ "$(counts)" == "$BASE_COUNTS" ]] || finish_stop protected_changed_post

STEP=complete
echo "PROD538V1=PASS"
echo "HEAD=$TARGET"
echo "SERVICES=resident:$RES_PID capture:$CAP_PID signer:$SIG_PID discord:$DIS_PID"
echo "PROTECTED=core:$CORE_E/$CORE_M bridge:$BRIDGE_E/$BRIDGE_M"
echo "TIMERS=ACTIVE_ENABLED unit_gate_install=YES"
echo "POST_GATE=${POST_GATE[*]}"
echo "RUNTIME_RESTART=NONE TECHNOCORE_POST=NO TRADE=NO"
echo "DO_NOT_RERUN=YES"
