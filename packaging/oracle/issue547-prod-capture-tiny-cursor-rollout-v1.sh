#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
PRE=58943a072eb0d752960e092970f06311344a8996
TARGET=81bba50432cdd7d6025787bd4b882d30bb139c4b

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service

RES_PID=2462149
CAP_PID=2462148
SIG_PID=2462068
DIS_PID=2660066
CORE_E=143
CORE_M=5652707
BRIDGE_E=26
BRIDGE_M=569552

stop_now() {
  echo "PROD547V1=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "PROD547V1=ERROR:rc_$rc"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_now not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" ]] || stop_now required_path_missing
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_now git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

snap() {
  local unit=$1
  printf '%s|%s|%s|%s|%s'     "$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p Result --value 2>/dev/null || true)"
}

state_line() {
  "$PY" - "$OBS" <<'PY'
import json,pathlib,sys
from datetime import UTC,datetime
o=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m=o.get("metrics") or {}; c=o.get("cursors") or {}
try:
 d=datetime.fromisoformat(str(o.get("updated_at","")).replace("Z","+00:00"))
 if d.tzinfo is None:d=d.replace(tzinfo=UTC)
 age=max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
except Exception: age=-1.0
print("|".join(map(str,[
 int(m.get("unrecoverable_core_gap_events",0) or 0),
 int(m.get("unrecoverable_core_gap_messages",0) or 0),
 int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),
 int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0),
 int(c.get("lobby",0) or 0),
 (o.get("health") or {}).get("current","unknown"),
 f"{age:.1f}",
])))
PY
}

require_state() {
  local label=$1 line ce cm be bm cursor health age
  line=$(state_line) || stop_now "${label}_state_read_failed"
  IFS='|' read -r ce cm be bm cursor health age <<<"$line"
  [[ "$ce" == "$CORE_E" && "$cm" == "$CORE_M" ]] || stop_now "${label}_core_changed"
  [[ "$be" == "$BRIDGE_E" && "$bm" == "$BRIDGE_M" ]] || stop_now "${label}_bridge_changed"
  [[ "$health" == ok ]] || stop_now "${label}_observer_not_ok"
  "$PY" - "$age" <<'PY' || stop_now "${label}_observer_stale"
import sys
raise SystemExit(0 if 0 <= float(sys.argv[1]) <= 120 else 1)
PY
  STATE_CURSOR=$cursor
}

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$PRE" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_now repo_baseline_changed

RES_PRE=$(snap "$RES"); CAP_PRE=$(snap "$CAP"); SIG_PRE=$(snap "$SIG"); DIS_PRE=$(snap "$DIS")
[[ "$RES_PRE" == "active|running|$RES_PID|0|success" ]] || stop_now resident_baseline_changed
[[ "$CAP_PRE" == "active|running|$CAP_PID|0|success" ]] || stop_now capture_baseline_changed
[[ "$SIG_PRE" == "active|running|$SIG_PID|0|success" ]] || stop_now signer_baseline_changed
[[ "$DIS_PRE" == "active|running|$DIS_PID|0|success" ]] || stop_now discord_baseline_changed
require_state PRE
PRE_CURSOR=$STATE_CURSOR

for base in stager preparer lock-watcher work-watcher reveal-preparer; do
  unit="technocore-safe-agent-tclk-$base.service"
  timer="technocore-safe-agent-tclk-$base.timer"
  cmp -s "$APP/packaging/oracle/$unit" "/etc/systemd/system/$unit" || stop_now tclk_unit_not_target
  [[ "$(systemctl show "$unit" -p ExecCondition --value 2>/dev/null || true)" == *tclk_timer_gate* ]] || stop_now tclk_gate_not_loaded
  systemctl is-active --quiet "$timer" || stop_now tclk_timer_not_active
  [[ "$(systemctl is-enabled "$timer" 2>/dev/null || true)" == enabled ]] || stop_now tclk_timer_not_enabled
done

git_owner fetch --no-tags origin main
REMOTE_MAIN=$(git_owner rev-parse FETCH_HEAD)
[[ "$REMOTE_MAIN" == "$TARGET" ]] || stop_now remote_main_moved
git_owner merge-base --is-ancestor "$PRE" "$TARGET" || stop_now target_not_ff
EXPECTED_DIFF='src/flop_agent/observer.py|src/flop_agent/observer_lobby_capture.py|tests/test_observer.py|tests/test_observer_lobby_capture.py|'
ACTUAL_DIFF=$(git_owner diff --name-only "$PRE" "$TARGET" | LC_ALL=C sort | tr '\n' '|')
[[ "$ACTUAL_DIFF" == "$EXPECTED_DIFF" ]] || stop_now target_diff_unexpected

git_owner merge --ff-only "$TARGET"
[[ "$(git_owner rev-parse HEAD)" == "$TARGET" && "$(git_owner branch --show-current)" == main ]] || stop_now source_update_mismatch
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_now worktree_dirty_after_update
for file in src/flop_agent/observer.py src/flop_agent/observer_lobby_capture.py; do
  chmod 0644 "$APP/$file"
  [[ "$(stat -c '%a|%U|%G' "$APP/$file")" == '644|root|root' ]] || stop_now source_metadata_mismatch
done

FALLBACK_CURSOR=$(runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$PY" - <<'PY'
from flop_agent import observer_lobby_capture as c
assert c.MAX_ROWS == 300_000
assert c.MAX_PROTECTED_ROWS == 2_000_000
assert c.OBSERVER_CURSOR_PREFIX_BYTES == 64 * 1024
print(c._observer_cursor())
PY
)
require_state PRE_RESTART
[[ "$FALLBACK_CURSOR" -ge "$PRE_CURSOR" && "$FALLBACK_CURSOR" -le "$STATE_CURSOR" ]] || stop_now rolling_fallback_cursor_mismatch
PRE_RESTART_CURSOR=$STATE_CURSOR

[[ "$(snap "$RES")" == "$RES_PRE" ]] || stop_now resident_changed_before_restart
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || stop_now signer_changed_before_restart
[[ "$(snap "$DIS")" == "$DIS_PRE" ]] || stop_now discord_changed_before_restart

systemctl restart "$CAP"
NEW_CAP_PID=''
for _ in $(seq 1 30); do
  s=$(snap "$CAP")
  IFS='|' read -r a sub p nr result <<<"$s"
  if [[ "$a" == active && "$sub" == running && "$p" != 0 && "$p" != "$CAP_PID" && "$nr" == 0 && "$result" == success ]]; then
    NEW_CAP_PID=$p
    break
  fi
  sleep 1
done
[[ -n "$NEW_CAP_PID" ]] || stop_now capture_restart_not_stable

sleep 60
require_state WARM
WARM_CURSOR=$STATE_CURSOR
[[ "$WARM_CURSOR" -ge "$PRE_RESTART_CURSOR" ]] || stop_now warm_cursor_regressed

TMP=$(mktemp /tmp/prod547.XXXXXX)
trap 'rm -f "$TMP"' EXIT
"$PY" - "$NEW_CAP_PID" "$CAP" >"$TMP" <<'PY'
import json,pathlib,subprocess,sys,time
pid=int(sys.argv[1]); unit=sys.argv[2]
def text(p):
 try:return pathlib.Path(p).read_text("utf-8")
 except Exception:return ""
def proc():
 status=text(f"/proc/{pid}/status"); rss=swap=0
 for line in status.splitlines():
  if line.startswith("VmRSS:"): rss=int(line.split()[1])*1024
  elif line.startswith("VmSwap:"): swap=int(line.split()[1])*1024
 try:maj=int(text(f"/proc/{pid}/stat").split()[11])
 except Exception:maj=-1
 rb=wb=-1
 for line in text(f"/proc/{pid}/io").splitlines():
  if line.startswith("read_bytes:"): rb=int(line.split(":",1)[1])
  elif line.startswith("write_bytes:"): wb=int(line.split(":",1)[1])
 return dict(rss=rss,swap=swap,maj=maj,rb=rb,wb=wb)
def vm():
 out={k:0 for k in ("pgmajfault","pswpin","pswpout")}
 for line in text("/proc/vmstat").splitlines():
  p=line.split()
  if len(p)==2 and p[0] in out: out[p[0]]=int(p[1])
 return out
def mem():
 for line in text("/proc/meminfo").splitlines():
  if line.startswith("MemAvailable:"): return int(line.split()[1])*1024
 return -1
def psi(kind):
 for line in text(f"/proc/pressure/{kind}").splitlines():
  if line.startswith("full "):
   for x in line.split()[1:]:
    if x.startswith("avg10="): return float(x.split("=",1)[1])
 return -1.0
def cg():
 try:
  path=subprocess.check_output(["systemctl","show",unit,"-pControlGroup","--value"],text=True).strip()
  base=pathlib.Path("/sys/fs/cgroup")/path.lstrip("/")
  return int((base/"memory.current").read_text()),int((base/"memory.swap.current").read_text())
 except Exception:return -1,-1
def sample():
 cm,cs=cg()
 return dict(proc=proc(),vm=vm(),mem=mem(),mpsi=psi("memory"),ipsi=psi("io"),cgm=cm,cgs=cs)
a=sample();time.sleep(30);b=sample();time.sleep(30);c=sample()
print(json.dumps({"a":a,"b":b,"c":c},separators=(",",":")))
PY

[[ "$(snap "$RES")" == "$RES_PRE" ]] || stop_now resident_changed_post
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || stop_now signer_changed_post
[[ "$(snap "$DIS")" == "$DIS_PRE" ]] || stop_now discord_changed_post
[[ "$(snap "$CAP")" == "active|running|$NEW_CAP_PID|0|success" ]] || stop_now capture_changed_post
require_state FINAL
FINAL_CURSOR=$STATE_CURSOR
[[ "$FINAL_CURSOR" -gt "$PRE_CURSOR" ]] || stop_now lobby_cursor_not_advancing

for base in stager preparer lock-watcher work-watcher reveal-preparer; do
  unit="technocore-safe-agent-tclk-$base.service"
  timer="technocore-safe-agent-tclk-$base.timer"
  [[ "$(systemctl show "$unit" -p ExecCondition --value 2>/dev/null || true)" == *tclk_timer_gate* ]] || stop_now tclk_gate_changed_post
  systemctl is-active --quiet "$timer" || stop_now tclk_timer_changed_post
done

"$PY" - "$TMP" "$PRE_CURSOR" "$FINAL_CURSOR" "$NEW_CAP_PID" <<'PY'
import json,pathlib,sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text());a=d["a"];b=d["b"];c=d["c"]
def mb(v): return -1.0 if v < 0 else v/1024/1024
p0=a["proc"];p1=c["proc"]
print("PROD547V1=PASS")
print(f"SOURCE=81bba50432cdd7d6025787bd4b882d30bb139c4b CAPTURE_PID={sys.argv[4]}")
print(f"CAPTURE=majflt_delta:{p1['maj']-p0['maj']} read_mb:{mb(p1['rb']-p0['rb']):.1f} write_mb:{mb(p1['wb']-p0['wb']):.1f} rss_mb:{mb(p0['rss']):.1f}->{mb(p1['rss']):.1f} swap_mb:{mb(p0['swap']):.1f}->{mb(p1['swap']):.1f} cg_mem_mb:{mb(a['cgm']):.1f}->{mb(c['cgm']):.1f} cg_swap_mb:{mb(a['cgs']):.1f}->{mb(c['cgs']):.1f}")
print(f"HOST=mem_avail_mb:{mb(a['mem']):.1f}->{mb(b['mem']):.1f}->{mb(c['mem']):.1f} memory_psi:{a['mpsi']:.2f}->{b['mpsi']:.2f}->{c['mpsi']:.2f} io_psi:{a['ipsi']:.2f}->{b['ipsi']:.2f}->{c['ipsi']:.2f}")
print("VMSTAT_DELTA="+" ".join(f"{k}:{c['vm'][k]-a['vm'][k]}" for k in ("pgmajfault","pswpin","pswpout")))
print(f"CONTINUITY=core:143/5652707 bridge:26/569552 cursor:{sys.argv[2]}->{sys.argv[3]}")
print("BASELINE_PROD542=capture_majflt:2929 capture_read_mb:109.7")
print("RESTARTS=capture:1 resident:0 signer:0 discord:0")
print("ACTIVE_CAPTURE_SQLITE_QUERY=NO TECHNOCORE_WRITE=NO FLOP_WRITE=NO TRADE=NO")
print("DO_NOT_RERUN=YES")
PY
