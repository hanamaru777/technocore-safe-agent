#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
HB=/var/lib/technocore-safe-agent/observer/observer-heartbeat.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json
BOOT=/var/lib/technocore-safe-agent/observer/observer-lobby-prune-cursor-bootstrap.json

PRE=81bba50432cdd7d6025787bd4b882d30bb139c4b
TARGET=498d332ff70cc6e5487982e27711097793a16c86

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
  echo "PROD556V1=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "PROD556V1=ERROR:rc_$rc"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_now not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" && -f "$HB" && -f "$SAFETY" ]] || stop_now required_path_missing
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
except Exception:
    age=-1.0
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

RES_PRE=$(snap "$RES")
CAP_PRE=$(snap "$CAP")
SIG_PRE=$(snap "$SIG")
DIS_PRE=$(snap "$DIS")
[[ "$RES_PRE" == "active|running|$RES_PID|0|success" ]] || stop_now resident_baseline_changed
[[ "$CAP_PRE" == "active|running|$CAP_PID|0|success" ]] || stop_now capture_baseline_changed
[[ "$SIG_PRE" == "active|running|$SIG_PID|0|success" ]] || stop_now signer_baseline_changed
[[ "$DIS_PRE" == "active|running|$DIS_PID|0|success" ]] || stop_now discord_baseline_changed
require_state PRE
PRE_CURSOR=$STATE_CURSOR
[[ "$PRE_CURSOR" -gt 0 ]] || stop_now lobby_cursor_invalid

SAFE_WINDOW=$("$PY" - "$HB" <<'PY'
import json,pathlib,sys,time
from datetime import UTC,datetime
hb=pathlib.Path(sys.argv[1])

def age(value):
    try:
        d=datetime.fromisoformat(str(value).replace("Z","+00:00"))
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:return -1.0
def heartbeat():
    try:
        h=json.loads(hb.read_text("utf-8"))
        return str(h.get("status","unknown")),age(h.get("updated_at"))
    except Exception:return "unreadable",-1.0
def mem():
    try:
        for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
            if line.startswith("MemAvailable:"):return int(line.split()[1])*1024
    except Exception:pass
    return -1
def psi(kind):
    try:
        for line in pathlib.Path(f"/proc/pressure/{kind}").read_text("utf-8").splitlines():
            if line.startswith("full "):
                for f in line.split()[1:]:
                    if f.startswith("avg10="):return float(f.split("=",1)[1])
    except Exception:pass
    return -1.0

streak=0
last=None
for i in range(13):
    status,a=heartbeat(); m=mem(); mp=psi("memory"); ip=psi("io")
    last=(status,a,m,mp,ip)
    safe=(status=="ok" and 0 <= a <= 120 and m >= 128*1024*1024 and 0 <= mp <= 30 and 0 <= ip <= 50)
    streak=streak+1 if safe else 0
    if streak>=3:
        print(f"PASS|{i+1}|{status}|{a:.1f}|{m/1024/1024:.1f}|{mp:.2f}|{ip:.2f}")
        break
    if i != 12:time.sleep(10)
else:
    status,a,m,mp,ip=last
    print(f"STOP|13|{status}|{a:.1f}|{m/1024/1024:.1f}|{mp:.2f}|{ip:.2f}")
PY
)
IFS='|' read -r WINDOW_RESULT WINDOW_SAMPLES WINDOW_HEALTH WINDOW_AGE WINDOW_MEM WINDOW_MPSI WINDOW_IPSI <<<"$SAFE_WINDOW"
echo "CAPTURE_WINDOW=result:$WINDOW_RESULT samples:$WINDOW_SAMPLES health:$WINDOW_HEALTH age_s:$WINDOW_AGE mem_mb:$WINDOW_MEM memory_psi:$WINDOW_MPSI io_psi:$WINDOW_IPSI"
[[ "$WINDOW_RESULT" == PASS ]] || stop_now no_safe_capture_window

[[ "$(snap "$RES")" == "$RES_PRE" ]] || stop_now resident_changed_before_mutation
[[ "$(snap "$CAP")" == "$CAP_PRE" ]] || stop_now capture_changed_before_mutation
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || stop_now signer_changed_before_mutation
[[ "$(snap "$DIS")" == "$DIS_PRE" ]] || stop_now discord_changed_before_mutation
require_state PRE_MUTATION
BOOT_CURSOR=$STATE_CURSOR
[[ "$BOOT_CURSOR" -ge "$PRE_CURSOR" ]] || stop_now lobby_cursor_regressed_before_mutation

"$PY" - "$BOOT" "$BOOT_CURSOR" <<'PY'
import json,os,pathlib,sys,tempfile
path=pathlib.Path(sys.argv[1]); cursor=int(sys.argv[2])
path.parent.mkdir(parents=True,exist_ok=True)
with tempfile.NamedTemporaryFile("w",encoding="utf-8",dir=path.parent,prefix=f".{path.name}.",suffix=".tmp",delete=False) as h:
    tmp=h.name
    json.dump({"schema_version":1,"lobby_cursor":cursor},h,separators=(",",":"),sort_keys=True)
    h.write("\n");h.flush();os.fsync(h.fileno())
os.replace(tmp,path)
os.chmod(path,0o644)
PY

BOOT_READ=$("$PY" - "$BOOT" <<'PY'
import json,pathlib,sys
v=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
print(v.get("lobby_cursor",""))
PY
)
[[ "$BOOT_READ" == "$BOOT_CURSOR" ]] || stop_now bootstrap_write_mismatch

git_owner fetch --no-tags origin main
REMOTE_MAIN=$(git_owner rev-parse FETCH_HEAD)
[[ "$REMOTE_MAIN" == "$TARGET" ]] || stop_now remote_main_moved
git_owner merge-base --is-ancestor "$PRE" "$TARGET" || stop_now target_not_ff
EXPECTED_DIFF='src/flop_agent/close1_discord_progress.py|src/flop_agent/observer_lobby_capture.py|tests/test_close1_discord_progress.py|tests/test_observer_lobby_capture.py|'
ACTUAL_DIFF=$(git_owner diff --name-only "$PRE" "$TARGET" | LC_ALL=C sort | tr '\n' '|')
[[ "$ACTUAL_DIFF" == "$EXPECTED_DIFF" ]] || stop_now target_diff_unexpected

git_owner merge --ff-only "$TARGET"
[[ "$(git_owner rev-parse HEAD)" == "$TARGET" && "$(git_owner branch --show-current)" == main ]] || stop_now source_update_mismatch
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_now worktree_dirty_after_update

FALLBACK_CURSOR=$(runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$PY" - <<'PY'
from flop_agent import observer_lobby_capture as c
assert c.MAX_ROWS == 300_000
assert c.MAX_PROTECTED_ROWS == 2_000_000
print(c._observer_cursor())
PY
)
[[ "$FALLBACK_CURSOR" == "$BOOT_CURSOR" ]] || stop_now bootstrap_fallback_mismatch

[[ "$(snap "$RES")" == "$RES_PRE" ]] || stop_now resident_changed_before_capture_restart
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || stop_now signer_changed_before_capture_restart
[[ "$(snap "$DIS")" == "$DIS_PRE" ]] || stop_now discord_changed_before_capture_restart

systemctl restart "$CAP"
NEW_CAP_PID=''
for _ in $(seq 1 30); do
  S=$(snap "$CAP")
  IFS='|' read -r a sub p nr result <<<"$S"
  if [[ "$a" == active && "$sub" == running && "$p" != 0 && "$p" != "$CAP_PID" && "$nr" == 0 && "$result" == success ]]; then
    NEW_CAP_PID=$p
    break
  fi
  sleep 1
done
[[ -n "$NEW_CAP_PID" ]] || stop_now capture_restart_not_stable

sleep 60

TMP=$(mktemp /tmp/prod556.XXXXXX)
trap 'rm -f "$TMP"' EXIT

"$PY" - "$HB" "$SAFETY" "$NEW_CAP_PID" >"$TMP" <<'PY'
import json,pathlib,sys,time
from datetime import UTC,datetime
hb=pathlib.Path(sys.argv[1]); safety=pathlib.Path(sys.argv[2]); pid=int(sys.argv[3])

def load(path):
    try:
        v=json.loads(path.read_text("utf-8"));return v if isinstance(v,dict) else {}
    except Exception:return {}
def age(v):
    try:
        d=datetime.fromisoformat(str(v).replace("Z","+00:00"))
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:return -1.0
def mem():
    try:
        for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
            if line.startswith("MemAvailable:"):return int(line.split()[1])*1024
    except Exception:pass
    return -1
def psi(kind):
    try:
        for line in pathlib.Path(f"/proc/pressure/{kind}").read_text("utf-8").splitlines():
            if line.startswith("full "):
                for f in line.split()[1:]:
                    if f.startswith("avg10="):return float(f.split("=",1)[1])
    except Exception:pass
    return -1.0
def vm():
    out={k:0 for k in ("pgmajfault","pswpin","pswpout")}
    try:
        for line in pathlib.Path("/proc/vmstat").read_text("utf-8").splitlines():
            p=line.split()
            if len(p)==2 and p[0] in out:out[p[0]]=int(p[1])
    except Exception:pass
    return out
def proc():
    status=pathlib.Path(f"/proc/{pid}/status")
    io=pathlib.Path(f"/proc/{pid}/io")
    rss=swap=0;maj=-1;rb=-1;wb=-1
    try:
        for line in status.read_text("utf-8").splitlines():
            if line.startswith("VmRSS:"):rss=int(line.split()[1])*1024
            elif line.startswith("VmSwap:"):swap=int(line.split()[1])*1024
        maj=int(pathlib.Path(f"/proc/{pid}/stat").read_text("utf-8").split()[11])
        for line in io.read_text("utf-8").splitlines():
            if line.startswith("read_bytes:"):rb=int(line.split(":",1)[1])
            elif line.startswith("write_bytes:"):wb=int(line.split(":",1)[1])
    except Exception:pass
    return {"rss":rss,"swap":swap,"maj":maj,"rb":rb,"wb":wb}

rows=[]
vm0=vm();p0=proc()
for i in range(7):
    h=load(hb);s=load(safety)
    rows.append({
        "hstatus":str(h.get("status","")),
        "hage":age(h.get("updated_at")),
        "shealth":str(s.get("health","")),
        "sage":age(s.get("updated_at")),
        "sce":s.get("unrecoverable_core_gap_events"),
        "scm":s.get("unrecoverable_core_gap_messages"),
        "mem":mem(),
        "mpsi":psi("memory"),
        "ipsi":psi("io"),
    })
    if i != 6:time.sleep(10)
vm1=vm();p1=proc()
print(json.dumps({"rows":rows,"vm0":vm0,"vm1":vm1,"p0":p0,"p1":p1},separators=(",",":")))
PY

[[ "$(snap "$RES")" == "$RES_PRE" ]] || stop_now resident_changed_post_capture
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || stop_now signer_changed_post_capture
[[ "$(snap "$DIS")" == "$DIS_PRE" ]] || stop_now discord_changed_post_capture
[[ "$(snap "$CAP")" == "active|running|$NEW_CAP_PID|0|success" ]] || stop_now capture_changed_post_capture
require_state POST_CAPTURE
POST_CURSOR=$STATE_CURSOR
[[ "$POST_CURSOR" -ge "$BOOT_CURSOR" ]] || stop_now lobby_cursor_regressed_post_capture

GATE=$("$PY" - "$TMP" "$CORE_E" "$CORE_M" <<'PY'
import json,pathlib,sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
ce=int(sys.argv[2]);cm=int(sys.argv[3]);rows=d["rows"]
checks=[]
for r in rows:
    checks.append(
        r["hstatus"]=="ok"
        and 0 <= r["hage"] <= 300
        and r["shealth"]=="ok"
        and 0 <= r["sage"] <= 300
        and r["sce"]==ce
        and r["scm"]==cm
        and r["mem"] >= 256*1024*1024
        and 0 <= r["mpsi"] <= 5
        and 0 <= r["ipsi"] <= 10
    )
print("PASS" if all(checks) else "STOP")
PY
)

"$PY" - "$TMP" <<'PY'
import json,pathlib,sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"));rows=d["rows"];p0=d["p0"];p1=d["p1"]
def mb(v):return -1.0 if v < 0 else v/1024/1024
print(f"CAPTURE=majflt_delta:{p1['maj']-p0['maj']} read_mb:{mb(p1['rb']-p0['rb']):.1f} write_mb:{mb(p1['wb']-p0['wb']):.1f} rss_mb:{mb(p0['rss']):.1f}->{mb(p1['rss']):.1f} swap_mb:{mb(p0['swap']):.1f}->{mb(p1['swap']):.1f}")
print(f"STRICT_WINDOW=mem_mb:{min(r['mem'] for r in rows)/1024/1024:.1f}->{rows[-1]['mem']/1024/1024:.1f} memory_psi_max:{max(r['mpsi'] for r in rows):.2f} end:{rows[-1]['mpsi']:.2f} io_psi_max:{max(r['ipsi'] for r in rows):.2f} end:{rows[-1]['ipsi']:.2f}")
v0=d["vm0"];v1=d["vm1"]
print(f"VMSTAT_DELTA=pgmajfault:{v1['pgmajfault']-v0['pgmajfault']} pswpin:{v1['pswpin']-v0['pswpin']} pswpout:{v1['pswpout']-v0['pswpout']}")
PY

if [[ "$GATE" != PASS ]]; then
  echo "STRICT_GATE=STOP:no_60s_safe_discord_window"
  echo "PROD556V1=PASS_CAPTURE_ONLY"
  echo "SOURCE=$TARGET CAPTURE_PID=$NEW_CAP_PID DISCORD_PID=$DIS_PID"
  echo "CONTINUITY=core:$CORE_E/$CORE_M bridge:$BRIDGE_E/$BRIDGE_M cursor:$PRE_CURSOR->$POST_CURSOR"
  echo "DISCORD_STRATEGY_RUNTIME=NOT_ACTIVATED"
  echo "TECHNOCORE_WRITE=NO FLOP_WRITE=NO TRADE=NO"
  echo "DO_NOT_RERUN=YES"
  exit 0
fi

echo "STRICT_GATE=PASS:60s"

[[ "$(snap "$RES")" == "$RES_PRE" ]] || stop_now resident_changed_before_discord_restart
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || stop_now signer_changed_before_discord_restart
[[ "$(snap "$CAP")" == "active|running|$NEW_CAP_PID|0|success" ]] || stop_now capture_changed_before_discord_restart
require_state PRE_DISCORD

systemctl restart "$DIS"
NEW_DIS_PID=''
for _ in $(seq 1 30); do
  S=$(snap "$DIS")
  IFS='|' read -r a sub p nr result <<<"$S"
  if [[ "$a" == active && "$sub" == running && "$p" != 0 && "$p" != "$DIS_PID" && "$nr" == 0 && "$result" == success ]]; then
    NEW_DIS_PID=$p
    break
  fi
  sleep 1
done
[[ -n "$NEW_DIS_PID" ]] || stop_now discord_restart_not_stable

sleep 30

[[ "$(snap "$RES")" == "$RES_PRE" ]] || stop_now resident_changed_final
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || stop_now signer_changed_final
[[ "$(snap "$CAP")" == "active|running|$NEW_CAP_PID|0|success" ]] || stop_now capture_changed_final
[[ "$(snap "$DIS")" == "active|running|$NEW_DIS_PID|0|success" ]] || stop_now discord_changed_final
require_state FINAL
FINAL_CURSOR=$STATE_CURSOR
[[ "$FINAL_CURSOR" -ge "$POST_CURSOR" ]] || stop_now lobby_cursor_regressed_final

PRESSURE_GATE_PRESENT=$(grep -c 'def _background_poll_allowed' "$APP/src/flop_agent/close1_discord_progress.py" || true)
SCANNER_PRESENT=$(grep -c 'close1_candidate_scanner' "$APP/src/flop_agent/close1_discord_progress.py" || true)
[[ "$PRESSURE_GATE_PRESENT" -ge 1 && "$SCANNER_PRESENT" -ge 1 ]] || stop_now close1_strategy_source_missing

echo "PROD556V1=PASS_FULL"
echo "SOURCE=$TARGET CAPTURE_PID=$NEW_CAP_PID DISCORD_PID=$NEW_DIS_PID"
echo "CONTINUITY=core:$CORE_E/$CORE_M bridge:$BRIDGE_E/$BRIDGE_M cursor:$PRE_CURSOR->$FINAL_CURSOR"
echo "DISCORD_STRATEGY_RUNTIME=ACTIVATED pressure_gate=YES candidate_scanner=YES"
echo "RESIDENT_RESTART=NO SIGNER_RESTART=NO"
echo "TECHNOCORE_WRITE=NO FLOP_WRITE=NO TRADE=NO"
echo "DO_NOT_RERUN=YES"
