#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
HB=/var/lib/technocore-safe-agent/observer/observer-heartbeat.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json
BOOT=/var/lib/technocore-safe-agent/observer/observer-lobby-prune-cursor-bootstrap.json
HEAD_EXPECTED=498d332ff70cc6e5487982e27711097793a16c86

CAP_FILE=$APP/src/flop_agent/observer_lobby_capture.py
DIS_FILE=$APP/src/flop_agent/close1_discord_progress.py
OBS_FILE=$APP/src/flop_agent/observer.py
SCAN_FILE=$APP/src/flop_agent/close1_candidate_scanner.py

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
  echo "PROD558V1=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "PROD558V1=ERROR:rc_$rc"
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
  printf '%s|%s|%s|%s|%s' \
    "$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p Result --value 2>/dev/null || true)"
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

require_protected() {
  local label=$1 line ce cm be bm cursor health age
  line=$(state_line) || stop_now "${label}_state_read_failed"
  IFS='|' read -r ce cm be bm cursor health age <<<"$line"
  [[ "$ce" == "$CORE_E" && "$cm" == "$CORE_M" ]] || stop_now "${label}_core_changed"
  [[ "$be" == "$BRIDGE_E" && "$bm" == "$BRIDGE_M" ]] || stop_now "${label}_bridge_changed"
  STATE_CURSOR=$cursor
  STATE_HEALTH=$health
  STATE_AGE=$age
}

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$HEAD_EXPECTED" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_now repo_baseline_changed

RES_PRE=$(snap "$RES")
CAP_PRE=$(snap "$CAP")
SIG_PRE=$(snap "$SIG")
DIS_PRE=$(snap "$DIS")
[[ "$RES_PRE" == "active|running|$RES_PID|0|success" ]] || stop_now resident_baseline_changed
[[ "$CAP_PRE" == "active|running|$CAP_PID|0|success" ]] || stop_now capture_baseline_changed
[[ "$SIG_PRE" == "active|running|$SIG_PID|0|success" ]] || stop_now signer_baseline_changed
[[ "$DIS_PRE" == "active|running|$DIS_PID|0|success" ]] || stop_now discord_baseline_changed

require_protected PRE
PRE_CURSOR=$STATE_CURSOR
[[ "$PRE_CURSOR" -gt 0 ]] || stop_now lobby_cursor_invalid

INDEX_MODES=$(git_owner ls-files -s \
  src/flop_agent/observer_lobby_capture.py \
  src/flop_agent/close1_discord_progress.py \
  src/flop_agent/observer.py \
  src/flop_agent/close1_candidate_scanner.py | awk '{print $1}' | sort -u | tr '\n' ',')
[[ "$INDEX_MODES" == "100644," ]] || stop_now git_index_mode_unexpected

[[ "$(stat -c %a "$CAP_FILE")" == 600 ]] || stop_now capture_mode_not_600
[[ "$(stat -c %a "$DIS_FILE")" == 600 ]] || stop_now discord_mode_not_600
[[ "$(stat -c %a "$OBS_FILE")" == 644 ]] || stop_now observer_mode_changed
[[ "$(stat -c %a "$SCAN_FILE")" == 644 ]] || stop_now scanner_mode_changed
[[ "$(stat -c %U:%G "$CAP_FILE")" == root:root ]] || stop_now capture_owner_changed
[[ "$(stat -c %U:%G "$DIS_FILE")" == root:root ]] || stop_now discord_owner_changed

SAFE_WINDOW=$("$PY" - "$HB" <<'PY'
import json,pathlib,sys,time
from datetime import UTC,datetime
hb=pathlib.Path(sys.argv[1])
def age(v):
    try:
        d=datetime.fromisoformat(str(v).replace("Z","+00:00"))
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:return -1.0
def sample():
    try:
        h=json.loads(hb.read_text("utf-8"))
        status=str(h.get("status","unknown")); a=age(h.get("updated_at"))
    except Exception:
        status="unreadable";a=-1.0
    mem=-1
    for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
        if line.startswith("MemAvailable:"):mem=int(line.split()[1])*1024
    def psi(kind):
        for line in pathlib.Path(f"/proc/pressure/{kind}").read_text("utf-8").splitlines():
            if line.startswith("full "):
                for f in line.split()[1:]:
                    if f.startswith("avg10="):return float(f.split("=",1)[1])
        return -1.0
    return status,a,mem,psi("memory"),psi("io")
streak=0;last=None
for i in range(13):
    last=sample();status,a,mem,mp,ip=last
    ok=status=="ok" and 0<=a<=120 and mem>=128*1024*1024 and 0<=mp<=30 and 0<=ip<=50
    streak=streak+1 if ok else 0
    if streak>=3:
        print(f"PASS|{i+1}|{status}|{a:.1f}|{mem/1024/1024:.1f}|{mp:.2f}|{ip:.2f}")
        break
    if i!=12:time.sleep(10)
else:
    status,a,mem,mp,ip=last
    print(f"STOP|13|{status}|{a:.1f}|{mem/1024/1024:.1f}|{mp:.2f}|{ip:.2f}")
PY
)
IFS='|' read -r WINDOW_RESULT WINDOW_SAMPLES WINDOW_HEALTH WINDOW_AGE WINDOW_MEM WINDOW_MPSI WINDOW_IPSI <<<"$SAFE_WINDOW"
echo "REPAIR_WINDOW=result:$WINDOW_RESULT samples:$WINDOW_SAMPLES health:$WINDOW_HEALTH age_s:$WINDOW_AGE mem_mb:$WINDOW_MEM memory_psi:$WINDOW_MPSI io_psi:$WINDOW_IPSI"
[[ "$WINDOW_RESULT" == PASS ]] || stop_now no_safe_capture_window

[[ "$(snap "$RES")" == "$RES_PRE" ]] || stop_now resident_changed_before_repair
[[ "$(snap "$CAP")" == "$CAP_PRE" ]] || stop_now capture_changed_before_repair
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || stop_now signer_changed_before_repair
[[ "$(snap "$DIS")" == "$DIS_PRE" ]] || stop_now discord_changed_before_repair
require_protected PRE_REPAIR
BOOT_CURSOR=$STATE_CURSOR
[[ "$BOOT_CURSOR" -ge "$PRE_CURSOR" ]] || stop_now cursor_regressed_before_repair

chmod 0644 "$CAP_FILE" "$DIS_FILE"
[[ "$(stat -c %a "$CAP_FILE")" == 644 && "$(stat -c %a "$DIS_FILE")" == 644 ]] || stop_now mode_repair_failed
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_now worktree_dirty_after_mode_repair

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

runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$PY" - <<'PY' || stop_now technocore_import_failed
from flop_agent import observer_lobby_capture as c
from flop_agent import close1_discord_progress as p
assert c._observer_cursor() >= 0
assert callable(p._background_poll_allowed)
assert callable(p.periodic_notices)
PY

FALLBACK_CURSOR=$(runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$PY" - <<'PY'
from flop_agent import observer_lobby_capture as c
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

sleep 30

TMP=$(mktemp /tmp/prod558v1.XXXXXX)
trap 'rm -f "$TMP"' EXIT
"$PY" - "$HB" "$SAFETY" "$NEW_CAP_PID" >"$TMP" <<'PY'
import json,pathlib,sys,time
from datetime import UTC,datetime
hb=pathlib.Path(sys.argv[1]);sf=pathlib.Path(sys.argv[2]);pid=int(sys.argv[3])
def load(p):
    try:
        v=json.loads(p.read_text("utf-8"));return v if isinstance(v,dict) else {}
    except Exception:return {}
def age(v):
    try:
        d=datetime.fromisoformat(str(v).replace("Z","+00:00"))
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:return -1.0
def mem():
    for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
        if line.startswith("MemAvailable:"):return int(line.split()[1])*1024
    return -1
def psi(kind):
    for line in pathlib.Path(f"/proc/pressure/{kind}").read_text("utf-8").splitlines():
        if line.startswith("full "):
            for f in line.split()[1:]:
                if f.startswith("avg10="):return float(f.split("=",1)[1])
    return -1.0
def vm():
    out={k:0 for k in ("pgmajfault","pswpin","pswpout")}
    for line in pathlib.Path("/proc/vmstat").read_text("utf-8").splitlines():
        p=line.split()
        if len(p)==2 and p[0] in out:out[p[0]]=int(p[1])
    return out
def proc():
    st=pathlib.Path(f"/proc/{pid}/status").read_text("utf-8").splitlines()
    io=pathlib.Path(f"/proc/{pid}/io").read_text("utf-8").splitlines()
    rss=swap=0
    for line in st:
        if line.startswith("VmRSS:"):rss=int(line.split()[1])*1024
        elif line.startswith("VmSwap:"):swap=int(line.split()[1])*1024
    maj=int(pathlib.Path(f"/proc/{pid}/stat").read_text("utf-8").split()[11])
    vals={}
    for line in io:
        if line.startswith("read_bytes:"):vals["rb"]=int(line.split(":",1)[1])
        elif line.startswith("write_bytes:"):vals["wb"]=int(line.split(":",1)[1])
    return {"rss":rss,"swap":swap,"maj":maj,"rb":vals.get("rb",-1),"wb":vals.get("wb",-1)}
rows=[];v0=vm();p0=proc()
for i in range(7):
    h=load(hb);s=load(sf)
    rows.append({
        "hs":str(h.get("status","")),"ha":age(h.get("updated_at")),
        "ss":str(s.get("health","")),"sa":age(s.get("updated_at")),
        "ce":s.get("unrecoverable_core_gap_events"),"cm":s.get("unrecoverable_core_gap_messages"),
        "mem":mem(),"mp":psi("memory"),"ip":psi("io"),
    })
    if i!=6:time.sleep(10)
print(json.dumps({"rows":rows,"v0":v0,"v1":vm(),"p0":p0,"p1":proc()},separators=(",",":")))
PY

[[ "$(snap "$RES")" == "$RES_PRE" ]] || stop_now resident_changed_post_capture
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || stop_now signer_changed_post_capture
[[ "$(snap "$DIS")" == "$DIS_PRE" ]] || stop_now discord_changed_post_capture
[[ "$(snap "$CAP")" == "active|running|$NEW_CAP_PID|0|success" ]] || stop_now capture_changed_post_capture
require_protected POST_CAPTURE
POST_CURSOR=$STATE_CURSOR
[[ "$POST_CURSOR" -ge "$BOOT_CURSOR" ]] || stop_now cursor_regressed_post_capture

GATE=$("$PY" - "$TMP" "$CORE_E" "$CORE_M" <<'PY'
import json,pathlib,sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"));ce=int(sys.argv[2]);cm=int(sys.argv[3])
ok=[]
for r in d["rows"]:
    ok.append(
        r["hs"]=="ok" and 0<=r["ha"]<=300 and
        r["ss"]=="ok" and 0<=r["sa"]<=300 and
        r["ce"]==ce and r["cm"]==cm and
        r["mem"]>=256*1024*1024 and
        0<=r["mp"]<=5 and 0<=r["ip"]<=10
    )
print("PASS" if all(ok) else "STOP")
PY
)

"$PY" - "$TMP" <<'PY'
import json,pathlib,sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"));r=d["rows"];a=d["p0"];b=d["p1"];v0=d["v0"];v1=d["v1"]
mb=lambda v:v/1024/1024
print(f"CAPTURE=majflt_delta:{b['maj']-a['maj']} read_mb:{mb(b['rb']-a['rb']):.1f} rss_mb:{mb(a['rss']):.1f}->{mb(b['rss']):.1f} swap_mb:{mb(a['swap']):.1f}->{mb(b['swap']):.1f}")
print(f"STRICT_WINDOW=mem_min_mb:{min(x['mem'] for x in r)/1024/1024:.1f} memory_psi_max:{max(x['mp'] for x in r):.2f} io_psi_max:{max(x['ip'] for x in r):.2f}")
print(f"VMSTAT_DELTA=pgmajfault:{v1['pgmajfault']-v0['pgmajfault']} pswpin:{v1['pswpin']-v0['pswpin']} pswpout:{v1['pswpout']-v0['pswpout']}")
PY

if [[ "$GATE" != PASS ]]; then
  echo "STRICT_GATE=STOP:no_60s_safe_discord_window"
  echo "PROD558V1=PASS_CAPTURE_ONLY"
  echo "SOURCE=$HEAD_EXPECTED CAPTURE_PID=$NEW_CAP_PID DISCORD_PID=$DIS_PID"
  echo "CONTINUITY=core:$CORE_E/$CORE_M bridge:$BRIDGE_E/$BRIDGE_M cursor:$PRE_CURSOR->$POST_CURSOR"
  echo "MODES=observer_lobby_capture:644 close1_discord_progress:644"
  echo "DISCORD_STRATEGY_RUNTIME=NOT_ACTIVATED"
  echo "RESIDENT_RESTART=NO SIGNER_RESTART=NO"
  echo "TECHNOCORE_WRITE=NO FLOP_WRITE=NO TRADE=NO"
  echo "DO_NOT_RERUN=YES"
  exit 0
fi

echo "STRICT_GATE=PASS:60s"

[[ "$(snap "$RES")" == "$RES_PRE" ]] || stop_now resident_changed_before_discord_restart
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || stop_now signer_changed_before_discord_restart
[[ "$(snap "$CAP")" == "active|running|$NEW_CAP_PID|0|success" ]] || stop_now capture_changed_before_discord_restart
require_protected PRE_DISCORD

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
require_protected FINAL
FINAL_CURSOR=$STATE_CURSOR
[[ "$FINAL_CURSOR" -ge "$POST_CURSOR" ]] || stop_now cursor_regressed_final

runuser -u technocore -- env FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH="$APP/src" "$PY" - <<'PY' || stop_now strategy_runtime_source_invalid
from flop_agent import close1_discord_progress as p
assert callable(p._background_poll_allowed)
assert callable(p.periodic_notices)
PY

echo "PROD558V1=PASS_FULL"
echo "SOURCE=$HEAD_EXPECTED CAPTURE_PID=$NEW_CAP_PID RESIDENT_PID=$RES_PID DISCORD_PID=$NEW_DIS_PID"
echo "CONTINUITY=core:$CORE_E/$CORE_M bridge:$BRIDGE_E/$BRIDGE_M cursor:$PRE_CURSOR->$FINAL_CURSOR"
echo "MODES=observer_lobby_capture:644 close1_discord_progress:644"
echo "DISCORD_STRATEGY_RUNTIME=ACTIVATED pressure_gate=YES candidate_scanner=YES"
echo "RESIDENT_RESTART=NO SIGNER_RESTART=NO"
echo "TECHNOCORE_WRITE=NO FLOP_WRITE=NO TRADE=NO"
echo "DO_NOT_RERUN=YES"
