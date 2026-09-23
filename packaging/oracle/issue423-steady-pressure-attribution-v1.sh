#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

APP=/opt/technocore-safe-agent
APP_PY=$APP/.venv/bin/python
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
OBHB=$STATE/observer/observer-heartbeat.json

TARGET=077d1e478363751bf5b73d810326f95f3a36b7a3
EXPECTED_CORE_EVENTS=120
EXPECTED_CORE_MESSAGES=5650166

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIGN=technocore-safe-agent-signer.service
DISC=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service

EXPECTED_RES_PID=2243415
EXPECTED_RES_RESTARTS=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0
EXPECTED_SIGN_PID=1539554
EXPECTED_SIGN_RESTARTS=1
EXPECTED_DISC_PID=1957840
EXPECTED_DISC_RESTARTS=0

OCA1=snap.oracle-cloud-agent.oracle-cloud-agent.service
OCA2=snap.oracle-cloud-agent.oracle-cloud-agent-updater.service

echo '=== ISSUE423 STEADY PRESSURE ATTRIBUTION V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

stop_now() {
  echo "ISSUE423_PRESSURE_V1=STOP:$1"
  exit 0
}

if [[ $EUID -ne 0 ]]; then stop_now not_root; fi
for cmd in git systemctl sleep; do
  command -v "$cmd" >/dev/null 2>&1 || stop_now "missing_command:$cmd"
done
[[ -x "$APP_PY" && -f "$OBS" && -f "$OBHB" ]] || stop_now required_path_missing

HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
BRANCH=$(git -C "$APP" branch --show-current 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "HEAD=$HEAD"
echo "BRANCH=$BRANCH"
if [[ -z "$WORKTREE" ]]; then echo 'WORKTREE_CLEAN=YES'; else echo 'WORKTREE_CLEAN=NO'; fi
[[ "$HEAD" == "$TARGET" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_now repo_not_exact_target

service_exact() {
  local label=$1 unit=$2 expected_pid=$3 expected_nr=$4
  local active sub pid nr result
  active=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  sub=$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active SUB=$sub PID=$pid NRESTARTS=$nr RESULT=$result"
  [[ "$active" == active && "$sub" == running && "$pid" == "$expected_pid" && "$nr" == "$expected_nr" && "$result" == success ]]
}

echo '--- ENTRY SERVICE GATES ---'
service_exact RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS" || stop_now resident_changed
service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS" || stop_now capture_changed
service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS" || stop_now signer_changed
service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS" || stop_now discord_changed
META_ACTIVE=$(systemctl is-active "$META" 2>/dev/null || true)
META_RESULT=$(systemctl show "$META" -p Result --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$META_ACTIVE RESULT=$META_RESULT"
[[ "$META_ACTIVE" == active && "$META_RESULT" == success ]] || stop_now metadata_block_changed

BASE=$("$APP_PY" - "$OBS" "$OBHB" <<'PY'
import json,pathlib,sys
from datetime import UTC,datetime
obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
hb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
m=obs.get("metrics") or {}
c=obs.get("cursors") or {}
try:
    d=datetime.fromisoformat(hb.get("updated_at",""))
    if d.tzinfo is None:d=d.replace(tzinfo=UTC)
    age=max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
except Exception:
    age=-1.0
print(
    f"{int(m.get('unrecoverable_core_gap_events',0) or 0)}|"
    f"{int(m.get('unrecoverable_core_gap_messages',0) or 0)}|"
    f"{int(c.get('lobby',0) or 0)}|"
    f"{obs.get('updated_at','missing')}|"
    f"{age:.1f}"
)
PY
)
BASE_EVENTS=$(printf '%s' "$BASE"|cut -d'|' -f1)
BASE_MESSAGES=$(printf '%s' "$BASE"|cut -d'|' -f2)
BASE_CURSOR=$(printf '%s' "$BASE"|cut -d'|' -f3)
BASE_UPDATED=$(printf '%s' "$BASE"|cut -d'|' -f4)
BASE_OBSERVER_HB_AGE=$(printf '%s' "$BASE"|cut -d'|' -f5)
echo "BASE_PROTECTED_CORE=$BASE_EVENTS/$BASE_MESSAGES"
echo "BASE_LOBBY_CURSOR=$BASE_CURSOR"
echo "BASE_OBSERVER_UPDATED_AT=$BASE_UPDATED"
echo "BASE_OBSERVER_HEARTBEAT_AGE=$BASE_OBSERVER_HB_AGE"
[[ "$BASE_EVENTS" == "$EXPECTED_CORE_EVENTS" && "$BASE_MESSAGES" == "$EXPECTED_CORE_MESSAGES" ]] || stop_now protected_core_changed

sample() {
  local label=$1
  echo "--- $label ---"
  "$APP_PY" - "$label" "$OBS" "$OBHB" "$RES" "$CAP" "$SIGN" "$DISC" "$OCA1" "$OCA2" <<'PY'
import json
import os
import pathlib
import re
import subprocess
import sys
from datetime import UTC, datetime

label, obs_s, hb_s, *units = sys.argv[1:]

def show(unit, prop):
    try:
        return subprocess.check_output(
            ["systemctl","show",unit,f"-p{prop}","--value"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=3,
        ).strip()
    except Exception:
        return ""

def read_int(path):
    try:
        return int(pathlib.Path(path).read_text("utf-8").strip())
    except Exception:
        return -1

def proc_metrics(pid):
    if pid <= 0:
        return dict(rss=-1, swap=-1, majflt=-1, rbytes=-1, wbytes=-1, state="MISSING")
    status={}
    try:
        for line in pathlib.Path(f"/proc/{pid}/status").read_text("utf-8").splitlines():
            if ":" in line:
                k,v=line.split(":",1)
                status[k]=v.strip()
    except OSError:
        pass
    rss=int(status.get("VmRSS","-1 kB").split()[0])*1024 if status.get("VmRSS") else -1
    swap=int(status.get("VmSwap","-1 kB").split()[0])*1024 if status.get("VmSwap") else -1
    state=status.get("State","MISSING").split()[0]
    majflt=-1
    try:
        stat=pathlib.Path(f"/proc/{pid}/stat").read_text("utf-8").split()
        majflt=int(stat[11])
    except Exception:
        pass
    rbytes=wbytes=-1
    try:
        for line in pathlib.Path(f"/proc/{pid}/io").read_text("utf-8").splitlines():
            if line.startswith("read_bytes:"):
                rbytes=int(line.split(":",1)[1].strip())
            elif line.startswith("write_bytes:"):
                wbytes=int(line.split(":",1)[1].strip())
    except Exception:
        pass
    return dict(rss=rss,swap=swap,majflt=majflt,rbytes=rbytes,wbytes=wbytes,state=state)

def cg_metrics(unit):
    cg=show(unit,"ControlGroup")
    if not cg or ".." in cg:
        return dict(cg="MISSING",mem=-1,swap=-1,rbytes=-1,wbytes=-1,rios=-1,wios=-1)
    base=pathlib.Path("/sys/fs/cgroup") / cg.lstrip("/")
    mem=read_int(base/"memory.current")
    swap=read_int(base/"memory.swap.current")
    totals={"rbytes":0,"wbytes":0,"rios":0,"wios":0}
    valid=False
    try:
        for line in (base/"io.stat").read_text("utf-8").splitlines():
            for field in line.split()[1:]:
                if "=" not in field:
                    continue
                key,value=field.split("=",1)
                if key in totals:
                    totals[key]+=int(value)
                    valid=True
    except Exception:
        pass
    if not valid:
        totals={k:-1 for k in totals}
    return dict(cg=cg,mem=mem,swap=swap,**totals)

names=["RESIDENT","CAPTURE","SIGNER","DISCORD","OCA_AGENT","OCA_UPDATER"]
for name,unit in zip(names,units):
    active=show(unit,"ActiveState")
    pid_s=show(unit,"MainPID")
    try: pid=int(pid_s or 0)
    except ValueError: pid=0
    p=proc_metrics(pid)
    cg=cg_metrics(unit)
    print(
        f"{label}_UNIT={name}"
        f" ACTIVE={active or 'missing'} PID={pid}"
        f" PROC_STATE={p['state']}"
        f" RSS_BYTES={p['rss']} SWAP_BYTES={p['swap']}"
        f" MAJFLT={p['majflt']} READ_BYTES={p['rbytes']} WRITE_BYTES={p['wbytes']}"
        f" CG_MEMORY_BYTES={cg['mem']} CG_SWAP_BYTES={cg['swap']}"
        f" CG_RBYTES={cg['rbytes']} CG_WBYTES={cg['wbytes']}"
        f" CG_RIOS={cg['rios']} CG_WIOS={cg['wios']}"
    )

obs=json.loads(pathlib.Path(obs_s).read_text("utf-8"))
hb=json.loads(pathlib.Path(hb_s).read_text("utf-8"))
m=obs.get("metrics") or {}
c=obs.get("cursors") or {}
try:
    d=datetime.fromisoformat(hb.get("updated_at",""))
    if d.tzinfo is None:d=d.replace(tzinfo=UTC)
    age=max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
except Exception:
    age=-1.0
print(f"{label}_PROTECTED_CORE={int(m.get('unrecoverable_core_gap_events',0) or 0)}/{int(m.get('unrecoverable_core_gap_messages',0) or 0)}")
print(f"{label}_LOBBY_CURSOR={int(c.get('lobby',0) or 0)}")
print(f"{label}_OBSERVER_UPDATED_AT={obs.get('updated_at','missing')}")
print(f"{label}_OBSERVER_HEARTBEAT_AGE={age:.1f}")

mem={}
for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
    if ":" not in line:
        continue
    k,v=line.split(":",1)
    if k in {"MemTotal","MemAvailable","SwapTotal","SwapFree","AnonPages","Dirty","Writeback"}:
        mem[k]=int(v.strip().split()[0])*1024
        print(f"{label}_MEM_{k.upper()}_BYTES={mem[k]}")
for kind in ("io","memory","cpu"):
    p=pathlib.Path(f"/proc/pressure/{kind}")
    if not p.exists():
        continue
    for idx,line in enumerate(p.read_text("utf-8").splitlines()[:2],1):
        cleaned=re.sub(r"[^A-Za-z0-9_.:/=-]","",line)[:160]
        print(f"{label}_PSI_{kind.upper()}_{idx}={cleaned}")

vm={}
try:
    for line in pathlib.Path("/proc/vmstat").read_text("utf-8").splitlines():
        parts=line.split()
        if len(parts)==2 and parts[0] in {"pgmajfault","pswpin","pswpout"}:
            vm[parts[0]]=int(parts[1])
except Exception:
    pass
for key in ("pgmajfault","pswpin","pswpout"):
    print(f"{label}_VM_{key.upper()}={vm.get(key,-1)}")
PY

  service_exact RESIDENT "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS" || return 21
  service_exact CAPTURE "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS" || return 22
  service_exact SIGNER "$SIGN" "$EXPECTED_SIGN_PID" "$EXPECTED_SIGN_RESTARTS" || return 23
  service_exact DISCORD "$DISC" "$EXPECTED_DISC_PID" "$EXPECTED_DISC_RESTARTS" || return 24
}

sample T0 || { rc=$?; echo "ISSUE423_PRESSURE_V1=STOP:t0_service_rc_$rc"; exit 0; }
sleep 30
sample T30 || { rc=$?; echo "ISSUE423_PRESSURE_V1=STOP:t30_service_rc_$rc"; exit 0; }
sleep 30
sample T60 || { rc=$?; echo "ISSUE423_PRESSURE_V1=STOP:t60_service_rc_$rc"; exit 0; }

echo '--- FINAL CONTINUITY ---'
FINAL=$("$APP_PY" - "$OBS" "$OBHB" "$BASE_CURSOR" "$BASE_UPDATED" <<'PY'
import json,pathlib,sys
from datetime import UTC,datetime
obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
hb=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
base_cursor=int(sys.argv[3]);base_updated=sys.argv[4]
m=obs.get("metrics") or {}
c=obs.get("cursors") or {}
try:
    d=datetime.fromisoformat(hb.get("updated_at",""))
    if d.tzinfo is None:d=d.replace(tzinfo=UTC)
    age=max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
except Exception:
    age=-1.0
print(
    f"{int(m.get('unrecoverable_core_gap_events',0) or 0)}|"
    f"{int(m.get('unrecoverable_core_gap_messages',0) or 0)}|"
    f"{int(c.get('lobby',0) or 0)}|"
    f"{obs.get('updated_at','missing')}|"
    f"{age:.1f}|"
    f"{1 if obs.get('updated_at') != base_updated else 0}|"
    f"{1 if int(c.get('lobby',0) or 0) >= base_cursor else 0}"
)
PY
)
F_EVENTS=$(printf '%s' "$FINAL"|cut -d'|' -f1)
F_MESSAGES=$(printf '%s' "$FINAL"|cut -d'|' -f2)
F_CURSOR=$(printf '%s' "$FINAL"|cut -d'|' -f3)
F_UPDATED=$(printf '%s' "$FINAL"|cut -d'|' -f4)
F_HB_AGE=$(printf '%s' "$FINAL"|cut -d'|' -f5)
F_UPDATED_MOVED=$(printf '%s' "$FINAL"|cut -d'|' -f6)
F_CURSOR_OK=$(printf '%s' "$FINAL"|cut -d'|' -f7)
echo "FINAL_PROTECTED_CORE=$F_EVENTS/$F_MESSAGES"
echo "FINAL_LOBBY_CURSOR=$F_CURSOR"
echo "FINAL_OBSERVER_UPDATED_AT=$F_UPDATED"
echo "FINAL_OBSERVER_HEARTBEAT_AGE=$F_HB_AGE"
echo "FINAL_OBSERVER_UPDATED_MOVED=$F_UPDATED_MOVED"
echo "FINAL_CURSOR_NONDECREASING=$F_CURSOR_OK"

[[ "$F_EVENTS" == "$EXPECTED_CORE_EVENTS" && "$F_MESSAGES" == "$EXPECTED_CORE_MESSAGES" ]] || stop_now protected_core_changed_during_watch
[[ "$F_UPDATED_MOVED" == 1 && "$F_CURSOR_OK" == 1 ]] || stop_now observer_not_progressing
"$APP_PY" - "$F_HB_AGE" <<'PY'
import sys
raise SystemExit(0 if 0 <= float(sys.argv[1]) <= 180 else 1)
PY
[[ $? -eq 0 ]] || stop_now observer_heartbeat_not_fresh

echo 'SERVICE_MUTATION=NO'
echo 'SERVICE_RESTART=NO'
echo 'SOURCE_MUTATION=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'NETWORK_PROBE=NO'
echo 'RAW_CMDLINE_OUTPUT=NO'
echo 'PROCESS_ENV_OUTPUT=NO'
echo 'TECHNOCORE_WRITE=NO'
echo '=== ISSUE423_STEADY_PRESSURE_ATTRIBUTION_V1=COMPLETE_READ_ONLY ==='
echo 'DO_NOT_RERUN=YES'
exit 0
