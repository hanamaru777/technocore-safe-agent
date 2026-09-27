#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
OBHB=/var/lib/technocore-safe-agent/observer/observer-heartbeat.json

EXPECTED_HEAD=58943a072eb0d752960e092970f06311344a8996
RES_PID=2462149
CAP_PID=2462148
SIG_PID=2462068
DIS_PID=2660066
CORE_E=143
CORE_M=5652707
BRIDGE_E=26
BRIDGE_M=569552

stop_diag() {
  echo "PROD542V1=STOP:$1"
  echo "MUTATION=NONE"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "PROD542V1=ERROR:rc_$rc"
  echo "MUTATION=NONE"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_diag not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" && -f "$OBHB" ]] || stop_diag required_path_missing
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_diag git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

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

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$EXPECTED_HEAD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_diag repo_baseline_changed

RES=$(snap technocore-safe-agent-resident.service)
CAP=$(snap technocore-safe-agent-lobby-capture.service)
SIG=$(snap technocore-safe-agent-signer.service)
DIS=$(snap technocore-safe-agent-discord.service)
[[ "$RES" == "active|running|$RES_PID|0|success" ]] || stop_diag resident_baseline_changed
[[ "$CAP" == "active|running|$CAP_PID|0|success" ]] || stop_diag capture_baseline_changed
[[ "$SIG" == "active|running|$SIG_PID|0|success" ]] || stop_diag signer_baseline_changed
[[ "$DIS" == "active|running|$DIS_PID|0|success" ]] || stop_diag discord_baseline_changed

BASE_COUNTS="$CORE_E|$CORE_M|$BRIDGE_E|$BRIDGE_M"
[[ "$(counts)" == "$BASE_COUNTS" ]] || stop_diag protected_baseline_changed

TMP=$(mktemp /tmp/prod542.XXXXXX)
trap 'rm -f "$TMP"' EXIT

"$PY" - "$RES_PID" "$CAP_PID" "$SIG_PID" "$DIS_PID" "$OBS" "$OBHB" >"$TMP" <<'PY'
import json, pathlib, subprocess, sys, time
from datetime import UTC, datetime

PIDS=list(map(int,sys.argv[1:5]))
OBS=pathlib.Path(sys.argv[5])
HB=pathlib.Path(sys.argv[6])
NAMES=("resident","capture","signer","discord")
UNITS=(
 "technocore-safe-agent-resident.service",
 "technocore-safe-agent-lobby-capture.service",
 "technocore-safe-agent-signer.service",
 "technocore-safe-agent-discord.service",
)

def text(path):
    try: return pathlib.Path(path).read_text("utf-8")
    except Exception: return ""

def show(unit, prop):
    try:
        return subprocess.check_output(
            ["systemctl","show",unit,f"-p{prop}","--value"],
            text=True, stderr=subprocess.DEVNULL, timeout=3,
        ).strip()
    except Exception:
        return ""

def proc(pid):
    status=text(f"/proc/{pid}/status")
    rss=swap=0
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            try: rss=int(line.split()[1])*1024
            except Exception: pass
        elif line.startswith("VmSwap:"):
            try: swap=int(line.split()[1])*1024
            except Exception: pass
    maj=-1
    try: maj=int(text(f"/proc/{pid}/stat").split()[11])
    except Exception: pass
    rb=wb=-1
    for line in text(f"/proc/{pid}/io").splitlines():
        if line.startswith("read_bytes:"):
            try: rb=int(line.split(":",1)[1])
            except Exception: pass
        elif line.startswith("write_bytes:"):
            try: wb=int(line.split(":",1)[1])
            except Exception: pass
    return {"rss":rss,"swap":swap,"maj":maj,"rb":rb,"wb":wb}

def cg(unit):
    path=show(unit,"ControlGroup")
    if not path or ".." in path:
        return {"mem":-1,"swap":-1,"rb":-1,"wb":-1}
    base=pathlib.Path("/sys/fs/cgroup")/path.lstrip("/")
    def readint(name):
        try:return int((base/name).read_text().strip())
        except Exception:return -1
    rb=wb=0
    valid=False
    try:
        for line in (base/"io.stat").read_text().splitlines():
            for field in line.split()[1:]:
                if "=" not in field: continue
                k,v=field.split("=",1)
                if k=="rbytes": rb+=int(v); valid=True
                elif k=="wbytes": wb+=int(v); valid=True
    except Exception:
        pass
    return {
        "mem":readint("memory.current"),
        "swap":readint("memory.swap.current"),
        "rb":rb if valid else -1,
        "wb":wb if valid else -1,
    }

def memavail():
    for line in text("/proc/meminfo").splitlines():
        if line.startswith("MemAvailable:"):
            try:return int(line.split()[1])*1024
            except Exception:return -1
    return -1

def psi(kind):
    for line in text(f"/proc/pressure/{kind}").splitlines():
        if line.startswith("full "):
            for field in line.split()[1:]:
                if field.startswith("avg10="):
                    try:return float(field.split("=",1)[1])
                    except Exception:return -1.0
    return -1.0

def vm():
    keys={"pgmajfault","pswpin","pswpout"}
    out={k:0 for k in keys}
    for line in text("/proc/vmstat").splitlines():
        p=line.split()
        if len(p)==2 and p[0] in keys:
            try:out[p[0]]=int(p[1])
            except Exception:pass
    return out

def continuity():
    obs=json.loads(OBS.read_text("utf-8"))
    hb=json.loads(HB.read_text("utf-8"))
    m=obs.get("metrics") or {}
    c=obs.get("cursors") or {}
    try:
        d=datetime.fromisoformat(str(hb.get("updated_at","")).replace("Z","+00:00"))
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        age=max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:
        age=-1.0
    return {
        "core_e":int(m.get("unrecoverable_core_gap_events",0) or 0),
        "core_m":int(m.get("unrecoverable_core_gap_messages",0) or 0),
        "bridge_e":int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),
        "bridge_m":int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0),
        "cursor":int(c.get("lobby",0) or 0),
        "updated":str(obs.get("updated_at","")),
        "hb_age":age,
    }

def sample():
    return {
      "proc":{n:proc(p) for n,p in zip(NAMES,PIDS)},
      "cg":{n:cg(u) for n,u in zip(NAMES,UNITS)},
      "mem":memavail(),
      "mpsi":psi("memory"),
      "ipsi":psi("io"),
      "vm":vm(),
      "cont":continuity(),
    }

a=sample()
time.sleep(30)
b=sample()
time.sleep(30)
c=sample()

print(json.dumps({"t0":a,"t30":b,"t60":c},separators=(",",":")))
PY

[[ "$(git_owner rev-parse HEAD)" == "$EXPECTED_HEAD" && "$(git_owner branch --show-current)" == main && -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_diag repo_changed_post
[[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || stop_diag resident_changed_post
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_diag capture_changed_post
[[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_diag signer_changed_post
[[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || stop_diag discord_changed_post
[[ "$(counts)" == "$BASE_COUNTS" ]] || stop_diag protected_changed_post

"$PY" - "$TMP" <<'PY'
import json,pathlib,sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text())
a=d["t0"]; b=d["t30"]; c=d["t60"]

def mb(v):
    return -1.0 if v < 0 else v/1024/1024

print("PROD542V1=PASS")
for name in ("resident","capture","signer","discord"):
    p0=a["proc"][name]; p1=c["proc"][name]
    g0=a["cg"][name]; g1=c["cg"][name]
    print(
        f"SERVICE={name} "
        f"majflt_delta:{p1['maj']-p0['maj']} "
        f"read_mb:{mb(p1['rb']-p0['rb']):.1f} write_mb:{mb(p1['wb']-p0['wb']):.1f} "
        f"rss_mb:{mb(p0['rss']):.1f}->{mb(p1['rss']):.1f} "
        f"swap_mb:{mb(p0['swap']):.1f}->{mb(p1['swap']):.1f} "
        f"cg_mem_mb:{mb(g0['mem']):.1f}->{mb(g1['mem']):.1f} "
        f"cg_swap_mb:{mb(g0['swap']):.1f}->{mb(g1['swap']):.1f} "
        f"cg_read_mb:{mb(g1['rb']-g0['rb']):.1f} cg_write_mb:{mb(g1['wb']-g0['wb']):.1f}"
    )
print(
    f"HOST=mem_avail_mb:{mb(a['mem']):.1f}->{mb(b['mem']):.1f}->{mb(c['mem']):.1f} "
    f"memory_psi:{a['mpsi']:.2f}->{b['mpsi']:.2f}->{c['mpsi']:.2f} "
    f"io_psi:{a['ipsi']:.2f}->{b['ipsi']:.2f}->{c['ipsi']:.2f}"
)
print(
    "VMSTAT_DELTA="
    + " ".join(f"{k}:{c['vm'][k]-a['vm'][k]}" for k in ("pgmajfault","pswpin","pswpout"))
)
co=c["cont"]; ao=a["cont"]
print(
    f"CONTINUITY=core:{co['core_e']}/{co['core_m']} "
    f"bridge:{co['bridge_e']}/{co['bridge_m']} "
    f"cursor:{ao['cursor']}->{co['cursor']} "
    f"observer_moved:{'YES' if co['updated'] != ao['updated'] else 'NO'} "
    f"heartbeat_age_s:{co['hb_age']:.1f}"
)
print("MUTATION=NONE")
print("DO_NOT_RERUN=YES")
PY
