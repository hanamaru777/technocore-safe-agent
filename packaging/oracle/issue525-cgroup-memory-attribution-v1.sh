#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json

EXPECTED_HEAD=a4016accdef7b1df591d68d1bcdc54c7a9de7320
RES_PID=2462149
CAP_PID=2462148
SIG_PID=2462068
DIS_PID=2660066
CORE_E=143
CORE_M=5652707
BRIDGE_E=26
BRIDGE_M=569552

stop_diag() {
  echo "PROD525V1=STOP:$1"
  echo "MUTATION=NONE"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "PROD525V1=ERROR:rc_$rc"
  echo "MUTATION=NONE"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_diag not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" ]] || stop_diag required_path_missing
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_diag git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

snap() {
  local unit=$1
  printf '%s|%s|%s|%s|%s'     "$(systemctl show "$unit" -p ActiveState --value)"     "$(systemctl show "$unit" -p SubState --value)"     "$(systemctl show "$unit" -p MainPID --value)"     "$(systemctl show "$unit" -p NRestarts --value)"     "$(systemctl show "$unit" -p Result --value)"
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

TMPDIR=$(mktemp -d /tmp/prod525.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

sample() {
  local out=$1
  "$PY" - "$RES_PID" "$CAP_PID" "$SIG_PID" "$DIS_PID" >"$out" <<'PY'
import json, pathlib, re, sys, time

pids=[int(v) for v in sys.argv[1:5]]

def read_text(path):
    try:
        return pathlib.Path(path).read_text("utf-8")
    except Exception:
        return ""

def meminfo():
    out={}
    for line in read_text("/proc/meminfo").splitlines():
        if ":" not in line:
            continue
        key,rest=line.split(":",1)
        parts=rest.split()
        if parts:
            try: out[key]=int(parts[0])
            except ValueError: pass
    return out

def psi(kind):
    out={"some":-1.0,"full":-1.0}
    for line in read_text(f"/proc/pressure/{kind}").splitlines():
        parts=line.split()
        if not parts:
            continue
        mode=parts[0]
        for field in parts[1:]:
            if field.startswith("avg10="):
                try: out[mode]=float(field.split("=",1)[1])
                except ValueError: pass
    return out

def vmstat():
    keys={"pswpin","pswpout","pgmajfault","pgscan_kswapd","pgsteal_kswapd"}
    out={k:0 for k in keys}
    for line in read_text("/proc/vmstat").splitlines():
        parts=line.split()
        if len(parts)==2 and parts[0] in keys:
            try: out[parts[0]]=int(parts[1])
            except ValueError: pass
    return out

def proc_meta(pid):
    status=read_text(f"/proc/{pid}/status")
    if not status:
        return None
    data={"pid":pid,"comm":read_text(f"/proc/{pid}/comm").strip()[:32] or "unknown","rss_kb":0,"state":"?","ppid":0}
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            try: data["rss_kb"]=int(line.split()[1])
            except Exception: pass
        elif line.startswith("State:"):
            parts=line.split()
            if len(parts)>1: data["state"]=parts[1][:2]
        elif line.startswith("PPid:"):
            try: data["ppid"]=int(line.split()[1])
            except Exception: pass
    return data

def cgroup_path(pid):
    for line in read_text(f"/proc/{pid}/cgroup").splitlines():
        if line.startswith("0::"):
            value=line[3:].strip()
            if value.startswith("/") and ".." not in value:
                return value
    return None

def read_int(path):
    try:
        raw=pathlib.Path(path).read_text("utf-8").strip()
        return int(raw)
    except Exception:
        return -1

def cgroup(pid):
    cg=cgroup_path(pid)
    if not cg:
        return {"path":"","memory_current":-1,"memory_peak":-1,"pids_current":-1,"procs":[]}
    base=pathlib.Path("/sys/fs/cgroup") / cg.lstrip("/")
    proc_ids=[]
    for token in read_text(base/"cgroup.procs").split():
        try: proc_ids.append(int(token))
        except ValueError: pass
    procs=[x for x in (proc_meta(x) for x in proc_ids) if x]
    procs.sort(key=lambda x:(-x["rss_kb"],x["pid"]))
    return {
        "path":cg,
        "memory_current":read_int(base/"memory.current"),
        "memory_peak":read_int(base/"memory.peak"),
        "pids_current":read_int(base/"pids.current"),
        "procs":procs[:8],
        "rss_sum_kb":sum(x["rss_kb"] for x in procs),
    }

all_procs=[]
for entry in pathlib.Path("/proc").iterdir():
    if entry.name.isdigit():
        meta=proc_meta(int(entry.name))
        if meta: all_procs.append(meta)
all_procs.sort(key=lambda x:(-x["rss_kb"],x["pid"]))

maintenance=[
    p for p in all_procs
    if "resident" in p["comm"].lower() or "flop" in p["comm"].lower()
]

mi=meminfo()
print(json.dumps({
    "ts":int(time.time()),
    "mem":{k:mi.get(k,-1) for k in (
        "MemTotal","MemAvailable","MemFree","Buffers","Cached","SReclaimable",
        "Shmem","AnonPages","Slab","PageTables","SwapTotal","SwapFree"
    )},
    "psi_memory":psi("memory"),
    "psi_io":psi("io"),
    "vmstat":vmstat(),
    "units":{
        "resident":cgroup(pids[0]),
        "capture":cgroup(pids[1]),
        "signer":cgroup(pids[2]),
        "discord":cgroup(pids[3]),
    },
    "top":all_procs[:10],
    "maintenance_like":maintenance[:10],
},sort_keys=True,separators=(",",":")))
PY
}

sample "$TMPDIR/t0.json"
sleep 60

[[ "$(git_owner rev-parse HEAD)" == "$EXPECTED_HEAD" && "$(git_owner branch --show-current)" == main && -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_diag repo_changed_during_sample
[[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || stop_diag resident_changed_during_sample
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_diag capture_changed_during_sample
[[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_diag signer_changed_during_sample
[[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || stop_diag discord_changed_during_sample
[[ "$(counts)" == "$BASE_COUNTS" ]] || stop_diag protected_changed_during_sample

sample "$TMPDIR/t60.json"

"$PY" - "$TMPDIR/t0.json" "$TMPDIR/t60.json" <<'PY'
import json, pathlib, sys
a=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
b=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))

def mb_kb(v):
    return -1 if v < 0 else round(v/1024,1)
def mb_bytes(v):
    return -1 if v < 0 else round(v/1024/1024,1)
def memline(tag,x):
    m=x["mem"]
    return (
        f"{tag}=total:{mb_kb(m['MemTotal'])} avail:{mb_kb(m['MemAvailable'])} "
        f"free:{mb_kb(m['MemFree'])} cached:{mb_kb(m['Cached'])} "
        f"sreclaim:{mb_kb(m['SReclaimable'])} shmem:{mb_kb(m['Shmem'])} "
        f"anon:{mb_kb(m['AnonPages'])} slab:{mb_kb(m['Slab'])} "
        f"pagetables:{mb_kb(m['PageTables'])} "
        f"swap_free:{mb_kb(m['SwapFree'])}/{mb_kb(m['SwapTotal'])}MB"
    )
def unitline(name,x):
    u=x["units"][name]
    procs=",".join(f"{p['pid']}:{p['comm']}:{mb_kb(p['rss_kb'])}MB:{p['state']}" for p in u.get("procs",[])[:4]) or "none"
    return (
        f"CGROUP_{name.upper()}=current:{mb_bytes(u.get('memory_current',-1))}MB "
        f"peak:{mb_bytes(u.get('memory_peak',-1))}MB tasks:{u.get('pids_current',-1)} "
        f"rss_sum:{mb_kb(u.get('rss_sum_kb',-1))}MB procs:{procs}"
    )

print("PROD525V1=PASS")
print(memline("MEM_T0",a))
print(memline("MEM_T60",b))
print(
    f"PSI_T0=memory_some:{a['psi_memory']['some']:.2f} memory_full:{a['psi_memory']['full']:.2f} "
    f"io_some:{a['psi_io']['some']:.2f} io_full:{a['psi_io']['full']:.2f}"
)
print(
    f"PSI_T60=memory_some:{b['psi_memory']['some']:.2f} memory_full:{b['psi_memory']['full']:.2f} "
    f"io_some:{b['psi_io']['some']:.2f} io_full:{b['psi_io']['full']:.2f}"
)
print(
    "VMSTAT_DELTA="+
    " ".join(f"{k}:{b['vmstat'].get(k,0)-a['vmstat'].get(k,0)}" for k in (
        "pswpin","pswpout","pgmajfault","pgscan_kswapd","pgsteal_kswapd"
    ))
)
for name in ("resident","capture","signer","discord"):
    print(unitline(name,b))
top=";".join(f"{p['pid']}:{p['comm']}:{mb_kb(p['rss_kb'])}MB:{p['state']}" for p in b["top"][:10])
print("TOP_RSS="+top)
maint=";".join(f"{p['pid']}:{p['comm']}:{mb_kb(p['rss_kb'])}MB:{p['state']}" for p in b.get("maintenance_like",[])[:10]) or "none"
print("FLOP_NAMED_PROCS="+maint)
print("PROTECTED=core:143/5652707 bridge:26/569552")
print("MUTATION=NONE")
print("DO_NOT_RERUN=YES")
PY
