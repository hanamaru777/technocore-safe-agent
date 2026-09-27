from __future__ import annotations

import collections
import json
import os
from pathlib import Path
import sys
import time
from datetime import UTC, datetime

OBS=Path(sys.argv[1])
SAFETY=Path(sys.argv[2])
LONG_RUNNING=set(map(int,sys.argv[3:7]))
CORE_E=int(sys.argv[7])
CORE_M=int(sys.argv[8])
SAMPLES=61
INTERVAL=2.0
SELF=os.getpid()
TCLK={
    "technocore-safe-agent-tclk-stager.service",
    "technocore-safe-agent-tclk-preparer.service",
    "technocore-safe-agent-tclk-lock-watcher.service",
    "technocore-safe-agent-tclk-work-watcher.service",
    "technocore-safe-agent-tclk-reveal-preparer.service",
}

def text(path):
    try:
        return Path(path).read_text("utf-8")
    except Exception:
        return ""

def load(path):
    try:
        value=json.loads(path.read_text("utf-8"))
        return value if isinstance(value,dict) else {}
    except Exception:
        return {}

def age(value):
    try:
        stamp=datetime.fromisoformat(str(value).replace("Z","+00:00")).astimezone(UTC)
        return max(0.0,(datetime.now(UTC)-stamp).total_seconds())
    except Exception:
        return -1.0

def mem_available_mb():
    for line in text("/proc/meminfo").splitlines():
        if line.startswith("MemAvailable:"):
            try:
                return int(line.split()[1])//1024
            except Exception:
                return -1
    return -1

def psi(kind):
    for line in text(f"/proc/pressure/{kind}").splitlines():
        if line.startswith("full "):
            for field in line.split()[1:]:
                if field.startswith("avg10="):
                    try:
                        return float(field.split("=",1)[1])
                    except ValueError:
                        return -1.0
    return -1.0

def vmstat():
    keys={"pswpin","pswpout","pgmajfault","pgscan_kswapd","pgsteal_kswapd"}
    out={k:0 for k in keys}
    for line in text("/proc/vmstat").splitlines():
        parts=line.split()
        if len(parts)==2 and parts[0] in keys:
            try:
                out[parts[0]]=int(parts[1])
            except ValueError:
                pass
    return out

def proc_meta(pid):
    status=text(f"/proc/{pid}/status")
    if not status:
        return None
    comm=text(f"/proc/{pid}/comm").strip()
    if comm not in {"python","python3","node"}:
        return None
    rss=0
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            try:
                rss=int(line.split()[1])
            except Exception:
                pass
            break
    label="unknown"
    for line in text(f"/proc/{pid}/cgroup").splitlines():
        if line.startswith("0::"):
            parts=[p for p in line[3:].strip().split("/") if p]
            for part in reversed(parts):
                if part.endswith(".service") or part.endswith(".scope"):
                    label=part
                    break
            if label=="unknown" and parts:
                label=parts[-1]
            break
    return pid,rss,label

def cgstats(pid):
    cpath=""
    for line in text(f"/proc/{pid}/cgroup").splitlines():
        if line.startswith("0::"):
            cpath=line[3:].strip()
            break
    if not cpath or ".." in cpath:
        return (-1,-1,-1)
    base=Path("/sys/fs/cgroup")/cpath.lstrip("/")
    def readint(name):
        try:
            return int((base/name).read_text().strip())
        except Exception:
            return -1
    return readint("memory.current"),readint("memory.peak"),readint("pids.current")

checks=collections.OrderedDict((k,[]) for k in (
    "obs_health","obs_age","safety_health","safety_age","safety_core",
    "mem","memory_psi","io_psi"
))
mems=[]; mpsis=[]; ipsis=[]; obsages=[]; safeages=[]
groups={}
peak_transient=0
t0=vmstat()

for idx in range(SAMPLES):
    obs=load(OBS)
    safe=load(SAFETY)
    oh=str((obs.get("health") or {}).get("current") or "")
    sh=str(safe.get("health") or "")
    oa=age(obs.get("updated_at"))
    sa=age(safe.get("updated_at"))
    mem=mem_available_mb()
    mp=psi("memory")
    ip=psi("io")
    checks["obs_health"].append(oh=="ok")
    checks["obs_age"].append(0 <= oa <= 300)
    checks["safety_health"].append(sh=="ok")
    checks["safety_age"].append(0 <= sa <= 300)
    checks["safety_core"].append(
        safe.get("unrecoverable_core_gap_events")==CORE_E
        and safe.get("unrecoverable_core_gap_messages")==CORE_M
    )
    checks["mem"].append(mem>=256)
    checks["memory_psi"].append(0 <= mp <= 5.0)
    checks["io_psi"].append(0 <= ip <= 10.0)
    mems.append(mem); mpsis.append(mp); ipsis.append(ip)
    obsages.append(oa); safeages.append(sa)

    by=collections.defaultdict(list)
    transient=0
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid=int(entry.name)
        if pid==SELF:
            continue
        row=proc_meta(pid)
        if row is None:
            continue
        by[row[2]].append(row)
        if pid not in LONG_RUNNING:
            transient += row[1]
    peak_transient=max(peak_transient,transient)
    for label,rows in by.items():
        rss=sum(r[1] for r in rows)
        rec=groups.setdefault(label,{"samples":0,"peak":0,"maxc":0,"pids":set()})
        rec["samples"]+=1
        rec["peak"]=max(rec["peak"],rss)
        rec["maxc"]=max(rec["maxc"],len(rows))
        rec["pids"].update(r[0] for r in rows)
    if idx+1<SAMPLES:
        time.sleep(INTERVAL)

t1=vmstat()
allpass=[all(values[i] for values in checks.values()) for i in range(SAMPLES)]
best=cur=0
for ok in allpass:
    cur=cur+1 if ok else 0
    best=max(best,cur)
blockers=",".join(
    f"{name}:{sum(not x for x in values)}"
    for name,values in checks.items() if not all(values)
) or "none"

print("PROD540_SAMPLE=COMPLETE")
print(f"WINDOW=samples:{SAMPLES} interval_s:{INTERVAL:.0f} gate_pass:{sum(allpass)}/{SAMPLES} max_safe_window_s:{max(0,(best-1)*INTERVAL):.0f}")
print("BLOCKERS="+blockers)
print(f"MEM_AVAILABLE_MB=min:{min(mems)} max:{max(mems)} end:{mems[-1]}")
print(f"MEMORY_PSI_FULL=max:{max(mpsis):.2f} end:{mpsis[-1]:.2f}")
print(f"IO_PSI_FULL=max:{max(ipsis):.2f} end:{ipsis[-1]:.2f}")
print(f"OBSERVER=health_pass:{sum(checks['obs_health'])}/{SAMPLES} age_max_s:{max(obsages):.1f}")
print(f"OBSERVER_SAFETY=health_pass:{sum(checks['safety_health'])}/{SAMPLES} age_max_s:{max(safeages):.1f} core_pass:{sum(checks['safety_core'])}/{SAMPLES}")
print("VMSTAT_DELTA="+" ".join(f"{k}:{t1[k]-t0[k]}" for k in ("pswpin","pswpout","pgmajfault","pgscan_kswapd","pgsteal_kswapd")))
print(f"TRANSIENT_RUNTIME_PEAK_RSS_MB={peak_transient/1024:.1f}")

for label in sorted(TCLK):
    rec=groups.get(label,{"samples":0,"peak":0,"maxc":0,"pids":set()})
    print(f"TCLK={label} active:{rec['samples']}/{SAMPLES} peak_rss_mb:{rec['peak']/1024:.1f} maxc:{rec['maxc']} unique_pids:{len(rec['pids'])}")

residual=[(label,rec) for label,rec in groups.items() if label not in TCLK]
residual.sort(key=lambda x:(-x[1]["peak"],-x[1]["samples"],x[0]))
for i,(label,rec) in enumerate(residual[:8],1):
    print(f"RESIDUAL_{i}={label} active:{rec['samples']}/{SAMPLES} peak_rss_mb:{rec['peak']/1024:.1f} maxc:{rec['maxc']} unique_pids:{len(rec['pids'])}")

for name,pid in zip(("resident","capture","signer","discord"),sys.argv[3:7]):
    cur_b,peak_b,pids=cgstats(int(pid))
    to_mb=lambda v: -1 if v<0 else round(v/1024/1024,1)
    print(f"CGROUP_{name.upper()}=current_mb:{to_mb(cur_b)} peak_mb:{to_mb(peak_b)} pids:{pids}")

print("PROTECTED=core:143/5652707 bridge:26/569552")
