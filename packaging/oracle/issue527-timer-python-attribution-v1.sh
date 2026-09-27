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
  echo "PROD527V1=STOP:$1"
  echo "MUTATION=NONE"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "PROD527V1=ERROR:rc_$rc"
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

"$PY" - "$RES_PID" "$CAP_PID" "$SIG_PID" "$DIS_PID" <<'PY'
import collections, os, pathlib, re, sys, time

LONG_RUNNING=set(map(int,sys.argv[1:5]))
SELF=os.getpid()
SAMPLES=61
INTERVAL=1.0

def read_text(path):
    try:
        return pathlib.Path(path).read_text("utf-8")
    except Exception:
        return ""

def proc_meta(pid):
    status=read_text(f"/proc/{pid}/status")
    if not status:
        return None
    comm=read_text(f"/proc/{pid}/comm").strip()
    if comm not in {"python","python3","node"}:
        return None
    rss=ppid=uid=0
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            try: rss=int(line.split()[1])
            except Exception: pass
        elif line.startswith("PPid:"):
            try: ppid=int(line.split()[1])
            except Exception: pass
        elif line.startswith("Uid:"):
            try: uid=int(line.split()[1])
            except Exception: pass
    cg=read_text(f"/proc/{pid}/cgroup")
    label="unknown"
    path=""
    for line in cg.splitlines():
        if line.startswith("0::"):
            path=line[3:].strip()
            parts=[p for p in path.split("/") if p]
            for part in reversed(parts):
                if part.endswith(".service") or part.endswith(".scope"):
                    label=part
                    break
            if label=="unknown" and parts:
                label=parts[-1]
            break
    return {
        "pid":pid,"ppid":ppid,"uid":uid,"comm":comm,"rss_kb":rss,
        "label":label[:96],"cgroup":path[:192],
    }

def psi(kind):
    out={"some":-1.0,"full":-1.0}
    for line in read_text(f"/proc/pressure/{kind}").splitlines():
        parts=line.split()
        if not parts: continue
        mode=parts[0]
        for field in parts[1:]:
            if field.startswith("avg10="):
                try: out[mode]=float(field.split("=",1)[1])
                except ValueError: pass
    return out

def vmstat():
    keys={"pswpin","pswpout","pgmajfault"}
    out={k:0 for k in keys}
    for line in read_text("/proc/vmstat").splitlines():
        parts=line.split()
        if len(parts)==2 and parts[0] in keys:
            try: out[parts[0]]=int(parts[1])
            except ValueError: pass
    return out

def memavail_mb():
    for line in read_text("/proc/meminfo").splitlines():
        if line.startswith("MemAvailable:"):
            try: return int(line.split()[1])//1024
            except Exception: return -1
    return -1

stats={}
peak_transient=0
peak_transient_count=0
t0_vm=vmstat()
t0_psi_mem=psi("memory")
t0_psi_io=psi("io")
t0_mem=memavail_mb()

for idx in range(SAMPLES):
    by_label=collections.defaultdict(list)
    transient_rss=0
    transient_count=0
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid=int(entry.name)
        if pid==SELF:
            continue
        meta=proc_meta(pid)
        if not meta:
            continue
        by_label[meta["label"]].append(meta)
        if pid not in LONG_RUNNING:
            transient_rss += meta["rss_kb"]
            transient_count += 1
    peak_transient=max(peak_transient,transient_rss)
    peak_transient_count=max(peak_transient_count,transient_count)
    for label,rows in by_label.items():
        cur=sum(r["rss_kb"] for r in rows)
        rec=stats.setdefault(label,{
            "samples":0,"peak_rss_kb":0,"max_concurrent":0,"pids":set(),
            "uids":set(),"ppids":set(),"comm":set(),"cgroup":set(),
        })
        rec["samples"] += 1
        rec["peak_rss_kb"]=max(rec["peak_rss_kb"],cur)
        rec["max_concurrent"]=max(rec["max_concurrent"],len(rows))
        for r in rows:
            rec["pids"].add(r["pid"]); rec["uids"].add(r["uid"])
            rec["ppids"].add(r["ppid"]); rec["comm"].add(r["comm"])
            if r["cgroup"]: rec["cgroup"].add(r["cgroup"])
    if idx+1 < SAMPLES:
        time.sleep(INTERVAL)

t60_vm=vmstat()
t60_psi_mem=psi("memory")
t60_psi_io=psi("io")
t60_mem=memavail_mb()

ranked=sorted(
    stats.items(),
    key=lambda kv:(-kv[1]["peak_rss_kb"],-kv[1]["samples"],kv[0]),
)

print("PROD527V1=PASS")
print(f"WINDOW=samples:{SAMPLES} interval_s:{INTERVAL:.0f} mem_avail_mb:{t0_mem}->{t60_mem}")
print(
    f"PSI=memory_full:{t0_psi_mem['full']:.2f}->{t60_psi_mem['full']:.2f} "
    f"io_full:{t0_psi_io['full']:.2f}->{t60_psi_io['full']:.2f}"
)
print(
    "VMSTAT_DELTA="+
    " ".join(f"{k}:{t60_vm[k]-t0_vm[k]}" for k in ("pswpin","pswpout","pgmajfault"))
)
print(f"TRANSIENT_PYTHON_PEAK=rss_mb:{peak_transient/1024:.1f} count:{peak_transient_count}")
for idx,(label,rec) in enumerate(ranked[:12],1):
    pids=",".join(map(str,sorted(rec["pids"])))[:160]
    ppids=",".join(map(str,sorted(rec["ppids"])))[:120]
    uids=",".join(map(str,sorted(rec["uids"])))[:80]
    comm=",".join(sorted(rec["comm"]))[:80]
    cgroups=";".join(sorted(rec["cgroup"]))[:220] or "-"
    print(
        f"GROUP_{idx}={label} active_samples:{rec['samples']}/{SAMPLES} "
        f"peak_rss_mb:{rec['peak_rss_kb']/1024:.1f} max_concurrent:{rec['max_concurrent']} "
        f"unique_pids:{len(rec['pids'])} pids:{pids} ppids:{ppids} uids:{uids} "
        f"comm:{comm} cgroup:{cgroups}"
    )
print("MUTATION=NONE")
print("DO_NOT_RERUN=YES")
PY

[[ "$(git_owner rev-parse HEAD)" == "$EXPECTED_HEAD" && "$(git_owner branch --show-current)" == main && -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_diag repo_changed_post
[[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || stop_diag resident_changed_post
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_diag capture_changed_post
[[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_diag signer_changed_post
[[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || stop_diag discord_changed_post
[[ "$(counts)" == "$BASE_COUNTS" ]] || stop_diag protected_changed_post
