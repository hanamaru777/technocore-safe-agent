#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json

EXPECTED_HEAD=a4016accdef7b1df591d68d1bcdc54c7a9de7320
RES_PID=2462149
CAP_PID=2462148
SIG_PID=2462068
DIS_PID=2560998
CORE_E=143
CORE_M=5652707
BRIDGE_E=26
BRIDGE_M=569552
SAMPLES=9
INTERVAL=15

stop_diag() {
  echo "PROD521V1=STOP:$1"
  echo "MUTATION=NONE"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "PROD521V1=ERROR:rc_$rc"
  echo "MUTATION=NONE"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_diag not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" && -f "$SAFETY" ]] || stop_diag required_path_missing
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

TMP=$(mktemp /tmp/prod521.XXXXXX)
trap 'rm -f "$TMP"' EXIT

for i in $(seq 1 "$SAMPLES"); do
  [[ "$(git_owner rev-parse HEAD)" == "$EXPECTED_HEAD" && "$(git_owner branch --show-current)" == main && -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_diag repo_changed_during_sampling
  [[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || stop_diag resident_changed_during_sampling
  [[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_diag capture_changed_during_sampling
  [[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_diag signer_changed_during_sampling
  [[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || stop_diag discord_changed_during_sampling
  [[ "$(counts)" == "$BASE_COUNTS" ]] || stop_diag protected_changed_during_sampling

  "$PY" - "$OBS" "$SAFETY" "$CORE_E" "$CORE_M" >>"$TMP" <<'PY'
import json, pathlib, sys, time
from datetime import UTC, datetime

obs_path, safety_path = map(pathlib.Path, sys.argv[1:3])
ce, cm = map(int, sys.argv[3:5])

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

def meminfo():
    out={}
    try:
        for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
            if ":" in line:
                key,rest=line.split(":",1)
                parts=rest.split()
                if parts:
                    out[key]=int(parts[0])
    except Exception:
        pass
    return out

def psi(kind):
    try:
        for line in pathlib.Path(f"/proc/pressure/{kind}").read_text().splitlines():
            if line.startswith("full "):
                for part in line.split()[1:]:
                    if part.startswith("avg10="):
                        return float(part.split("=",1)[1])
    except Exception:
        return -1.0
    return -1.0

obs=load(obs_path)
safe=load(safety_path)
mi=meminfo()
obs_health=str((obs.get("health") or {}).get("current") or "")
safe_health=str(safe.get("health") or "")
safe_ce=safe.get("unrecoverable_core_gap_events")
safe_cm=safe.get("unrecoverable_core_gap_messages")
mem_mb=(mi.get("MemAvailable",-1024)//1024)
swap_free_mb=(mi.get("SwapFree",-1024)//1024)
print("|".join([
    str(int(time.time())),
    obs_health,
    f"{age(obs.get('updated_at')):.1f}",
    safe_health,
    f"{age(safe.get('updated_at')):.1f}",
    str(safe_ce if safe_ce is not None else ""),
    str(safe_cm if safe_cm is not None else ""),
    str(mem_mb),
    f"{psi('memory'):.2f}",
    f"{psi('io'):.2f}",
    str(swap_free_mb),
]))
PY

  if (( i < SAMPLES )); then sleep "$INTERVAL"; fi
done

[[ "$(git_owner rev-parse HEAD)" == "$EXPECTED_HEAD" && -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_diag repo_changed_post_sampling
[[ "$(snap technocore-safe-agent-resident.service)" == "$RES" ]] || stop_diag resident_changed_post_sampling
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "$CAP" ]] || stop_diag capture_changed_post_sampling
[[ "$(snap technocore-safe-agent-signer.service)" == "$SIG" ]] || stop_diag signer_changed_post_sampling
[[ "$(snap technocore-safe-agent-discord.service)" == "$DIS" ]] || stop_diag discord_changed_post_sampling
[[ "$(counts)" == "$BASE_COUNTS" ]] || stop_diag protected_changed_post_sampling

"$PY" - "$TMP" "$CORE_E" "$CORE_M" "$INTERVAL" "$SAMPLES" "$RES_PID" "$CAP_PID" "$SIG_PID" "$DIS_PID" <<'PY'
import pathlib, sys

path=pathlib.Path(sys.argv[1])
ce,cm,interval,expected=map(int,sys.argv[2:6])
pids=list(map(int,sys.argv[6:10]))
rows=[]
for line in path.read_text("utf-8").splitlines():
    parts=line.split("|")
    if len(parts)!=11:
        raise SystemExit("bad_sample")
    rows.append({
        "obs_health":parts[1],
        "obs_age":float(parts[2]),
        "safe_health":parts[3],
        "safe_age":float(parts[4]),
        "safe_ce":parts[5],
        "safe_cm":parts[6],
        "mem":int(parts[7]),
        "mpsi":float(parts[8]),
        "ipsi":float(parts[9]),
        "swap_free":int(parts[10]),
    })
if len(rows)!=expected:
    raise SystemExit("sample_count_mismatch")

checks={
    "obs_health":[r["obs_health"]=="ok" for r in rows],
    "obs_age":[0 <= r["obs_age"] <= 300 for r in rows],
    "safety_health":[r["safe_health"]=="ok" for r in rows],
    "safety_age":[0 <= r["safe_age"] <= 300 for r in rows],
    "safety_core":[r["safe_ce"]==str(ce) and r["safe_cm"]==str(cm) for r in rows],
    "mem":[r["mem"]>=256 for r in rows],
    "memory_psi":[0 <= r["mpsi"]<=5.0 for r in rows],
    "io_psi":[0 <= r["ipsi"]<=10.0 for r in rows],
}
all_pass=[all(values[i] for values in checks.values()) for i in range(len(rows))]
best=cur=0
for value in all_pass:
    cur=cur+1 if value else 0
    best=max(best,cur)
blockers=[f"{name}:{sum(not x for x in values)}" for name,values in checks.items() if not all(values)]
if not blockers:
    blockers=["none"]

def rss_mb(pid):
    try:
        for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])//1024
    except Exception:
        return -1
    return -1

mems=[r["mem"] for r in rows]
mpsis=[r["mpsi"] for r in rows]
ipsis=[r["ipsi"] for r in rows]
obsages=[r["obs_age"] for r in rows]
safeages=[r["safe_age"] for r in rows]
swaps=[r["swap_free"] for r in rows]

print("PROD521V1=PASS")
print(f"SAMPLES={len(rows)} interval_s={interval} gate_pass={sum(all_pass)}/{len(rows)} max_safe_streak={best} max_safe_window_s={max(0,(best-1)*interval)}")
print("BLOCKERS="+",".join(blockers))
print(f"MEM_AVAILABLE_MB=min:{min(mems)} max:{max(mems)} pass:{sum(checks['mem'])}/{len(rows)}")
print(f"MEMORY_PSI_FULL_AVG10=max:{max(mpsis):.2f} pass:{sum(checks['memory_psi'])}/{len(rows)}")
print(f"IO_PSI_FULL_AVG10=max:{max(ipsis):.2f} pass:{sum(checks['io_psi'])}/{len(rows)}")
print(f"OBSERVER=health_pass:{sum(checks['obs_health'])}/{len(rows)} age_max_s:{max(obsages):.1f} age_pass:{sum(checks['obs_age'])}/{len(rows)}")
print(f"OBSERVER_SAFETY=health_pass:{sum(checks['safety_health'])}/{len(rows)} age_max_s:{max(safeages):.1f} age_pass:{sum(checks['safety_age'])}/{len(rows)} core_pass:{sum(checks['safety_core'])}/{len(rows)}")
print(f"SWAP_FREE_MB=min:{min(swaps)} max:{max(swaps)}")
print(f"RSS_MB=resident:{rss_mb(pids[0])} capture:{rss_mb(pids[1])} signer:{rss_mb(pids[2])} discord:{rss_mb(pids[3])}")
print(f"PROTECTED=core:{ce}/{cm} bridge:26/569552")
print("MUTATION=NONE")
print("DO_NOT_RERUN=YES")
PY
