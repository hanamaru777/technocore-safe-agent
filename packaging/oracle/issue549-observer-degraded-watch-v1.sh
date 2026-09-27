#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
HB=/var/lib/technocore-safe-agent/observer/observer-heartbeat.json
EXPECTED_HEAD=58943a072eb0d752960e092970f06311344a8996

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
  echo "PROD549V1=STOP:$1"
  echo "MUTATION=NONE"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "PROD549V1=ERROR:rc_$rc"
  echo "MUTATION=NONE"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_now not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" && -f "$HB" ]] || stop_now required_path_missing
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_now git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

snap() {
  local unit=$1
  printf '%s|%s|%s|%s|%s'     "$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)"     "$(systemctl show "$unit" -p Result --value 2>/dev/null || true)"
}

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$EXPECTED_HEAD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_now repo_baseline_changed

RES_PRE=$(snap "$RES")
CAP_PRE=$(snap "$CAP")
SIG_PRE=$(snap "$SIG")
DIS_PRE=$(snap "$DIS")
[[ "$RES_PRE" == "active|running|$RES_PID|0|success" ]] || stop_now resident_baseline_changed
[[ "$CAP_PRE" == "active|running|$CAP_PID|0|success" ]] || stop_now capture_baseline_changed
[[ "$SIG_PRE" == "active|running|$SIG_PID|0|success" ]] || stop_now signer_baseline_changed
[[ "$DIS_PRE" == "active|running|$DIS_PID|0|success" ]] || stop_now discord_baseline_changed

TMP=$(mktemp /tmp/prod549.XXXXXX)
trap 'rm -f "$TMP"' EXIT

"$PY" - "$OBS" "$HB" >"$TMP" <<'PY'
import json,pathlib,sys,time
from datetime import UTC,datetime

OBS=pathlib.Path(sys.argv[1])
HB=pathlib.Path(sys.argv[2])

def read_json(path):
    return json.loads(path.read_text("utf-8"))

def age(value):
    try:
        d=datetime.fromisoformat(str(value).replace("Z","+00:00"))
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:
        return -1.0

def state_summary():
    o=read_json(OBS)
    m=o.get("metrics") or {}
    c=o.get("cursors") or {}
    rooms=o.get("health",{}).get("rooms",{}) or {}
    bad=[]
    if isinstance(rooms,dict):
        for room,rec in rooms.items():
            if isinstance(rec,dict) and rec.get("status")=="error":
                bad.append(f"{room}:{rec.get('kind','error')}")
    recent=[]
    for rec in (o.get("error_history") or [])[-8:]:
        if isinstance(rec,dict):
            recent.append(f"{rec.get('room','?')}:{rec.get('kind','?')}")
    return {
        "core_e":int(m.get("unrecoverable_core_gap_events",0) or 0),
        "core_m":int(m.get("unrecoverable_core_gap_messages",0) or 0),
        "bridge_e":int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),
        "bridge_m":int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0),
        "cursor":int(c.get("lobby",0) or 0),
        "health":str((o.get("health") or {}).get("current","unknown")),
        "age":age(o.get("updated_at")),
        "bad":bad,
        "recent":recent,
    }

def heartbeat():
    h=read_json(HB)
    return str(h.get("status","unknown")),age(h.get("updated_at"))

def memavail():
    for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1])*1024
    return -1

def psi(kind):
    for line in pathlib.Path(f"/proc/pressure/{kind}").read_text("utf-8").splitlines():
        if line.startswith("full "):
            for field in line.split()[1:]:
                if field.startswith("avg10="):
                    return float(field.split("=",1)[1])
    return -1.0

def vm():
    out={k:0 for k in ("pgmajfault","pswpin","pswpout")}
    for line in pathlib.Path("/proc/vmstat").read_text("utf-8").splitlines():
        p=line.split()
        if len(p)==2 and p[0] in out:
            out[p[0]]=int(p[1])
    return out

start=state_summary()
vm0=vm()
samples=[]
for i in range(7):
    status,hbage=heartbeat()
    samples.append({
        "status":status,
        "age":hbage,
        "mem":memavail(),
        "mpsi":psi("memory"),
        "ipsi":psi("io"),
    })
    if i != 6:
        time.sleep(15)
end=state_summary()
vm1=vm()

print(json.dumps({
    "start":start,
    "end":end,
    "samples":samples,
    "vm_delta":{k:vm1[k]-vm0[k] for k in vm0},
},separators=(",",":")))
PY

[[ "$(git_owner rev-parse HEAD)" == "$EXPECTED_HEAD" && "$(git_owner branch --show-current)" == main ]] || stop_now repo_changed_post
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop_now worktree_changed_post
[[ "$(snap "$RES")" == "$RES_PRE" ]] || stop_now resident_changed_post
[[ "$(snap "$CAP")" == "$CAP_PRE" ]] || stop_now capture_changed_post
[[ "$(snap "$SIG")" == "$SIG_PRE" ]] || stop_now signer_changed_post
[[ "$(snap "$DIS")" == "$DIS_PRE" ]] || stop_now discord_changed_post

"$PY" - "$TMP" <<'PY'
import json,pathlib,sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text())
s=d["start"]; e=d["end"]; rows=d["samples"]
expected=(143,5652707,26,569552)
start_counts=(s["core_e"],s["core_m"],s["bridge_e"],s["bridge_m"])
end_counts=(e["core_e"],e["core_m"],e["bridge_e"],e["bridge_m"])
if start_counts != expected or end_counts != expected:
    print("PROD549V1=STOP:protected_counts_changed")
    print("MUTATION=NONE")
    print("DO_NOT_RERUN=YES")
    raise SystemExit(0)

statuses=[r["status"] for r in rows]
ok=sum(x=="ok" for x in statuses)
degraded=sum(x=="degraded" for x in statuses)
max_age=max(r["age"] for r in rows)
mems=[r["mem"]/1024/1024 for r in rows]
mpsi=[r["mpsi"] for r in rows]
ipsi=[r["ipsi"] for r in rows]
first_ok=next((i*15 for i,x in enumerate(statuses) if x=="ok"),None)

print("PROD549V1=PASS")
print(f"HEALTH=start:{s['health']} end:{e['health']} samples_ok:{ok}/7 degraded:{degraded}/7 first_ok_s:{first_ok if first_ok is not None else 'none'} heartbeat_age_max_s:{max_age:.1f}")
print("HEALTH_SEQUENCE="+",".join(statuses))
print("START_BAD_ROOMS="+(",".join(s["bad"]) if s["bad"] else "none"))
print("START_RECENT_ERRORS="+(",".join(s["recent"]) if s["recent"] else "none"))
print("END_BAD_ROOMS="+(",".join(e["bad"]) if e["bad"] else "none"))
print(f"PRESSURE=mem_mb:{min(mems):.1f}->{mems[-1]:.1f} memory_psi_max:{max(mpsi):.2f} end:{mpsi[-1]:.2f} io_psi_max:{max(ipsi):.2f} end:{ipsi[-1]:.2f}")
v=d["vm_delta"]
print(f"VMSTAT_DELTA=pgmajfault:{v['pgmajfault']} pswpin:{v['pswpin']} pswpout:{v['pswpout']}")
print(f"CONTINUITY=core:{e['core_e']}/{e['core_m']} bridge:{e['bridge_e']}/{e['bridge_m']} cursor:{s['cursor']}->{e['cursor']} state_age_start_s:{s['age']:.1f} state_age_end_s:{e['age']:.1f}")
print("SERVICES=UNCHANGED")
print("MUTATION=NONE")
print("DO_NOT_RERUN=YES")
PY
