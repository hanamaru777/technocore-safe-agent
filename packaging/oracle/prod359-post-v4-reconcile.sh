#!/usr/bin/env bash
# Independent read-only post-PROD359-v4 reconcile.
# Public-safe output only: no OCIDs, IMDS body, public IP, raw logs, or secrets.
set -u
umask 077

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
OBHB=$STATE/observer/observer-heartbeat.json
RESHB=$STATE/observer/resident-heartbeat.json
CAP_WAL=$STATE/observer/lobby-capture-service.sqlite3-wal
CAP_SHM=$STATE/observer/lobby-capture-service.sqlite3-shm

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service
OCA=snap.oracle-cloud-agent.oracle-cloud-agent.service
OCA_UPDATER=snap.oracle-cloud-agent.oracle-cloud-agent-updater.service

META_CHAIN=TECHNOCORE_METADATA
META_IP=169.254.169.254/32
IMDS_URL=http://169.254.169.254/opc/v2/instance/

TMPDIR=$(mktemp -d /tmp/prod359-post-v4.XXXXXX)
cleanup() {
  rm -rf -- "$TMPDIR"
}
trap cleanup EXIT

echo '=== PROD359 V4 INDEPENDENT READ-ONLY RECONCILE ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

echo '--- GIT / APPLICATION ---'
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
echo "GIT_OWNER=${OWNER:-UNKNOWN}"
if [[ -n "$OWNER" ]]; then
  HEAD_VALUE=$(sudo -u "$OWNER" git -C "$APP" rev-parse HEAD 2>/dev/null || true)
  BRANCH_VALUE=$(sudo -u "$OWNER" git -C "$APP" symbolic-ref --short HEAD 2>/dev/null || true)
  ORIGIN_VALUE=$(sudo -u "$OWNER" git -C "$APP" rev-parse refs/remotes/origin/main 2>/dev/null || true)
  WORKTREE=$(sudo -u "$OWNER" git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
  echo "HEAD=${HEAD_VALUE:-UNAVAILABLE}"
  echo "BRANCH=${BRANCH_VALUE:-UNAVAILABLE}"
  echo "LOCAL_ORIGIN_MAIN=${ORIGIN_VALUE:-UNAVAILABLE}"
  if [[ -z "$WORKTREE" ]]; then echo 'WORKTREE_CLEAN=YES'; else echo 'WORKTREE_CLEAN=NO'; fi
fi

echo '--- OCA SNAP ---'
snap list oracle-cloud-agent >"$TMPDIR/snap-list.txt" 2>&1
SNAP_LIST_RC=$?
snap info oracle-cloud-agent >"$TMPDIR/snap-info.txt" 2>&1
SNAP_INFO_RC=$?
snap changes >"$TMPDIR/snap-changes.txt" 2>&1
SNAP_CHANGES_RC=$?
echo "SNAP_LIST_RC=$SNAP_LIST_RC"
echo "SNAP_INFO_RC=$SNAP_INFO_RC"
echo "SNAP_CHANGES_RC=$SNAP_CHANGES_RC"

python3 - "$TMPDIR/snap-list.txt" "$TMPDIR/snap-info.txt" <<'PY'
import re, sys
from pathlib import Path
list_text=Path(sys.argv[1]).read_text("utf-8", errors="replace")
info_text=Path(sys.argv[2]).read_text("utf-8", errors="replace")
version=revision="UNAVAILABLE"
rows=[line.split() for line in list_text.splitlines() if line.strip()]
if len(rows)>=2 and len(rows[1])>=3:
    version,revision=rows[1][1],rows[1][2]
def field(name):
    m=re.search(rf"(?m)^{re.escape(name)}:\s*(.+?)\s*$",info_text)
    return m.group(1).strip() if m else "UNAVAILABLE"
tracking=field("tracking")
hold=field("hold")
stable_version=stable_revision="UNAVAILABLE"
for line in info_text.splitlines():
    stripped=line.strip()
    if stripped.startswith("latest/stable:"):
        parts=stripped.split()
        if len(parts)>=2: stable_version=parts[1]
        nums=[p for p in parts[2:] if p.isdigit()]
        if nums: stable_revision=nums[-1]
        break
print("OCA_VERSION="+version)
print("OCA_REVISION="+revision)
print("OCA_TRACKING="+tracking)
print("OCA_HOLD="+hold)
print("OCA_STABLE_VERSION="+stable_version)
print("OCA_STABLE_REVISION="+stable_revision)
PY

echo '--- SNAP CHANGE HISTORY ---'
cat "$TMPDIR/snap-changes.txt"

service_snapshot() {
  local label=$1
  echo "--- SERVICES $label ---"
  for svc in "$META" "$RES" "$CAP" "$SIG" "$DIS" "$OCA" "$OCA_UPDATER"; do
    active=$(systemctl is-active "$svc" 2>/dev/null || true)
    enabled=$(systemctl is-enabled "$svc" 2>/dev/null || true)
    pid=$(systemctl show "$svc" -p MainPID --value 2>/dev/null || true)
    restarts=$(systemctl show "$svc" -p NRestarts --value 2>/dev/null || true)
    result=$(systemctl show "$svc" -p Result --value 2>/dev/null || true)
    echo "SERVICE=$svc ACTIVE=${active:-UNKNOWN} ENABLED=${enabled:-UNKNOWN} PID=${pid:-UNKNOWN} NRESTARTS=${restarts:-UNKNOWN} RESULT=${result:-UNKNOWN}"
  done
}

state_snapshot() {
  local label=$1
  python3 - "$label" "$OBS" "$OBHB" "$RESHB" <<'PY'
import json, pathlib, sys
from datetime import UTC, datetime
label,obs_path,obhb_path,reshb_path=sys.argv[1:]
def load(path):
    try: return json.loads(pathlib.Path(path).read_text("utf-8"))
    except Exception as exc: return {"__error__":type(exc).__name__}
def age(value):
    try: dt=datetime.fromisoformat(value)
    except Exception: return "UNKNOWN"
    return f"{max(0,(datetime.now(UTC)-dt).total_seconds()):.1f}"
state=load(obs_path); obhb=load(obhb_path); reshb=load(reshb_path)
health=state.get("health") or {}; metrics=state.get("metrics") or {}
resident_status=reshb.get("resident_status") or {}
print(f"--- OBSERVER / RESIDENT {label} ---")
print("HEALTH_CURRENT="+str(health.get("current","MISSING")))
print("CORE_EVENTS="+str(metrics.get("unrecoverable_core_gap_events","MISSING")))
print("CORE_MESSAGES="+str(metrics.get("unrecoverable_core_gap_messages","MISSING")))
errors=[(room,record) for room,record in (health.get("rooms") or {}).items() if isinstance(record,dict) and record.get("status")=="error"]
print("ERROR_ROOM_COUNT="+str(len(errors)))
for index,(room,record) in enumerate(errors,1):
    room_class=room if room in ("lobby","events") else "other"
    print(f"ERROR_ROOM_{index}={room_class} KIND={record.get('kind','MISSING')} AGE_SECONDS={age(record.get('at'))}")
print("OBSERVER_HEARTBEAT_STATUS="+str(obhb.get("status","MISSING")))
print("OBSERVER_HEARTBEAT_AGE_SECONDS="+age(obhb.get("updated_at")))
print("RESIDENT_HEARTBEAT_STATUS="+str(reshb.get("status","MISSING")))
print("RESIDENT_HEARTBEAT_AGE_SECONDS="+age(reshb.get("updated_at")))
print("RESIDENT_LAST_REFRESH_AGE_SECONDS="+age(resident_status.get("last_refresh_at")))
PY
}

capture_snapshot() {
  local label=$1
  local pid
  pid=$(systemctl show "$CAP" -p MainPID --value 2>/dev/null || true)
  echo "--- CAPTURE $label ---"
  echo "CAPTURE_PID=${pid:-UNKNOWN}"
  echo "CAPTURE_NRESTARTS=$(systemctl show "$CAP" -p NRestarts --value 2>/dev/null || true)"
  python3 - "$pid" "$CAP_WAL" "$CAP_SHM" <<'PY'
import pathlib, sys
try: pid=int(sys.argv[1])
except Exception:
    print("CAPTURE_ACTIVITY=UNAVAILABLE"); raise SystemExit
proc=pathlib.Path(f"/proc/{pid}/stat")
if not proc.exists():
    print("CAPTURE_ACTIVITY=PROCESS_MISSING"); raise SystemExit
raw=proc.read_text("utf-8"); right=raw.rfind(")"); fields=raw[right+2:].split()
ticks=int(fields[11])+int(fields[12])
def sig(path):
    p=pathlib.Path(path)
    if not p.exists(): return (-1,-1)
    st=p.stat(); return (st.st_mtime_ns,st.st_size)
wal=sig(sys.argv[2]); shm=sig(sys.argv[3])
print("CAPTURE_CPU_TICKS="+str(ticks))
print("CAPTURE_WAL_MTIME_NS="+str(wal[0]))
print("CAPTURE_WAL_SIZE="+str(wal[1]))
print("CAPTURE_SHM_MTIME_NS="+str(shm[0]))
print("CAPTURE_SHM_SIZE="+str(shm[1]))
PY
}

direct_probe() {
  local label=$1
  echo "--- SAME-USER DIRECT READ $label ---"
  sudo -u technocore env PYTHONPATH="$APP/src" "$APP/.venv/bin/python" - <<'PY'
import asyncio,time,httpx
from flop_agent import core
async def main():
    timeout=httpx.Timeout(15.0,connect=3.0,pool=3.0)
    tests=(
        ("rooms",f"{core.BASE_URL}/rooms",None),
        ("events",f"{core.BASE_URL}/r/events",{"format":"json","since":0,"wait":0,"limit":1}),
        ("lobby",f"{core.BASE_URL}/r/lobby",{"format":"json","since":0,"wait":0,"limit":1}),
    )
    async with httpx.AsyncClient() as client:
        for name,url,params in tests:
            start=time.monotonic()
            try:
                response=await client.get(url,params=params,timeout=timeout)
                print(f"PROBE={name} HTTP={response.status_code} SECONDS={time.monotonic()-start:.3f}")
            except Exception as exc:
                print(f"PROBE={name} ERROR={type(exc).__name__} SECONDS={time.monotonic()-start:.3f}")
asyncio.run(main())
PY
}

security_snapshot() {
  echo '--- SECURITY / CLOCK ---'
  root_code=$(curl -sS --connect-timeout 3 --max-time 5 -H 'Authorization: Bearer Oracle' -o "$TMPDIR/imds.json" -w '%{http_code}' "$IMDS_URL" 2>/dev/null || true)
  echo "ROOT_IMDS_HTTP=${root_code:-000}"
  tc_code=$(sudo -u technocore curl -sS --connect-timeout 2 --max-time 3 -H 'Authorization: Bearer Oracle' -o /dev/null -w '%{http_code}' "$IMDS_URL" 2>/dev/null || true)
  echo "TECHNOCORE_IMDS_HTTP=${tc_code:-000}"
  if [[ "$tc_code" == "200" ]]; then echo 'TECHNOCORE_IMDS_BLOCKED=NO'; else echo 'TECHNOCORE_IMDS_BLOCKED=YES'; fi
  if iptables -C OUTPUT -p tcp -d "$META_IP" --dport 80 -j "$META_CHAIN" >/dev/null 2>&1; then echo 'METADATA_OUTPUT_JUMP=YES'; else echo 'METADATA_OUTPUT_JUMP=NO'; fi
  if iptables -C "$META_CHAIN" -m owner --uid-owner 0 -j RETURN >/dev/null 2>&1; then echo 'METADATA_ROOT_RETURN=YES'; else echo 'METADATA_ROOT_RETURN=NO'; fi
  signer_uid=$(id -u technocore-signer 2>/dev/null || true)
  if [[ -n "$signer_uid" ]] && iptables -C "$META_CHAIN" -m owner --uid-owner "$signer_uid" -j RETURN >/dev/null 2>&1; then echo 'METADATA_SIGNER_RETURN=YES'; else echo 'METADATA_SIGNER_RETURN=NO'; fi
  if iptables -C "$META_CHAIN" -j REJECT >/dev/null 2>&1; then echo 'METADATA_FINAL_REJECT=YES'; else echo 'METADATA_FINAL_REJECT=NO'; fi
  echo "NTP_SYNCHRONIZED=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
}

agent_config_snapshot() {
  echo '--- AGENT CONFIG / RUN COMMAND ---'
  python3 - "$TMPDIR/imds.json" <<'PY'
import json,pathlib,sys
path=pathlib.Path(sys.argv[1])
try: doc=json.loads(path.read_text("utf-8"))
except Exception:
    print("AGENT_CONFIG_PARSE=FAIL"); print("RUN_COMMAND_ADVERTISED=UNKNOWN"); print("RUN_COMMAND_DESIRED_STATE=unknown"); raise SystemExit
cfg=doc.get("agentConfig")
if not isinstance(cfg,dict):
    print("AGENT_CONFIG_PARSE=NO_CONFIG"); print("RUN_COMMAND_ADVERTISED=UNKNOWN"); print("RUN_COMMAND_DESIRED_STATE=unknown"); raise SystemExit
def yn(value):
    if value is True: return "true"
    if value is False: return "false"
    return "unknown"
management=cfg.get("managementDisabled",cfg.get("isManagementDisabled"))
all_disabled=cfg.get("allPluginsDisabled",cfg.get("areAllPluginsDisabled"))
rows=cfg.get("pluginsConfig"); rows=rows if isinstance(rows,list) else []
safe=[]; run_command=None
for row in rows:
    if not isinstance(row,dict): continue
    name=row.get("name"); state=row.get("desiredState")
    if not isinstance(name,str): continue
    clean_name="".join(ch for ch in name if ch.isalnum() or ch in " ._-/")[:120]
    clean_state="".join(ch for ch in str(state or "unknown") if ch.isalnum() or ch in "._-")[:40]
    safe.append((clean_name,clean_state))
    if name=="Compute Instance Run Command": run_command=clean_state
print("AGENT_CONFIG_PARSE=PASS")
print("AGENT_CONFIG_MANAGEMENT_DISABLED="+yn(management))
print("AGENT_CONFIG_ALL_PLUGINS_DISABLED="+yn(all_disabled))
print("AGENT_CONFIG_PLUGIN_COUNT="+str(len(safe)))
for name,state in sorted(safe): print(f"AGENT_CONFIG_PLUGIN name={name} desired={state}")
print("RUN_COMMAND_ADVERTISED="+("YES" if run_command is not None else "NO"))
print("RUN_COMMAND_DESIRED_STATE="+(run_command or "absent"))
PY

  if id -u ocarun >/dev/null 2>&1; then echo 'OCARUN_ACCOUNT_PRESENT=YES'; else echo 'OCARUN_ACCOUNT_PRESENT=NO'; fi

  python3 - <<'PY'
import os
from pathlib import Path
roots=(Path("/etc/oracle-cloud-agent"),Path("/var/snap/oracle-cloud-agent"),Path("/snap/oracle-cloud-agent/current"))
found=False
for root in roots:
    if not root.exists(): continue
    root_depth=len(root.parts)
    for current,dirs,files in os.walk(root):
        if len(Path(current).parts)-root_depth>=8: dirs[:]=[]
        if any("runcommand" in n.lower() or "run-command" in n.lower() for n in [*dirs,*files]):
            found=True; break
    if found: break
print("RUN_COMMAND_LOCAL_ARTIFACT="+("YES" if found else "NO"))
configs=(Path("/etc/oracle-cloud-agent/plugins/runcommand/config.yml"),Path("/var/snap/oracle-cloud-agent/common/etc/oracle-cloud-agent/plugins/runcommand/config.yml"))
logs=(Path("/var/log/oracle-cloud-agent/plugins/runcommand/runcommand.log"),Path("/var/snap/oracle-cloud-agent/common/log/plugins/runcommand/runcommand.log"))
print("RUN_COMMAND_CONFIG_PRESENT="+("YES" if any(p.is_file() for p in configs) else "NO"))
print("RUN_COMMAND_LOG_PRESENT="+("YES" if any(p.is_file() for p in logs) else "NO"))
count=0
for proc in Path("/proc").iterdir():
    if not proc.name.isdigit(): continue
    try: comm=(proc/"comm").read_text("utf-8",errors="replace").strip().lower()
    except Exception: continue
    if "runcommand" in comm or "run-command" in comm: count+=1
print("RUN_COMMAND_PROCESS_COUNT="+str(count))
PY
}

service_snapshot T0
state_snapshot T0
capture_snapshot T0
direct_probe T0
security_snapshot
agent_config_snapshot

echo '=== WAIT 20 SECONDS READ-ONLY ==='
sleep 20

service_snapshot T_PLUS_20S
state_snapshot T_PLUS_20S
capture_snapshot T_PLUS_20S
direct_probe T_PLUS_20S

echo '--- EXPECTED BASELINE ---'
echo 'EXPECTED_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe'
echo 'EXPECTED_ORIGIN_MAIN=43db3595a52bb2e19777a1c1c91842c06408f48b'
echo 'EXPECTED_OCA_VERSION=1.61.0-6'
echo 'EXPECTED_OCA_REVISION=126'
echo 'EXPECTED_TRACKING=latest/stable/ubuntu-24.04'
echo 'EXPECTED_HOLD=forever'
echo 'EXPECTED_CORE=117/5083155'
echo 'EXPECTED_RESIDENT=1868797/0'
echo 'EXPECTED_CAPTURE=1868796/0'
echo 'EXPECTED_SIGNER=1539554/1'
echo 'EXPECTED_DISCORD=1957840/0'

echo '=== PROD359_POST_V4_RECONCILE=COMPLETE_READ_ONLY ==='
echo 'MUTATION_COMMANDS=NONE'
echo 'SERVICE_RESTART=NO'
echo 'SNAP_MUTATION=NO'
echo 'FIREWALL_CHANGE=NO'
echo 'AGENT_CONFIG_CHANGE=NO'
echo 'RUN_COMMAND_CREATED=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'TECHNOCORE_WRITE=NO'
