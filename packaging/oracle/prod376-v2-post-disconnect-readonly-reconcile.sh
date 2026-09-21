#!/usr/bin/env bash
# Independent read-only reconcile after PROD376 v2 hard-gate PASS + SSH disconnect.
set -u
umask 077

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
INSTALLED=/usr/local/libexec/technocore-safe-agent-block-metadata
CHAIN=TECHNOCORE_METADATA
META=169.254.169.254/32
IMDS_URL=http://169.254.169.254/opc/v2/instance/

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service
META_SVC=technocore-safe-agent-metadata-block.service
OCA=snap.oracle-cloud-agent.oracle-cloud-agent.service
UPD=snap.oracle-cloud-agent.oracle-cloud-agent-updater.service

EXPECTED_APP_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe
EXPECTED_LOCAL_ORIGIN=43db3595a52bb2e19777a1c1c91842c06408f48b
EXPECTED_INSTALLED_BLOB=a21ac47654bc3c49598954e5915af6936628f6d7
EXPECTED_CORE_EVENTS=117
EXPECTED_CORE_MESSAGES=5083155
EXPECTED_OCA_VERSION=1.61.0-6
EXPECTED_OCA_REVISION=126

EXPECTED_RES_PID=1868797
EXPECTED_RES_RESTARTS=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0
EXPECTED_SIG_PID=1539554
EXPECTED_SIG_RESTARTS=1
EXPECTED_DIS_PID=1957840
EXPECTED_DIS_RESTARTS=0

TMPDIR=$(mktemp -d /tmp/prod376-v2-reconcile.XXXXXX)
cleanup() { rm -rf -- "$TMPDIR"; }
trap cleanup EXIT

echo '=== PROD376 V2 POST-DISCONNECT INDEPENDENT READ-ONLY RECONCILE ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

echo '--- APPLICATION / INSTALLED HELPER ---'
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
HEAD_VALUE=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
ORIGIN_VALUE=$(git -C "$APP" rev-parse refs/remotes/origin/main 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
INSTALLED_BLOB=$(git hash-object "$INSTALLED" 2>/dev/null || true)
INSTALLED_STAT=$(stat -c '%U:%G:%a' "$INSTALLED" 2>/dev/null || true)

echo "GIT_OWNER=${OWNER:-UNKNOWN}"
echo "HEAD=${HEAD_VALUE:-UNAVAILABLE}"
echo "LOCAL_ORIGIN_MAIN=${ORIGIN_VALUE:-UNAVAILABLE}"
if [[ -z "$WORKTREE" ]]; then echo 'WORKTREE_CLEAN=YES'; else echo 'WORKTREE_CLEAN=NO'; fi
if [[ "$HEAD_VALUE" == "$EXPECTED_APP_HEAD" ]]; then echo 'APP_HEAD_MATCH=YES'; else echo 'APP_HEAD_MATCH=NO'; fi
if [[ "$ORIGIN_VALUE" == "$EXPECTED_LOCAL_ORIGIN" ]]; then echo 'LOCAL_ORIGIN_MATCH=YES'; else echo 'LOCAL_ORIGIN_MATCH=NO'; fi
echo "INSTALLED_HELPER_BLOB=${INSTALLED_BLOB:-UNAVAILABLE}"
echo "INSTALLED_HELPER_STAT=${INSTALLED_STAT:-UNAVAILABLE}"
if [[ "$INSTALLED_BLOB" == "$EXPECTED_INSTALLED_BLOB" ]]; then echo 'INSTALLED_HELPER_MATCH=YES'; else echo 'INSTALLED_HELPER_MATCH=NO'; fi

echo '--- SERVICES ---'
for item in   "$RES|RESIDENT|$EXPECTED_RES_PID|$EXPECTED_RES_RESTARTS"   "$CAP|CAPTURE|$EXPECTED_CAP_PID|$EXPECTED_CAP_RESTARTS"   "$SIG|SIGNER|$EXPECTED_SIG_PID|$EXPECTED_SIG_RESTARTS"   "$DIS|DISCORD|$EXPECTED_DIS_PID|$EXPECTED_DIS_RESTARTS"
do
  IFS='|' read -r svc label expected_pid expected_restarts <<<"$item"
  active=$(systemctl is-active "$svc" 2>/dev/null || true)
  pid=$(systemctl show "$svc" -p MainPID --value 2>/dev/null || true)
  restarts=$(systemctl show "$svc" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$svc" -p Result --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active PID=$pid NRESTARTS=$restarts RESULT=$result"
  if [[ "$pid" == "$expected_pid" && "$restarts" == "$expected_restarts" ]]; then
    echo "SERVICE_BASELINE_$label=YES"
  else
    echo "SERVICE_BASELINE_$label=NO"
  fi
done

for item in "$OCA|OCA" "$UPD|OCA_UPDATER"; do
  IFS='|' read -r svc label <<<"$item"
  active=$(systemctl is-active "$svc" 2>/dev/null || true)
  pid=$(systemctl show "$svc" -p MainPID --value 2>/dev/null || true)
  restarts=$(systemctl show "$svc" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$svc" -p Result --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active PID=$pid NRESTARTS=$restarts RESULT=$result"
done

meta_active=$(systemctl is-active "$META_SVC" 2>/dev/null || true)
meta_enabled=$(systemctl is-enabled "$META_SVC" 2>/dev/null || true)
meta_result=$(systemctl show "$META_SVC" -p Result --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$meta_active ENABLED=$meta_enabled RESULT=$meta_result"

echo '--- OCA VERSION / RUNTIME SCOPE ---'
snap list oracle-cloud-agent >"$TMPDIR/snap.txt" 2>/dev/null || true
python3 - "$TMPDIR/snap.txt" <<'PY'
from pathlib import Path
import sys
rows=[line.split() for line in Path(sys.argv[1]).read_text("utf-8",errors="replace").splitlines() if line.strip()]
if len(rows)>=2 and len(rows[1])>=3:
    print("OCA_VERSION="+rows[1][1])
    print("OCA_REVISION="+rows[1][2])
    print("OCA_VERSION_MATCH="+("YES" if rows[1][1]=="1.61.0-6" and rows[1][2]=="126" else "NO"))
else:
    print("OCA_VERSION=UNAVAILABLE")
    print("OCA_REVISION=UNAVAILABLE")
    print("OCA_VERSION_MATCH=NO")
PY

python3 - "$(systemctl show "$OCA" -p MainPID --value 2>/dev/null || true)" <<'PY'
import pathlib,pwd,sys
try:
    pid=int(sys.argv[1])
    status=pathlib.Path(f"/proc/{pid}/status").read_text("utf-8",errors="replace")
    uid=None
    for line in status.splitlines():
        if line.startswith("Uid:"):
            uid=int(line.split()[1]); break
    user=pwd.getpwuid(uid).pw_name if uid is not None else "UNKNOWN"
    comm=pathlib.Path(f"/proc/{pid}/comm").read_text("utf-8",errors="replace").strip()
    print("OCA_MAIN_USER="+user[:80])
    print("OCA_MAIN_COMM="+comm[:80])
except Exception as exc:
    print("OCA_MAIN_ERROR="+type(exc).__name__)
PY

python3 - <<'PY'
import pathlib,pwd
try:
    uid=pwd.getpwnam("snap_daemon").pw_uid
except KeyError:
    print("SNAP_DAEMON_PROCESS_COUNT=0")
    print("SNAP_DAEMON_PROCESS_SCOPE=NO_ACCOUNT")
    raise SystemExit
names=[]
for proc in pathlib.Path("/proc").iterdir():
    if not proc.name.isdigit(): continue
    try:
        status=(proc/"status").read_text("utf-8",errors="replace")
        euid=None
        for line in status.splitlines():
            if line.startswith("Uid:"):
                euid=int(line.split()[2]); break
        if euid != uid: continue
        names.append((proc/"comm").read_text("utf-8",errors="replace").strip())
    except Exception:
        continue
names=sorted(names)
print("SNAP_DAEMON_PROCESS_COUNT="+str(len(names)))
print("SNAP_DAEMON_PROCESS_COMMS="+",".join(names))
print("SNAP_DAEMON_PROCESS_SCOPE="+("PASS" if names==["agent","updater"] else "CHANGED"))
PY

echo '--- PROTECTED CORE ---'
python3 - "$OBS" <<'PY'
import json,pathlib,sys
try:
    data=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
except Exception as exc:
    print("CORE_READ_ERROR="+type(exc).__name__)
    raise SystemExit
metrics=data.get("metrics") or {}
events=metrics.get("unrecoverable_core_gap_events","MISSING")
messages=metrics.get("unrecoverable_core_gap_messages","MISSING")
print(f"CORE_EVENTS={events}")
print(f"CORE_MESSAGES={messages}")
print("CORE_MATCH="+("YES" if str(events)=="117" and str(messages)=="5083155" else "NO"))
PY

echo '--- FIREWALL ---'
signer_uid=$(id -u technocore-signer 2>/dev/null || true)
snap_uid=$(id -u snap_daemon 2>/dev/null || true)
if iptables -C OUTPUT -p tcp -d "$META" --dport 80 -j "$CHAIN" >/dev/null 2>&1; then echo 'METADATA_OUTPUT_JUMP=YES'; else echo 'METADATA_OUTPUT_JUMP=NO'; fi
if iptables -C "$CHAIN" -m owner --uid-owner 0 -j RETURN >/dev/null 2>&1; then echo 'ROOT_IMDS_RETURN_RULE=YES'; else echo 'ROOT_IMDS_RETURN_RULE=NO'; fi
if [[ -n "$signer_uid" ]] && iptables -C "$CHAIN" -m owner --uid-owner "$signer_uid" -j RETURN >/dev/null 2>&1; then echo 'SIGNER_IMDS_RETURN_RULE=YES'; else echo 'SIGNER_IMDS_RETURN_RULE=NO'; fi
if [[ -n "$snap_uid" ]] && iptables -C "$CHAIN" -m owner --uid-owner "$snap_uid" -j RETURN >/dev/null 2>&1; then echo 'SNAP_DAEMON_IMDS_RETURN_RULE=YES'; else echo 'SNAP_DAEMON_IMDS_RETURN_RULE=NO'; fi
if iptables -C "$CHAIN" -j REJECT >/dev/null 2>&1; then echo 'METADATA_FINAL_REJECT=YES'; else echo 'METADATA_FINAL_REJECT=NO'; fi

probe() {
  label=$1
  shift
  rc=0
  code=$("$@" curl -sS --connect-timeout 2 --max-time 5 -H 'Authorization: Bearer Oracle' -o /dev/null -w '%{http_code}' "$IMDS_URL" 2>/dev/null) || rc=$?
  if [[ -z "$code" ]]; then code=000; fi
  echo "${label}_IMDS_CURL_RC=$rc"
  echo "${label}_IMDS_HTTP=$code"
}

echo '--- IDENTITY IMDS PROBES ---'
probe ROOT
probe SNAP_DAEMON sudo -n -u snap_daemon --
probe TECHNOCORE sudo -n -u technocore --

echo '--- AGENT CONFIG / RUN COMMAND CURRENT ---'
root_code=$(curl -sS --connect-timeout 3 --max-time 5 -H 'Authorization: Bearer Oracle' -o "$TMPDIR/imds.json" -w '%{http_code}' "$IMDS_URL" 2>/dev/null || true)
if [[ -z "$root_code" ]]; then root_code=000; fi
echo "ROOT_AGENT_CONFIG_HTTP=$root_code"
python3 - "$TMPDIR/imds.json" <<'PY'
import json,pathlib,sys
path=pathlib.Path(sys.argv[1])
try:
    doc=json.loads(path.read_text("utf-8"))
except Exception:
    print("AGENT_CONFIG_PARSE=FAIL")
    print("RUN_COMMAND_ADVERTISED=UNKNOWN")
    print("RUN_COMMAND_DESIRED_STATE=unknown")
    raise SystemExit
cfg=doc.get("agentConfig")
if not isinstance(cfg,dict):
    print("AGENT_CONFIG_PARSE=NO_CONFIG")
    print("RUN_COMMAND_ADVERTISED=UNKNOWN")
    print("RUN_COMMAND_DESIRED_STATE=unknown")
    raise SystemExit
rows=cfg.get("pluginsConfig")
rows=rows if isinstance(rows,list) else []
run=None
for row in rows:
    if not isinstance(row,dict): continue
    if row.get("name")=="Compute Instance Run Command":
        run=str(row.get("desiredState","UNKNOWN"))
        break
print("AGENT_CONFIG_PARSE=PASS")
print("AGENT_CONFIG_PLUGIN_COUNT="+str(len(rows)))
print("RUN_COMMAND_ADVERTISED="+("YES" if run is not None else "NO"))
print("RUN_COMMAND_DESIRED_STATE="+(run or "absent"))
PY

if id -u ocarun >/dev/null 2>&1; then echo 'OCARUN_ACCOUNT_PRESENT=YES'; else echo 'OCARUN_ACCOUNT_PRESENT=NO'; fi
python3 - <<'PY'
import os
from pathlib import Path
roots=(Path("/etc/oracle-cloud-agent"),Path("/var/snap/oracle-cloud-agent"),Path("/snap/oracle-cloud-agent/current"))
found=False
for root in roots:
    if not root.exists(): continue
    depth=len(root.parts)
    for current,dirs,files in os.walk(root):
        if len(Path(current).parts)-depth>=8:
            dirs[:]=[]
        if any("runcommand" in n.lower() or "run-command" in n.lower() for n in [*dirs,*files]):
            found=True
            break
    if found: break
configs=(Path("/etc/oracle-cloud-agent/plugins/runcommand/config.yml"),Path("/var/snap/oracle-cloud-agent/common/etc/oracle-cloud-agent/plugins/runcommand/config.yml"))
logs=(Path("/var/log/oracle-cloud-agent/plugins/runcommand/runcommand.log"),Path("/var/snap/oracle-cloud-agent/common/log/plugins/runcommand/runcommand.log"))
count=0
for proc in Path("/proc").iterdir():
    if not proc.name.isdigit(): continue
    try: comm=(proc/"comm").read_text("utf-8",errors="replace").strip().lower()
    except Exception: continue
    if "runcommand" in comm or "run-command" in comm: count+=1
print("RUN_COMMAND_LOCAL_ARTIFACT="+("YES" if found else "NO"))
print("RUN_COMMAND_CONFIG_PRESENT="+("YES" if any(p.is_file() for p in configs) else "NO"))
print("RUN_COMMAND_LOG_PRESENT="+("YES" if any(p.is_file() for p in logs) else "NO"))
print("RUN_COMMAND_PROCESS_COUNT="+str(count))
PY

echo '--- OCA LOG CLASSIFICATION SINCE REPAIR WINDOW ---'
journalctl -u "$OCA" -u "$UPD" --since '2026-09-21 07:24:00 UTC' --no-pager --output=cat >"$TMPDIR/oca.log" 2>/dev/null || true
python3 - "$TMPDIR/oca.log" <<'PY'
import pathlib,sys
text=pathlib.Path(sys.argv[1]).read_text("utf-8",errors="replace").lower()
patterns={
    "AUTH_401":("status code: 401","http status code: 401","notauthenticated"),
    "AUTH_403":("status code: 403","http status code: 403","notauthorized"),
    "HTTP_5XX":("status code: 500","status code: 502","status code: 503","status code: 504"),
    "TIMEOUT":("timeout","timed out","deadline exceeded"),
    "CONNECT":("connection refused","no route to host","network is unreachable","connection reset"),
    "TLS":("x509","tls handshake","certificate verify"),
    "SUCCESS_200":("status: 200","status 200","200 ok"),
    "RUNCOMMAND":("runcommand","run command"),
}
for label,needles in patterns.items():
    print("POST_REPAIR_LOG_CLASS_"+label+"="+str(sum(text.count(n) for n in needles)))
PY

echo '=== PROD376_V2_POST_DISCONNECT_RECONCILE=COMPLETE_READ_ONLY ==='
echo 'MUTATION_COMMANDS=NONE'
echo 'HELPER_INSTALL=NO'
echo 'FIREWALL_CHANGE=NO'
echo 'SERVICE_RESTART=NO'
echo 'SNAP_MUTATION=NO'
echo 'AGENT_CONFIG_CHANGE=NO'
echo 'RUN_COMMAND_CREATED=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'RAW_LOG_OUTPUT=NO'
echo 'TECHNOCORE_WRITE=NO'
