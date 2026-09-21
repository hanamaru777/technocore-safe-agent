#!/usr/bin/env bash
# Independent read-only reconcile after PROD376 v1 pre-mutation STOP.
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
EXPECTED_INSTALLED_BLOB=28a53036454abf86b63a3d6571625c1440d67b71
EXPECTED_RES_PID=1868797
EXPECTED_RES_RESTARTS=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0
EXPECTED_SIG_PID=1539554
EXPECTED_SIG_RESTARTS=1
EXPECTED_DIS_PID=1957840
EXPECTED_DIS_RESTARTS=0
EXPECTED_OCA_PID=2038593
EXPECTED_OCA_RESTARTS=0
EXPECTED_UPD_PID=2038595
EXPECTED_UPD_RESTARTS=0

echo '=== PROD376 V1 POST-STOP INDEPENDENT READ-ONLY RECONCILE ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

echo '--- APPLICATION ---'
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
HEAD_VALUE=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
ORIGIN_VALUE=$(git -C "$APP" rev-parse refs/remotes/origin/main 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "GIT_OWNER=${OWNER:-UNKNOWN}"
echo "HEAD=${HEAD_VALUE:-UNAVAILABLE}"
echo "LOCAL_ORIGIN_MAIN=${ORIGIN_VALUE:-UNAVAILABLE}"
if [[ -z "$WORKTREE" ]]; then echo 'WORKTREE_CLEAN=YES'; else echo 'WORKTREE_CLEAN=NO'; fi
if [[ "$HEAD_VALUE" == "$EXPECTED_APP_HEAD" ]]; then echo 'APP_HEAD_MATCH=YES'; else echo 'APP_HEAD_MATCH=NO'; fi
if [[ "$ORIGIN_VALUE" == "$EXPECTED_LOCAL_ORIGIN" ]]; then echo 'LOCAL_ORIGIN_MATCH=YES'; else echo 'LOCAL_ORIGIN_MATCH=NO'; fi

echo '--- INSTALLED METADATA HELPER ---'
if [[ -f "$INSTALLED" ]]; then
  INSTALLED_BLOB=$(git hash-object "$INSTALLED" 2>/dev/null || true)
  INSTALLED_STAT=$(stat -c '%U:%G:%a' "$INSTALLED" 2>/dev/null || true)
  echo "INSTALLED_HELPER_BLOB=${INSTALLED_BLOB:-UNAVAILABLE}"
  echo "INSTALLED_HELPER_STAT=${INSTALLED_STAT:-UNAVAILABLE}"
  if [[ "$INSTALLED_BLOB" == "$EXPECTED_INSTALLED_BLOB" ]]; then echo 'INSTALLED_HELPER_MATCH=YES'; else echo 'INSTALLED_HELPER_MATCH=NO'; fi
else
  echo 'INSTALLED_HELPER_PRESENT=NO'
fi

echo '--- SERVICES ---'
for item in   "$RES|RESIDENT|$EXPECTED_RES_PID|$EXPECTED_RES_RESTARTS"   "$CAP|CAPTURE|$EXPECTED_CAP_PID|$EXPECTED_CAP_RESTARTS"   "$SIG|SIGNER|$EXPECTED_SIG_PID|$EXPECTED_SIG_RESTARTS"   "$DIS|DISCORD|$EXPECTED_DIS_PID|$EXPECTED_DIS_RESTARTS"   "$OCA|OCA|$EXPECTED_OCA_PID|$EXPECTED_OCA_RESTARTS"   "$UPD|OCA_UPDATER|$EXPECTED_UPD_PID|$EXPECTED_UPD_RESTARTS"
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

meta_active=$(systemctl is-active "$META_SVC" 2>/dev/null || true)
meta_enabled=$(systemctl is-enabled "$META_SVC" 2>/dev/null || true)
meta_result=$(systemctl show "$META_SVC" -p Result --value 2>/dev/null || true)
echo "SERVICE=METADATA_BLOCK ACTIVE=$meta_active ENABLED=$meta_enabled RESULT=$meta_result"

echo '--- PROTECTED CORE ---'
python3 - "$OBS" <<'PY'
import json
import pathlib
import sys
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

if iptables -C OUTPUT -p tcp -d "$META" --dport 80 -j "$CHAIN" >/dev/null 2>&1; then
  echo 'METADATA_OUTPUT_JUMP=YES'
else
  echo 'METADATA_OUTPUT_JUMP=NO'
fi

if iptables -C "$CHAIN" -m owner --uid-owner 0 -j RETURN >/dev/null 2>&1; then
  echo 'ROOT_IMDS_RETURN_RULE=YES'
else
  echo 'ROOT_IMDS_RETURN_RULE=NO'
fi

if [[ -n "$signer_uid" ]] && iptables -C "$CHAIN" -m owner --uid-owner "$signer_uid" -j RETURN >/dev/null 2>&1; then
  echo 'SIGNER_IMDS_RETURN_RULE=YES'
else
  echo 'SIGNER_IMDS_RETURN_RULE=NO'
fi

if [[ -n "$snap_uid" ]] && iptables -C "$CHAIN" -m owner --uid-owner "$snap_uid" -j RETURN >/dev/null 2>&1; then
  echo 'SNAP_DAEMON_IMDS_RETURN_RULE=YES'
else
  echo 'SNAP_DAEMON_IMDS_RETURN_RULE=NO'
fi

if iptables -C "$CHAIN" -j REJECT >/dev/null 2>&1; then
  echo 'METADATA_FINAL_REJECT=YES'
else
  echo 'METADATA_FINAL_REJECT=NO'
fi

probe() {
  label=$1
  shift
  rc=0
  code=$("$@" curl -sS --connect-timeout 2 --max-time 5     -H 'Authorization: Bearer Oracle'     -o /dev/null     -w '%{http_code}'     "$IMDS_URL" 2>/dev/null) || rc=$?
  if [[ -z "$code" ]]; then code=000; fi
  echo "${label}_IMDS_CURL_RC=$rc"
  echo "${label}_IMDS_HTTP=$code"
}

echo '--- IDENTITY IMDS PROBES ---'
probe ROOT
if id -u snap_daemon >/dev/null 2>&1; then
  probe SNAP_DAEMON sudo -n -u snap_daemon --
else
  echo 'SNAP_DAEMON_IMDS_CURL_RC=SKIPPED'
  echo 'SNAP_DAEMON_IMDS_HTTP=SKIPPED'
fi
if id -u technocore >/dev/null 2>&1; then
  probe TECHNOCORE sudo -n -u technocore --
else
  echo 'TECHNOCORE_IMDS_CURL_RC=SKIPPED'
  echo 'TECHNOCORE_IMDS_HTTP=SKIPPED'
fi

echo '--- OCA RUNTIME IDENTITY ---'
MAIN_PID=$(systemctl show "$OCA" -p MainPID --value 2>/dev/null || true)
python3 - "$MAIN_PID" <<'PY'
import pathlib,pwd,sys
try:
    pid=int(sys.argv[1])
    status=pathlib.Path(f"/proc/{pid}/status").read_text("utf-8",errors="replace")
    uid=None
    for line in status.splitlines():
        if line.startswith("Uid:"):
            uid=int(line.split()[1])
            break
    user=pwd.getpwuid(uid).pw_name if uid is not None else "UNKNOWN"
    comm=pathlib.Path(f"/proc/{pid}/comm").read_text("utf-8",errors="replace").strip()
    print("OCA_MAIN_USER="+user[:80])
    print("OCA_MAIN_COMM="+comm[:80])
except Exception as exc:
    print("OCA_MAIN_ERROR="+type(exc).__name__)
PY

echo '=== PROD376_POST_STOP_RECONCILE=COMPLETE_READ_ONLY ==='
echo 'MUTATION_COMMANDS=NONE'
echo 'HELPER_INSTALL=NO'
echo 'FIREWALL_CHANGE=NO'
echo 'SERVICE_RESTART=NO'
echo 'SNAP_MUTATION=NO'
echo 'AGENT_CONFIG_CHANGE=NO'
echo 'RUN_COMMAND_CREATED=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'TECHNOCORE_WRITE=NO'
