#!/usr/bin/env bash
# Issue #371: prove whether the actual Oracle Cloud Agent runtime UID can reach IMDS.
# Read-only. Never prints IMDS body, UID numbers, OCIDs, IPs, or raw logs.
set -u
umask 077

OCA=snap.oracle-cloud-agent.oracle-cloud-agent.service
CHAIN=TECHNOCORE_METADATA
IMDS_URL=http://169.254.169.254/opc/v2/instance/

echo '=== ISSUE371 OCA RUNTIME-USER IMDS READ-ONLY PROOF ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

MAIN_PID=$(systemctl show "$OCA" -p MainPID --value 2>/dev/null || true)

python3 - "$MAIN_PID" <<'PY'
import pathlib,pwd,sys
try:
    pid=int(sys.argv[1])
except Exception:
    print("OCA_MAIN_PROCESS=UNAVAILABLE")
    raise SystemExit
try:
    status=pathlib.Path(f"/proc/{pid}/status").read_text("utf-8",errors="replace")
    uid=None
    for line in status.splitlines():
        if line.startswith("Uid:"):
            uid=int(line.split()[1])
            break
    user=pwd.getpwuid(uid).pw_name if uid is not None else "UNKNOWN"
    comm=pathlib.Path(f"/proc/{pid}/comm").read_text("utf-8",errors="replace").strip()
    print("OCA_MAIN_PROCESS=FOUND")
    print("OCA_MAIN_USER="+user[:80])
    print("OCA_MAIN_COMM="+comm[:80])
except Exception as exc:
    print("OCA_MAIN_PROCESS_ERROR="+type(exc).__name__)
PY

if id -u snap_daemon >/dev/null 2>&1; then
  echo 'SNAP_DAEMON_ACCOUNT_PRESENT=YES'
  SNAP_UID=$(id -u snap_daemon)
else
  echo 'SNAP_DAEMON_ACCOUNT_PRESENT=NO'
  SNAP_UID=''
fi

echo '--- SNAP_DAEMON PROCESS INVENTORY ---'
python3 - <<'PY'
import pathlib,pwd
try:
    uid=pwd.getpwnam("snap_daemon").pw_uid
except KeyError:
    print("SNAP_DAEMON_PROCESS_COUNT=0")
    raise SystemExit
names=[]
for proc in pathlib.Path("/proc").iterdir():
    if not proc.name.isdigit():
        continue
    try:
        status=(proc/"status").read_text("utf-8",errors="replace")
        euid=None
        for line in status.splitlines():
            if line.startswith("Uid:"):
                parts=line.split()
                euid=int(parts[2])
                break
        if euid != uid:
            continue
        comm=(proc/"comm").read_text("utf-8",errors="replace").strip()
        if comm:
            names.append(comm[:80])
    except Exception:
        continue
print("SNAP_DAEMON_PROCESS_COUNT="+str(len(names)))
for name in sorted(set(names)):
    print("SNAP_DAEMON_PROCESS_COMM="+name)
PY

echo '--- METADATA FIREWALL MATCHES ---'
if [[ -n "$SNAP_UID" ]] && iptables -C "$CHAIN" -m owner --uid-owner "$SNAP_UID" -j RETURN >/dev/null 2>&1; then
  echo 'SNAP_DAEMON_IMDS_RETURN_RULE=YES'
else
  echo 'SNAP_DAEMON_IMDS_RETURN_RULE=NO'
fi

if iptables -C "$CHAIN" -m owner --uid-owner 0 -j RETURN >/dev/null 2>&1; then
  echo 'ROOT_IMDS_RETURN_RULE=YES'
else
  echo 'ROOT_IMDS_RETURN_RULE=NO'
fi

if signer_uid=$(id -u technocore-signer 2>/dev/null); then
  if iptables -C "$CHAIN" -m owner --uid-owner "$signer_uid" -j RETURN >/dev/null 2>&1; then
    echo 'SIGNER_IMDS_RETURN_RULE=YES'
  else
    echo 'SIGNER_IMDS_RETURN_RULE=NO'
  fi
else
  echo 'SIGNER_IMDS_RETURN_RULE=NO_ACCOUNT'
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
  code=$("$@" curl -sS --connect-timeout 2 --max-time 4     -H 'Authorization: Bearer Oracle'     -o /dev/null     -w '%{http_code}'     "$IMDS_URL" 2>/dev/null) || rc=$?
  echo "${label}_IMDS_CURL_RC=$rc"
  echo "${label}_IMDS_HTTP=${code:-000}"
}

echo '--- SAME-IDENTITY IMDS PROBES ---'
probe ROOT

if [[ -n "$SNAP_UID" ]]; then
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

echo '--- SAFETY TAIL ---'
echo 'MUTATION_COMMANDS=NONE'
echo 'SERVICE_RESTART=NO'
echo 'FIREWALL_CHANGE=NO'
echo 'NETWORK_CHANGE=NO'
echo 'AGENT_CONFIG_CHANGE=NO'
echo 'RUN_COMMAND_CREATED=NO'
echo 'PACKAGE_INSTALL=NO'
echo 'IMDS_BODY_OUTPUT=NO'
echo 'UID_NUMBER_OUTPUT=NO'
echo 'OCID_OUTPUT=NO'
echo 'IP_OUTPUT=NO'
echo '=== ISSUE371_IMDS_RUNTIME_USER_PROOF=COMPLETE_READ_ONLY ==='
