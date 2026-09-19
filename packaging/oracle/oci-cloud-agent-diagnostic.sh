#!/usr/bin/env bash
# Read-only OCI Oracle Cloud Agent / Run Command diagnostic.
# Public-safe output: do not emit OCIDs, public IPs, IMDS body, raw logs, or secrets.
set -Eeuo pipefail
umask 077

IMDS_URL="http://169.254.169.254/opc/v2/instance/"
OCA_UNIT="snap.oracle-cloud-agent.oracle-cloud-agent.service"
OCA_UPDATER_UNIT="snap.oracle-cloud-agent.oracle-cloud-agent-updater.service"
META_CHAIN="TECHNOCORE_METADATA"
META_IP="169.254.169.254/32"

tmp=""
cleanup() {
  [[ -n "$tmp" && -f "$tmp" ]] && rm -f -- "$tmp"
}
trap cleanup EXIT

bool() {
  if "$@" >/dev/null 2>&1; then
    printf 'YES'
  else
    printf 'NO'
  fi
}

echo "=== OCI CLOUD AGENT READ-ONLY DIAGNOSTIC ==="

echo "--- PLATFORM / PACKAGE ---"
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  echo "OS_ID=${ID:-unknown}"
  echo "OS_VERSION=${VERSION_ID:-unknown}"
else
  echo "OS_ID=unknown"
  echo "OS_VERSION=unknown"
fi

if command -v snap >/dev/null 2>&1 && snap list oracle-cloud-agent >/dev/null 2>&1; then
  echo "OCA_SNAP_INSTALLED=YES"
  version=$(snap list oracle-cloud-agent 2>/dev/null | awk 'NR==2 {print $2; exit}')
  revision=$(snap list oracle-cloud-agent 2>/dev/null | awk 'NR==2 {print $3; exit}')
  echo "OCA_SNAP_VERSION=${version:-unknown}"
  echo "OCA_SNAP_REVISION=${revision:-unknown}"
else
  echo "OCA_SNAP_INSTALLED=NO"
  echo "OCA_SNAP_VERSION=none"
  echo "OCA_SNAP_REVISION=none"
fi

echo "--- SERVICES ---"
for unit in "$OCA_UNIT" "$OCA_UPDATER_UNIT"; do
  echo "$unit ACTIVE=$(systemctl is-active "$unit" 2>/dev/null || true) ENABLED=$(systemctl is-enabled "$unit" 2>/dev/null || true) RESULT=$(systemctl show "$unit" -p Result --value 2>/dev/null || true)"
done

service_user=$(systemctl show "$OCA_UNIT" -p User --value 2>/dev/null || true)
if [[ -z "$service_user" || "$service_user" == root ]]; then
  echo "OCA_SERVICE_USER_CLASS=root"
else
  echo "OCA_SERVICE_USER_CLASS=nonroot"
fi

echo "OCARUN_ACCOUNT_PRESENT=$(bool getent passwd ocarun)"
echo "OCA_PROCESS_COUNT=$(ps -eo comm= 2>/dev/null | awk '/oracle-cloud-agent/ {n++} END {print n+0}')"
echo "OCARUN_PROCESS_COUNT=$(ps -eo comm= 2>/dev/null | awk '$1=="ocarun" {n++} END {print n+0}')"

echo "--- METADATA FIREWALL ---"
if command -v iptables >/dev/null 2>&1; then
  echo "META_CHAIN_PRESENT=$(bool iptables -S "$META_CHAIN")"
  echo "META_OUTPUT_JUMP_PRESENT=$(bool iptables -C OUTPUT -p tcp -d "$META_IP" --dport 80 -j "$META_CHAIN")"
  echo "META_ROOT_RETURN_PRESENT=$(bool iptables -C "$META_CHAIN" -m owner --uid-owner 0 -j RETURN)"
  if signer_uid=$(id -u technocore-signer 2>/dev/null); then
    echo "META_SIGNER_RETURN_PRESENT=$(bool iptables -C "$META_CHAIN" -m owner --uid-owner "$signer_uid" -j RETURN)"
  else
    echo "META_SIGNER_RETURN_PRESENT=NO_ACCOUNT"
  fi
  echo "META_FINAL_REJECT_PRESENT=$(bool iptables -C "$META_CHAIN" -j REJECT)"
else
  echo "META_CHAIN_PRESENT=NO_IPTABLES"
fi

echo "--- IMDS ---"
tmp=$(mktemp /tmp/oca-imds.XXXXXX)
chmod 0600 "$tmp"

root_rc=0
root_code=$(curl -sS --connect-timeout 3 --max-time 5 \
  -H 'Authorization: Bearer Oracle' \
  -o "$tmp" -w '%{http_code}' "$IMDS_URL" 2>/dev/null) || root_rc=$?
echo "ROOT_IMDS_CURL_RC=$root_rc"
echo "ROOT_IMDS_HTTP=${root_code:-000}"

if [[ "$root_rc" -eq 0 && "$root_code" == "200" ]]; then
  python3 - "$tmp" <<'PY'
import json, sys
from pathlib import Path

try:
    doc=json.loads(Path(sys.argv[1]).read_text("utf-8"))
except Exception:
    print("AGENT_CONFIG_PARSE=FAIL")
    raise SystemExit(0)

cfg=doc.get("agentConfig")
if not isinstance(cfg, dict):
    print("AGENT_CONFIG_PARSE=NO_CONFIG")
    raise SystemExit(0)

def yn(value):
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "unknown"

management=cfg.get("managementDisabled")
if management is None:
    management=cfg.get("isManagementDisabled")
all_disabled=cfg.get("allPluginsDisabled")
if all_disabled is None:
    all_disabled=cfg.get("areAllPluginsDisabled")

print("AGENT_CONFIG_PARSE=PASS")
print("AGENT_CONFIG_MANAGEMENT_DISABLED="+yn(management))
print("AGENT_CONFIG_ALL_PLUGINS_DISABLED="+yn(all_disabled))

rows=cfg.get("pluginsConfig")
if not isinstance(rows, list):
    rows=[]

safe=[]
run_command=None
for row in rows:
    if not isinstance(row, dict):
        continue
    name=row.get("name")
    state=row.get("desiredState")
    if not isinstance(name, str):
        continue
    state=state if isinstance(state, str) else "unknown"
    safe.append((name, state))
    if name == "Compute Instance Run Command":
        run_command=state

print("AGENT_CONFIG_PLUGIN_COUNT="+str(len(safe)))
for name,state in sorted(safe):
    clean_name="".join(ch for ch in name if ch.isalnum() or ch in " ._-/")[:120]
    clean_state="".join(ch for ch in state if ch.isalnum() or ch in "._-")[:40]
    print(f"AGENT_CONFIG_PLUGIN name={clean_name} desired={clean_state}")
print("RUN_COMMAND_ADVERTISED="+("YES" if run_command is not None else "NO"))
print("RUN_COMMAND_DESIRED_STATE="+(run_command or "absent"))
PY
else
  echo "AGENT_CONFIG_PARSE=SKIPPED"
  echo "RUN_COMMAND_ADVERTISED=UNKNOWN"
  echo "RUN_COMMAND_DESIRED_STATE=unknown"
fi

if id -u technocore >/dev/null 2>&1; then
  tc_rc=0
  tc_code=$(sudo -u technocore curl -sS --connect-timeout 2 --max-time 3 \
    -H 'Authorization: Bearer Oracle' \
    -o /dev/null -w '%{http_code}' "$IMDS_URL" 2>/dev/null) || tc_rc=$?
  echo "TECHNOCORE_IMDS_CURL_RC=$tc_rc"
  echo "TECHNOCORE_IMDS_HTTP=${tc_code:-000}"
  if [[ "$tc_code" == "200" ]]; then
    echo "TECHNOCORE_IMDS_BLOCKED=NO"
  else
    echo "TECHNOCORE_IMDS_BLOCKED=YES"
  fi
else
  echo "TECHNOCORE_IMDS_BLOCKED=NO_ACCOUNT"
fi

rm -f -- "$tmp"
tmp=""

echo "--- CLOCK ---"
echo "NTP_SYNCHRONIZED=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
echo "SYSTEM_CLOCK_USE_UTC=$(timedatectl show -p LocalRTC --value 2>/dev/null | awk '{if ($0=="no") print "YES"; else if ($0=="yes") print "NO"; else print "UNKNOWN"}')"

echo "--- LOCAL RUN COMMAND SURFACE ---"
runcommand_local=NO
for base in \
  /etc/oracle-cloud-agent \
  /var/snap/oracle-cloud-agent \
  /snap/oracle-cloud-agent/current
do
  if [[ -e "$base" ]] && find "$base" -maxdepth 7 \( -iname '*runcommand*' -o -iname '*run-command*' \) -print -quit 2>/dev/null | grep -q .; then
    runcommand_local=YES
    break
  fi
done
echo "RUN_COMMAND_LOCAL_ARTIFACT=$runcommand_local"

config_present=NO
for path in \
  /etc/oracle-cloud-agent/plugins/runcommand/config.yml \
  /var/snap/oracle-cloud-agent/common/etc/oracle-cloud-agent/plugins/runcommand/config.yml
do
  if [[ -f "$path" ]]; then
    config_present=YES
    break
  fi
done
echo "RUN_COMMAND_CONFIG_PRESENT=$config_present"

log_present=NO
for path in \
  /var/log/oracle-cloud-agent/plugins/runcommand/runcommand.log \
  /var/snap/oracle-cloud-agent/common/log/plugins/runcommand/runcommand.log
do
  if [[ -f "$path" ]]; then
    log_present=YES
    break
  fi
done
echo "RUN_COMMAND_LOG_PRESENT=$log_present"

echo "--- ERROR CLASSIFICATION (COUNTS ONLY) ---"
{
  journalctl -u "$OCA_UNIT" -u "$OCA_UPDATER_UNIT" -n 600 --no-pager --output=cat 2>/dev/null || true
  for path in \
    /var/log/oracle-cloud-agent/plugins/runcommand/runcommand.log \
    /var/log/oracle-cloud-agent/plugins/gomon/monitoring.log \
    /var/snap/oracle-cloud-agent/common/log/plugins/runcommand/runcommand.log \
    /var/snap/oracle-cloud-agent/common/log/plugins/gomon/monitoring.log
  do
    [[ -f "$path" ]] && tail -c 262144 "$path" 2>/dev/null || true
  done
} | python3 - <<'PY'
import sys

text=sys.stdin.read().lower()
patterns={
    "metadata": ("metadata", "169.254.169.254"),
    "timeout": ("timeout", "timed out", "deadline exceeded"),
    "dns": ("no such host", "name resolution", "temporary failure in name resolution"),
    "connect": ("connection refused", "no route to host", "network is unreachable", "connection reset"),
    "tls": ("x509", "certificate", "tls handshake"),
    "auth401": ("notauthenticated", "status code: 401", "http status code: 401"),
    "auth403": ("notauthorized", "status code: 403", "http status code: 403"),
    "clock": ("clock skew", "not within allowed clock skew"),
    "runcommand": ("runcommand", "run command"),
}
for key,needles in patterns.items():
    count=sum(text.count(needle) for needle in needles)
    print(f"LOG_CLASS_{key.upper()}={count}")
PY

echo "--- DIAGNOSTIC CONCLUSION INPUTS ---"
echo "EXPECTED_SECURITY_ROOT_IMDS=200"
echo "EXPECTED_SECURITY_TECHNOCORE_IMDS_BLOCKED=YES"
echo "EXPECTED_META_ROOT_RETURN_PRESENT=YES"
echo "EXPECTED_META_FINAL_REJECT_PRESENT=YES"
echo "EXPECTED_OCA_INSTALLED=YES"
echo "EXPECTED_OCA_ACTIVE=active"
echo "EXPECTED_NTP_SYNCHRONIZED=yes"

echo "MUTATION_PERFORMED=NO"
echo "SERVICE_RESTART=NO"
echo "PACKAGE_CHANGE=NO"
echo "FIREWALL_CHANGE=NO"
echo "RUN_COMMAND_CREATED=NO"
echo "TECHNOCORE_WRITE=NO"
echo "=== OCI CLOUD AGENT DIAGNOSTIC END ==="
