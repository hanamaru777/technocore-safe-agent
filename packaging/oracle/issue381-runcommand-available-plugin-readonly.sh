#!/usr/bin/env bash
# Issue #381: read-only OCI available-plugin support check for Compute Instance Run Command.
set -u
umask 077

IMDS_URL=http://169.254.169.254/opc/v2/instance/
TARGET_PLUGIN='Compute Instance Run Command'
EXPECTED_SDK=2.185.0
EXPECTED_OS_ID=ubuntu
EXPECTED_OS_VERSION=24.04
OCI_OS_NAME='Canonical Ubuntu'

TMPDIR=$(mktemp -d /tmp/issue381.XXXXXX)
cleanup() { rm -rf -- "$TMPDIR"; }
trap cleanup EXIT

echo '=== ISSUE381 OCI AVAILABLE-PLUGIN READ-ONLY CHECK ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

PYTHON=''
for candidate in   /opt/technocore-safe-agent/.venv/bin/python   /usr/bin/python3
do
  if [[ -x "$candidate" ]]; then
    if "$candidate" - <<'PY' >/dev/null 2>&1
import oci
from oci.compute_instance_agent import PluginconfigClient
from oci.auth.signers import InstancePrincipalsSecurityTokenSigner
PY
    then
      PYTHON=$candidate
      break
    fi
  fi
done

if [[ -z "$PYTHON" ]]; then
  echo 'OCI_PYTHON_SDK_PRESENT=NO'
  echo 'CONTROL_PLANE_PROBE=UNAVAILABLE_NO_EXISTING_SDK'
  echo 'PACKAGE_INSTALL=NO'
  echo 'MUTATION_COMMANDS=NONE'
  echo 'PLUGIN_ENABLE=NO'
  echo 'RUN_COMMAND_CREATED=NO'
  echo 'SERVICE_RESTART=NO'
  exit 0
fi

SDK_VERSION=$("$PYTHON" - <<'PY'
import oci
print(getattr(oci, "__version__", "UNKNOWN"))
PY
)
echo 'OCI_PYTHON_SDK_PRESENT=YES'
echo "OCI_PYTHON_SDK_VERSION=$SDK_VERSION"
if [[ "$SDK_VERSION" != "$EXPECTED_SDK" ]]; then
  echo 'CONTROL_PLANE_PROBE=STOP:unexpected_sdk_version'
  echo 'PACKAGE_INSTALL=NO'
  echo 'MUTATION_COMMANDS=NONE'
  echo 'PLUGIN_ENABLE=NO'
  echo 'RUN_COMMAND_CREATED=NO'
  echo 'SERVICE_RESTART=NO'
  exit 0
fi

echo '--- OS SELECTOR ---'
OS_ID=$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print $2}' /etc/os-release 2>/dev/null || true)
OS_VERSION=$(awk -F= '$1=="VERSION_ID"{gsub(/"/,"",$2); print $2}' /etc/os-release 2>/dev/null || true)
echo "LOCAL_OS_ID=${OS_ID:-UNKNOWN}"
echo "LOCAL_OS_VERSION=${OS_VERSION:-UNKNOWN}"
if [[ "$OS_ID" != "$EXPECTED_OS_ID" || "$OS_VERSION" != "$EXPECTED_OS_VERSION" ]]; then
  echo 'CONTROL_PLANE_PROBE=STOP:unexpected_local_os'
  echo 'PACKAGE_INSTALL=NO'
  echo 'MUTATION_COMMANDS=NONE'
  echo 'PLUGIN_ENABLE=NO'
  echo 'RUN_COMMAND_CREATED=NO'
  echo 'SERVICE_RESTART=NO'
  exit 0
fi
echo "OCI_OS_SELECTOR_NAME=$OCI_OS_NAME"
echo "OCI_OS_SELECTOR_VERSION=$EXPECTED_OS_VERSION"

echo '--- IMDS ---'
IMDS_CODE=$(curl -sS --connect-timeout 3 --max-time 5   -H 'Authorization: Bearer Oracle'   -o "$TMPDIR/imds.json"   -w '%{http_code}' "$IMDS_URL" 2>/dev/null || true)
if [[ -z "$IMDS_CODE" ]]; then IMDS_CODE=000; fi
echo "ROOT_IMDS_HTTP=$IMDS_CODE"
if [[ "$IMDS_CODE" != 200 ]]; then
  echo 'CONTROL_PLANE_PROBE=STOP:root_imds_not_200'
  echo 'PACKAGE_INSTALL=NO'
  echo 'MUTATION_COMMANDS=NONE'
  echo 'PLUGIN_ENABLE=NO'
  echo 'RUN_COMMAND_CREATED=NO'
  echo 'SERVICE_RESTART=NO'
  exit 0
fi

echo '--- AVAILABLE PLUGIN API ---'
"$PYTHON" - "$TMPDIR/imds.json" "$OCI_OS_NAME" "$EXPECTED_OS_VERSION" "$TARGET_PLUGIN" <<'PY'
import json
import pathlib
import sys

import oci
from oci.auth.signers import InstancePrincipalsSecurityTokenSigner
from oci.compute_instance_agent import PluginconfigClient
from oci.exceptions import ServiceError
from oci.retry import NoneRetryStrategy

imds_path = pathlib.Path(sys.argv[1])
os_name = sys.argv[2]
os_version = sys.argv[3]
plugin_name = sys.argv[4]

def classify(exc):
    if isinstance(exc, ServiceError):
        status = int(getattr(exc, "status", 0) or 0)
        code = str(getattr(exc, "code", "") or "")
        if status in (401, 403) or code in ("NotAuthorized", "NotAuthenticated", "NotAuthorizedOrNotFound"):
            return "AUTHORIZATION", status, code or "UNKNOWN"
        if status == 404:
            return "NOT_FOUND", status, code or "UNKNOWN"
        if status in (408, 429, 500, 502, 503, 504):
            return "TRANSIENT_SERVICE", status, code or "UNKNOWN"
        return "SERVICE_OTHER", status, code or "UNKNOWN"
    name = type(exc).__name__
    lower = (name + " " + str(exc)).lower()
    if "instanceprincipal" in lower or "federation" in lower or "securitytoken" in lower:
        return "INSTANCE_PRINCIPAL", 0, name
    if "timeout" in lower or "connection" in lower or "network" in lower:
        return "NETWORK", 0, name
    return "OTHER", 0, name

try:
    doc = json.loads(imds_path.read_text("utf-8"))
except Exception as exc:
    print("CONTROL_PLANE_CALL=FAIL")
    print("CONTROL_PLANE_ERROR_CLASS=IMDS_PARSE")
    print("CONTROL_PLANE_ERROR_TYPE=" + type(exc).__name__)
    raise SystemExit(0)

compartment_id = doc.get("compartmentId")
region = doc.get("region") or doc.get("canonicalRegionName")
if not isinstance(compartment_id, str) or not compartment_id:
    print("CONTROL_PLANE_CALL=FAIL")
    print("CONTROL_PLANE_ERROR_CLASS=IMDS_NO_COMPARTMENT")
    raise SystemExit(0)
if not isinstance(region, str) or not region:
    print("CONTROL_PLANE_CALL=FAIL")
    print("CONTROL_PLANE_ERROR_CLASS=IMDS_NO_REGION")
    raise SystemExit(0)

try:
    signer = InstancePrincipalsSecurityTokenSigner()
    client = PluginconfigClient(
        {"region": region},
        signer=signer,
        timeout=(5, 15),
        retry_strategy=NoneRetryStrategy(),
    )
    response = client.list_instanceagent_available_plugins(
        compartment_id,
        os_name,
        os_version,
        name=plugin_name,
        retry_strategy=NoneRetryStrategy(),
    )
except Exception as exc:
    error_class, status, code = classify(exc)
    print("CONTROL_PLANE_CALL=FAIL")
    print("CONTROL_PLANE_ERROR_CLASS=" + error_class)
    if status:
        print("CONTROL_PLANE_HTTP_STATUS=" + str(status))
    print("CONTROL_PLANE_ERROR_CODE=" + str(code)[:120])
    raise SystemExit(0)

rows = list(getattr(response, "data", None) or [])
print("CONTROL_PLANE_CALL=PASS")
print("AVAILABLE_PLUGIN_MATCHES=" + str(len(rows)))

for row in rows[:5]:
    name = str(getattr(row, "name", "") or "")
    supported = getattr(row, "is_supported", None)
    enabled = getattr(row, "is_enabled_by_default", None)
    safe_name = "".join(ch for ch in name if ch.isalnum() or ch in " ._-/")[:120]
    print("AVAILABLE_PLUGIN_NAME=" + safe_name)
    print("AVAILABLE_PLUGIN_SUPPORTED=" + ("true" if supported is True else "false" if supported is False else "unknown"))
    print("AVAILABLE_PLUGIN_ENABLED_BY_DEFAULT=" + ("true" if enabled is True else "false" if enabled is False else "unknown"))

if len(rows) == 0:
    print("RUN_COMMAND_AVAILABLE_RESULT=ABSENT")
elif len(rows) == 1:
    supported = getattr(rows[0], "is_supported", None)
    if supported is True:
        print("RUN_COMMAND_AVAILABLE_RESULT=SUPPORTED")
    elif supported is False:
        print("RUN_COMMAND_AVAILABLE_RESULT=NOT_SUPPORTED")
    else:
        print("RUN_COMMAND_AVAILABLE_RESULT=UNKNOWN")
else:
    print("RUN_COMMAND_AVAILABLE_RESULT=AMBIGUOUS_MULTIPLE")
PY

echo '--- SAFETY TAIL ---'
echo 'PACKAGE_INSTALL=NO'
echo 'MUTATION_COMMANDS=NONE'
echo 'AGENT_CONFIG_CHANGE=NO'
echo 'IAM_CHANGE=NO'
echo 'PLUGIN_ENABLE=NO'
echo 'RUN_COMMAND_CREATED=NO'
echo 'SERVICE_RESTART=NO'
echo 'SNAP_MUTATION=NO'
echo 'OCID_OUTPUT=NO'
echo 'RAW_OCI_ERROR_OUTPUT=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo '=== ISSUE381_AVAILABLE_PLUGIN_CHECK=COMPLETE_READ_ONLY ==='
