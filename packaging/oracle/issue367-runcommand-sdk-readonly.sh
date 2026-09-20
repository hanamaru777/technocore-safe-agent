#!/usr/bin/env bash
# Read-only OCI SDK fallback probe for Compute Instance Run Command plugin state.
# Never installs packages and never prints OCIDs, IMDS body, credentials, or raw OCI errors.
set -u
umask 077

APP=/opt/technocore-safe-agent
IMDS_URL=http://169.254.169.254/opc/v2/instance/
PLUGIN_NAME='Compute Instance Run Command'

TMPDIR=$(mktemp -d /tmp/issue367-sdk.XXXXXX)
cleanup() {
  rm -rf -- "$TMPDIR"
}
trap cleanup EXIT

echo '=== ISSUE367 OCI SDK READ-ONLY FALLBACK ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

PYTHON_BIN=""
for candidate in "$APP/.venv/bin/python" /usr/bin/python3 "$(command -v python3 2>/dev/null || true)"; do
  [[ -n "$candidate" && -x "$candidate" ]] || continue
  if "$candidate" - <<'PY' >/dev/null 2>&1
import oci
from oci.compute_instance_agent import PluginClient
from oci.auth.signers import InstancePrincipalsSecurityTokenSigner
PY
  then
    PYTHON_BIN="$candidate"
    break
  fi
done

if [[ -z "$PYTHON_BIN" ]]; then
  echo 'OCI_PYTHON_SDK_PRESENT=NO'
  echo 'CONTROL_PLANE_PROBE=UNAVAILABLE_NO_EXISTING_SDK'
  echo 'PACKAGE_INSTALL=NO'
  echo 'MUTATION_COMMANDS=NONE'
  echo 'AGENT_CONFIG_CHANGE=NO'
  echo 'PLUGIN_ENABLE=NO'
  echo 'RUN_COMMAND_CREATED=NO'
  echo 'SERVICE_RESTART=NO'
  exit 0
fi

echo 'OCI_PYTHON_SDK_PRESENT=YES'
SDK_VERSION=$("$PYTHON_BIN" - <<'PY'
import oci
print(getattr(oci, "__version__", "UNKNOWN"))
PY
)
echo "OCI_PYTHON_SDK_VERSION=${SDK_VERSION:-UNKNOWN}"

IMDS_CODE=$(curl -sS --connect-timeout 3 --max-time 5   -H 'Authorization: Bearer Oracle'   -o "$TMPDIR/imds.json"   -w '%{http_code}'   "$IMDS_URL" 2>/dev/null || true)

echo "ROOT_IMDS_HTTP=${IMDS_CODE:-000}"

if [[ "$IMDS_CODE" != "200" ]]; then
  echo 'CONTROL_PLANE_PROBE=UNAVAILABLE_IMDS'
  echo 'PACKAGE_INSTALL=NO'
  echo 'MUTATION_COMMANDS=NONE'
  echo 'AGENT_CONFIG_CHANGE=NO'
  echo 'PLUGIN_ENABLE=NO'
  echo 'RUN_COMMAND_CREATED=NO'
  echo 'SERVICE_RESTART=NO'
  exit 0
fi

"$PYTHON_BIN" - "$TMPDIR/imds.json" "$PLUGIN_NAME" <<'PY'
import json
import pathlib
import re
import sys

import oci
from oci.auth.signers import InstancePrincipalsSecurityTokenSigner
from oci.compute_instance_agent import PluginClient

source=pathlib.Path(sys.argv[1])
plugin_name=sys.argv[2]

def clean(value, allowed=" ._-/+:TZ"):
    text=str(value if value is not None else "UNKNOWN")
    return "".join(ch for ch in text if ch.isalnum() or ch in allowed)[:160]

try:
    doc=json.loads(source.read_text("utf-8"))
except Exception:
    print("CONTROL_PLANE_PARSE=IMDS_JSON_FAIL")
    raise SystemExit(0)

instance_id=doc.get("id")
compartment_id=doc.get("compartmentId")
region=doc.get("region") or doc.get("canonicalRegionName")

if not all(isinstance(v,str) and v for v in (instance_id,compartment_id,region)):
    print("CONTROL_PLANE_PARSE=IMDS_IDENTIFIER_MISSING")
    raise SystemExit(0)

try:
    signer=InstancePrincipalsSecurityTokenSigner()
    client=PluginClient(
        {"region": region},
        signer=signer,
        timeout=(5, 15),
        retry_strategy=oci.retry.NoneRetryStrategy(),
    )
    response=client.list_instance_agent_plugins(
        compartment_id,
        instance_id,
        name=plugin_name,
        retry_strategy=oci.retry.NoneRetryStrategy(),
    )
except Exception as exc:
    status=getattr(exc,"status",None)
    code=getattr(exc,"code",None)
    if status in (401,403):
        cls="AUTHORIZATION"
    elif status == 404:
        cls="NOT_FOUND"
    elif status in (408,429,500,502,503,504):
        cls="TRANSIENT_SERVICE"
    elif type(exc).__name__ in ("ConnectTimeout","ReadTimeout","ConnectionError","TimeoutError"):
        cls="NETWORK"
    elif "InstancePrincipals" in type(exc).__name__ or "Federation" in type(exc).__name__:
        cls="INSTANCE_PRINCIPAL"
    else:
        cls="OTHER"
    print("CONTROL_PLANE_CALL=FAIL")
    print("CONTROL_PLANE_ERROR_CLASS="+cls)
    print("CONTROL_PLANE_HTTP_STATUS="+clean(status))
    print("CONTROL_PLANE_ERROR_CODE="+clean(code))
    raise SystemExit(0)

rows=response.data if isinstance(response.data,list) else []
safe=[]
for row in rows:
    name=getattr(row,"name",None)
    status=getattr(row,"status",None)
    updated=getattr(row,"time_last_updated_utc",None)
    if not isinstance(name,str):
        continue
    safe.append((clean(name),clean(status),clean(updated)))

print("CONTROL_PLANE_CALL=PASS")
print("RUN_COMMAND_PLUGIN_MATCHES="+str(len(safe)))
for name,status,updated in safe:
    print(f"RUN_COMMAND_PLUGIN name={name} status={status} updated={updated}")
if not safe:
    print("RUN_COMMAND_CONTROL_PLANE_STATUS=ABSENT")
elif len(safe)==1:
    print("RUN_COMMAND_CONTROL_PLANE_STATUS="+safe[0][1])
else:
    print("RUN_COMMAND_CONTROL_PLANE_STATUS=AMBIGUOUS_MULTIPLE")
PY
PROBE_RC=$?

echo "SDK_PROBE_PROCESS_RC=$PROBE_RC"
echo 'PACKAGE_INSTALL=NO'
echo 'MUTATION_COMMANDS=NONE'
echo 'AGENT_CONFIG_CHANGE=NO'
echo 'PLUGIN_ENABLE=NO'
echo 'RUN_COMMAND_CREATED=NO'
echo 'SERVICE_RESTART=NO'
echo 'OCID_OUTPUT=NO'
echo 'RAW_OCI_ERROR_OUTPUT=NO'
echo '=== ISSUE367_SDK_PROBE=COMPLETE_READ_ONLY ==='
