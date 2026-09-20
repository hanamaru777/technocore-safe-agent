#!/usr/bin/env bash
# Read-only OCI control-plane status probe for Compute Instance Run Command.
# Never prints instance/compartment OCIDs, IMDS body, credentials, or raw OCI errors.
set -u
umask 077

IMDS_URL=http://169.254.169.254/opc/v2/instance/
PLUGIN_NAME='Compute Instance Run Command'

TMPDIR=$(mktemp -d /tmp/issue367.XXXXXX)
cleanup() {
  rm -rf -- "$TMPDIR"
}
trap cleanup EXIT

echo '=== ISSUE367 RUN COMMAND CONTROL-PLANE READ-ONLY PROBE ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if command -v oci >/dev/null 2>&1; then
  echo 'OCI_CLI_PRESENT=YES'
  OCI_VERSION=$(oci --version 2>/dev/null || true)
  echo "OCI_CLI_VERSION=${OCI_VERSION:-UNKNOWN}"
else
  echo 'OCI_CLI_PRESENT=NO'
  echo 'CONTROL_PLANE_PROBE=UNAVAILABLE_NO_OCI_CLI'
  echo 'MUTATION_COMMANDS=NONE'
  echo 'AGENT_CONFIG_CHANGE=NO'
  echo 'PLUGIN_ENABLE=NO'
  echo 'RUN_COMMAND_CREATED=NO'
  echo 'SERVICE_RESTART=NO'
  exit 0
fi

IMDS_CODE=$(curl -sS --connect-timeout 3 --max-time 5   -H 'Authorization: Bearer Oracle'   -o "$TMPDIR/imds.json"   -w '%{http_code}'   "$IMDS_URL" 2>/dev/null || true)

echo "ROOT_IMDS_HTTP=${IMDS_CODE:-000}"

if [[ "$IMDS_CODE" != "200" ]]; then
  echo 'CONTROL_PLANE_PROBE=UNAVAILABLE_IMDS'
  echo 'MUTATION_COMMANDS=NONE'
  echo 'AGENT_CONFIG_CHANGE=NO'
  echo 'PLUGIN_ENABLE=NO'
  echo 'RUN_COMMAND_CREATED=NO'
  echo 'SERVICE_RESTART=NO'
  exit 0
fi

python3 - "$TMPDIR/imds.json" "$TMPDIR/ids.env" <<'PY'
import json
import pathlib
import shlex
import sys

source=pathlib.Path(sys.argv[1])
target=pathlib.Path(sys.argv[2])

try:
    doc=json.loads(source.read_text("utf-8"))
except Exception:
    raise SystemExit(2)

instance=doc.get("id")
compartment=doc.get("compartmentId")
region=doc.get("region") or doc.get("canonicalRegionName")

if not all(isinstance(v,str) and v for v in (instance,compartment,region)):
    raise SystemExit(3)

target.write_text(
    "INSTANCE_ID="+shlex.quote(instance)+"\n"
    "COMPARTMENT_ID="+shlex.quote(compartment)+"\n"
    "REGION="+shlex.quote(region)+"\n",
    encoding="utf-8",
)
target.chmod(0o600)
PY
ID_RC=$?

if [[ "$ID_RC" -ne 0 ]]; then
  echo "IMDS_IDENTIFIER_PARSE_RC=$ID_RC"
  echo 'CONTROL_PLANE_PROBE=UNAVAILABLE_IDENTIFIER_PARSE'
  echo 'MUTATION_COMMANDS=NONE'
  echo 'AGENT_CONFIG_CHANGE=NO'
  echo 'PLUGIN_ENABLE=NO'
  echo 'RUN_COMMAND_CREATED=NO'
  echo 'SERVICE_RESTART=NO'
  exit 0
fi

. "$TMPDIR/ids.env"

oci instance-agent plugin list   --compartment-id "$COMPARTMENT_ID"   --instanceagent-id "$INSTANCE_ID"   --name "$PLUGIN_NAME"   --auth instance_principal   --region "$REGION"   --no-retry   --connection-timeout 5   --read-timeout 15   --output json   >"$TMPDIR/plugin.json"   2>"$TMPDIR/plugin.err"
OCI_RC=$?

echo "CONTROL_PLANE_LIST_RC=$OCI_RC"

if [[ "$OCI_RC" -eq 0 ]]; then
  python3 - "$TMPDIR/plugin.json" <<'PY'
import json
import pathlib
import sys

try:
    doc=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
except Exception:
    print("CONTROL_PLANE_PARSE=FAIL")
    raise SystemExit

rows=doc.get("data")
if not isinstance(rows,list):
    print("CONTROL_PLANE_PARSE=FAIL")
    raise SystemExit

safe=[]
for row in rows:
    if not isinstance(row,dict):
        continue
    name=row.get("name")
    status=row.get("status")
    updated=row.get("time-last-updated-utc") or row.get("timeLastUpdatedUtc")
    if not isinstance(name,str):
        continue
    clean_name="".join(ch for ch in name if ch.isalnum() or ch in " ._-/")[:120]
    clean_status="".join(ch for ch in str(status or "UNKNOWN") if ch.isalnum() or ch in "._-")[:40]
    clean_updated="".join(ch for ch in str(updated or "UNKNOWN") if ch.isalnum() or ch in "-:+.TZ")[:80]
    safe.append((clean_name,clean_status,clean_updated))

print("CONTROL_PLANE_PARSE=PASS")
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
else
  python3 - "$TMPDIR/plugin.err" <<'PY'
import pathlib
import sys

text=pathlib.Path(sys.argv[1]).read_text("utf-8",errors="replace").lower()

if any(x in text for x in ("notauthorized","not authorized","authorization failed","401","403","permission")):
    cls="AUTHORIZATION"
elif any(x in text for x in ("timeout","timed out","connection","network","dns","name resolution")):
    cls="NETWORK"
elif any(x in text for x in ("instance principal","federation","security token","dynamic group")):
    cls="INSTANCE_PRINCIPAL"
else:
    cls="OTHER"

print("CONTROL_PLANE_ERROR_CLASS="+cls)
PY
fi

echo 'MUTATION_COMMANDS=NONE'
echo 'AGENT_CONFIG_CHANGE=NO'
echo 'PLUGIN_ENABLE=NO'
echo 'RUN_COMMAND_CREATED=NO'
echo 'SERVICE_RESTART=NO'
echo 'OCID_OUTPUT=NO'
echo 'RAW_OCI_ERROR_OUTPUT=NO'
echo '=== ISSUE367_PROBE=COMPLETE_READ_ONLY ==='
