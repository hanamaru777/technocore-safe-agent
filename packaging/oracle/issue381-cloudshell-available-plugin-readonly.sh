#!/usr/bin/env bash
# Issue #381: read-only Cloud Shell check for Compute Instance Run Command availability.
set -u
umask 077

TARGET_PLUGIN='Compute Instance Run Command'
OS_NAME='Canonical Ubuntu'
OS_VERSION='24.04'
TMPDIR=$(mktemp -d /tmp/issue381-cloudshell.XXXXXX)

cleanup() {
  rm -rf -- "$TMPDIR"
}
trap cleanup EXIT

echo '=== ISSUE381 CLOUD SHELL AVAILABLE-PLUGIN READ-ONLY CHECK ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if ! command -v oci >/dev/null 2>&1; then
  echo 'OCI_CLI_PRESENT=NO'
  echo 'CLOUDSHELL_PROBE=UNAVAILABLE_NO_OCI_CLI'
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
fi

echo 'OCI_CLI_PRESENT=YES'
OCI_VERSION=$(oci --version 2>/dev/null || true)
echo "OCI_CLI_VERSION=${OCI_VERSION:-UNKNOWN}"

CONFIG_FILE=${OCI_CLI_CONFIG_FILE:-/etc/oci/config}
PROFILE=${OCI_CLI_PROFILE:-DEFAULT}

TENANCY=$(
python3 - "$CONFIG_FILE" "$PROFILE" <<'PY'
import configparser
import pathlib
import sys

path=pathlib.Path(sys.argv[1])
profile=sys.argv[2]

if not path.is_file():
    raise SystemExit(2)

cfg=configparser.ConfigParser(interpolation=None)
cfg.read(path)
if profile not in cfg:
    raise SystemExit(3)

tenancy=cfg[profile].get("tenancy","").strip()
if not tenancy:
    raise SystemExit(4)

print(tenancy)
PY
)
CFG_RC=$?

if [[ "$CFG_RC" -ne 0 || -z "$TENANCY" ]]; then
  echo "CLOUDSHELL_CONFIG=FAIL rc=$CFG_RC"
  echo 'TENANCY_OUTPUT=NO'
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
fi

echo 'CLOUDSHELL_CONFIG=PASS'
echo 'TENANCY_OUTPUT=NO'
echo "OCI_OS_SELECTOR_NAME=$OS_NAME"
echo "OCI_OS_SELECTOR_VERSION=$OS_VERSION"

STDOUT="$TMPDIR/stdout.json"
STDERR="$TMPDIR/stderr.txt"

set +e
oci instance-agent available-plugins get   --compartment-id "$TENANCY"   --os-name "$OS_NAME"   --os-version "$OS_VERSION"   --name "$TARGET_PLUGIN"   --no-retry   --output json   >"$STDOUT" 2>"$STDERR"
RC=$?
set -e

if [[ "$RC" -ne 0 ]]; then
  python3 - "$STDERR" "$RC" <<'PY'
import pathlib
import re
import sys

text=pathlib.Path(sys.argv[1]).read_text("utf-8",errors="replace")
rc=sys.argv[2]
lower=text.lower()

error_class="OTHER"
if "notauthorizedornotfound" in lower or "not authorized" in lower or "notauthenticated" in lower:
    error_class="AUTHORIZATION"
elif "serviceerror" in lower and "404" in lower:
    error_class="NOT_FOUND_OR_AUTHORIZATION"
elif "timeout" in lower or "timed out" in lower:
    error_class="TIMEOUT"
elif "connection" in lower or "network" in lower:
    error_class="NETWORK"

status="UNAVAILABLE"
m=re.search(r"(?:status|status code)[^0-9]{0,10}([1-5][0-9]{2})", text, re.I)
if m:
    status=m.group(1)

code="UNAVAILABLE"
for candidate in (
    "NotAuthorizedOrNotFound",
    "NotAuthorized",
    "NotAuthenticated",
    "TooManyRequests",
    "InternalServerError",
    "ServiceUnavailable",
):
    if candidate.lower() in lower:
        code=candidate
        break

print("CONTROL_PLANE_CALL=FAIL")
print("CONTROL_PLANE_ERROR_CLASS="+error_class)
print("CONTROL_PLANE_HTTP_STATUS="+status)
print("CONTROL_PLANE_ERROR_CODE="+code)
print("OCI_CLI_RC="+rc)
PY

  echo 'RAW_OCI_ERROR_OUTPUT=NO'
  echo 'MUTATION_COMMANDS=NONE'
  echo 'IAM_CHANGE=NO'
  echo 'PLUGIN_ENABLE=NO'
  echo 'RUN_COMMAND_CREATED=NO'
  exit 0
fi

python3 - "$STDOUT" <<'PY'
import json
import pathlib
import sys

path=pathlib.Path(sys.argv[1])

try:
    doc=json.loads(path.read_text("utf-8"))
except Exception as exc:
    print("CONTROL_PLANE_CALL=FAIL")
    print("CONTROL_PLANE_ERROR_CLASS=JSON_PARSE")
    print("CONTROL_PLANE_ERROR_TYPE="+type(exc).__name__)
    raise SystemExit(0)

rows=doc.get("data")
if not isinstance(rows,list):
    print("CONTROL_PLANE_CALL=FAIL")
    print("CONTROL_PLANE_ERROR_CLASS=UNEXPECTED_RESPONSE_SHAPE")
    raise SystemExit(0)

print("CONTROL_PLANE_CALL=PASS")
print("AVAILABLE_PLUGIN_MATCHES="+str(len(rows)))

for row in rows[:5]:
    if not isinstance(row,dict):
        continue
    name=str(row.get("name") or "")
    supported=row.get("is-supported")
    enabled=row.get("is-enabled-by-default")
    safe_name="".join(ch for ch in name if ch.isalnum() or ch in " ._-/")[:120]
    print("AVAILABLE_PLUGIN_NAME="+safe_name)
    print("AVAILABLE_PLUGIN_SUPPORTED="+("true" if supported is True else "false" if supported is False else "unknown"))
    print("AVAILABLE_PLUGIN_ENABLED_BY_DEFAULT="+("true" if enabled is True else "false" if enabled is False else "unknown"))

if len(rows)==0:
    result="ABSENT"
elif len(rows)==1:
    supported=rows[0].get("is-supported") if isinstance(rows[0],dict) else None
    if supported is True:
        result="SUPPORTED"
    elif supported is False:
        result="NOT_SUPPORTED"
    else:
        result="UNKNOWN"
else:
    result="AMBIGUOUS_MULTIPLE"

print("RUN_COMMAND_AVAILABLE_RESULT="+result)
PY

echo '--- SAFETY TAIL ---'
echo 'MUTATION_COMMANDS=NONE'
echo 'PACKAGE_INSTALL=NO'
echo 'IAM_CHANGE=NO'
echo 'INSTANCE_CHANGE=NO'
echo 'AGENT_CONFIG_CHANGE=NO'
echo 'PLUGIN_ENABLE=NO'
echo 'RUN_COMMAND_CREATED=NO'
echo 'OCID_OUTPUT=NO'
echo 'TENANCY_OUTPUT=NO'
echo 'RAW_OCI_ERROR_OUTPUT=NO'
echo '=== ISSUE381_CLOUDSHELL_CHECK=COMPLETE_READ_ONLY ==='
