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

echo '=== ISSUE381 CLOUD SHELL AVAILABLE-PLUGIN READ-ONLY CHECK V2 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ "${OCI_CLI_AUTH:-}" != "instance_obo_user" ]]; then
  echo 'CLOUDSHELL_ENV=STOP:not_instance_obo_user'
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
fi

if [[ "${OCI_CLI_CONFIG_FILE:-}" != "/etc/oci/config" ]]; then
  echo 'CLOUDSHELL_ENV=STOP:unexpected_config_path'
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
fi

if [[ -z "${OCI_CLI_PROFILE:-}" ]]; then
  echo 'CLOUDSHELL_ENV=STOP:missing_profile'
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
fi

if ! command -v oci >/dev/null 2>&1; then
  echo 'CLOUDSHELL_ENV=STOP:oci_cli_missing'
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
fi

echo 'CLOUDSHELL_ENV=PASS'

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

CANDIDATES="$TMPDIR/candidates.txt"
COMPARTMENTS_JSON="$TMPDIR/compartments.json"
COMPARTMENTS_ERR="$TMPDIR/compartments.err"

printf '%s\n' "$TENANCY" >"$CANDIDATES"

set +e
oci iam compartment list   --compartment-id "$TENANCY"   --compartment-id-in-subtree true   --access-level ACCESSIBLE   --all   --no-retry   --output json   >"$COMPARTMENTS_JSON" 2>"$COMPARTMENTS_ERR"
COMPARTMENT_LIST_RC=$?
set -e

if [[ "$COMPARTMENT_LIST_RC" -eq 0 ]]; then
  python3 - "$COMPARTMENTS_JSON" "$CANDIDATES" <<'PY'
import json
import pathlib
import sys

doc=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
rows=doc.get("data")
if not isinstance(rows,list):
    raise SystemExit(0)

out=pathlib.Path(sys.argv[2])
with out.open("a",encoding="utf-8") as fh:
    for row in rows:
        if not isinstance(row,dict):
            continue
        value=row.get("id")
        if isinstance(value,str) and value:
            fh.write(value+"\n")
PY
  echo 'ACCESSIBLE_COMPARTMENT_DISCOVERY=PASS'
else
  echo 'ACCESSIBLE_COMPARTMENT_DISCOVERY=UNAVAILABLE'
fi

python3 - "$CANDIDATES" <<'PY'
import pathlib
import sys
path=pathlib.Path(sys.argv[1])
seen=set()
values=[]
for line in path.read_text("utf-8").splitlines():
    value=line.strip()
    if value and value not in seen:
        seen.add(value)
        values.append(value)
path.write_text("\n".join(values)+"\n","utf-8")
print("CANDIDATE_SCOPE_COUNT="+str(len(values)))
PY

STDOUT="$TMPDIR/stdout.json"
STDERR="$TMPDIR/stderr.txt"
SUCCESS=0
ATTEMPTS=0
AUTH_FAILURES=0
OTHER_FAILURES=0
LAST_STATUS=UNAVAILABLE
LAST_CODE=UNAVAILABLE
LAST_CLASS=UNAVAILABLE

while IFS= read -r COMPARTMENT_ID; do
  [[ -n "$COMPARTMENT_ID" ]] || continue
  ATTEMPTS=$((ATTEMPTS+1))
  : >"$STDOUT"
  : >"$STDERR"

  set +e
  oci instance-agent available-plugins get     --compartment-id "$COMPARTMENT_ID"     --os-name "$OS_NAME"     --os-version "$OS_VERSION"     --name "$TARGET_PLUGIN"     --no-retry     --output json     >"$STDOUT" 2>"$STDERR"
  RC=$?
  set -e

  if [[ "$RC" -eq 0 ]]; then
    SUCCESS=1
    break
  fi

  CLASSIFICATION=$(python3 - "$STDERR" <<'PY'
import pathlib
import re
import sys

text=pathlib.Path(sys.argv[1]).read_text("utf-8",errors="replace")
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

print(error_class+"|"+status+"|"+code)
PY
)
  IFS='|' read -r LAST_CLASS LAST_STATUS LAST_CODE <<<"$CLASSIFICATION"

  if [[ "$LAST_CLASS" == AUTHORIZATION || "$LAST_CLASS" == NOT_FOUND_OR_AUTHORIZATION ]]; then
    AUTH_FAILURES=$((AUTH_FAILURES+1))
  else
    OTHER_FAILURES=$((OTHER_FAILURES+1))
  fi
done <"$CANDIDATES"

echo "CONTROL_PLANE_SCOPE_ATTEMPTS=$ATTEMPTS"
echo "CONTROL_PLANE_AUTH_FAILURES=$AUTH_FAILURES"
echo "CONTROL_PLANE_OTHER_FAILURES=$OTHER_FAILURES"

if [[ "$SUCCESS" -ne 1 ]]; then
  echo 'CONTROL_PLANE_CALL=FAIL'
  echo "CONTROL_PLANE_ERROR_CLASS=$LAST_CLASS"
  echo "CONTROL_PLANE_HTTP_STATUS=$LAST_STATUS"
  echo "CONTROL_PLANE_ERROR_CODE=$LAST_CODE"
  echo 'CONTROL_PLANE_AUTHORIZED_SCOPE_FOUND=NO'
  echo 'RAW_OCI_ERROR_OUTPUT=NO'
  echo 'MUTATION_COMMANDS=NONE'
  echo 'IAM_CHANGE=NO'
  echo 'PLUGIN_ENABLE=NO'
  echo 'RUN_COMMAND_CREATED=NO'
  exit 0
fi

echo 'CONTROL_PLANE_AUTHORIZED_SCOPE_FOUND=YES'

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
