#!/usr/bin/env bash
# Issue #381 v3: robust read-only Cloud Shell Run Command availability check.
set -u
umask 077

TARGET_PLUGIN='Compute Instance Run Command'
OS_NAME='Canonical Ubuntu'
OS_VERSION='24.04'
TMPDIR=$(mktemp -d /tmp/issue381-cloudshell-v3.XXXXXX)

cleanup() { rm -rf -- "$TMPDIR"; }
trap cleanup EXIT

echo '=== ISSUE381 CLOUD SHELL AVAILABLE-PLUGIN READ-ONLY CHECK V3 ==='
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
echo 'OCI_CLI_PRESENT=YES'
echo "OCI_CLI_VERSION=$(oci --version 2>/dev/null || echo UNKNOWN)"

CONFIG_FILE=$OCI_CLI_CONFIG_FILE
PROFILE=$OCI_CLI_PROFILE
TENANCY=$(
python3 - "$CONFIG_FILE" "$PROFILE" <<'PY'
import configparser,pathlib,sys
p=pathlib.Path(sys.argv[1]); profile=sys.argv[2]
if not p.is_file(): raise SystemExit(2)
cfg=configparser.ConfigParser(interpolation=None); cfg.read(p)
if profile not in cfg: raise SystemExit(3)
v=cfg[profile].get("tenancy","").strip()
if not v: raise SystemExit(4)
print(v)
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

classify_stderr() {
  python3 - "$1" <<'PY'
import pathlib,re,sys
text=pathlib.Path(sys.argv[1]).read_text("utf-8",errors="replace")
low=text.lower()
cls="OTHER"
if "notauthorizedornotfound" in low or "not authorized" in low or "notauthenticated" in low:
    cls="AUTHORIZATION"
elif "serviceerror" in low and "404" in low:
    cls="NOT_FOUND_OR_AUTHORIZATION"
elif "timeout" in low or "timed out" in low:
    cls="TIMEOUT"
elif "connection" in low or "network" in low:
    cls="NETWORK"
status="UNAVAILABLE"
m=re.search(r"(?:status|status code)[^0-9]{0,10}([1-5][0-9]{2})", text, re.I)
if m: status=m.group(1)
code="UNAVAILABLE"
for c in ("NotAuthorizedOrNotFound","NotAuthorized","NotAuthenticated","TooManyRequests","InternalServerError","ServiceUnavailable"):
    if c.lower() in low:
        code=c; break
print(cls+"|"+status+"|"+code)
PY
}

parse_available_json() {
  python3 - "$1" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
raw=p.read_text("utf-8",errors="replace")
if not raw.strip():
    print("PARSE_RESULT=EMPTY")
    raise SystemExit(0)
try:
    doc=json.loads(raw)
except Exception:
    print("PARSE_RESULT=INVALID_JSON")
    raise SystemExit(0)
rows=doc.get("data")
if not isinstance(rows,list):
    print("PARSE_RESULT=UNEXPECTED_SHAPE")
    raise SystemExit(0)
print("PARSE_RESULT=PASS")
print("AVAILABLE_PLUGIN_MATCHES="+str(len(rows)))
for row in rows[:5]:
    if not isinstance(row,dict): continue
    name=str(row.get("name") or "")
    supported=row.get("is-supported")
    enabled=row.get("is-enabled-by-default")
    safe="".join(ch for ch in name if ch.isalnum() or ch in " ._-/")[:120]
    print("AVAILABLE_PLUGIN_NAME="+safe)
    print("AVAILABLE_PLUGIN_SUPPORTED="+("true" if supported is True else "false" if supported is False else "unknown"))
    print("AVAILABLE_PLUGIN_ENABLED_BY_DEFAULT="+("true" if enabled is True else "false" if enabled is False else "unknown"))
if len(rows)==0:
    result="ABSENT"
elif len(rows)==1 and isinstance(rows[0],dict):
    supported=rows[0].get("is-supported")
    result="SUPPORTED" if supported is True else "NOT_SUPPORTED" if supported is False else "UNKNOWN"
else:
    result="AMBIGUOUS_MULTIPLE"
print("RUN_COMMAND_AVAILABLE_RESULT="+result)
PY
}

call_available() {
  local scope="$1"
  local out="$2"
  local err="$3"
  : >"$out"; : >"$err"
  set +e
  oci instance-agent available-plugins get     --compartment-id "$scope"     --os-name "$OS_NAME"     --os-version "$OS_VERSION"     --name "$TARGET_PLUGIN"     --no-retry     --output json     >"$out" 2>"$err"
  local rc=$?
  set -e
  return "$rc"
}

ROOT_OUT="$TMPDIR/root.json"
ROOT_ERR="$TMPDIR/root.err"

echo '--- DIRECT TENANCY-SCOPE PROBE ---'
if call_available "$TENANCY" "$ROOT_OUT" "$ROOT_ERR"; then
  echo 'TENANCY_SCOPE_CALL=PASS'
  parse_available_json "$ROOT_OUT"
  PARSE_RC=$?
  echo "TENANCY_SCOPE_PARSE_RC=$PARSE_RC"
  echo 'AUTHORIZED_SCOPE_SOURCE=TENANCY'
  echo 'CONTROL_PLANE_CALL=PASS'
  echo '--- SAFETY TAIL ---'
  echo 'MUTATION_COMMANDS=NONE'
  echo 'IAM_CHANGE=NO'
  echo 'INSTANCE_CHANGE=NO'
  echo 'PLUGIN_ENABLE=NO'
  echo 'RUN_COMMAND_CREATED=NO'
  echo 'OCID_OUTPUT=NO'
  echo 'RAW_OCI_ERROR_OUTPUT=NO'
  echo '=== ISSUE381_CLOUDSHELL_V3=COMPLETE_READ_ONLY ==='
  exit 0
fi

ROOT_CLASS=$(classify_stderr "$ROOT_ERR")
IFS='|' read -r ROOT_CLASS_NAME ROOT_STATUS ROOT_CODE <<<"$ROOT_CLASS"
echo 'TENANCY_SCOPE_CALL=FAIL'
echo "TENANCY_SCOPE_ERROR_CLASS=$ROOT_CLASS_NAME"
echo "TENANCY_SCOPE_HTTP_STATUS=$ROOT_STATUS"
echo "TENANCY_SCOPE_ERROR_CODE=$ROOT_CODE"

if [[ "$ROOT_CLASS_NAME" != AUTHORIZATION && "$ROOT_CLASS_NAME" != NOT_FOUND_OR_AUTHORIZATION ]]; then
  echo 'CONTROL_PLANE_CALL=FAIL'
  echo 'CONTROL_PLANE_AUTHORIZED_SCOPE_FOUND=NO'
  echo 'MUTATION_COMMANDS=NONE'
  echo 'IAM_CHANGE=NO'
  echo 'PLUGIN_ENABLE=NO'
  echo 'RUN_COMMAND_CREATED=NO'
  echo 'RAW_OCI_ERROR_OUTPUT=NO'
  exit 0
fi

echo '--- ACCESSIBLE COMPARTMENT FALLBACK ---'
COMP_JSON="$TMPDIR/compartments.json"
COMP_ERR="$TMPDIR/compartments.err"
set +e
oci iam compartment list   --compartment-id "$TENANCY"   --compartment-id-in-subtree true   --access-level ACCESSIBLE   --all   --no-retry   --output json   >"$COMP_JSON" 2>"$COMP_ERR"
COMP_RC=$?
set -e

echo "COMPARTMENT_DISCOVERY_CLI_RC=$COMP_RC"
if [[ "$COMP_RC" -ne 0 ]]; then
  DISC_CLASS=$(classify_stderr "$COMP_ERR")
  IFS='|' read -r DCLASS DSTATUS DCODE <<<"$DISC_CLASS"
  echo 'ACCESSIBLE_COMPARTMENT_DISCOVERY=FAIL'
  echo "DISCOVERY_ERROR_CLASS=$DCLASS"
  echo "DISCOVERY_HTTP_STATUS=$DSTATUS"
  echo "DISCOVERY_ERROR_CODE=$DCODE"
  echo 'RAW_OCI_ERROR_OUTPUT=NO'
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
fi

CANDIDATES="$TMPDIR/candidates.txt"
DISCOVERY_PARSE=$(python3 - "$COMP_JSON" "$CANDIDATES" <<'PY'
import json,pathlib,sys
src=pathlib.Path(sys.argv[1]); dst=pathlib.Path(sys.argv[2])
raw=src.read_text("utf-8",errors="replace")
if not raw.strip():
    print("EMPTY"); raise SystemExit
try: doc=json.loads(raw)
except Exception:
    print("INVALID_JSON"); raise SystemExit
rows=doc.get("data")
if not isinstance(rows,list):
    print("UNEXPECTED_SHAPE"); raise SystemExit
vals=[]
seen=set()
for row in rows:
    if not isinstance(row,dict): continue
    v=row.get("id")
    if isinstance(v,str) and v and v not in seen:
        seen.add(v); vals.append(v)
dst.write_text("\n".join(vals)+("\n" if vals else ""),"utf-8")
print("PASS:"+str(len(vals)))
PY
)
echo "ACCESSIBLE_COMPARTMENT_DISCOVERY_PARSE=$DISCOVERY_PARSE"

if [[ "$DISCOVERY_PARSE" != PASS:* ]]; then
  echo 'CONTROL_PLANE_CALL=FAIL'
  echo 'CONTROL_PLANE_ERROR_CLASS=COMPARTMENT_DISCOVERY_PARSE'
  echo 'CONTROL_PLANE_AUTHORIZED_SCOPE_FOUND=NO'
  echo 'RAW_OCI_ERROR_OUTPUT=NO'
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
fi

COUNT=${DISCOVERY_PARSE#PASS:}
echo "ACCESSIBLE_COMPARTMENT_COUNT=$COUNT"

ATTEMPTS=0
AUTH_FAILURES=0
OTHER_FAILURES=0
SUCCESS=0
OUT="$TMPDIR/scope.json"
ERR="$TMPDIR/scope.err"

while IFS= read -r CID; do
  [[ -n "$CID" ]] || continue
  ATTEMPTS=$((ATTEMPTS+1))
  if call_available "$CID" "$OUT" "$ERR"; then
    SUCCESS=1
    break
  fi
  C=$(classify_stderr "$ERR")
  IFS='|' read -r CNAME CSTATUS CCODE <<<"$C"
  if [[ "$CNAME" == AUTHORIZATION || "$CNAME" == NOT_FOUND_OR_AUTHORIZATION ]]; then
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
  echo 'CONTROL_PLANE_AUTHORIZED_SCOPE_FOUND=NO'
  echo 'RAW_OCI_ERROR_OUTPUT=NO'
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
fi

echo 'CONTROL_PLANE_AUTHORIZED_SCOPE_FOUND=YES'
echo 'AUTHORIZED_SCOPE_SOURCE=ACCESSIBLE_COMPARTMENT'
parse_available_json "$OUT"

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
echo '=== ISSUE381_CLOUDSHELL_V3=COMPLETE_READ_ONLY ==='
