#!/usr/bin/env bash
# Issue #381 v4: read-only Cloud Shell SDK check for Compute Instance Run Command availability.
set -u
umask 077

echo '=== ISSUE381 CLOUD SHELL SDK AVAILABLE-PLUGIN READ-ONLY CHECK V4 ==='
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
if [[ ! -r /etc/oci/delegation_token ]]; then
  echo 'CLOUDSHELL_ENV=STOP:delegation_token_unreadable'
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
fi

PYTHON=''
for candidate in python3 /usr/bin/python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" - <<'PY' >/dev/null 2>&1
import oci
from oci.auth.signers import InstancePrincipalsDelegationTokenSigner
from oci.compute_instance_agent import PluginconfigClient
from oci.identity import IdentityClient
PY
    then
      PYTHON=$(command -v "$candidate")
      break
    fi
  fi
done

if [[ -z "$PYTHON" ]]; then
  echo 'OCI_PYTHON_SDK_PRESENT=NO'
  echo 'CLOUDSHELL_SDK_PROBE=UNAVAILABLE'
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
fi

echo 'CLOUDSHELL_ENV=PASS'
echo 'OCI_PYTHON_SDK_PRESENT=YES'

"$PYTHON" - "$OCI_CLI_CONFIG_FILE" "$OCI_CLI_PROFILE" <<'PY'
import configparser
import pathlib
import sys

import oci
from oci.auth.signers import InstancePrincipalsDelegationTokenSigner
from oci.compute_instance_agent import PluginconfigClient
from oci.exceptions import ServiceError
from oci.identity import IdentityClient
from oci.retry import NoneRetryStrategy

CONFIG_PATH = pathlib.Path(sys.argv[1])
PROFILE = sys.argv[2]
TOKEN_PATH = pathlib.Path("/etc/oci/delegation_token")
TARGET = "Compute Instance Run Command"
OS_NAME = "Canonical Ubuntu"
OS_VERSION = "24.04"

print("OCI_PYTHON_SDK_VERSION=" + str(getattr(oci, "__version__", "UNKNOWN")))

def safe_service_error(exc: ServiceError):
    status = int(getattr(exc, "status", 0) or 0)
    code = str(getattr(exc, "code", "") or "UNKNOWN")
    if status in (401, 403) or code in ("NotAuthorized", "NotAuthenticated", "NotAuthorizedOrNotFound"):
        cls = "AUTHORIZATION"
    elif status == 404:
        cls = "NOT_FOUND_OR_AUTHORIZATION"
    elif status in (408, 429, 500, 502, 503, 504):
        cls = "TRANSIENT_SERVICE"
    else:
        cls = "SERVICE_OTHER"
    return cls, status, code[:120]

def safe_other_error(exc: Exception):
    name = type(exc).__name__
    lower = (name + " " + str(exc)).lower()
    if "timeout" in lower:
        return "TIMEOUT", name
    if "connection" in lower or "network" in lower:
        return "NETWORK", name
    if "json" in lower or "decode" in lower:
        return "PARSE", name
    return "OTHER", name

cfg = configparser.ConfigParser(interpolation=None)
try:
    cfg.read(CONFIG_PATH)
except Exception as exc:
    print("SDK_CONFIG=FAIL")
    print("SDK_CONFIG_ERROR_TYPE=" + type(exc).__name__)
    raise SystemExit(0)

if PROFILE not in cfg:
    print("SDK_CONFIG=FAIL:profile_missing")
    raise SystemExit(0)

section = cfg[PROFILE]
tenancy = section.get("tenancy", "").strip()
region = section.get("region", "").strip()
if not tenancy or not region:
    print("SDK_CONFIG=FAIL:tenancy_or_region_missing")
    raise SystemExit(0)

try:
    token = TOKEN_PATH.read_text("utf-8").strip()
except Exception as exc:
    print("DELEGATION_TOKEN=FAIL")
    print("DELEGATION_TOKEN_ERROR_TYPE=" + type(exc).__name__)
    raise SystemExit(0)

if not token:
    print("DELEGATION_TOKEN=FAIL:empty")
    raise SystemExit(0)

print("SDK_CONFIG=PASS")
print("DELEGATION_TOKEN=PASS")
print("TENANCY_OUTPUT=NO")
print("OCI_OS_SELECTOR_NAME=" + OS_NAME)
print("OCI_OS_SELECTOR_VERSION=" + OS_VERSION)

try:
    signer = InstancePrincipalsDelegationTokenSigner(
        delegation_token=token,
        federation_client_retry_strategy=NoneRetryStrategy(),
    )
    plugin_client = PluginconfigClient(
        {"region": region},
        signer=signer,
        timeout=(5, 20),
        retry_strategy=NoneRetryStrategy(),
    )
    identity_client = IdentityClient(
        {"region": region},
        signer=signer,
        timeout=(5, 20),
        retry_strategy=NoneRetryStrategy(),
    )
except Exception as exc:
    cls, typ = safe_other_error(exc)
    print("SDK_CLIENT_INIT=FAIL")
    print("SDK_CLIENT_ERROR_CLASS=" + cls)
    print("SDK_CLIENT_ERROR_TYPE=" + typ)
    raise SystemExit(0)

print("SDK_CLIENT_INIT=PASS")

def inspect_scope(scope):
    try:
        filtered = plugin_client.list_instanceagent_available_plugins(
            scope,
            OS_NAME,
            OS_VERSION,
            name=TARGET,
            retry_strategy=NoneRetryStrategy(),
        )
    except ServiceError as exc:
        cls, status, code = safe_service_error(exc)
        return {"call": "FAIL", "class": cls, "status": status, "code": code}
    except Exception as exc:
        cls, typ = safe_other_error(exc)
        return {"call": "FAIL", "class": cls, "status": 0, "code": typ}

    rows = list(getattr(filtered, "data", None) or [])
    if len(rows) == 1:
        row = rows[0]
        return {
            "call": "PASS",
            "matches": 1,
            "name": str(getattr(row, "name", "") or ""),
            "supported": getattr(row, "is_supported", None),
            "enabled": getattr(row, "is_enabled_by_default", None),
            "source": "FILTERED",
        }
    if len(rows) > 1:
        return {"call": "PASS", "matches": len(rows), "ambiguous": True, "source": "FILTERED"}

    # Filter returned no rows. Confirm against an unfiltered authoritative list.
    try:
        unfiltered = plugin_client.list_instanceagent_available_plugins(
            scope,
            OS_NAME,
            OS_VERSION,
            retry_strategy=NoneRetryStrategy(),
        )
    except ServiceError as exc:
        cls, status, code = safe_service_error(exc)
        return {"call": "FAIL_AFTER_EMPTY_FILTER", "class": cls, "status": status, "code": code}
    except Exception as exc:
        cls, typ = safe_other_error(exc)
        return {"call": "FAIL_AFTER_EMPTY_FILTER", "class": cls, "status": 0, "code": typ}

    all_rows = list(getattr(unfiltered, "data", None) or [])
    matches = [r for r in all_rows if str(getattr(r, "name", "") or "") == TARGET]
    if len(matches) == 1:
        row = matches[0]
        return {
            "call": "PASS",
            "matches": 1,
            "name": TARGET,
            "supported": getattr(row, "is_supported", None),
            "enabled": getattr(row, "is_enabled_by_default", None),
            "source": "UNFILTERED_CONFIRM",
            "total": len(all_rows),
        }
    if len(matches) > 1:
        return {
            "call": "PASS",
            "matches": len(matches),
            "ambiguous": True,
            "source": "UNFILTERED_CONFIRM",
            "total": len(all_rows),
        }
    return {
        "call": "PASS",
        "matches": 0,
        "source": "UNFILTERED_CONFIRM",
        "total": len(all_rows),
    }

def emit_result(label, result):
    print(label + "_CALL=" + result.get("call", "UNKNOWN"))
    if "class" in result:
        print(label + "_ERROR_CLASS=" + str(result["class"]))
        if result.get("status"):
            print(label + "_HTTP_STATUS=" + str(result["status"]))
        print(label + "_ERROR_CODE=" + str(result.get("code", "UNKNOWN")))
        return
    print(label + "_MATCHES=" + str(result.get("matches", 0)))
    if "total" in result:
        print(label + "_UNFILTERED_TOTAL=" + str(result["total"]))
    if result.get("ambiguous"):
        print("RUN_COMMAND_AVAILABLE_RESULT=AMBIGUOUS_MULTIPLE")
        return
    matches = int(result.get("matches", 0) or 0)
    if matches == 0:
        print("RUN_COMMAND_AVAILABLE_RESULT=ABSENT")
        return
    name = str(result.get("name", ""))
    safe_name = "".join(ch for ch in name if ch.isalnum() or ch in " ._-/")[:120]
    supported = result.get("supported")
    enabled = result.get("enabled")
    print("AVAILABLE_PLUGIN_NAME=" + safe_name)
    print("AVAILABLE_PLUGIN_SUPPORTED=" + ("true" if supported is True else "false" if supported is False else "unknown"))
    print("AVAILABLE_PLUGIN_ENABLED_BY_DEFAULT=" + ("true" if enabled is True else "false" if enabled is False else "unknown"))
    if supported is True:
        print("RUN_COMMAND_AVAILABLE_RESULT=SUPPORTED")
    elif supported is False:
        print("RUN_COMMAND_AVAILABLE_RESULT=NOT_SUPPORTED")
    else:
        print("RUN_COMMAND_AVAILABLE_RESULT=UNKNOWN")

print("--- SDK TENANCY-SCOPE PROBE ---")
root = inspect_scope(tenancy)
emit_result("TENANCY_SCOPE", root)

if root.get("call") == "PASS":
    print("CONTROL_PLANE_AUTHORIZED_SCOPE_FOUND=YES")
    print("AUTHORIZED_SCOPE_SOURCE=TENANCY")
    raise SystemExit(0)

if root.get("class") not in ("AUTHORIZATION", "NOT_FOUND_OR_AUTHORIZATION"):
    print("CONTROL_PLANE_AUTHORIZED_SCOPE_FOUND=NO")
    raise SystemExit(0)

print("--- SDK ACCESSIBLE COMPARTMENT FALLBACK ---")
try:
    response = oci.pagination.list_call_get_all_results(
        identity_client.list_compartments,
        tenancy,
        compartment_id_in_subtree=True,
        access_level="ACCESSIBLE",
        retry_strategy=NoneRetryStrategy(),
    )
    compartments = list(getattr(response, "data", None) or [])
except ServiceError as exc:
    cls, status, code = safe_service_error(exc)
    print("ACCESSIBLE_COMPARTMENT_DISCOVERY=FAIL")
    print("DISCOVERY_ERROR_CLASS=" + cls)
    if status:
        print("DISCOVERY_HTTP_STATUS=" + str(status))
    print("DISCOVERY_ERROR_CODE=" + code)
    print("CONTROL_PLANE_AUTHORIZED_SCOPE_FOUND=NO")
    raise SystemExit(0)
except Exception as exc:
    cls, typ = safe_other_error(exc)
    print("ACCESSIBLE_COMPARTMENT_DISCOVERY=FAIL")
    print("DISCOVERY_ERROR_CLASS=" + cls)
    print("DISCOVERY_ERROR_TYPE=" + typ)
    print("CONTROL_PLANE_AUTHORIZED_SCOPE_FOUND=NO")
    raise SystemExit(0)

candidates = []
seen = set()
for row in compartments:
    cid = str(getattr(row, "id", "") or "")
    if cid and cid not in seen:
        seen.add(cid)
        candidates.append(cid)

print("ACCESSIBLE_COMPARTMENT_DISCOVERY=PASS")
print("ACCESSIBLE_COMPARTMENT_COUNT=" + str(len(candidates)))

attempts = 0
auth_failures = 0
other_failures = 0
for cid in candidates:
    attempts += 1
    result = inspect_scope(cid)
    if result.get("call") == "PASS":
        emit_result("ACCESSIBLE_SCOPE", result)
        print("CONTROL_PLANE_SCOPE_ATTEMPTS=" + str(attempts))
        print("CONTROL_PLANE_AUTH_FAILURES=" + str(auth_failures))
        print("CONTROL_PLANE_OTHER_FAILURES=" + str(other_failures))
        print("CONTROL_PLANE_AUTHORIZED_SCOPE_FOUND=YES")
        print("AUTHORIZED_SCOPE_SOURCE=ACCESSIBLE_COMPARTMENT")
        raise SystemExit(0)
    if result.get("class") in ("AUTHORIZATION", "NOT_FOUND_OR_AUTHORIZATION"):
        auth_failures += 1
    else:
        other_failures += 1

print("CONTROL_PLANE_SCOPE_ATTEMPTS=" + str(attempts))
print("CONTROL_PLANE_AUTH_FAILURES=" + str(auth_failures))
print("CONTROL_PLANE_OTHER_FAILURES=" + str(other_failures))
print("CONTROL_PLANE_AUTHORIZED_SCOPE_FOUND=NO")
PY

RC=$?
echo "ISSUE381_SDK_PROCESS_RC=$RC"
echo '--- SAFETY TAIL ---'
echo 'MUTATION_COMMANDS=NONE'
echo 'PACKAGE_INSTALL=NO'
echo 'IAM_CHANGE=NO'
echo 'INSTANCE_CHANGE=NO'
echo 'AGENT_CONFIG_CHANGE=NO'
echo 'PLUGIN_ENABLE=NO'
echo 'RUN_COMMAND_CREATED=NO'
echo 'OCID_OUTPUT=NO'
echo 'DELEGATION_TOKEN_OUTPUT=NO'
echo 'RAW_OCI_ERROR_OUTPUT=NO'
echo '=== ISSUE381_CLOUDSHELL_SDK_V4=COMPLETE_READ_ONLY ==='
exit 0
