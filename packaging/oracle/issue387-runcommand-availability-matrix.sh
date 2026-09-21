#!/usr/bin/env bash
# Issue #387: read-only OCI Run Command availability matrix via Cloud Shell SDK.
set -u
umask 077

echo '=== ISSUE387 RUN COMMAND AVAILABILITY MATRIX READ-ONLY ==='
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
PY
    then
      PYTHON=$(command -v "$candidate")
      break
    fi
  fi
done

if [[ -z "$PYTHON" ]]; then
  echo 'OCI_PYTHON_SDK_PRESENT=NO'
  echo 'MATRIX_PROBE=UNAVAILABLE'
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
fi

echo 'CLOUDSHELL_ENV=PASS'
echo 'OCI_PYTHON_SDK_PRESENT=YES'

"$PYTHON" - "$OCI_CLI_CONFIG_FILE" "$OCI_CLI_PROFILE" <<'PY'
import configparser
import hashlib
import pathlib
import sys

import oci
from oci.auth.signers import InstancePrincipalsDelegationTokenSigner
from oci.compute_instance_agent import PluginconfigClient
from oci.exceptions import ServiceError
from oci.retry import NoneRetryStrategy

CONFIG_PATH = pathlib.Path(sys.argv[1])
PROFILE = sys.argv[2]
TOKEN_PATH = pathlib.Path("/etc/oci/delegation_token")
TARGET = "Compute Instance Run Command"

MATRIX = [
    ("UBUNTU_20_04", "Canonical Ubuntu", "20.04"),
    ("UBUNTU_22_04", "Canonical Ubuntu", "22.04"),
    ("UBUNTU_24_04", "Canonical Ubuntu", "24.04"),
    ("ORACLE_LINUX_8", "Oracle Linux", "8"),
    ("ORACLE_LINUX_9", "Oracle Linux", "9"),
]

print("OCI_PYTHON_SDK_VERSION=" + str(getattr(oci, "__version__", "UNKNOWN")))

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

try:
    signer = InstancePrincipalsDelegationTokenSigner(
        delegation_token=token,
        federation_client_retry_strategy=NoneRetryStrategy(),
    )
    client = PluginconfigClient(
        {"region": region},
        signer=signer,
        timeout=(5, 20),
        retry_strategy=NoneRetryStrategy(),
    )
except Exception as exc:
    print("SDK_CLIENT_INIT=FAIL")
    print("SDK_CLIENT_ERROR_TYPE=" + type(exc).__name__)
    raise SystemExit(0)

print("SDK_CLIENT_INIT=PASS")

def safe_service_error(exc):
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

def emit_error(label, exc):
    if isinstance(exc, ServiceError):
        cls, status, code = safe_service_error(exc)
        print(label + "_CALL=FAIL")
        print(label + "_ERROR_CLASS=" + cls)
        if status:
            print(label + "_HTTP_STATUS=" + str(status))
        print(label + "_ERROR_CODE=" + code)
    else:
        print(label + "_CALL=FAIL")
        print(label + "_ERROR_CLASS=OTHER")
        print(label + "_ERROR_TYPE=" + type(exc).__name__)

for label, os_name, os_version in MATRIX:
    print("--- " + label + " ---")
    print(label + "_OS_NAME=" + os_name)
    print(label + "_OS_VERSION=" + os_version)

    try:
        filtered = client.list_instanceagent_available_plugins(
            tenancy,
            os_name,
            os_version,
            name=TARGET,
            retry_strategy=NoneRetryStrategy(),
        )
        filtered_rows = list(getattr(filtered, "data", None) or [])
    except Exception as exc:
        emit_error(label + "_FILTERED", exc)
        continue

    print(label + "_FILTERED_CALL=PASS")
    print(label + "_FILTERED_MATCHES=" + str(len(filtered_rows)))

    try:
        unfiltered = client.list_instanceagent_available_plugins(
            tenancy,
            os_name,
            os_version,
            retry_strategy=NoneRetryStrategy(),
        )
        all_rows = list(getattr(unfiltered, "data", None) or [])
    except Exception as exc:
        emit_error(label + "_UNFILTERED", exc)
        continue

    names = sorted(str(getattr(row, "name", "") or "") for row in all_rows)
    exact = [row for row in all_rows if str(getattr(row, "name", "") or "") == TARGET]
    fingerprint = hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()[:16]

    print(label + "_UNFILTERED_CALL=PASS")
    print(label + "_UNFILTERED_TOTAL=" + str(len(all_rows)))
    print(label + "_PLUGINSET_FINGERPRINT=" + fingerprint)
    print(label + "_TARGET_PRESENT=" + ("YES" if len(exact) == 1 else "NO" if len(exact) == 0 else "AMBIGUOUS"))

    if len(exact) == 1:
        row = exact[0]
        supported = getattr(row, "is_supported", None)
        enabled = getattr(row, "is_enabled_by_default", None)
        print(label + "_TARGET_SUPPORTED=" + ("true" if supported is True else "false" if supported is False else "unknown"))
        print(label + "_TARGET_ENABLED_BY_DEFAULT=" + ("true" if enabled is True else "false" if enabled is False else "unknown"))
    else:
        print(label + "_TARGET_SUPPORTED=absent")
        print(label + "_TARGET_ENABLED_BY_DEFAULT=absent")

print("MATRIX_COMPLETE=YES")
PY

RC=$?
echo "ISSUE387_SDK_PROCESS_RC=$RC"
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
echo '=== ISSUE387_MATRIX=COMPLETE_READ_ONLY ==='
exit 0
