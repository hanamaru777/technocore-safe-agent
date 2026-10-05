#!/usr/bin/env bash
# Issue #733: read-only OCI Bastion feasibility preflight via real OCI Cloud Shell.
#
# The target instance OCID is accepted only through the local environment and is
# never printed, persisted, committed, or included in an error message or argv.
set -u
umask 077

echo '=== ISSUE733 OCI BASTION READ-ONLY PREFLIGHT ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

stop_safe() {
  echo "CLOUDSHELL_ENV=STOP:$1"
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
}

if [[ "${OCI_CLI_AUTH:-}" != "instance_obo_user" ]]; then
  stop_safe 'not_instance_obo_user'
fi
if [[ "${OCI_CLI_CONFIG_FILE:-}" != "/etc/oci/config" ]]; then
  stop_safe 'unexpected_config_path'
fi
if [[ -z "${OCI_CLI_PROFILE:-}" ]]; then
  stop_safe 'missing_profile'
fi
if [[ ! -r /etc/oci/delegation_token ]]; then
  stop_safe 'delegation_token_unreadable'
fi
if [[ -z "${TECHNOCORE_TARGET_INSTANCE_OCID:-}" ]]; then
  echo 'CLOUDSHELL_ENV=PASS'
  echo 'TARGET_INSTANCE_INPUT=STOP:missing_private_env'
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
fi

PYTHON=''
for candidate in python3 /usr/bin/python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" - <<'PY' >/dev/null 2>&1
import oci
from oci.auth.signers import InstancePrincipalsDelegationTokenSigner
from oci.bastion import BastionClient
from oci.core import ComputeClient, VirtualNetworkClient
PY
    then
      PYTHON=$(command -v "$candidate")
      break
    fi
  fi
done

if [[ -z "$PYTHON" ]]; then
  echo 'CLOUDSHELL_ENV=PASS'
  echo 'OCI_PYTHON_SDK_PRESENT=NO'
  echo 'BASTION_PREFLIGHT=UNAVAILABLE'
  echo 'MUTATION_COMMANDS=NONE'
  exit 0
fi

echo 'CLOUDSHELL_ENV=PASS'
echo 'OCI_PYTHON_SDK_PRESENT=YES'
echo 'TARGET_INSTANCE_INPUT=ACCEPTED_PRIVATE'

"$PYTHON" - "$OCI_CLI_CONFIG_FILE" "$OCI_CLI_PROFILE" <<'PY'
import configparser
import os
import pathlib
import re
import sys

import oci
from oci.auth.signers import InstancePrincipalsDelegationTokenSigner
from oci.bastion import BastionClient
from oci.core import ComputeClient, VirtualNetworkClient
from oci.exceptions import ServiceError
from oci.retry import NoneRetryStrategy

CONFIG_PATH = pathlib.Path(sys.argv[1])
PROFILE = sys.argv[2]
TARGET_INSTANCE_ID = os.environ.get('TECHNOCORE_TARGET_INSTANCE_OCID', '')
TOKEN_PATH = pathlib.Path('/etc/oci/delegation_token')
OCID_RE = re.compile(r'^ocid1\.instance\.[A-Za-z0-9._-]+$')


def emit_service_failure(prefix, exc):
    status = int(getattr(exc, 'status', 0) or 0)
    code = str(getattr(exc, 'code', '') or '')
    if status in (401, 403) or code in {
        'NotAuthorized', 'NotAuthenticated', 'NotAuthorizedOrNotFound'
    }:
        classification = 'AUTHORIZATION'
    elif status == 404:
        classification = 'NOT_FOUND_OR_AUTHORIZATION'
    elif status in (408, 429, 500, 502, 503, 504):
        classification = 'TRANSIENT_SERVICE'
    else:
        classification = 'SERVICE_OTHER'
    print(prefix + '=FAIL')
    print(prefix + '_ERROR_CLASS=' + classification)
    if status:
        print(prefix + '_HTTP_STATUS=' + str(status))


def stop(label):
    print('BASTION_PREFLIGHT=STOP:' + label)
    raise SystemExit(0)


if not OCID_RE.fullmatch(TARGET_INSTANCE_ID):
    stop('target_instance_input_invalid')

cfg = configparser.ConfigParser(interpolation=None)
try:
    cfg.read(CONFIG_PATH)
except Exception:
    stop('config_read_failed')
if PROFILE not in cfg:
    stop('profile_missing')
section = cfg[PROFILE]
region = section.get('region', '').strip()
if not region:
    stop('region_missing')

try:
    token = TOKEN_PATH.read_text('utf-8').strip()
except Exception:
    stop('delegation_token_read_failed')
if not token:
    stop('delegation_token_empty')

try:
    signer = InstancePrincipalsDelegationTokenSigner(
        delegation_token=token,
        federation_client_retry_strategy=NoneRetryStrategy(),
    )
    client_config = {'region': region}
    compute = ComputeClient(
        client_config,
        signer=signer,
        timeout=(5, 20),
        retry_strategy=NoneRetryStrategy(),
    )
    network = VirtualNetworkClient(
        client_config,
        signer=signer,
        timeout=(5, 20),
        retry_strategy=NoneRetryStrategy(),
    )
    bastion = BastionClient(
        client_config,
        signer=signer,
        timeout=(5, 20),
        retry_strategy=NoneRetryStrategy(),
    )
except Exception:
    stop('sdk_client_init_failed')

print('SDK_CLIENT_INIT=PASS')
print('OCI_PYTHON_SDK_VERSION=' + str(getattr(oci, '__version__', 'UNKNOWN')))
print('OCID_OUTPUT=NO')
print('IP_OUTPUT=NO')
print('DELEGATION_TOKEN_OUTPUT=NO')

try:
    instance = compute.get_instance(
        TARGET_INSTANCE_ID,
        retry_strategy=NoneRetryStrategy(),
    ).data
except ServiceError as exc:
    emit_service_failure('TARGET_INSTANCE_READ', exc)
    stop('target_instance_read_failed')
except Exception:
    print('TARGET_INSTANCE_READ=FAIL')
    print('TARGET_INSTANCE_READ_ERROR_CLASS=OTHER')
    stop('target_instance_read_failed')

compartment_id = str(getattr(instance, 'compartment_id', '') or '')
instance_state = str(getattr(instance, 'lifecycle_state', '') or '').upper()
if not compartment_id:
    stop('target_instance_compartment_missing')
print('TARGET_INSTANCE_READ=PASS')
print('TARGET_INSTANCE_RUNNING=' + ('YES' if instance_state == 'RUNNING' else 'NO'))

try:
    attachments = list(
        compute.list_vnic_attachments(
            compartment_id,
            instance_id=TARGET_INSTANCE_ID,
            retry_strategy=NoneRetryStrategy(),
        ).data or []
    )
except ServiceError as exc:
    emit_service_failure('TARGET_VNIC_READ', exc)
    stop('target_vnic_read_failed')
except Exception:
    print('TARGET_VNIC_READ=FAIL')
    print('TARGET_VNIC_READ_ERROR_CLASS=OTHER')
    stop('target_vnic_read_failed')

attached = [
    row for row in attachments
    if str(getattr(row, 'lifecycle_state', '') or '').upper() == 'ATTACHED'
    and getattr(row, 'vnic_id', None)
]
if not attached:
    stop('target_attached_vnic_missing')
print('TARGET_VNIC_READ=PASS')
print('TARGET_ATTACHED_VNIC_COUNT=' + str(len(attached)))

try:
    vnic = network.get_vnic(
        attached[0].vnic_id,
        retry_strategy=NoneRetryStrategy(),
    ).data
    subnet_id = str(getattr(vnic, 'subnet_id', '') or '')
    if not subnet_id:
        stop('target_subnet_missing')
    subnet = network.get_subnet(
        subnet_id,
        retry_strategy=NoneRetryStrategy(),
    ).data
    vcn_id = str(getattr(subnet, 'vcn_id', '') or '')
    subnet_compartment_id = str(getattr(subnet, 'compartment_id', '') or '')
    if not vcn_id or not subnet_compartment_id:
        stop('target_network_context_missing')
except ServiceError as exc:
    emit_service_failure('TARGET_NETWORK_READ', exc)
    stop('target_network_read_failed')
except Exception:
    print('TARGET_NETWORK_READ=FAIL')
    print('TARGET_NETWORK_READ_ERROR_CLASS=OTHER')
    stop('target_network_read_failed')

print('TARGET_NETWORK_READ=PASS')
print('TARGET_NETWORK_CONTEXT=RESOLVED_PRIVATE')

# Read only the VCN compartment. This is sufficient to identify a directly
# colocated existing candidate without claiming tenancy-wide absence.
try:
    rows = list(
        bastion.list_bastions(
            subnet_compartment_id,
            bastion_lifecycle_state='ACTIVE',
            retry_strategy=NoneRetryStrategy(),
        ).data or []
    )
except ServiceError as exc:
    emit_service_failure('BASTION_LIST_READ', exc)
    stop('bastion_list_read_failed')
except Exception:
    print('BASTION_LIST_READ=FAIL')
    print('BASTION_LIST_READ_ERROR_CLASS=OTHER')
    stop('bastion_list_read_failed')

same_vcn = [
    row for row in rows
    if str(getattr(row, 'target_vcn_id', '') or '') == vcn_id
]
print('BASTION_LIST_READ=PASS')
print('BASTION_SEARCH_SCOPE=TARGET_VCN_COMPARTMENT')
print('ACTIVE_BASTION_COUNT_IN_SCOPE=' + str(len(rows)))
print('ACTIVE_BASTION_SAME_VCN_COUNT=' + str(len(same_vcn)))
print('EXISTING_BASTION_SAME_VCN=' + ('YES' if same_vcn else 'NO'))

# A read-only query cannot prove create-session IAM or the actual target-port
# network path. Keep these explicitly unverified until a separate controlled
# short-lived session proof is authorized and executed.
print('SESSION_CREATE_PERMISSION=UNVERIFIED_READ_ONLY')
print('TARGET_PORT22_PATH=UNVERIFIED_READ_ONLY')
print('CONTROL_PATH_READY=NO')
if same_vcn:
    print('PHASE1_RESULT=EXISTING_BASTION_CANDIDATE')
else:
    print('PHASE1_RESULT=NO_EXISTING_BASTION_IN_TARGET_VCN_COMPARTMENT')
print('BASTION_PREFLIGHT=PASS_READ_ONLY')
PY

RC=$?
echo "ISSUE733_SDK_PROCESS_RC=$RC"
echo '--- SAFETY TAIL ---'
echo 'MUTATION_COMMANDS=NONE'
echo 'BASTION_CREATED=NO'
echo 'SESSION_CREATED=NO'
echo 'IAM_CHANGE=NO'
echo 'NETWORK_CHANGE=NO'
echo 'PLUGIN_CHANGE=NO'
echo 'INSTANCE_CHANGE=NO'
echo 'PRODUCTION_SSH_ACTION=NO'
echo 'OCID_OUTPUT=NO'
echo 'IP_OUTPUT=NO'
echo 'DELEGATION_TOKEN_OUTPUT=NO'
echo 'RAW_OCI_ERROR_OUTPUT=NO'
echo 'CONTROL_PATH_REDUNDANCY_GATE_CHANGED=NO'
echo '=== ISSUE733_PREFLIGHT=COMPLETE_READ_ONLY ==='
exit 0
