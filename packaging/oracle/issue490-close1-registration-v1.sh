#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json
VDID=/var/lib/technocore-safe-agent/verified-did.json
STATE=/var/lib/technocore-safe-agent/signer/close1-registration.json
SIGNER_ENV=/etc/technocore-safe-agent/signer.env
MODULE=${CLOSE1_REGISTER_MODULE:-}

EXPECTED_HEAD=9baa91be7267b22143c33a06df3c67e1074dba0d
EXPECTED_DID=did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB
MODULE_SHA_A=b1fe435a7fe8ca54584876ce09c1a228
MODULE_SHA_B=5b47e57bd0e82b1d5e0badf2a1e7959d
RES_PID=2462149
CAP_PID=2462148
SIG_PID=2462068
DIS_PID=2462020
CORE_E=124
CORE_M=5651120
BRIDGE_E=7
BRIDGE_M=567965
LOCK_EPOCH=1791104400

stop_reg() {
  echo "CLOSE1_REGISTER_HELPER=STOP:$1"
  echo "POST_ATTEMPTED=NO"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "CLOSE1_REGISTER_HELPER=ERROR:rc_$rc"
  echo "POST_ATTEMPTED=UNKNOWN"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_reg not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" && -f "$SAFETY" && -f "$VDID" && -f "$SIGNER_ENV" ]] || stop_reg required_path_missing
[[ -n "$MODULE" && -f "$MODULE" ]] || stop_reg module_missing
[[ "$(sha256sum "$MODULE" | awk '{print $1}')" == "${MODULE_SHA_A}${MODULE_SHA_B}" ]] || stop_reg module_hash_mismatch
[[ ! -e "$STATE" ]] || stop_reg prior_registration_state_exists
[[ $(date -u +%s) -lt $LOCK_EPOCH ]] || stop_reg registration_window_closed

OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_reg git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

snap() {
  local unit=$1
  printf '%s|%s|%s|%s|%s\n' \
    "$(systemctl show "$unit" -p ActiveState --value)" \
    "$(systemctl show "$unit" -p SubState --value)" \
    "$(systemctl show "$unit" -p MainPID --value)" \
    "$(systemctl show "$unit" -p NRestarts --value)" \
    "$(systemctl show "$unit" -p Result --value)"
}

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$EXPECTED_HEAD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_reg repo_state_changed

[[ "$(snap technocore-safe-agent-resident.service)" == "active|running|$RES_PID|0|success" ]] || stop_reg resident_changed
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "active|running|$CAP_PID|0|success" ]] || stop_reg capture_changed
[[ "$(snap technocore-safe-agent-signer.service)" == "active|running|$SIG_PID|0|success" ]] || stop_reg signer_changed
[[ "$(snap technocore-safe-agent-discord.service)" == "active|running|$DIS_PID|0|success" ]] || stop_reg discord_changed

PREFLIGHT=$("$PY" - "$OBS" "$SAFETY" "$VDID" "$CORE_E" "$CORE_M" "$BRIDGE_E" "$BRIDGE_M" "$EXPECTED_DID" <<'PY'
import json, pathlib, sys
from datetime import UTC, datetime

obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
safety=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
verified=json.loads(pathlib.Path(sys.argv[3]).read_text("utf-8"))
core_e,core_m,bridge_e,bridge_m=map(int,sys.argv[4:8])
expected_did=sys.argv[8]
m=obs.get("metrics") or {}
actual=(
    int(m.get("unrecoverable_core_gap_events",0) or 0),
    int(m.get("unrecoverable_core_gap_messages",0) or 0),
    int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),
    int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0),
)
if actual != (core_e,core_m,bridge_e,bridge_m):
    raise RuntimeError("protected_baseline_changed")
if verified.get("did") != expected_did:
    raise RuntimeError("verified_did_changed")
if (
    safety.get("schema_version") != 1
    or safety.get("health") != "ok"
    or safety.get("unrecoverable_core_gap_events") != core_e
    or safety.get("unrecoverable_core_gap_messages") != core_m
):
    raise RuntimeError("observer_safety_not_ok")
stamp=datetime.fromisoformat(str(safety.get("updated_at","")).replace("Z","+00:00"))
age=(datetime.now(UTC)-stamp).total_seconds()
if not 0 <= age <= 300:
    raise RuntimeError("observer_safety_stale")
print(f"{actual[0]}/{actual[1]}")
print(f"{actual[2]}/{actual[3]}")
PY
) || stop_reg production_safety_preflight_failed

echo "REPO=head:$HEAD branch:$BRANCH clean:YES"
echo "SERVICES=resident:$RES_PID capture:$CAP_PID signer:$SIG_PID discord:$DIS_PID nr0"
echo "PROTECTED=core:$(printf '%s\n' "$PREFLIGHT" | sed -n '1p') bridge:$(printf '%s\n' "$PREFLIGHT" | sed -n '2p')"
echo "APPROVED_DID=$EXPECTED_DID"
echo 'APPROVED_ROOM=close1'
echo 'APPROVED_TEXT={"key":"did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB","season":"close-1","t":"owner"}'

unset SIGN_SEED || true
set -a
# shellcheck disable=SC1090
source "$SIGNER_ENV"
set +a
[[ "${TECHNOCORE_SIGNER_EXPECTED_DID:-}" == "$EXPECTED_DID" ]] || stop_reg signer_expected_did_changed
[[ -n "${OCI_VAULT_SECRET_OCID:-}" ]] || stop_reg vault_identifier_missing
[[ -z "${SIGN_SEED:-}" ]] || stop_reg raw_seed_env_forbidden

ENV_TMP=$(mktemp /run/close1-register-env.XXXXXX)
trap 'rm -f "$ENV_TMP"' EXIT
{
  printf 'OCI_VAULT_SECRET_OCID=%q\n' "$OCI_VAULT_SECRET_OCID"
  printf 'TECHNOCORE_SIGNER_EXPECTED_DID=%q\n' "$TECHNOCORE_SIGNER_EXPECTED_DID"
  printf 'FLOP_STATE_DIR=%q\n' /var/lib/technocore-safe-agent
  printf 'PYTHONPATH=%q\n' /opt/technocore-safe-agent/src
  printf 'UV_CACHE_DIR=%q\n' /var/lib/technocore-safe-agent/signer/uv-cache
  printf 'PATH=%q\n' /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
} > "$ENV_TMP"
chown technocore-signer:technocore-signer "$ENV_TMP"
chmod 0400 "$ENV_TMP"

echo "CLOSE1_REGISTER_HELPER=INVOKING_APPROVED_BINDING_ACTION"
set +e
runuser -u technocore-signer -- /bin/bash -c 'set -a; source "$1"; set +a; exec "$2" "$3"' _ "$ENV_TMP" "$PY" "$MODULE"
CHILD_RC=$?
set -e

if [[ $CHILD_RC -ne 0 ]]; then
  echo "CLOSE1_REGISTER_HELPER=CHILD_RC_$CHILD_RC"
  echo "DO_NOT_RERUN=YES"
  exit 0
fi

POSTCHECK=$("$PY" - "$OBS" "$CORE_E" "$CORE_M" "$BRIDGE_E" "$BRIDGE_M" <<'PY'
import json, pathlib, sys
obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
expected=tuple(map(int,sys.argv[2:6]))
m=obs.get("metrics") or {}
actual=(
 int(m.get("unrecoverable_core_gap_events",0) or 0),
 int(m.get("unrecoverable_core_gap_messages",0) or 0),
 int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),
 int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0),
)
if actual != expected:
    raise RuntimeError("protected_baseline_changed")
print(f"{actual[0]}/{actual[1]} {actual[2]}/{actual[3]}")
PY
) || {
  echo "CLOSE1_REGISTER_HELPER=POSTCHECK_STOP:protected_changed"
  echo "DO_NOT_RERUN=YES"
  exit 0
}

[[ "$(snap technocore-safe-agent-resident.service)" == "active|running|$RES_PID|0|success" ]] || {
  echo "CLOSE1_REGISTER_HELPER=POSTCHECK_STOP:resident_changed"; echo "DO_NOT_RERUN=YES"; exit 0;
}
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "active|running|$CAP_PID|0|success" ]] || {
  echo "CLOSE1_REGISTER_HELPER=POSTCHECK_STOP:capture_changed"; echo "DO_NOT_RERUN=YES"; exit 0;
}
[[ "$(snap technocore-safe-agent-signer.service)" == "active|running|$SIG_PID|0|success" ]] || {
  echo "CLOSE1_REGISTER_HELPER=POSTCHECK_STOP:signer_changed"; echo "DO_NOT_RERUN=YES"; exit 0;
}
[[ "$(snap technocore-safe-agent-discord.service)" == "active|running|$DIS_PID|0|success" ]] || {
  echo "CLOSE1_REGISTER_HELPER=POSTCHECK_STOP:discord_changed"; echo "DO_NOT_RERUN=YES"; exit 0;
}

echo "POST_PROTECTED=$POSTCHECK"
echo "CLOSE1_REGISTER_HELPER=COMPLETE"
echo "DO_NOT_RERUN=YES"
