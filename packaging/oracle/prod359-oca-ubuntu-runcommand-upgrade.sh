#!/usr/bin/env bash
# One-shot guarded Oracle Cloud Agent snap upgrade for Ubuntu Run Command support.
# Branch-only operational helper. DO NOT MERGE.
# Any terminal PASS/STOP/disconnect => DO_NOT_RERUN until independent reconciliation.
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
OBS="$STATE/observer/observer-state.json"

EXPECTED_REPO=b7bf27dbaa605971d340aa926fdffc17489c3afe
EXPECTED_CORE_EVENTS=117
EXPECTED_CORE_MESSAGES=5083155
PRE_VERSION=1.60.0-1
PRE_REVISION=121
TARGET_VERSION=1.61.0-6

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service
OCA=snap.oracle-cloud-agent.oracle-cloud-agent.service
OCA_UPDATER=snap.oracle-cloud-agent.oracle-cloud-agent-updater.service

META_CHAIN=TECHNOCORE_METADATA
META_IP=169.254.169.254/32
IMDS_URL=http://169.254.169.254/opc/v2/instance/

REFRESH_COMPLETED=0
DONE=0

stop() {
  local reason=$1
  trap - ERR
  echo "PROD359=STOP:$reason"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'stop unexpected_rc_$?' ERR

[[ $EUID -eq 0 ]] || stop run_as_root
[[ -d $APP/.git && -f $OBS ]] || stop production_paths_missing
command -v snap >/dev/null 2>&1 || stop snap_missing
command -v curl >/dev/null 2>&1 || stop curl_missing
command -v iptables >/dev/null 2>&1 || stop iptables_missing

OWNER=$(stat -c %U "$APP/.git") || stop git_owner_unreadable
[[ -n $OWNER ]] || stop git_owner_missing

git_owner() { sudo -u "$OWNER" git -C "$APP" "$@"; }
svc_value() { systemctl show "$1" -p "$2" --value; }

snap_version() {
  snap list oracle-cloud-agent 2>/dev/null | awk 'NR==2 {print $2; exit}'
}

snap_revision() {
  snap list oracle-cloud-agent 2>/dev/null | awk 'NR==2 {print $3; exit}'
}

stable_version() {
  snap info oracle-cloud-agent 2>/dev/null | awk '$1=="latest/stable:" {print $2; exit}'
}

snap_tracking() {
  snap info oracle-cloud-agent 2>/dev/null | awk '$1=="tracking:" {print $2; exit}'
}

observer_snapshot() {
  python3 - "$OBS" <<'PY'
import json, pathlib, sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
h=d.get("health") or {}
m=d.get("metrics") or {}
print(
    h.get("current","missing"),
    m.get("unrecoverable_core_gap_events","missing"),
    m.get("unrecoverable_core_gap_messages","missing"),
)
PY
}

root_imds_code() {
  curl -sS --connect-timeout 3 --max-time 5     -H 'Authorization: Bearer Oracle'     -o /dev/null -w '%{http_code}' "$IMDS_URL" 2>/dev/null || true
}

technocore_imds_code() {
  sudo -u technocore curl -sS --connect-timeout 2 --max-time 3     -H 'Authorization: Bearer Oracle'     -o /dev/null -w '%{http_code}' "$IMDS_URL" 2>/dev/null || true
}

metadata_gate() {
  iptables -C OUTPUT -p tcp -d "$META_IP" --dport 80 -j "$META_CHAIN" >/dev/null 2>&1     || stop metadata_output_jump_missing
  iptables -C "$META_CHAIN" -m owner --uid-owner 0 -j RETURN >/dev/null 2>&1     || stop metadata_root_return_missing
  signer_uid=$(id -u technocore-signer 2>/dev/null) || stop signer_account_missing
  iptables -C "$META_CHAIN" -m owner --uid-owner "$signer_uid" -j RETURN >/dev/null 2>&1     || stop metadata_signer_return_missing
  iptables -C "$META_CHAIN" -j REJECT >/dev/null 2>&1     || stop metadata_final_reject_missing
}

app_gate() {
  local label=$1
  for svc in "$META" "$RES" "$CAP" "$SIG" "$DIS"; do
    systemctl is-active --quiet "$svc" || stop "$label:required_service_not_active:$svc"
  done

  local health events messages
  read -r health events messages < <(observer_snapshot) || stop "$label:observer_unreadable"
  [[ $health == ok ]] || stop "$label:observer_not_ok:$health"
  [[ $events == "$EXPECTED_CORE_EVENTS" && $messages == "$EXPECTED_CORE_MESSAGES" ]]     || stop "$label:protected_core_changed:$events/$messages"

  [[ "$(root_imds_code)" == 200 ]] || stop "$label:root_imds_not_200"
  tc_code=$(technocore_imds_code)
  [[ $tc_code != 200 ]] || stop "$label:technocore_imds_unexpectedly_allowed"

  metadata_gate
  [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == yes ]]     || stop "$label:ntp_not_synchronized"

  echo "PROD359_GATE=$label observer=$health core=$events/$messages root_imds=200 technocore_imds_blocked=yes"
}

wait_oca() {
  for _ in {1..60}; do
    if systemctl is-active --quiet "$OCA" && systemctl is-active --quiet "$OCA_UPDATER"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

rollback() {
  local rc=$?
  trap - ERR
  set +e

  if [[ $DONE -eq 0 && $REFRESH_COMPLETED -eq 1 ]]; then
    snap revert oracle-cloud-agent >/tmp/prod359-snap-revert.log 2>&1
    revert_rc=$?
    wait_oca
    echo "PROD359_ROLLBACK_RC=$revert_rc" >&2
    echo "PROD359_ROLLBACK_VERSION=$(snap_version)" >&2
    echo "PROD359_ROLLBACK_REVISION=$(snap_revision)" >&2
  fi

  rm -f /tmp/prod359-snap-revert.log
  exit "$rc"
}
trap rollback EXIT

cd "$APP"
[[ "$(git_owner symbolic-ref --short HEAD)" == main ]] || stop branch_not_main
[[ "$(git_owner rev-parse HEAD)" == "$EXPECTED_REPO" ]]   || stop "unexpected_production_head:$(git_owner rev-parse HEAD)"
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop dirty_worktree

declare -A PID_PRE RESTART_PRE
for svc in "$RES" "$CAP" "$SIG" "$DIS"; do
  PID_PRE["$svc"]=$(svc_value "$svc" MainPID)
  RESTART_PRE["$svc"]=$(svc_value "$svc" NRestarts)
  [[ ${PID_PRE[$svc]:-0} =~ ^[1-9][0-9]*$ ]] || stop "invalid_mainpid:$svc"
done

systemctl is-active --quiet "$OCA" || stop oca_not_active
systemctl is-active --quiet "$OCA_UPDATER" || stop oca_updater_not_active
[[ "$(systemctl is-enabled "$OCA" 2>/dev/null)" == enabled ]] || stop oca_not_enabled
[[ "$(systemctl is-enabled "$OCA_UPDATER" 2>/dev/null)" == enabled ]] || stop oca_updater_not_enabled
[[ "$(svc_value "$OCA" Result)" == success ]] || stop oca_result_not_success
[[ "$(svc_value "$OCA_UPDATER" Result)" == success ]] || stop oca_updater_result_not_success

PRE_ACTUAL_VERSION=$(snap_version)
PRE_ACTUAL_REVISION=$(snap_revision)
[[ $PRE_ACTUAL_VERSION == "$PRE_VERSION" ]]   || stop "unexpected_oca_version:$PRE_ACTUAL_VERSION"
[[ $PRE_ACTUAL_REVISION == "$PRE_REVISION" ]]   || stop "unexpected_oca_revision:$PRE_ACTUAL_REVISION"

REMOTE_STABLE=$(stable_version)
TRACKING=$(snap_tracking)
[[ $REMOTE_STABLE == "$TARGET_VERSION" ]]   || stop "stable_target_moved:expected=$TARGET_VERSION:actual=$REMOTE_STABLE"

if snap changes 2>/dev/null | awk 'NR>1 && $2=="Doing" {found=1} END {exit found?0:1}'; then
  stop snap_change_in_progress
fi

FREE_KIB=$(df -Pk /var/lib/snapd 2>/dev/null | awk 'NR==2 {print $4}')
[[ $FREE_KIB =~ ^[0-9]+$ && $FREE_KIB -ge 524288 ]] || stop "insufficient_snap_disk_kib:$FREE_KIB"

app_gate pre

echo "PROD359_PREFLIGHT=PASS version=$PRE_ACTUAL_VERSION revision=$PRE_ACTUAL_REVISION tracking=${TRACKING:-unknown} stable=$REMOTE_STABLE"

if ! snap refresh oracle-cloud-agent --channel=latest/stable; then
  CURRENT_AFTER_FAILED_REFRESH=$(snap_version)
  if [[ $CURRENT_AFTER_FAILED_REFRESH != "$PRE_VERSION" ]]; then
    REFRESH_COMPLETED=1
  fi
  stop "snap_refresh_failed:current=$CURRENT_AFTER_FAILED_REFRESH"
fi
REFRESH_COMPLETED=1

wait_oca || stop oca_services_not_active_after_refresh
sleep 5

POST_VERSION=$(snap_version)
POST_REVISION=$(snap_revision)
[[ $POST_VERSION == "$TARGET_VERSION" ]]   || stop "post_version_mismatch:$POST_VERSION"

systemctl is-active --quiet "$OCA" || stop post_oca_not_active
systemctl is-active --quiet "$OCA_UPDATER" || stop post_oca_updater_not_active
[[ "$(svc_value "$OCA" Result)" == success ]] || stop post_oca_result_not_success
[[ "$(svc_value "$OCA_UPDATER" Result)" == success ]] || stop post_oca_updater_result_not_success

for svc in "$RES" "$CAP" "$SIG" "$DIS"; do
  [[ "$(svc_value "$svc" MainPID)" == "${PID_PRE[$svc]}" ]]     || stop "unexpected_app_pid_change:$svc"
  [[ "$(svc_value "$svc" NRestarts)" == "${RESTART_PRE[$svc]}" ]]     || stop "unexpected_app_restart_change:$svc"
done

app_gate post

OCARUN_PRESENT=NO
id -u ocarun >/dev/null 2>&1 && OCARUN_PRESENT=YES

RUNCOMMAND_ARTIFACT=NO
for base in /snap/oracle-cloud-agent/current /var/snap/oracle-cloud-agent/common; do
  if [[ -e "$base" ]]; then
    artifact=$(find "$base" -maxdepth 8 \( -iname '*runcommand*' -o -iname '*run-command*' \) -print -quit 2>/dev/null || true)
    if [[ -n "$artifact" ]]; then
      RUNCOMMAND_ARTIFACT=YES
      break
    fi
  fi
done

DONE=1
trap - EXIT

printf '%s\n'   "PROD359=PASS"   "REPO_HEAD=$(git_owner rev-parse HEAD)"   "OCA_PRE_VERSION=$PRE_ACTUAL_VERSION"   "OCA_PRE_REVISION=$PRE_ACTUAL_REVISION"   "OCA_POST_VERSION=$POST_VERSION"   "OCA_POST_REVISION=$POST_REVISION"   "OCA_TRACKING_BEFORE=${TRACKING:-unknown}"   "OCA_SERVICE=active"   "OCA_UPDATER=active"   "OCARUN_ACCOUNT_PRESENT=$OCARUN_PRESENT"   "RUN_COMMAND_LOCAL_ARTIFACT=$RUNCOMMAND_ARTIFACT"   "ROOT_IMDS_HTTP=200"   "TECHNOCORE_IMDS_BLOCKED=YES"   "PROTECTED_CORE=$EXPECTED_CORE_EVENTS/$EXPECTED_CORE_MESSAGES"   "RESIDENT_PRESERVED=${PID_PRE[$RES]}/NRestarts=${RESTART_PRE[$RES]}"   "CAPTURE_PRESERVED=${PID_PRE[$CAP]}/NRestarts=${RESTART_PRE[$CAP]}"   "SIGNER_PRESERVED=${PID_PRE[$SIG]}/NRestarts=${RESTART_PRE[$SIG]}"   "DISCORD_PRESERVED=${PID_PRE[$DIS]}/NRestarts=${RESTART_PRE[$DIS]}"   "APP_RESTART=NO"   "FIREWALL_CHANGE=NO"   "RUN_COMMAND_CREATED=NO"   "OCI_AGENT_CONFIG_CHANGE=NO"   "TECHNOCORE_WRITE=NO"   "FLOP_EXTERNAL_WRITE=NO"   "X_WRITE=NO"   "DO_NOT_RERUN=YES"
