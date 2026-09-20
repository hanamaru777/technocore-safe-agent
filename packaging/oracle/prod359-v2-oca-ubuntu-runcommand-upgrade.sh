#!/usr/bin/env bash
# Successor one-shot guarded Oracle Cloud Agent snap upgrade for Ubuntu Run Command support.
# Built only after the #361 independent read-only reconciliation. Branch-only; DO NOT MERGE.
# PR #360 is consumed and must never be rerun. Any terminal PASS/STOP/disconnect here => DO_NOT_RERUN until a new independent reconciliation.
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
OBHB=$STATE/observer/observer-heartbeat.json
RESHB=$STATE/observer/resident-heartbeat.json

EXPECTED_REPO=b7bf27dbaa605971d340aa926fdffc17489c3afe
EXPECTED_ORIGIN_MAIN=43db3595a52bb2e19777a1c1c91842c06408f48b
EXPECTED_CORE_EVENTS=117
EXPECTED_CORE_MESSAGES=5083155
PRE_VERSION=1.60.0-1
PRE_REVISION=121
TARGET_VERSION=1.61.0-6
TARGET_REVISION=126
EXPECTED_TRACKING=latest/stable/ubuntu-24.04
EXPECTED_HOLD=forever

EXPECTED_RES_PID=1868797
EXPECTED_RES_RESTARTS=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0
EXPECTED_SIG_PID=1539554
EXPECTED_SIG_RESTARTS=1
EXPECTED_DIS_PID=1957840
EXPECTED_DIS_RESTARTS=0

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
  echo "PROD359V2=STOP:$reason"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'stop unexpected_rc_$?' ERR

[[ $EUID -eq 0 ]] || stop run_as_root
[[ -d $APP/.git && -f $OBS && -f $OBHB && -f $RESHB ]] || stop production_paths_missing
command -v snap >/dev/null 2>&1 || stop snap_missing
command -v curl >/dev/null 2>&1 || stop curl_missing
command -v iptables >/dev/null 2>&1 || stop iptables_missing
command -v python3 >/dev/null 2>&1 || stop python_missing

OWNER=$(stat -c %U "$APP/.git") || stop git_owner_unreadable
[[ -n $OWNER ]] || stop git_owner_missing

git_owner() { sudo -u "$OWNER" git -C "$APP" "$@"; }
svc_value() { systemctl show "$1" -p "$2" --value; }

read_snap_list_state() {
  local raw fields
  raw=$(snap list oracle-cloud-agent 2>&1) || stop snap_list_failed
  fields=$(python3 - "$raw" <<'PY'
import sys
lines=[line for line in sys.argv[1].splitlines() if line.strip()]
if len(lines) < 2:
    raise SystemExit(2)
parts=lines[1].split()
if len(parts) < 6 or parts[0] != "oracle-cloud-agent":
    raise SystemExit(3)
version, revision, notes = parts[1], parts[2], parts[-1]
if not revision.isdigit():
    raise SystemExit(4)
print("\t".join((version, revision, notes)))
PY
) || stop snap_list_parse_failed
  IFS=$'\t' read -r SNAP_VERSION SNAP_REVISION SNAP_NOTES <<< "$fields"
  [[ -n $SNAP_VERSION && -n $SNAP_REVISION && -n $SNAP_NOTES ]] || stop snap_list_fields_missing
}

read_snap_info_state() {
  local raw fields
  raw=$(snap info oracle-cloud-agent 2>&1) || stop snap_info_failed
  fields=$(python3 - "$raw" <<'PY'
import re, sys
tracking=hold=stable_version=stable_revision=None
for line in sys.argv[1].splitlines():
    stripped=line.strip()
    if stripped.startswith("tracking:"):
        tracking=stripped.split(None,1)[1].strip()
    elif stripped.startswith("hold:"):
        hold=stripped.split(None,1)[1].strip()
    elif stripped.startswith("latest/stable:"):
        m=re.match(r"latest/stable:\s+(\S+).*?\((\d+)\)", stripped)
        if m:
            stable_version, stable_revision=m.groups()
if not all((tracking, hold, stable_version, stable_revision)):
    raise SystemExit(2)
print("\t".join((tracking, hold, stable_version, stable_revision)))
PY
) || stop snap_info_parse_failed
  IFS=$'\t' read -r SNAP_TRACKING SNAP_HOLD SNAP_STABLE_VERSION SNAP_STABLE_REVISION <<< "$fields"
}

read_snap_change_state() {
  local raw state
  raw=$(snap changes 2>&1) || stop snap_changes_failed
  state=$(python3 - "$raw" <<'PY'
import sys
lines=[line for line in sys.argv[1].splitlines() if line.strip()]
if lines == ["no changes found"]:
    print("NO")
    raise SystemExit
if not lines:
    raise SystemExit(2)
for line in lines[1:]:
    parts=line.split()
    if len(parts) >= 2 and parts[1] in {"Doing","Undo","Hold"}:
        print("YES")
        raise SystemExit
print("NO")
PY
) || stop snap_changes_parse_failed
  SNAP_CHANGE_IN_PROGRESS=$state
}

read_snap_free_kib() {
  local raw value
  raw=$(df -Pk /var/lib/snapd 2>&1) || stop snap_df_failed
  value=$(python3 - "$raw" <<'PY'
import sys
lines=[line for line in sys.argv[1].splitlines() if line.strip()]
if len(lines) < 2:
    raise SystemExit(2)
parts=lines[-1].split()
if len(parts) < 6 or not parts[3].isdigit():
    raise SystemExit(3)
print(parts[3])
PY
) || stop snap_df_parse_failed
  SNAP_FREE_KIB=$value
}

observer_snapshot() {
  python3 - "$OBS" "$OBHB" "$RESHB" <<'PY'
import json, pathlib, sys
from datetime import UTC, datetime

def load(path):
    return json.loads(pathlib.Path(path).read_text("utf-8"))

def age(value):
    try:
        dt=datetime.fromisoformat(value)
    except Exception:
        return -1
    return max(0, int((datetime.now(UTC)-dt).total_seconds()))

state=load(sys.argv[1])
observer_hb=load(sys.argv[2])
resident_hb=load(sys.argv[3])
health=state.get("health") or {}
metrics=state.get("metrics") or {}
resident_status=resident_hb.get("resident_status") or {}
values=(
    health.get("current","missing"),
    metrics.get("unrecoverable_core_gap_events","missing"),
    metrics.get("unrecoverable_core_gap_messages","missing"),
    age(state.get("updated_at")),
    observer_hb.get("status","missing"),
    age(observer_hb.get("updated_at")),
    resident_hb.get("status","missing"),
    age(resident_hb.get("updated_at")),
    age(resident_status.get("last_refresh_at")),
)
print("\t".join(map(str, values)))
PY
}

wait_observer_ready() {
  local label=$1
  local attempt snapshot health events messages state_age observer_status observer_age resident_status resident_age refresh_age

  for attempt in {1..13}; do
    snapshot=$(observer_snapshot) || stop "$label:observer_unreadable"
    IFS=$'\t' read -r health events messages state_age observer_status observer_age resident_status resident_age refresh_age <<< "$snapshot"

    [[ $events == "$EXPECTED_CORE_EVENTS" && $messages == "$EXPECTED_CORE_MESSAGES" ]] \
      || stop "$label:protected_core_changed:$events/$messages"

    if [[ $health == ok && $observer_status == ok && $resident_status == ok \
          && $state_age =~ ^[0-9]+$ && $observer_age =~ ^[0-9]+$ \
          && $resident_age =~ ^[0-9]+$ && $refresh_age =~ ^[0-9]+$ \
          && $state_age -le 300 && $observer_age -le 300 \
          && $resident_age -le 300 && $refresh_age -le 300 ]]; then
      echo "PROD359V2_OBSERVER=$label health=ok core=$events/$messages state_age=$state_age observer_hb_age=$observer_age resident_hb_age=$resident_age refresh_age=$refresh_age"
      return 0
    fi

    if [[ $attempt -lt 13 ]]; then
      sleep 10
    fi
  done

  stop "$label:observer_not_ready:health=$health:observer_hb=$observer_status:resident_hb=$resident_status"
}

root_imds_code() {
  curl -sS --connect-timeout 3 --max-time 5 \
    -H 'Authorization: Bearer Oracle' \
    -o /dev/null -w '%{http_code}' "$IMDS_URL" 2>/dev/null || true
}

technocore_imds_code() {
  sudo -u technocore curl -sS --connect-timeout 2 --max-time 3 \
    -H 'Authorization: Bearer Oracle' \
    -o /dev/null -w '%{http_code}' "$IMDS_URL" 2>/dev/null || true
}

metadata_gate() {
  iptables -C OUTPUT -p tcp -d "$META_IP" --dport 80 -j "$META_CHAIN" >/dev/null 2>&1 \
    || stop metadata_output_jump_missing
  iptables -C "$META_CHAIN" -m owner --uid-owner 0 -j RETURN >/dev/null 2>&1 \
    || stop metadata_root_return_missing
  signer_uid=$(id -u technocore-signer 2>/dev/null) || stop signer_account_missing
  iptables -C "$META_CHAIN" -m owner --uid-owner "$signer_uid" -j RETURN >/dev/null 2>&1 \
    || stop metadata_signer_return_missing
  iptables -C "$META_CHAIN" -j REJECT >/dev/null 2>&1 \
    || stop metadata_final_reject_missing
}

app_gate() {
  local label=$1
  local tc_code
  for svc in "$META" "$RES" "$CAP" "$SIG" "$DIS"; do
    systemctl is-active --quiet "$svc" || stop "$label:required_service_not_active:$svc"
  done

  wait_observer_ready "$label"

  [[ "$(root_imds_code)" == 200 ]] || stop "$label:root_imds_not_200"
  tc_code=$(technocore_imds_code)
  [[ $tc_code != 200 ]] || stop "$label:technocore_imds_unexpectedly_allowed"

  metadata_gate
  [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == yes ]] \
    || stop "$label:ntp_not_synchronized"

  echo "PROD359V2_GATE=$label observer_ready=yes core=$EXPECTED_CORE_EVENTS/$EXPECTED_CORE_MESSAGES root_imds=200 technocore_imds_blocked=yes"
}

wait_oca() {
  local attempt
  for attempt in {1..60}; do
    if systemctl is-active --quiet "$OCA" && systemctl is-active --quiet "$OCA_UPDATER"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

rollback() {
  local rc=$?
  local revert_rc
  trap - ERR
  set +e

  if [[ $DONE -eq 0 && $REFRESH_COMPLETED -eq 1 ]]; then
    snap revert oracle-cloud-agent --revision="$PRE_REVISION" >/tmp/prod359-v2-snap-revert.log 2>&1
    revert_rc=$?
    wait_oca
    read_snap_list_state
    echo "PROD359V2_ROLLBACK_RC=$revert_rc" >&2
    echo "PROD359V2_ROLLBACK_VERSION=$SNAP_VERSION" >&2
    echo "PROD359V2_ROLLBACK_REVISION=$SNAP_REVISION" >&2
  fi

  rm -f /tmp/prod359-v2-snap-revert.log
  exit "$rc"
}
trap rollback EXIT

cd "$APP"
[[ "$(git_owner symbolic-ref --short HEAD)" == main ]] || stop branch_not_main
[[ "$(git_owner rev-parse HEAD)" == "$EXPECTED_REPO" ]] || stop "unexpected_production_head:$(git_owner rev-parse HEAD)"
[[ "$(git_owner rev-parse refs/remotes/origin/main)" == "$EXPECTED_ORIGIN_MAIN" ]] || stop "unexpected_local_origin_main:$(git_owner rev-parse refs/remotes/origin/main)"
[[ -z "$(git_owner status --porcelain=v1 --untracked-files=all)" ]] || stop dirty_worktree

RES_PID=$(svc_value "$RES" MainPID)
RES_RESTARTS=$(svc_value "$RES" NRestarts)
CAP_PID=$(svc_value "$CAP" MainPID)
CAP_RESTARTS=$(svc_value "$CAP" NRestarts)
SIG_PID=$(svc_value "$SIG" MainPID)
SIG_RESTARTS=$(svc_value "$SIG" NRestarts)
DIS_PID=$(svc_value "$DIS" MainPID)
DIS_RESTARTS=$(svc_value "$DIS" NRestarts)

[[ $RES_PID == "$EXPECTED_RES_PID" && $RES_RESTARTS == "$EXPECTED_RES_RESTARTS" ]] || stop "resident_baseline_changed:$RES_PID/$RES_RESTARTS"
[[ $CAP_PID == "$EXPECTED_CAP_PID" && $CAP_RESTARTS == "$EXPECTED_CAP_RESTARTS" ]] || stop "capture_baseline_changed:$CAP_PID/$CAP_RESTARTS"
[[ $SIG_PID == "$EXPECTED_SIG_PID" && $SIG_RESTARTS == "$EXPECTED_SIG_RESTARTS" ]] || stop "signer_baseline_changed:$SIG_PID/$SIG_RESTARTS"
[[ $DIS_PID == "$EXPECTED_DIS_PID" && $DIS_RESTARTS == "$EXPECTED_DIS_RESTARTS" ]] || stop "discord_baseline_changed:$DIS_PID/$DIS_RESTARTS"

systemctl is-active --quiet "$OCA" || stop oca_not_active
systemctl is-active --quiet "$OCA_UPDATER" || stop oca_updater_not_active
[[ "$(systemctl is-enabled "$OCA" 2>/dev/null)" == enabled ]] || stop oca_not_enabled
[[ "$(systemctl is-enabled "$OCA_UPDATER" 2>/dev/null)" == enabled ]] || stop oca_updater_not_enabled
[[ "$(svc_value "$OCA" Result)" == success ]] || stop oca_result_not_success
[[ "$(svc_value "$OCA_UPDATER" Result)" == success ]] || stop oca_updater_result_not_success

read_snap_list_state
PRE_ACTUAL_VERSION=$SNAP_VERSION
PRE_ACTUAL_REVISION=$SNAP_REVISION
[[ $PRE_ACTUAL_VERSION == "$PRE_VERSION" ]] || stop "unexpected_oca_version:$PRE_ACTUAL_VERSION"
[[ $PRE_ACTUAL_REVISION == "$PRE_REVISION" ]] || stop "unexpected_oca_revision:$PRE_ACTUAL_REVISION"
[[ $SNAP_NOTES == *held* ]] || stop snap_hold_note_missing

read_snap_info_state
TRACKING=$SNAP_TRACKING
HOLD=$SNAP_HOLD
REMOTE_STABLE=$SNAP_STABLE_VERSION
REMOTE_STABLE_REVISION=$SNAP_STABLE_REVISION
[[ $TRACKING == "$EXPECTED_TRACKING" ]] || stop "tracking_changed:expected=$EXPECTED_TRACKING:actual=$TRACKING"
[[ $HOLD == "$EXPECTED_HOLD" ]] || stop "hold_changed:expected=$EXPECTED_HOLD:actual=$HOLD"
[[ $REMOTE_STABLE == "$TARGET_VERSION" && $REMOTE_STABLE_REVISION == "$TARGET_REVISION" ]] || stop "stable_target_moved:expected=$TARGET_VERSION/$TARGET_REVISION:actual=$REMOTE_STABLE/$REMOTE_STABLE_REVISION"

read_snap_change_state
[[ $SNAP_CHANGE_IN_PROGRESS == NO ]] || stop snap_change_in_progress

read_snap_free_kib
FREE_KIB=$SNAP_FREE_KIB
[[ $FREE_KIB =~ ^[0-9]+$ && $FREE_KIB -ge 524288 ]] || stop "insufficient_snap_disk_kib:$FREE_KIB"

app_gate pre

echo "PROD359V2_PREFLIGHT=PASS version=$PRE_ACTUAL_VERSION revision=$PRE_ACTUAL_REVISION tracking=$TRACKING hold=$HOLD stable=$REMOTE_STABLE/$REMOTE_STABLE_REVISION"

if ! snap refresh oracle-cloud-agent --revision="$TARGET_REVISION"; then
  read_snap_list_state
  CURRENT_AFTER_FAILED_REFRESH=$SNAP_VERSION
  CURRENT_REVISION_AFTER_FAILED_REFRESH=$SNAP_REVISION
  if [[ $CURRENT_AFTER_FAILED_REFRESH != "$PRE_VERSION" || $CURRENT_REVISION_AFTER_FAILED_REFRESH != "$PRE_REVISION" ]]; then
    REFRESH_COMPLETED=1
  fi
  stop "snap_refresh_failed:current=$CURRENT_AFTER_FAILED_REFRESH/$CURRENT_REVISION_AFTER_FAILED_REFRESH"
fi
REFRESH_COMPLETED=1

wait_oca || stop oca_services_not_active_after_refresh
sleep 5

read_snap_list_state
POST_VERSION=$SNAP_VERSION
POST_REVISION=$SNAP_REVISION
[[ $POST_VERSION == "$TARGET_VERSION" ]] || stop "post_version_mismatch:$POST_VERSION"
[[ $POST_REVISION == "$TARGET_REVISION" ]] || stop "post_revision_mismatch:$POST_REVISION"
[[ $SNAP_NOTES == *held* ]] || stop post_snap_hold_note_missing

read_snap_info_state
[[ $SNAP_TRACKING == "$EXPECTED_TRACKING" ]] || stop "post_tracking_changed:expected=$EXPECTED_TRACKING:actual=$SNAP_TRACKING"
[[ $SNAP_HOLD == "$EXPECTED_HOLD" ]] || stop "post_hold_changed:expected=$EXPECTED_HOLD:actual=$SNAP_HOLD"

systemctl is-active --quiet "$OCA" || stop post_oca_not_active
systemctl is-active --quiet "$OCA_UPDATER" || stop post_oca_updater_not_active
[[ "$(svc_value "$OCA" Result)" == success ]] || stop post_oca_result_not_success
[[ "$(svc_value "$OCA_UPDATER" Result)" == success ]] || stop post_oca_updater_result_not_success

[[ "$(svc_value "$RES" MainPID)" == "$RES_PID" ]] || stop unexpected_resident_pid_change
[[ "$(svc_value "$RES" NRestarts)" == "$RES_RESTARTS" ]] || stop unexpected_resident_restart_change
[[ "$(svc_value "$CAP" MainPID)" == "$CAP_PID" ]] || stop unexpected_capture_pid_change
[[ "$(svc_value "$CAP" NRestarts)" == "$CAP_RESTARTS" ]] || stop unexpected_capture_restart_change
[[ "$(svc_value "$SIG" MainPID)" == "$SIG_PID" ]] || stop unexpected_signer_pid_change
[[ "$(svc_value "$SIG" NRestarts)" == "$SIG_RESTARTS" ]] || stop unexpected_signer_restart_change
[[ "$(svc_value "$DIS" MainPID)" == "$DIS_PID" ]] || stop unexpected_discord_pid_change
[[ "$(svc_value "$DIS" NRestarts)" == "$DIS_RESTARTS" ]] || stop unexpected_discord_restart_change

app_gate post

OCARUN_PRESENT=NO
id -u ocarun >/dev/null 2>&1 && OCARUN_PRESENT=YES

RUNCOMMAND_ARTIFACT=NO
for base in /snap/oracle-cloud-agent/current /var/snap/oracle-cloud-agent/common; do
  if [[ -e $base ]]; then
    artifact=$(find "$base" -maxdepth 8 \( -iname '*runcommand*' -o -iname '*run-command*' \) -print -quit 2>/dev/null || true)
    if [[ -n $artifact ]]; then
      RUNCOMMAND_ARTIFACT=YES
      break
    fi
  fi
done

DONE=1
trap - EXIT

echo "PROD359V2=PASS"
echo "REPO_HEAD=$(git_owner rev-parse HEAD)"
echo "OCA_PRE_VERSION=$PRE_ACTUAL_VERSION"
echo "OCA_PRE_REVISION=$PRE_ACTUAL_REVISION"
echo "OCA_POST_VERSION=$POST_VERSION"
echo "OCA_POST_REVISION=$POST_REVISION"
echo "OCA_TRACKING_BEFORE=$TRACKING"
echo "OCA_TRACKING_AFTER=$SNAP_TRACKING"
echo "OCA_HOLD_PRESERVED=$SNAP_HOLD"
echo "OCA_SERVICE=active"
echo "OCA_UPDATER=active"
echo "OCARUN_ACCOUNT_PRESENT=$OCARUN_PRESENT"
echo "RUN_COMMAND_LOCAL_ARTIFACT=$RUNCOMMAND_ARTIFACT"
echo "ROOT_IMDS_HTTP=200"
echo "TECHNOCORE_IMDS_BLOCKED=YES"
echo "PROTECTED_CORE=$EXPECTED_CORE_EVENTS/$EXPECTED_CORE_MESSAGES"
echo "RESIDENT_PRESERVED=$RES_PID/NRestarts=$RES_RESTARTS"
echo "CAPTURE_PRESERVED=$CAP_PID/NRestarts=$CAP_RESTARTS"
echo "SIGNER_PRESERVED=$SIG_PID/NRestarts=$SIG_RESTARTS"
echo "DISCORD_PRESERVED=$DIS_PID/NRestarts=$DIS_RESTARTS"
echo "APP_RESTART=NO"
echo "FIREWALL_CHANGE=NO"
echo "RUN_COMMAND_CREATED=NO"
echo "OCI_AGENT_CONFIG_CHANGE=NO"
echo "TECHNOCORE_WRITE=NO"
echo "FLOP_EXTERNAL_WRITE=NO"
echo "X_WRITE=NO"
echo "DO_NOT_RERUN=YES"
