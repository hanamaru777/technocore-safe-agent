#!/usr/bin/env bash
# PROD376: persistent least-privilege OCA snap_daemon IMDS repair.
# One-shot guarded Production helper. Branch-only; DO NOT MERGE.
set -u
umask 077

APP=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
INSTALLED=/usr/local/libexec/technocore-safe-agent-block-metadata
CHAIN=TECHNOCORE_METADATA
META=169.254.169.254/32
IMDS_URL=http://169.254.169.254/opc/v2/instance/

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service
META_SVC=technocore-safe-agent-metadata-block.service
OCA=snap.oracle-cloud-agent.oracle-cloud-agent.service
UPD=snap.oracle-cloud-agent.oracle-cloud-agent-updater.service

SOURCE_COMMIT=f627b0b8fbc329d845cade8efc47d9bc08bedf73
SOURCE_BLOB=a21ac47654bc3c49598954e5915af6936628f6d7
EXPECTED_OLD_BLOB=28a53036454abf86b63a3d6571625c1440d67b71

EXPECTED_REPO=b7bf27dbaa605971d340aa926fdffc17489c3afe
EXPECTED_ORIGIN_MAIN=43db3595a52bb2e19777a1c1c91842c06408f48b
EXPECTED_CORE_EVENTS=117
EXPECTED_CORE_MESSAGES=5083155

EXPECTED_RES_PID=1868797
EXPECTED_RES_RESTARTS=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0
EXPECTED_SIG_PID=1539554
EXPECTED_SIG_RESTARTS=1
EXPECTED_DIS_PID=1957840
EXPECTED_DIS_RESTARTS=0
EXPECTED_OCA_PID=2038593
EXPECTED_OCA_RESTARTS=0
EXPECTED_UPD_PID=2038595
EXPECTED_UPD_RESTARTS=0

TMPDIR=$(mktemp -d /tmp/prod376.XXXXXX)
NEW_HELPER=$TMPDIR/new-metadata-helper
OLD_HELPER=$TMPDIR/old-metadata-helper
IPTABLES_BEFORE=$TMPDIR/iptables.before
DONE=0
MUTATED=0

rollback_and_cleanup() {
  rc=$?
  if [[ $MUTATED -eq 1 && $DONE -eq 0 ]]; then
    echo 'PROD376_ROLLBACK=START'
    file_rc=0
    fw_rc=0

    if [[ -f "$OLD_HELPER" ]]; then
      cp -a -- "$OLD_HELPER" "$INSTALLED" || file_rc=$?
    else
      file_rc=97
    fi

    if [[ -f "$IPTABLES_BEFORE" ]]; then
      iptables-restore <"$IPTABLES_BEFORE" || fw_rc=$?
    else
      fw_rc=98
    fi

    echo "PROD376_ROLLBACK_FILE_RC=$file_rc"
    echo "PROD376_ROLLBACK_FIREWALL_RC=$fw_rc"
    echo 'PROD376_ROLLBACK=COMPLETE'
  fi
  rm -rf -- "$TMPDIR"
  exit "$rc"
}
trap rollback_and_cleanup EXIT

stop() {
  echo "PROD376=STOP:$1"
  echo 'DO_NOT_RERUN=YES'
  exit 1
}

blob_of() {
  git hash-object "$1" 2>/dev/null || true
}

assert_service() {
  svc=$1
  expected_pid=$2
  expected_restarts=$3
  label=$4

  active=$(systemctl is-active "$svc" 2>/dev/null || true)
  pid=$(systemctl show "$svc" -p MainPID --value 2>/dev/null || true)
  restarts=$(systemctl show "$svc" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$svc" -p Result --value 2>/dev/null || true)

  [[ "$active" == active ]] || stop "$label:not_active:$active"
  [[ "$pid" == "$expected_pid" ]] || stop "$label:pid_changed:$pid"
  [[ "$restarts" == "$expected_restarts" ]] || stop "$label:restarts_changed:$restarts"
  [[ "$result" == success ]] || stop "$label:result_not_success:$result"

  echo "SERVICE=$label ACTIVE=$active PID=$pid NRESTARTS=$restarts RESULT=$result"
}

assert_metadata_service() {
  active=$(systemctl is-active "$META_SVC" 2>/dev/null || true)
  enabled=$(systemctl is-enabled "$META_SVC" 2>/dev/null || true)
  result=$(systemctl show "$META_SVC" -p Result --value 2>/dev/null || true)

  [[ "$active" == active ]] || stop "metadata_service_not_active:$active"
  [[ "$enabled" == enabled ]] || stop "metadata_service_not_enabled:$enabled"
  [[ "$result" == success ]] || stop "metadata_service_result:$result"

  echo "SERVICE=METADATA_BLOCK ACTIVE=$active ENABLED=$enabled RESULT=$result"
}

core_snapshot() {
  python3 - "$OBS" <<'PY'
import json
import pathlib
import sys

try:
    data=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
except Exception as exc:
    print("ERROR="+type(exc).__name__)
    raise SystemExit(1)

metrics=data.get("metrics") or {}
print(str(metrics.get("unrecoverable_core_gap_events","MISSING"))+" "+str(metrics.get("unrecoverable_core_gap_messages","MISSING")))
PY
}

assert_core() {
  snap=$(core_snapshot) || stop "core_unreadable"
  read -r events messages <<<"$snap"
  [[ "$events" == "$EXPECTED_CORE_EVENTS" && "$messages" == "$EXPECTED_CORE_MESSAGES" ]] || stop "protected_core_changed:$events/$messages"
  echo "PROTECTED_CORE=$events/$messages"
}

probe_imds() {
  shift
  rc=0
  code=$("$@" curl -sS --connect-timeout 2 --max-time 5     -H 'Authorization: Bearer Oracle'     -o /dev/null     -w '%{http_code}'     "$IMDS_URL" 2>/dev/null) || rc=$?
  echo "$rc $${code:-000}"
}

assert_pre_imds() {
  read -r root_rc root_code <<<"$(probe_imds ROOT)"
  read -r snap_rc snap_code <<<"$(probe_imds SNAP sudo -n -u snap_daemon --)"
  read -r tech_rc tech_code <<<"$(probe_imds TECHNOCORE sudo -n -u technocore --)"

  [[ "$root_rc" == 0 && "$root_code" == 200 ]] || stop "pre_root_imds:$root_rc/$root_code"
  [[ "$snap_code" != 200 ]] || stop "pre_snap_daemon_already_allowed"
  [[ "$tech_code" != 200 ]] || stop "pre_technocore_imds_unexpectedly_allowed"

  echo "PRE_ROOT_IMDS_HTTP=$root_code"
  echo "PRE_SNAP_DAEMON_IMDS_HTTP=$snap_code"
  echo 'PRE_TECHNOCORE_IMDS_BLOCKED=YES'
}

assert_post_imds() {
  read -r root_rc root_code <<<"$(probe_imds ROOT)"
  read -r snap_rc snap_code <<<"$(probe_imds SNAP sudo -n -u snap_daemon --)"
  read -r tech_rc tech_code <<<"$(probe_imds TECHNOCORE sudo -n -u technocore --)"

  [[ "$root_rc" == 0 && "$root_code" == 200 ]] || stop "post_root_imds:$root_rc/$root_code"
  [[ "$snap_rc" == 0 && "$snap_code" == 200 ]] || stop "post_snap_daemon_imds:$snap_rc/$snap_code"
  [[ "$tech_code" != 200 ]] || stop "post_technocore_imds_unexpectedly_allowed"

  echo "POST_ROOT_IMDS_HTTP=$root_code"
  echo "POST_SNAP_DAEMON_IMDS_HTTP=$snap_code"
  echo 'POST_TECHNOCORE_IMDS_BLOCKED=YES'
}

assert_pre_firewall() {
  signer_uid=$(id -u technocore-signer 2>/dev/null) || stop "signer_account_missing"
  snap_uid=$(id -u snap_daemon 2>/dev/null) || stop "snap_daemon_account_missing"

  iptables -C OUTPUT -p tcp -d "$META" --dport 80 -j "$CHAIN" >/dev/null 2>&1 || stop "metadata_output_jump_missing"
  iptables -C "$CHAIN" -m owner --uid-owner 0 -j RETURN >/dev/null 2>&1 || stop "metadata_root_return_missing"
  iptables -C "$CHAIN" -m owner --uid-owner "$signer_uid" -j RETURN >/dev/null 2>&1 || stop "metadata_signer_return_missing"
  if iptables -C "$CHAIN" -m owner --uid-owner "$snap_uid" -j RETURN >/dev/null 2>&1; then
    stop "snap_daemon_return_already_present"
  fi
  iptables -C "$CHAIN" -j REJECT >/dev/null 2>&1 || stop "metadata_final_reject_missing"

  echo 'PRE_FIREWALL=PASS snap_daemon_return=NO'
}

assert_post_firewall() {
  signer_uid=$(id -u technocore-signer 2>/dev/null) || stop "signer_account_missing_post"
  snap_uid=$(id -u snap_daemon 2>/dev/null) || stop "snap_daemon_account_missing_post"

  iptables -C OUTPUT -p tcp -d "$META" --dport 80 -j "$CHAIN" >/dev/null 2>&1 || stop "post_metadata_output_jump_missing"
  iptables -C "$CHAIN" -m owner --uid-owner 0 -j RETURN >/dev/null 2>&1 || stop "post_metadata_root_return_missing"
  iptables -C "$CHAIN" -m owner --uid-owner "$signer_uid" -j RETURN >/dev/null 2>&1 || stop "post_metadata_signer_return_missing"
  iptables -C "$CHAIN" -m owner --uid-owner "$snap_uid" -j RETURN >/dev/null 2>&1 || stop "post_snap_daemon_return_missing"
  iptables -C "$CHAIN" -j REJECT >/dev/null 2>&1 || stop "post_metadata_final_reject_missing"

  echo 'POST_FIREWALL=PASS snap_daemon_return=YES'
}

assert_oca_runtime_user() {
  pid=$(systemctl show "$OCA" -p MainPID --value 2>/dev/null || true)
  user=$(python3 - "$pid" <<'PY'
import pathlib
import pwd
import sys

try:
    pid=int(sys.argv[1])
    status=pathlib.Path(f"/proc/{pid}/status").read_text("utf-8",errors="replace")
    uid=None
    for line in status.splitlines():
        if line.startswith("Uid:"):
            uid=int(line.split()[1])
            break
    print(pwd.getpwuid(uid).pw_name if uid is not None else "UNKNOWN")
except Exception:
    print("UNKNOWN")
PY
)
  [[ "$user" == snap_daemon ]] || stop "oca_runtime_user:$user"
  echo 'OCA_RUNTIME_USER=snap_daemon'
}

agent_config_snapshot() {
  label=$1
  file=$TMPDIR/imds-$label.json
  code=$(curl -sS --connect-timeout 3 --max-time 5     -H 'Authorization: Bearer Oracle'     -o "$file"     -w '%{http_code}'     "$IMDS_URL" 2>/dev/null || true)
  printf 'AGENT_CONFIG_%s_HTTP=%s\n' "$label" "$${code:-000}"
  [[ "$code" == 200 ]] || return 0

  python3 - "$label" "$file" <<'PY'
import json
import pathlib
import sys

label=sys.argv[1]
path=pathlib.Path(sys.argv[2])

try:
    doc=json.loads(path.read_text("utf-8"))
except Exception:
    print(f"AGENT_CONFIG_{label}_PARSE=FAIL")
    raise SystemExit

cfg=doc.get("agentConfig")
if not isinstance(cfg,dict):
    print(f"AGENT_CONFIG_{label}_PARSE=NO_CONFIG")
    raise SystemExit

rows=cfg.get("pluginsConfig")
rows=rows if isinstance(rows,list) else []
run=None
for row in rows:
    if isinstance(row,dict) and row.get("name")=="Compute Instance Run Command":
        run=str(row.get("desiredState","UNKNOWN"))
        break

print(f"AGENT_CONFIG_{label}_PARSE=PASS")
print(f"AGENT_CONFIG_{label}_PLUGIN_COUNT={len(rows)}")
print(f"RUN_COMMAND_{label}_ADVERTISED="+("YES" if run is not None else "NO"))
print(f"RUN_COMMAND_{label}_DESIRED_STATE="+(run or "absent"))
PY
}

echo '=== PROD376 OCA SNAP_DAEMON IMDS REPAIR ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

[[ $(id -u) -eq 0 ]] || stop "must_run_as_root"

echo '--- PRE / REPOSITORY ---'
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ "$OWNER" == root ]] || stop "unexpected_repo_owner:$OWNER"
HEAD_VALUE=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
ORIGIN_VALUE=$(git -C "$APP" rev-parse refs/remotes/origin/main 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
[[ "$HEAD_VALUE" == "$EXPECTED_REPO" ]] || stop "unexpected_repo_head:$HEAD_VALUE"
[[ "$ORIGIN_VALUE" == "$EXPECTED_ORIGIN_MAIN" ]] || stop "unexpected_origin_main:$ORIGIN_VALUE"
[[ -z "$WORKTREE" ]] || stop "worktree_not_clean"
echo "APP_HEAD=$HEAD_VALUE"
echo "LOCAL_ORIGIN_MAIN=$ORIGIN_VALUE"
echo 'WORKTREE_CLEAN=YES'

echo '--- PRE / INSTALLED HELPER ---'
[[ -f "$INSTALLED" ]] || stop "installed_helper_missing"
INSTALLED_BLOB=$(blob_of "$INSTALLED")
[[ "$INSTALLED_BLOB" == "$EXPECTED_OLD_BLOB" ]] || stop "unexpected_installed_helper_blob:$INSTALLED_BLOB"
META_STAT=$(stat -c '%U:%G:%a' "$INSTALLED" 2>/dev/null || true)
[[ "$META_STAT" == root:root:755 ]] || stop "unexpected_installed_helper_stat:$META_STAT"
echo "INSTALLED_HELPER_BLOB=$INSTALLED_BLOB"
echo "INSTALLED_HELPER_STAT=$META_STAT"

echo '--- PRE / REVIEWED SOURCE ---'
curl -fsSL   "https://raw.githubusercontent.com/hanamaru777/technocore-safe-agent/$SOURCE_COMMIT/packaging/oracle/block-technocore-metadata.sh"   -o "$NEW_HELPER" || stop "source_download_failed"
NEW_BLOB=$(blob_of "$NEW_HELPER")
[[ "$NEW_BLOB" == "$SOURCE_BLOB" ]] || stop "source_blob_mismatch:$NEW_BLOB"
sh -n "$NEW_HELPER" || stop "source_shell_syntax_failed"
echo "SOURCE_COMMIT=$SOURCE_COMMIT"
echo "SOURCE_BLOB=$NEW_BLOB"

echo '--- PRE / SERVICES + CORE ---'
assert_service "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS" RESIDENT
assert_service "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS" CAPTURE
assert_service "$SIG" "$EXPECTED_SIG_PID" "$EXPECTED_SIG_RESTARTS" SIGNER
assert_service "$DIS" "$EXPECTED_DIS_PID" "$EXPECTED_DIS_RESTARTS" DISCORD
assert_service "$OCA" "$EXPECTED_OCA_PID" "$EXPECTED_OCA_RESTARTS" OCA
assert_service "$UPD" "$EXPECTED_UPD_PID" "$EXPECTED_UPD_RESTARTS" OCA_UPDATER
assert_metadata_service
assert_core
assert_oca_runtime_user

echo '--- PRE / FIREWALL + IMDS ---'
assert_pre_firewall
assert_pre_imds
agent_config_snapshot PRE

echo '--- BACKUP ---'
cp -a -- "$INSTALLED" "$OLD_HELPER" || stop "helper_backup_failed"
iptables-save >"$IPTABLES_BEFORE" || stop "iptables_backup_failed"
echo 'BACKUP=PASS'

echo '--- APPLY EXACT REVIEWED FIX ---'
MUTATED=1
install -o root -g root -m 0755 "$NEW_HELPER" "$INSTALLED" || stop "install_new_helper_failed"
"$INSTALLED" || stop "metadata_helper_apply_failed"

echo '--- POST / HARD GATES ---'
POST_BLOB=$(blob_of "$INSTALLED")
[[ "$POST_BLOB" == "$SOURCE_BLOB" ]] || stop "post_installed_blob:$POST_BLOB"
POST_STAT=$(stat -c '%U:%G:%a' "$INSTALLED" 2>/dev/null || true)
[[ "$POST_STAT" == root:root:755 ]] || stop "post_installed_stat:$POST_STAT"
echo "POST_INSTALLED_HELPER_BLOB=$POST_BLOB"
echo "POST_INSTALLED_HELPER_STAT=$POST_STAT"

assert_post_firewall
assert_post_imds

assert_service "$RES" "$EXPECTED_RES_PID" "$EXPECTED_RES_RESTARTS" RESIDENT
assert_service "$CAP" "$EXPECTED_CAP_PID" "$EXPECTED_CAP_RESTARTS" CAPTURE
assert_service "$SIG" "$EXPECTED_SIG_PID" "$EXPECTED_SIG_RESTARTS" SIGNER
assert_service "$DIS" "$EXPECTED_DIS_PID" "$EXPECTED_DIS_RESTARTS" DISCORD
assert_service "$OCA" "$EXPECTED_OCA_PID" "$EXPECTED_OCA_RESTARTS" OCA
assert_service "$UPD" "$EXPECTED_UPD_PID" "$EXPECTED_UPD_RESTARTS" OCA_UPDATER
assert_metadata_service
assert_core
assert_oca_runtime_user

echo 'PROD376_HARD_GATES=PASS'
DONE=1

echo '--- NATURAL OCA RETRY OBSERVATION / NO RESTART ---'
agent_config_snapshot POST_T0
echo 'WAIT_SECONDS=90'
sleep 90
assert_post_imds
assert_service "$OCA" "$EXPECTED_OCA_PID" "$EXPECTED_OCA_RESTARTS" OCA
assert_service "$UPD" "$EXPECTED_UPD_PID" "$EXPECTED_UPD_RESTARTS" OCA_UPDATER
assert_core
agent_config_snapshot POST_T90

echo '=== PROD376=PASS ==='
echo "PERSISTENT_HELPER_BLOB=$SOURCE_BLOB"
echo 'SNAP_DAEMON_IMDS=ALLOWED'
echo 'TECHNOCORE_IMDS=BLOCKED'
echo 'SERVICE_RESTART=NO'
echo 'SNAP_MUTATION=NO'
echo 'NETWORK_ROUTE_PROXY_CHANGE=NO'
echo 'AGENT_CONFIG_CHANGE=NO'
echo 'RUN_COMMAND_CREATED=NO'
echo 'APPLICATION_GIT_CUTOVER=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'DO_NOT_RERUN=YES'
