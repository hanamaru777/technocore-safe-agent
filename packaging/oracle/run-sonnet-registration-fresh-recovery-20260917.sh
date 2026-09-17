#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  trap - ERR
  echo "FRESH_REGISTRATION=STOP:$1"
  echo "NO_BLIND_RERUN=YES"
  exit 1
}
trap 'fail unexpected_rc_$?' ERR

REPO=/opt/technocore-safe-agent
REF=refs/remotes/origin/maru-registration-fresh-recovery-helper
PROD_HEAD=baf5a3e1d5d36a24b28cf9fa7dfa2dd41ccdf20f
MODULE_BLOB=ef64a67837c8efbd53c6ef2ef4b92e102a547da1
MODULE=/run/sonnet_registration_fresh_recovery_20260917.py
LAUNCHER=/run/sonnet_registration_fresh_recovery_20260917_launcher.py
UNIT=/run/systemd/system/technocore-safe-agent-sonnet-registration-fresh-recovery.service
UNIT_NAME=technocore-safe-agent-sonnet-registration-fresh-recovery.service
STATE=/var/lib/technocore-safe-agent/signer/sonnet-2-registration-fresh-recovery-20260917.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json

cleanup() {
  rm -f "$UNIT" "$MODULE" "$LAUNCHER"
  systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$REPO"
OWNER=$(stat -c %U .git) || fail git_owner_unreadable
GIT=(sudo -u "$OWNER" git -C "$REPO")

[[ "$("${GIT[@]}" symbolic-ref --short -q HEAD)" == main ]] || fail branch_not_main
[[ "$("${GIT[@]}" rev-parse HEAD)" == "$PROD_HEAD" ]] || fail unexpected_head
[[ -z "$("${GIT[@]}" status --porcelain=v1 --untracked-files=all)" ]] || fail dirty_tree
[[ "$("${GIT[@]}" rev-parse "$REF:src/flop_agent/sonnet_registration_fresh_recovery_20260917.py")" == "$MODULE_BLOB" ]] || fail module_blob_mismatch

# A prior invocation is resumable only if it never crossed the durable POST-attempt
# boundary. Once attempted_at is set, this runner will never start the write again.
if [[ -e "$STATE" ]]; then
  timeout 5s python3 - "$STATE" <<'PY' || fail fresh_state_not_safe_to_resume
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)
assert d.get("state") in {"new", "prepared"}
assert d.get("attempted_at") is None
assert d.get("post_seq") is None
assert d.get("receipt") is None
print("FRESH_STATE_RESUME=PRE_ATTEMPT_ONLY state=" + str(d.get("state")))
PY
fi

for svc in \
  technocore-safe-agent-resident.service \
  technocore-safe-agent-lobby-capture.service \
  technocore-safe-agent-signer.service \
  technocore-safe-agent-discord.service \
  technocore-safe-agent-metadata-block.service; do
  systemctl is-active --quiet "$svc" || fail "service_not_active:$svc"
done

read -r HEALTH AGE EVENTS MESSAGES < <(
  timeout 5s python3 - "$SAFETY" <<'PY'
import datetime, json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)
t = datetime.datetime.fromisoformat(d["updated_at"].replace("Z", "+00:00"))
if t.tzinfo is None:
    t = t.replace(tzinfo=datetime.timezone.utc)
age = (datetime.datetime.now(datetime.timezone.utc) - t.astimezone(datetime.timezone.utc)).total_seconds()
print(d["health"], round(age, 3), d["unrecoverable_core_gap_events"], d["unrecoverable_core_gap_messages"])
PY
) || fail safety_snapshot_unavailable
[[ "$HEALTH" == ok ]] || fail strict_health_not_ok
python3 - "$AGE" <<'PY' || fail safety_stale
import sys
age = float(sys.argv[1])
raise SystemExit(0 if 0 <= age <= 300 else 1)
PY
[[ "$EVENTS" == 117 && "$MESSAGES" == 5083155 ]] || fail "P0_core_changed:$EVENTS/$MESSAGES"
echo "FRESH_REGISTRATION_PREFLIGHT=PASS health=$HEALTH age=$AGE core=$EVENTS/$MESSAGES"

RES_PID=$(systemctl show technocore-safe-agent-resident.service -p MainPID --value)
RES_NR=$(systemctl show technocore-safe-agent-resident.service -p NRestarts --value)
CAP_PID=$(systemctl show technocore-safe-agent-lobby-capture.service -p MainPID --value)
CAP_NR=$(systemctl show technocore-safe-agent-lobby-capture.service -p NRestarts --value)
SIG_PID=$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)
SIG_NR=$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)
DIS_PID=$(systemctl show technocore-safe-agent-discord.service -p MainPID --value)
DIS_NR=$(systemctl show technocore-safe-agent-discord.service -p NRestarts --value)
META_PID=$(systemctl show technocore-safe-agent-metadata-block.service -p MainPID --value)
META_NR=$(systemctl show technocore-safe-agent-metadata-block.service -p NRestarts --value)

"${GIT[@]}" show "$REF:src/flop_agent/sonnet_registration_fresh_recovery_20260917.py" > "$MODULE"
chmod 0444 "$MODULE"
cat > "$LAUNCHER" <<'PY'
import importlib.util
import sys
name = "flop_agent.sonnet_registration_fresh_recovery_20260917"
spec = importlib.util.spec_from_file_location(name, "/run/sonnet_registration_fresh_recovery_20260917.py")
if spec is None or spec.loader is None:
    raise SystemExit("loader_unavailable")
module = importlib.util.module_from_spec(spec)
sys.modules[name] = module
spec.loader.exec_module(module)
module.main()
PY
chmod 0444 "$LAUNCHER"

cat > "$UNIT" <<'UNIT'
[Unit]
Description=One exactly-once fresh Sonnet-2 MARU writer registration recovery
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=technocore-signer
Group=technocore-signer
SupplementaryGroups=technocore-autopilot
WorkingDirectory=/opt/technocore-safe-agent
EnvironmentFile=/etc/technocore-safe-agent/signer.env
Environment=FLOP_STATE_DIR=/var/lib/technocore-safe-agent
Environment=PYTHONPATH=/opt/technocore-safe-agent/src
Environment=UV_CACHE_DIR=/var/lib/technocore-safe-agent/signer/uv-cache
ExecStart=/opt/technocore-safe-agent/.venv/bin/python /run/sonnet_registration_fresh_recovery_20260917_launcher.py
TimeoutStartSec=240s
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectKernelLogs=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadOnlyPaths=/run/sonnet_registration_fresh_recovery_20260917.py /run/sonnet_registration_fresh_recovery_20260917_launcher.py
ReadWritePaths=/var/lib/technocore-safe-agent/signer /var/lib/technocore-safe-agent/nonces.json
UNIT

systemctl daemon-reload
systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true
if ! timeout 250s systemctl start "$UNIT_NAME"; then
  echo 'FRESH_REGISTRATION=FAIL:oneshot'
  if [[ -f "$STATE" ]]; then
    timeout 5s python3 - "$STATE" <<'PY' || true
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)
print("FAIL_STATE=" + str(d.get("state")))
print("FAIL_ATTEMPTED=" + ("YES" if d.get("attempted_at") else "NO"))
print("FAIL_POST_SEQ=" + str(d.get("post_seq")))
r = d.get("receipt")
print("FAIL_RECEIPT_STATUS=" + (str(r.get("status")) if isinstance(r, dict) else "NONE"))
PY
  else
    echo 'FAIL_STATE=ABSENT'
    echo 'FAIL_ATTEMPTED=NO'
  fi
  journalctl -u "$UNIT_NAME" -n 30 --no-pager -o cat || true
  echo 'NO_BLIND_RERUN=YES'
  exit 1
fi

[[ -f "$STATE" ]] || fail no_state_after_oneshot
timeout 5s python3 - "$STATE" <<'PY' || fail final_state_invalid
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)
state = d.get("state")
print("FRESH_STATE=" + str(state))
print("REQUEST_ID=" + str(d.get("request_id")))
print("POST_SEQ=" + str(d.get("post_seq")))
print("POST_TS=" + str(d.get("post_ts")))
r = d.get("receipt")
if state == "resolved":
    assert isinstance(r, dict) and r.get("status") in {"accepted", "rejected"}
    print("OFFICIAL_STATUS=" + str(r.get("status")))
    print("OFFICIAL_RECEIPT_ROOM_SEQ=" + str(r.get("room_seq")))
    print("OFFICIAL_RECEIPT_TS=" + str(r.get("room_ts")))
    print("OFFICIAL_INTAKE_SEQ=" + str(r.get("intake_seq")))
    print("OFFICIAL_REASON=" + str(r.get("reason")))
elif state == "fresh_posted":
    assert isinstance(d.get("post_seq"), int)
    print("OFFICIAL_STATUS=RECEIPT_PENDING_OR_GAP")
else:
    raise SystemExit("unexpected terminal state: " + str(state))
PY

[[ "$(systemctl show technocore-safe-agent-resident.service -p MainPID --value)" == "$RES_PID" ]] || fail resident_pid_changed
[[ "$(systemctl show technocore-safe-agent-resident.service -p NRestarts --value)" == "$RES_NR" ]] || fail resident_restarts_changed
[[ "$(systemctl show technocore-safe-agent-lobby-capture.service -p MainPID --value)" == "$CAP_PID" ]] || fail capture_pid_changed
[[ "$(systemctl show technocore-safe-agent-lobby-capture.service -p NRestarts --value)" == "$CAP_NR" ]] || fail capture_restarts_changed
[[ "$(systemctl show technocore-safe-agent-signer.service -p MainPID --value)" == "$SIG_PID" ]] || fail signer_pid_changed
[[ "$(systemctl show technocore-safe-agent-signer.service -p NRestarts --value)" == "$SIG_NR" ]] || fail signer_restarts_changed
[[ "$(systemctl show technocore-safe-agent-discord.service -p MainPID --value)" == "$DIS_PID" ]] || fail discord_pid_changed
[[ "$(systemctl show technocore-safe-agent-discord.service -p NRestarts --value)" == "$DIS_NR" ]] || fail discord_restarts_changed
[[ "$(systemctl show technocore-safe-agent-metadata-block.service -p MainPID --value)" == "$META_PID" ]] || fail metadata_pid_changed
[[ "$(systemctl show technocore-safe-agent-metadata-block.service -p NRestarts --value)" == "$META_NR" ]] || fail metadata_restarts_changed
[[ "$("${GIT[@]}" rev-parse HEAD)" == "$PROD_HEAD" ]] || fail repo_head_changed
[[ -z "$("${GIT[@]}" status --porcelain=v1 --untracked-files=all)" ]] || fail final_dirty_tree

read -r POST_EVENTS POST_MESSAGES < <(
  timeout 5s python3 - "$SAFETY" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)
print(d["unrecoverable_core_gap_events"], d["unrecoverable_core_gap_messages"])
PY
) || fail post_safety_unavailable
[[ "$POST_EVENTS" == 117 && "$POST_MESSAGES" == 5083155 ]] || fail "P0_post_core_changed:$POST_EVENTS/$POST_MESSAGES"

trap - ERR
echo 'FRESH_REGISTRATION=PASS'
echo "PROTECTED_CORE=$POST_EVENTS/$POST_MESSAGES"
echo "RESIDENT_PRESERVED=$RES_PID/NRestarts=$RES_NR"
echo "CAPTURE_PRESERVED=$CAP_PID/NRestarts=$CAP_NR"
echo "SIGNER_PRESERVED=$SIG_PID/NRestarts=$SIG_NR"
echo "DISCORD_PRESERVED=$DIS_PID/NRestarts=$DIS_NR"
echo "METADATA_PRESERVED=$META_PID/NRestarts=$META_NR"
echo 'NO_BLIND_RERUN=YES'
