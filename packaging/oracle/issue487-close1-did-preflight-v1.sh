#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
VDID=/var/lib/technocore-safe-agent/verified-did.json

EXPECTED_HEAD=9baa91be7267b22143c33a06df3c67e1074dba0d
RES_PID=2462149
CAP_PID=2462148
SIG_PID=2462068
DIS_PID=2462020
CORE_E=124
CORE_M=5651120
BRIDGE_E=7
BRIDGE_M=567965

stop_diag() {
  echo "CLOSE1_PRE487=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "CLOSE1_PRE487=ERROR:rc_$rc"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_diag not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" && -f "$VDID" ]] || stop_diag required_path_missing

OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_diag git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

snap() {
  local unit=$1
  printf '%s|%s|%s|%s|%s\n'     "$(systemctl show "$unit" -p ActiveState --value)"     "$(systemctl show "$unit" -p SubState --value)"     "$(systemctl show "$unit" -p MainPID --value)"     "$(systemctl show "$unit" -p NRestarts --value)"     "$(systemctl show "$unit" -p Result --value)"
}

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$EXPECTED_HEAD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_diag repo_state_changed
echo "REPO=head:$HEAD branch:$BRANCH clean:YES"

[[ "$(snap technocore-safe-agent-resident.service)" == "active|running|$RES_PID|0|success" ]] || stop_diag resident_changed
[[ "$(snap technocore-safe-agent-lobby-capture.service)" == "active|running|$CAP_PID|0|success" ]] || stop_diag capture_changed
[[ "$(snap technocore-safe-agent-signer.service)" == "active|running|$SIG_PID|0|success" ]] || stop_diag signer_changed
[[ "$(snap technocore-safe-agent-discord.service)" == "active|running|$DIS_PID|0|success" ]] || stop_diag discord_changed
echo "SERVICES=resident:$RES_PID capture:$CAP_PID signer:$SIG_PID discord:$DIS_PID nr0"

RESULT=$("$PY" - "$OBS" "$VDID" "$CORE_E" "$CORE_M" "$BRIDGE_E" "$BRIDGE_M" <<'PY'
import json, pathlib, re, sys

obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
verified=json.loads(pathlib.Path(sys.argv[2]).read_text("utf-8"))
expected=list(map(int,sys.argv[3:7]))
m=obs.get("metrics") or {}
actual=[
 int(m.get("unrecoverable_core_gap_events",0) or 0),
 int(m.get("unrecoverable_core_gap_messages",0) or 0),
 int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),
 int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0),
]
if actual != expected:
    raise RuntimeError("protected_baseline_changed")
did=verified.get("did")
if not isinstance(did,str) or not re.fullmatch(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}",did):
    raise RuntimeError("verified_did_invalid")
payload=json.dumps({"key":did,"season":"close-1","t":"owner"},sort_keys=True,separators=(",",":"))
print(did)
print(payload)
PY
) || stop_diag local_public_did_read_failed

DID=$(printf '%s\n' "$RESULT" | sed -n '1p')
REG=$(printf '%s\n' "$RESULT" | sed -n '2p')
[[ -n "$DID" && -n "$REG" ]] || stop_diag render_failed

echo "PUBLIC_DID=$DID"
echo "REGISTRATION_ROOM=close1"
echo "REGISTRATION_TEXT=$REG"
echo "PROTECTED=core:$CORE_E/$CORE_M bridge:$BRIDGE_E/$BRIDGE_M"
echo "BINDING_ACTION_EXECUTED=NO"
echo "SECRET_OR_VAULT_ACCESS=NO"
echo "CLOSE1_PRE487=PASS"
echo "DO_NOT_RERUN=YES"
