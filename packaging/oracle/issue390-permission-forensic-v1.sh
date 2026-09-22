#!/usr/bin/env bash
set -u
umask 077

APP=/opt/technocore-safe-agent
RES=technocore-safe-agent-resident.service
TARGET=473e4f73426069c682cfd716f611e0bfad7d4fe8
TMP=$(mktemp /tmp/issue390-perm.XXXXXX)
trap 'rm -f -- "$TMP"' EXIT

echo '=== ISSUE390 PERMISSION FORENSIC V1 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'ISSUE390_PERMV1=STOP:not_root'
  exit 0
fi

for cmd in git systemctl stat runuser journalctl python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ISSUE390_PERMV1=STOP:missing_command:$cmd"
    exit 0
  fi
done

HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
BRANCH=$(git -C "$APP" branch --show-current 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "HEAD=$HEAD"
echo "BRANCH=$BRANCH"
if [[ -z "$WORKTREE" ]]; then echo 'WORKTREE_CLEAN=YES'; else echo 'WORKTREE_CLEAN=NO'; fi
if [[ "$HEAD" != "$TARGET" || "$BRANCH" != main || -n "$WORKTREE" ]]; then
  echo 'ISSUE390_PERMV1=STOP:repo_not_exact_target'
  exit 0
fi

echo '--- SERVICE IDENTITY ---'
USER_VALUE=$(systemctl show "$RES" -p User --value 2>/dev/null || true)
GROUP_VALUE=$(systemctl show "$RES" -p Group --value 2>/dev/null || true)
DYNAMIC_VALUE=$(systemctl show "$RES" -p DynamicUser --value 2>/dev/null || true)
if [[ -z "$GROUP_VALUE" ]]; then GROUP_VALUE=DEFAULT; fi
echo "RESIDENT_USER=$USER_VALUE"
echo "RESIDENT_GROUP=$GROUP_VALUE"
echo "RESIDENT_DYNAMIC_USER=$DYNAMIC_VALUE"
if [[ -z "$USER_VALUE" ]]; then
  echo 'ISSUE390_PERMV1=STOP:resident_user_missing'
  exit 0
fi

echo '--- EXACT FILE METADATA ---'
for path in \
  "$APP/src" \
  "$APP/src/flop_agent" \
  "$APP/src/flop_agent/resident_daemon.py" \
  "$APP/src/flop_agent/observer_core_local_continuity.py" \
  "$APP/src/flop_agent/observer_lobby_capture.py" \
  "$APP/src/flop_agent/observer_lobby_startup_hole_bridge.py" \
  "$APP/src/flop_agent/observer_resident_isolation.py"
do
  rel=$(python3 - "$APP" "$path" <<'PY'
import pathlib,sys
app=pathlib.Path(sys.argv[1])
path=pathlib.Path(sys.argv[2])
try:
    print(path.relative_to(app))
except ValueError:
    print(path)
PY
)
  if [[ ! -e "$path" ]]; then
    echo "STAT=MISSING path=$rel"
    continue
  fi
  mode=$(stat -c '%a' "$path" 2>/dev/null || true)
  owner=$(stat -c '%U' "$path" 2>/dev/null || true)
  group=$(stat -c '%G' "$path" 2>/dev/null || true)
  kind=$(stat -c '%F' "$path" 2>/dev/null || true)
  echo "STAT path=$rel mode=$mode owner=$owner group=$group kind=$kind"
done

echo '--- RESIDENT READABILITY AS SERVICE USER ---'
for rel in \
  src/flop_agent/resident_daemon.py \
  src/flop_agent/observer_core_local_continuity.py \
  src/flop_agent/observer_lobby_capture.py \
  src/flop_agent/observer_lobby_startup_hole_bridge.py \
  src/flop_agent/observer_resident_isolation.py
do
  if runuser -u "$USER_VALUE" -- test -r "$APP/$rel"; then
    echo "READABLE_AS_RESIDENT path=$rel result=YES"
  else
    echo "READABLE_AS_RESIDENT path=$rel result=NO"
  fi
done

echo '--- SANITIZED PERMISSION TARGETS ---'
journalctl -u "$RES" --since '30 minutes ago' --no-pager --output=cat >"$TMP" 2>/dev/null || true

python3 - "$TMP" "$APP" <<'PY'
import pathlib
import re
import sys

text=pathlib.Path(sys.argv[1]).read_text("utf-8",errors="replace")
app=pathlib.Path(sys.argv[2]).resolve()
state=pathlib.Path("/var/lib/technocore-safe-agent").resolve()
patterns=[
    re.compile(r"PermissionError: \[Errno 13\] Permission denied: ['\"]([^'\"]+)['\"]"),
    re.compile(r"\[Errno 13\] Permission denied: ['\"]([^'\"]+)['\"]"),
]
seen=[]
for pattern in patterns:
    for match in pattern.finditer(text):
        raw=match.group(1)
        try:
            path=pathlib.Path(raw).resolve()
        except Exception:
            continue
        label=None
        try:
            label="repo/"+str(path.relative_to(app))
        except ValueError:
            try:
                label="state/"+str(path.relative_to(state))
            except ValueError:
                pass
        if label is not None and label not in seen:
            seen.append(label)
for idx,label in enumerate(seen[:20],1):
    print(f"PERMISSION_TARGET idx={idx} path={label}")
print(f"PERMISSION_TARGET_COUNT={len(seen[:20])}")
PY

echo '--- CURRENT RESIDENT STATE ---'
ACTIVE=$(systemctl show "$RES" -p ActiveState --value 2>/dev/null || true)
SUB=$(systemctl show "$RES" -p SubState --value 2>/dev/null || true)
PID=$(systemctl show "$RES" -p MainPID --value 2>/dev/null || true)
NR=$(systemctl show "$RES" -p NRestarts --value 2>/dev/null || true)
RESULT=$(systemctl show "$RES" -p Result --value 2>/dev/null || true)
CODE=$(systemctl show "$RES" -p ExecMainCode --value 2>/dev/null || true)
STATUS=$(systemctl show "$RES" -p ExecMainStatus --value 2>/dev/null || true)
echo "RESIDENT ACTIVE=$ACTIVE SUB=$SUB PID=$PID NRESTARTS=$NR RESULT=$RESULT EXEC_CODE=$CODE EXEC_STATUS=$STATUS"

echo '--- SAFETY TAIL ---'
echo 'MUTATION_COMMANDS=NONE'
echo 'SERVICE_RESTART=NO'
echo 'PROCESS_SIGNAL=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'NETWORK_PROBE=NO'
echo 'RAW_JOURNAL_OUTPUT=NO'
echo 'TECHNOCORE_WRITE=NO'
echo '=== ISSUE390_PERMISSION_FORENSIC_V1=COMPLETE_READ_ONLY ==='
echo 'DO_NOT_RERUN=YES'
exit 0
