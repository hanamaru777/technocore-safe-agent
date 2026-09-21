#!/usr/bin/env bash
# Issue #390 v2: read-only Lobby retained-window probe using the app runtime.
set -u
umask 077

APP=/opt/technocore-safe-agent
APP_PY=$APP/.venv/bin/python
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service

EXPECTED_APP_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe
EXPECTED_CORE_EVENTS=118
EXPECTED_CORE_MESSAGES=5092411
EXPECTED_RES_PID=1868797
EXPECTED_RES_RESTARTS=0
EXPECTED_CAP_PID=1868796
EXPECTED_CAP_RESTARTS=0

echo '=== ISSUE390 LOBBY RETAINED-WINDOW READ-ONLY ATTRIBUTION V2 ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ $EUID -ne 0 ]]; then
  echo 'ISSUE390_LAGV2=STOP:not_root'
  exit 0
fi

for path in "$APP/.git" "$OBS" "$APP_PY"; do
  if [[ ! -e "$path" ]]; then
    echo 'ISSUE390_LAGV2=STOP:required_path_missing'
    exit 0
  fi
done

APP_HEAD=$(git -C "$APP" rev-parse HEAD 2>/dev/null || true)
WORKTREE=$(git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
echo "APP_HEAD=$APP_HEAD"
if [[ -z "$WORKTREE" ]]; then echo 'WORKTREE_CLEAN=YES'; else echo 'WORKTREE_CLEAN=NO'; fi
if [[ "$APP_HEAD" != "$EXPECTED_APP_HEAD" || -n "$WORKTREE" ]]; then
  echo 'ISSUE390_LAGV2=STOP:repo_baseline_changed'
  exit 0
fi

for item in   "$RES|RESIDENT|$EXPECTED_RES_PID|$EXPECTED_RES_RESTARTS"   "$CAP|CAPTURE|$EXPECTED_CAP_PID|$EXPECTED_CAP_RESTARTS"
do
  IFS='|' read -r svc label expected_pid expected_nr <<<"$item"
  active=$(systemctl is-active "$svc" 2>/dev/null || true)
  pid=$(systemctl show "$svc" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$svc" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$svc" -p Result --value 2>/dev/null || true)
  echo "SERVICE=$label ACTIVE=$active PID=$pid NRESTARTS=$nr RESULT=$result"
  if [[ "$active" != active || "$pid" != "$expected_pid" || "$nr" != "$expected_nr" || "$result" != success ]]; then
    echo "ISSUE390_LAGV2=STOP:service_baseline_changed:$label"
    exit 0
  fi
done

if ! "$APP_PY" - <<'PY' >/dev/null 2>&1
import httpx
PY
then
  echo 'APP_RUNTIME_HTTPX=NO'
  echo 'ISSUE390_LAGV2=STOP:app_runtime_httpx_missing'
  exit 0
fi

echo 'APP_RUNTIME_HTTPX=YES'

"$APP_PY" - "$OBS" "$EXPECTED_CORE_EVENTS" "$EXPECTED_CORE_MESSAGES" <<'PY'
import json
import pathlib
import sys

import httpx

BASE="https://technocore.chat"
ROOM="lobby"
obs_path=pathlib.Path(sys.argv[1])
expected_events=int(sys.argv[2])
expected_messages=int(sys.argv[3])

state=json.loads(obs_path.read_text("utf-8"))
metrics=state.get("metrics") or {}
events=int(metrics.get("unrecoverable_core_gap_events",0) or 0)
messages=int(metrics.get("unrecoverable_core_gap_messages",0) or 0)
print(f"PROTECTED_CORE={events}/{messages}")
if (events,messages)!=(expected_events,expected_messages):
    print("ISSUE390_LAGV2_STATE=STOP:core_moved_again")
    raise SystemExit(20)

cursor=int((state.get("cursors") or {}).get(ROOM,0) or 0)
print(f"LOBBY_CURSOR={cursor}")
print(f"OBSERVER_UPDATED_AT={state.get('updated_at','missing')}")
print(f"OBSERVER_HEALTH_CURRENT={(state.get('health') or {}).get('current','missing')}")

timeout=httpx.Timeout(10.0,connect=3.0,pool=3.0)

def valid_seqs(payload):
    messages=payload.get("messages",payload if isinstance(payload,list) else [])
    if not isinstance(messages,list):
        return []
    seqs=[]
    for item in messages:
        if isinstance(item,dict) and isinstance(item.get("seq"),int):
            seqs.append(int(item["seq"]))
    return sorted(seqs)

with httpx.Client(timeout=timeout,follow_redirects=False) as client:
    try:
        response=client.get(
            BASE+"/r/lobby",
            params={"format":"json","since":cursor,"wait":0,"limit":200},
        )
        print("LIVE_HTTP_STATUS="+str(response.status_code))
        response.raise_for_status()
        seqs=valid_seqs(response.json())
        print("LIVE_ROW_COUNT="+str(len(seqs)))
        if seqs:
            print("LIVE_FIRST_SEQ="+str(seqs[0]))
            print("LIVE_LAST_SEQ="+str(seqs[-1]))
            print("LIVE_FIRST_DISTANCE_FROM_CURSOR="+str(seqs[0]-cursor))
            print("LIVE_LAST_DISTANCE_FROM_CURSOR="+str(seqs[-1]-cursor))
        else:
            print("LIVE_FIRST_SEQ=NONE")
            print("LIVE_LAST_SEQ=NONE")
    except Exception as exc:
        print("LIVE_PROBE=FAIL")
        print("LIVE_ERROR_TYPE="+type(exc).__name__)

    count=0
    first=None
    last=None
    invalid=0
    try:
        with client.stream("GET",BASE+"/r/lobby/export") as response:
            print("EXPORT_HTTP_STATUS="+str(response.status_code))
            response.raise_for_status()
            for raw in response.iter_lines():
                if not raw or not raw.strip():
                    continue
                try:
                    item=json.loads(raw)
                except Exception:
                    invalid+=1
                    continue
                seq=item.get("seq") if isinstance(item,dict) else None
                if not isinstance(seq,int):
                    invalid+=1
                    continue
                count+=1
                if first is None:
                    first=seq
                last=seq
        print("EXPORT_VALID_ROW_COUNT="+str(count))
        print("EXPORT_INVALID_ROW_COUNT="+str(invalid))
        print("EXPORT_FIRST_SEQ="+(str(first) if first is not None else "NONE"))
        print("EXPORT_LAST_SEQ="+(str(last) if last is not None else "NONE"))
        if first is not None:
            print("EXPORT_FIRST_DISTANCE_FROM_CURSOR="+str(first-cursor))
        if last is not None:
            print("EXPORT_LAST_DISTANCE_FROM_CURSOR="+str(last-cursor))
        if first is None:
            print("SERVER_RETAINED_HAS_CURSOR_NEXT=UNKNOWN")
        elif first > cursor + 1:
            print("SERVER_RETAINED_HAS_CURSOR_NEXT=NO")
            print("SERVER_CURRENT_MISSING_PREFIX="+str(first-cursor-1))
        else:
            print("SERVER_RETAINED_HAS_CURSOR_NEXT=YES")
            print("SERVER_CURRENT_MISSING_PREFIX=0")
    except Exception as exc:
        print("EXPORT_PROBE=FAIL")
        print("EXPORT_ERROR_TYPE="+type(exc).__name__)

print("NETWORK_PROBE_MODE=GET_ONLY_SEQ_METADATA")
print("RAW_MESSAGE_OUTPUT=NO")
print("DID_OUTPUT=NO")
PY
PY_RC=$?
echo "ISSUE390_LAGV2_PYTHON_RC=$PY_RC"

echo '--- POST SERVICE CONTINUITY ---'
for item in   "$RES|RESIDENT|$EXPECTED_RES_PID|$EXPECTED_RES_RESTARTS"   "$CAP|CAPTURE|$EXPECTED_CAP_PID|$EXPECTED_CAP_RESTARTS"
do
  IFS='|' read -r svc label expected_pid expected_nr <<<"$item"
  active=$(systemctl is-active "$svc" 2>/dev/null || true)
  pid=$(systemctl show "$svc" -p MainPID --value 2>/dev/null || true)
  nr=$(systemctl show "$svc" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$svc" -p Result --value 2>/dev/null || true)
  echo "POST_SERVICE=$label ACTIVE=$active PID=$pid NRESTARTS=$nr RESULT=$result"
done

echo '--- SAFETY TAIL ---'
echo 'MUTATION_COMMANDS=NONE'
echo 'SERVICE_RESTART=NO'
echo 'PROCESS_SIGNAL=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'NETWORK_WRITE=NO'
echo 'NETWORK_READ=YES_GET_ONLY'
echo 'TECHNOCORE_WRITE=NO'
echo 'RAW_MESSAGE_OUTPUT=NO'
echo 'DID_OUTPUT=NO'
echo '=== ISSUE390_LOBBY_LAG_ATTRIBUTION_V2=COMPLETE_READ_ONLY ==='
echo 'DO_NOT_RERUN=YES'
exit 0
