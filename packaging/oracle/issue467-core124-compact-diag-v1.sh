#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
STATE=/var/lib/technocore-safe-agent
OBS=$STATE/observer/observer-state.json
RESHB=$STATE/observer/resident-heartbeat.json
EXPECTED_HEAD=62fbd7c34c0671d10bcbb3cd3f86c54937040c7c
BASE_CORE_E=121
BASE_CORE_M=5650187
BASE_BRIDGE_E=4
BASE_BRIDGE_M=567032
BASE_BRIDGE_ATTEMPTS=13
BASE_BRIDGE_SUCCESSES=12
BASE_BRIDGE_FAILURES=1
BASE_SUFFIX_HANDOFFS=2
BASE_AVOIDED=297047

stop_diag() {
  echo "PROD467V1=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 0
}

on_error() {
  local rc=$?
  trap - ERR
  echo "PROD467V1=ERROR:rc_$rc"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_diag not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" && -f "$RESHB" ]] || stop_diag required_path_missing

OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_diag git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$EXPECTED_HEAD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_diag repo_state_unexpected
echo "REPO=head:$HEAD branch:$BRANCH clean:YES"

for spec in \
  "resident:technocore-safe-agent-resident.service" \
  "capture:technocore-safe-agent-lobby-capture.service" \
  "signer:technocore-safe-agent-signer.service" \
  "discord:technocore-safe-agent-discord.service"
do
  label=${spec%%:*}
  unit=${spec#*:}
  echo "SERVICE=$label active:$(systemctl show "$unit" -p ActiveState --value) sub:$(systemctl show "$unit" -p SubState --value) pid:$(systemctl show "$unit" -p MainPID --value) nr:$(systemctl show "$unit" -p NRestarts --value) result:$(systemctl show "$unit" -p Result --value)"
done

"$PY" - "$OBS" "$RESHB" \
  "$BASE_CORE_E" "$BASE_CORE_M" "$BASE_BRIDGE_E" "$BASE_BRIDGE_M" \
  "$BASE_BRIDGE_ATTEMPTS" "$BASE_BRIDGE_SUCCESSES" "$BASE_BRIDGE_FAILURES" \
  "$BASE_SUFFIX_HANDOFFS" "$BASE_AVOIDED" <<'PY'
import json, pathlib, sys
from collections import Counter
from datetime import UTC, datetime

obs=json.loads(pathlib.Path(sys.argv[1]).read_text('utf-8'))
hb=json.loads(pathlib.Path(sys.argv[2]).read_text('utf-8'))
base=list(map(int,sys.argv[3:12]))
(core_e0,core_m0,bridge_e0,bridge_m0,att0,suc0,fail0,suffix0,avoided0)=base
m=obs.get('metrics') or {}

def i(key):
    return int(m.get(key,0) or 0)

core_e=i('unrecoverable_core_gap_events')
core_m=i('unrecoverable_core_gap_messages')
bridge_e=i('lobby_startup_bridge_unrecoverable_events')
bridge_m=i('lobby_startup_bridge_unrecoverable_messages')
attempts=i('lobby_startup_bridge_attempts')
successes=i('lobby_startup_bridge_successes')
failures=i('lobby_startup_bridge_failures')
suffix=i('lobby_startup_bridge_local_suffix_handoffs')
avoided=i('lobby_startup_bridge_avoided_unrecoverable_messages')

print(f'CORE=current:{core_e}/{core_m} delta:+{core_e-core_e0}/+{core_m-core_m0}')
print(f'BRIDGE=current:{bridge_e}/{bridge_m} delta:+{bridge_e-bridge_e0}/+{bridge_m-bridge_m0}')
exact=(core_e-core_e0==bridge_e-bridge_e0 and core_m-core_m0==bridge_m-bridge_m0)
print('ATTRIBUTION=startup_bridge_exact_match:'+('YES' if exact else 'NO'))
print(f'BRIDGE_FLOW=attempts:{attempts}(+{attempts-att0}) success:{successes}(+{successes-suc0}) failures:{failures}(+{failures-fail0}) suffix_handoffs:{suffix}(+{suffix-suffix0}) avoided:{avoided}(+{avoided-avoided0})')

last=obs.get('last_unrecoverable_gap')
if isinstance(last,dict):
    print('LAST_GAP='+f"room:{last.get('room')} lane:{last.get('lane')} range:{last.get('missing_from')}..{last.get('missing_to')} count:{last.get('estimated_missing')} reason:{last.get('recovery_reason')} at:{last.get('observed_at')}")
else:
    print('LAST_GAP=none')

now=datetime.now(UTC)
def age(value):
    try:
        d=datetime.fromisoformat(str(value).replace('Z','+00:00')).astimezone(UTC)
        return max(0.0,(now-d).total_seconds())
    except Exception:
        return -1.0

print(f"HEALTH=observer:{((obs.get('health') or {}).get('current'))} lobby_cursor:{int((obs.get('cursors') or {}).get('lobby',0) or 0)} resident_hb:{hb.get('status')} resident_hb_age:{age(hb.get('updated_at')):.1f}s")

since=datetime.fromisoformat('2026-09-24T13:45:00+00:00')
counts=Counter()
for row in obs.get('error_history') or []:
    if not isinstance(row,dict):
        continue
    try:
        at=datetime.fromisoformat(str(row.get('at','')).replace('Z','+00:00')).astimezone(UTC)
    except Exception:
        continue
    if at < since:
        continue
    counts[(str(row.get('room')),str(row.get('kind')))] += 1
parts=[f'{room}/{kind}:{count}' for (room,kind),count in counts.most_common(8)]
print('RECENT_ERRORS='+(','.join(parts) if parts else 'none'))

mem=-1
for line in pathlib.Path('/proc/meminfo').read_text('utf-8').splitlines():
    if line.startswith('MemAvailable:'):
        mem=int(line.split()[1])
        break

def psi(kind):
    try:
        for line in pathlib.Path(f'/proc/pressure/{kind}').read_text('utf-8').splitlines():
            if line.startswith('full '):
                for part in line.split()[1:]:
                    if part.startswith('avg10='):
                        return part.split('=',1)[1]
    except Exception:
        pass
    return '-1'

print(f"PRESSURE=mem_available_kb:{mem} mem_full_avg10:{psi('memory')} io_full_avg10:{psi('io')}")
PY

RES_J=$(journalctl -u technocore-safe-agent-resident.service --since '2026-09-24 13:45:00 UTC' --until '2026-09-24 14:15:00 UTC' --no-pager 2>/dev/null | grep -Eic 'timeout|stale|RuntimeError|protected_backlog_capacity|gap|recover' || true)
CAP_J=$(journalctl -u technocore-safe-agent-lobby-capture.service --since '2026-09-24 13:45:00 UTC' --until '2026-09-24 14:15:00 UTC' --no-pager 2>/dev/null | grep -Eic 'timeout|stale|RuntimeError|protected_backlog_capacity|gap|recover' || true)
echo "JOURNAL_MATCH_COUNTS=resident:$RES_J capture:$CAP_J"
echo "SAFETY=mutation:NO restart:NO sqlite:NO network_probe:NO signer:NO external_write:NO"
echo "PROD467V1=PASS"
echo "DO_NOT_RERUN=YES"
