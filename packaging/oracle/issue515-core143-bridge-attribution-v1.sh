#!/usr/bin/env bash
set -Eeuo pipefail

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json

[[ -x "$PY" && -f "$OBS" ]] || { echo "PROD515V1=STOP:missing_input"; echo "DO_NOT_RERUN=YES"; exit 0; }

"$PY" - "$OBS" <<'PY'
import collections, json, pathlib, re, sys
obs=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m=obs.get("metrics") or {}

base_core=(124,5651120)
base_bridge=(7,567965)
core=(int(m.get("unrecoverable_core_gap_events",0) or 0),int(m.get("unrecoverable_core_gap_messages",0) or 0))
bridge=(int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0))
dc=(core[0]-base_core[0],core[1]-base_core[1])
db=(bridge[0]-base_bridge[0],bridge[1]-base_bridge[1])

print(f"COUNTERS=core:{core[0]}/{core[1]} bridge:{bridge[0]}/{bridge[1]}")
print(f"DELTA=core:{dc[0]}/{dc[1]} bridge:{db[0]}/{db[1]} exact_match:{'YES' if dc==db else 'NO'}")

keys=[
"lobby_startup_bridge_attempts","lobby_startup_bridge_successes",
"lobby_startup_bridge_messages","lobby_startup_bridge_failures",
"lobby_startup_bridge_local_suffix_handoffs",
"lobby_startup_bridge_avoided_unrecoverable_messages",
"lobby_startup_spool_attempts","lobby_startup_spool_recoveries",
"lobby_spool_catchup_waits","lobby_spool_catchup_successes",
"lobby_spool_catchup_timeouts",
]
print("METRICS="+" ".join(f"{k}={int(m.get(k,0) or 0)}" for k in keys))

last=obs.get("last_unrecoverable_gap")
if isinstance(last,dict):
    allow=("room","lane","start_seq","end_seq","missing_messages","reason","observed_at")
    last={k:last.get(k) for k in allow}
print("LAST_GAP="+json.dumps(last,sort_keys=True,separators=(",",":")))

health=obs.get("health") or {}
print(f"LOBBY_CURSOR={int((obs.get('cursors') or {}).get('lobby',0) or 0)} OBS_HEALTH={health.get('current')}")

rows=[r for r in (obs.get("error_history") or [])[-40:] if isinstance(r,dict) and r.get("room")=="lobby"]
counts=collections.Counter(str(r.get("kind") or "unknown") for r in rows)
print("LOBBY_ERROR_KINDS="+",".join(f"{k}:{v}" for k,v in sorted(counts.items())))
for i,row in enumerate(rows[-3:],1):
    detail=re.sub(r"[^A-Za-z0-9_:.+/-]","",str(row.get("detail") or ""))[:70]
    print(f"LOBBY_ERROR_{i}=kind:{row.get('kind')} detail:{detail or '-'}")
PY

echo "MUTATION=NONE"
echo "PROD515V1=PASS"
echo "DO_NOT_RERUN=YES"
