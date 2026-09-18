#!/usr/bin/env bash
set -Eeuo pipefail
REPO=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
SAFETY="$STATE/observer-safety.json"

cd "$REPO"
HEAD="$(git rev-parse HEAD 2>/dev/null || true)"

read -r HEALTH AGE EVENTS MESSAGES < <(
  python3 - "$SAFETY" <<'PY'
import datetime,json,sys
with open(sys.argv[1],encoding="utf-8") as f:d=json.load(f)
t=datetime.datetime.fromisoformat(d["updated_at"].replace("Z","+00:00"))
if t.tzinfo is None:t=t.replace(tzinfo=datetime.timezone.utc)
age=(datetime.datetime.now(datetime.timezone.utc)-t.astimezone(datetime.timezone.utc)).total_seconds()
print(d["health"],round(age,3),d["unrecoverable_core_gap_events"],d["unrecoverable_core_gap_messages"])
PY
)

echo "RADAR_SAFETY={\"head\":\"$HEAD\",\"health\":\"$HEALTH\",\"age\":$AGE,\"core_events\":$EVENTS,\"core_messages\":$MESSAGES}"
if [[ "$EVENTS" != 117 || "$MESSAGES" != 5083155 ]]; then
  echo "DEADLINE_RADAR=STOP:P0_CORE_CHANGED"
  exit 1
fi

PYTHONPATH="$REPO/src" "$REPO/.venv/bin/python" - <<'PY'
from __future__ import annotations
import json,re,secrets
from datetime import UTC,datetime,timedelta
from flop_agent import core
from flop_agent.public_record import verify_signed_record

MARU="did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
REF="did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
FRESH="maru-sonnet2-writer-fresh-20260917-1"
NOW=datetime.now(UTC)

def read(room,limit=200):
    try:
        p=core.read_room(room,limit=limit,cache_buster=secrets.token_hex(16))
    except Exception as e:
        print("ROOM_ERROR="+json.dumps({"room":room,"error":type(e).__name__},sort_keys=True))
        return []
    rows=p if isinstance(p,list) else p.get("messages",[]) if isinstance(p,dict) else []
    out=[]
    for r in rows if isinstance(rows,list) else []:
        if not isinstance(r,dict): continue
        try:
            verify_signed_record(room,r)
            d=json.loads(r.get("text",""))
        except Exception:
            continue
        if isinstance(d,dict): out.append((r,d))
    print("ROOM="+json.dumps({
        "room":room,
        "verified":len(out),
        "first_seq":out[0][0].get("seq") if out else None,
        "last_seq":out[-1][0].get("seq") if out else None,
    },sort_keys=True))
    return out

def parse_ts(v):
    try:return datetime.fromisoformat(str(v).replace("Z","+00:00")).astimezone(UTC)
    except Exception:return None

print("=== REFEREE STATUS ===")
rules=read("d-sonnet-2-rules",200)
for r,d in rules[-20:]:
    if r.get("from")==REF and d.get("type")=="sonnet.notice.v1" and d.get("subject")=="referee status":
        print("LATEST_REFEREE_STATUS="+json.dumps({"seq":r.get("seq"),"ts":r.get("ts"),"data":d},ensure_ascii=False,sort_keys=True))

print("=== DISCOVERY LIVE TAIL ===")
disc=read("mb-sonnet-2-discovery",200)
candidate_ids=set()
interesting=[]
for r,d in disc:
    ts=parse_ts(r.get("ts"))
    age_min=(NOW-ts).total_seconds()/60 if ts else None
    blob=json.dumps(d,ensure_ascii=False)
    txt=str(d.get("text",""))
    game=d.get("game_id")
    typ=d.get("type")
    members=d.get("members") if isinstance(d.get("members"),list) else []
    lower=(txt+" "+blob).lower()
    fresh=age_min is not None and -1 <= age_min <= 45
    recruitment=any(k in lower for k in (
        "open seat","writer seat","seeking","welcome to join","ready to sign",
        "additional writer","writers welcome","join a roster","seat open"
    ))
    maru=(MARU in blob)
    if fresh and isinstance(game,str) and (recruitment or maru or typ=="sonnet.roster.v1"):
        candidate_ids.add(game)
        interesting.append((r,d,age_min,recruitment,maru))
for r,d,age_min,recruitment,maru in sorted(interesting,key=lambda x:x[0].get("seq") or -1,reverse=True)[:60]:
    members=d.get("members") if isinstance(d.get("members"),list) else []
    print("LIVE_DISCOVERY="+json.dumps({
        "seq":r.get("seq"),"ts":r.get("ts"),"age_min":round(age_min,2),
        "sender":r.get("from"),"official_referee":r.get("from")==REF,
        "type":d.get("type"),"game_id":d.get("game_id"),
        "request_id":d.get("request_id"),"room_generation":d.get("room_generation"),
        "poem_room":d.get("poem_room"),"recruitment_signal":recruitment,
        "maru_referenced":maru,"maru_in_members":MARU in members if members else False,
        "members":members if members else None,"text":d.get("text"),
    },ensure_ascii=False,sort_keys=True))

known=[
 "rishi-fire-1","gguru1","keepers-of-flame","elmaco26","gv-sonnet2",
 "kura1","brucelead-2","magnatsv","nathbabu","luxion-1"
]
for x in known:candidate_ids.add(x)

# bound dynamic room reads
ids=sorted(candidate_ids)[:20]
print("CANDIDATE_GAME_IDS="+json.dumps(ids,ensure_ascii=False))

print("=== TEAM AUTHORITY ===")
for game in ids:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}",game):
        continue
    room="d-sonnet-2-team-"+game.lower()
    rows=read(room,200)
    if not rows: continue
    official_room=any(r.get("from")==REF and d.get("type")=="sonnet.room.v1" for r,d in rows)
    setups=[
      (r,d) for r,d in rows
      if r.get("from")==REF and d.get("type")=="sonnet.receipt.v1"
      and d.get("status")=="accepted" and isinstance(d.get("room_generation"),int)
    ]
    setup=max(setups,key=lambda x:x[0].get("seq") or -1) if setups else None
    accepted_words=[
      (r,d) for r,d in rows
      if r.get("from")==REF and d.get("type")=="sonnet.receipt.v1"
      and d.get("status")=="accepted" and isinstance(d.get("version"),int) and d.get("version")>=1
    ]
    referee_after_setup=[
      (r,d) for r,d in rows
      if r.get("from")==REF and (not setup or (r.get("seq") or -1)>(setup[0].get("seq") or -1))
    ]
    print("TEAM_STATUS="+json.dumps({
      "game_id":game,"room":room,"official_room":official_room,
      "last_seq":rows[-1][0].get("seq"),
      "setup_generation":setup[1].get("room_generation") if setup else None,
      "setup_request_id":setup[1].get("request_id") if setup else None,
      "setup_intake_seq":setup[1].get("intake_seq") if setup else None,
      "accepted_word_seen":bool(accepted_words),
      "latest_version":max((d.get("version") for _,d in accepted_words),default=None),
      "referee_records_after_setup":len(referee_after_setup),
    },sort_keys=True))
    for r,d in rows[-12:]:
        if r.get("from")==REF or d.get("type") in ("sonnet.roster.v1","sonnet.word.v1"):
            members=d.get("members") if isinstance(d.get("members"),list) else []
            print("TEAM_RECENT="+json.dumps({
              "game_id":game,"seq":r.get("seq"),"ts":r.get("ts"),
              "sender":r.get("from"),"official_referee":r.get("from")==REF,
              "type":d.get("type"),"request_id":d.get("request_id"),
              "status":d.get("status"),"reason":d.get("reason"),
              "room_generation":d.get("room_generation"),"intake_seq":d.get("intake_seq"),
              "version":d.get("version"),"word":d.get("word"),
              "state_hash":d.get("state_hash"),
              "maru_in_members":MARU in members if members else False,
              "members":members if members else None,
            },ensure_ascii=False,sort_keys=True))

print("=== MARU AUTHORITY ===")
for room in ("mb-sonnet-2-registration","d-sonnet-2-results"):
    rows=read(room,200)
    hits=0
    for r,d in rows:
        if r.get("from")!=REF: continue
        blob=json.dumps(d,ensure_ascii=False,sort_keys=True)
        if MARU in blob or FRESH in blob:
            hits+=1
            print("MARU_AUTHORITY="+json.dumps({
              "room":room,"seq":r.get("seq"),"ts":r.get("ts"),
              "type":d.get("type"),"request_id":d.get("request_id"),
              "status":d.get("status"),"reason":d.get("reason"),
              "intake_seq":d.get("intake_seq"),"role":d.get("role"),
            },ensure_ascii=False,sort_keys=True))
    print("MARU_AUTHORITY_HITS="+json.dumps({"room":room,"hits":hits},sort_keys=True))

print("DEADLINE_LIVE_RADAR=COMPLETE_READ_ONLY NO_SIGNING=YES NO_POST=YES NO_RESTART=YES")
PY
