#!/usr/bin/env bash
set -Eeuo pipefail

REPO=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
EXPECTED_HEAD=b8dc6ef0b1ac689f1c45a0fb1451800c75dd5c1f
REQ=maru-kof-apply-20260918-1
SAFETY="$STATE/observer-safety.json"

stop() {
  trap - ERR
  echo "KOF_APPLICATION=STOP:$1"
  echo "REQUEST_ID=$REQ"
  echo "DO_NOT_RERUN_THIS_BLOCK=YES"
  exit 1
}
trap 'stop unexpected_rc_$?' ERR

cd "$REPO"
OWNER=$(stat -c %U .git) || stop git_owner_unreadable
HEAD=$(sudo -u "$OWNER" git -C "$REPO" rev-parse HEAD) || stop git_head_unreadable
[[ "$HEAD" == "$EXPECTED_HEAD" ]] || stop "unexpected_head:$HEAD"

for svc in   technocore-safe-agent-resident.service   technocore-safe-agent-lobby-capture.service   technocore-safe-agent-signer.service   technocore-safe-agent-discord.service   technocore-safe-agent-metadata-block.service
do
  systemctl is-active --quiet "$svc" || stop "service_not_active:$svc"
done

read -r HEALTH AGE EVENTS MESSAGES < <(
  timeout 5s python3 - "$SAFETY" <<'PY'
import datetime,json,sys
with open(sys.argv[1],encoding="utf-8") as f:d=json.load(f)
t=datetime.datetime.fromisoformat(d["updated_at"].replace("Z","+00:00"))
if t.tzinfo is None:t=t.replace(tzinfo=datetime.timezone.utc)
age=(datetime.datetime.now(datetime.timezone.utc)-t.astimezone(datetime.timezone.utc)).total_seconds()
print(d["health"],round(age,3),d["unrecoverable_core_gap_events"],d["unrecoverable_core_gap_messages"])
PY
) || stop safety_unreadable

[[ "$HEALTH" == ok || "$HEALTH" == degraded ]] || stop "health_not_allowed:$HEALTH"
python3 - "$AGE" <<'PY' || stop safety_stale
import sys
age=float(sys.argv[1])
raise SystemExit(0 if 0 <= age <= 300 else 1)
PY
[[ "$EVENTS" == 117 && "$MESSAGES" == 5083155 ]] || stop "P0_core_changed:$EVENTS/$MESSAGES"
echo "KOF_PREFLIGHT=PASS health=$HEALTH age=$AGE core=$EVENTS/$MESSAGES"

TMP=$(mktemp /tmp/maru-kof-deadline.XXXXXX.py)
trap 'rm -f "$TMP"' EXIT

cat >"$TMP" <<'PY'
from __future__ import annotations
import hashlib,json,os,secrets,subprocess,sys,time
from datetime import UTC,datetime,timedelta
from flop_agent import core,observer,oracle_signer
from flop_agent.public_record import verify_signed_record

DISCOVERY="mb-sonnet-2-discovery"
TEAM="d-sonnet-2-team-keepers-of-flame"
REG="mb-sonnet-2-registration"
RESULTS="d-sonnet-2-results"

MARU="did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
LEADER="did:key:z6MkpRDNDS5WBPmvnx7nTqWa4T7RWX8hSnt8ssVyJC8HTyqB"
REF="did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
FRESH_REG="maru-sonnet2-writer-fresh-20260917-1"
REQUEST_ID="maru-kof-apply-20260918-1"
STATE=core.STATE/"signer"/"sonnet-2-kof-application-20260918.json"

PAYLOAD={
  "type":"sonnet.application.v1",
  "contest_id":"sonnet-2",
  "game_id":"keepers-of-flame",
  "request_id":REQUEST_ID,
  "target_did":LEADER,
  "text":(
    "MARU application. DID "+MARU+". "
    "no_live_roster_consent:true. "
    "Pre-open signed identity evidence: lobby seq 13745384. "
    "Writer registration delivery: seq 82764 request 32c15433c6d73af1cea5d6467dece016; "
    "fresh recovery delivery: seq 3269740 request maru-sonnet2-writer-fresh-20260917-1. "
    "Authoritative writer receipt is still pending operator lookup in official challenge issue #25, "
    "so I am NOT claiming accepted writer status. "
    "Please independently verify eligibility and exact solver fit. "
    "If both pass, send the exact current generation-2 roster proposal."
  ),
}
TEXT=json.dumps(PAYLOAD,sort_keys=True,separators=(",",":"),ensure_ascii=True)
TEXT_HASH=hashlib.sha256(TEXT.encode()).hexdigest()
FRESHNESS=timedelta(minutes=20)

def stop(reason):
    print("KOF_APPLICATION=STOP:"+reason)
    print("REQUEST_ID="+REQUEST_ID)
    print("DO_NOT_RERUN_THIS_BLOCK=YES")
    raise SystemExit(1)

def read_room(room,limit=200):
    try:p=core.read_room(room,limit=limit,cache_buster=secrets.token_hex(16))
    except Exception as e:
        print("READ_ERROR room="+room+" error="+type(e).__name__)
        stop("room_read_failed")
    rows=p if isinstance(p,list) else p.get("messages",[]) if isinstance(p,dict) else []
    return rows if isinstance(rows,list) else []

def verified(room,limit=200):
    out=[]
    for r in read_room(room,limit):
        if not isinstance(r,dict):continue
        try:
            verify_signed_record(room,r)
            d=json.loads(r.get("text",""))
        except Exception:continue
        if isinstance(d,dict):out.append((r,d))
    return out

def parse_ts(v):
    try:return datetime.fromisoformat(str(v).replace("Z","+00:00")).astimezone(UTC)
    except Exception:return None

def persist(state,**extra):
    observer.atomic_json_write(STATE,{
      "schema_version":1,"request_id":REQUEST_ID,"state":state,"text_hash":TEXT_HASH,**extra
    },compact=True,mode=0o600)

def require_team_open():
    rows=verified(TEAM)
    room_ok=any(r.get("from")==REF and r.get("seq")==2 and d.get("type")=="sonnet.room.v1" and d.get("game_id")=="keepers-of-flame" for r,d in rows)
    setup_ok=any(
      r.get("from")==REF and r.get("seq")==3 and d.get("type")=="sonnet.receipt.v1"
      and d.get("request_id")=="resetup-keepers-of-flame-2"
      and d.get("status")=="accepted" and d.get("room_generation")==2
      and d.get("intake_seq")==425583
      for r,d in rows
    )
    if not room_ok or not setup_ok:stop("kof_authoritative_setup_changed")
    later=[r.get("seq") for r,_ in rows if type(r.get("seq")) is int and r["seq"]>3]
    if later:
        print("KOF_TEAM_NEW_SEQS="+",".join(map(str,sorted(later))))
        stop("kof_team_already_advanced")

def inspect_discovery():
    rows=verified(DISCOVERY)
    now=datetime.now(UTC)
    latest=None
    existing=None
    for r,d in rows:
        if d.get("request_id")==REQUEST_ID:
            if r.get("from")!=MARU:stop("request_id_collision")
            if d!=PAYLOAD or r.get("text")!=TEXT:stop("existing_request_payload_conflict")
            existing=r
        members=d.get("members") if isinstance(d.get("members"),list) else []
        if d.get("type")=="sonnet.roster.v1" and d.get("game_id")=="keepers-of-flame" and MARU in members:
            print("KOF_MARU_ROSTER_ALREADY_PRESENT="+json.dumps({
              "seq":r.get("seq"),"ts":r.get("ts"),"sender":r.get("from"),
              "request_id":d.get("request_id"),"room_generation":d.get("room_generation"),
              "poem_room":d.get("poem_room"),"members":members
            },ensure_ascii=False,sort_keys=True))
            stop("maru_in_kof_roster_already")
        if r.get("from")==LEADER and d.get("game_id")=="keepers-of-flame" and d.get("type")=="sonnet.note.v1":
            txt=str(d.get("text","")).lower()
            if "seats open now" not in txt and "writers welcome" not in txt:continue
            when=parse_ts(r.get("ts"))
            if when and -timedelta(minutes=1) <= now-when <= FRESHNESS:
                if latest is None or (r.get("seq") or -1)>(latest[0].get("seq") or -1): latest=(r,d)
    if existing:return "existing",existing,latest
    if latest is None:stop("no_fresh_kof_open_seat_recruit")
    r,d=latest
    print("KOF_RECRUIT_CONFIRMED="+json.dumps({
      "seq":r.get("seq"),"ts":r.get("ts"),"sender":r.get("from"),
      "request_id":d.get("request_id"),"text":d.get("text")
    },ensure_ascii=False,sort_keys=True))
    return "none",None,latest

def print_maru_authority():
    for room in (REG,RESULTS):
        for r,d in verified(room):
            if r.get("from")!=REF:continue
            blob=json.dumps(d,ensure_ascii=False,sort_keys=True)
            if MARU in blob or FRESH_REG in blob:
                print("NEW_MARU_AUTHORITY="+json.dumps({
                  "room":room,"seq":r.get("seq"),"ts":r.get("ts"),
                  "type":d.get("type"),"request_id":d.get("request_id"),
                  "status":d.get("status"),"reason":d.get("reason"),
                  "intake_seq":d.get("intake_seq"),"role":d.get("role")
                },ensure_ascii=False,sort_keys=True))

def sign_official(nonce):
    def op():
        env=os.environ.copy()
        p=subprocess.run([
          sys.executable,str(core.ROOT/"scripts"/"sign.py"),"say",DISCOVERY,nonce,TEXT
        ],cwd=core.ROOT,env=env,text=True,capture_output=True,check=False)
        if p.returncode!=0:raise RuntimeError("official_signer_failed")
        return [x.strip() for x in p.stdout.splitlines() if x.strip()]
    return oracle_signer.with_vault_seed(op)

def followup():
    end=time.monotonic()+120
    seen=set()
    while True:
        for r,d in verified(DISCOVERY):
            seq=r.get("seq")
            if not isinstance(seq,int):continue
            key=(seq,r.get("from"))
            if key in seen:continue
            members=d.get("members") if isinstance(d.get("members"),list) else []
            relevant=d.get("game_id")=="keepers-of-flame" and (
              r.get("from") in (LEADER,REF) or MARU in members or MARU in json.dumps(d,ensure_ascii=False)
            )
            if not relevant:continue
            seen.add(key)
            print("KOF_FOLLOWUP="+json.dumps({
              "seq":seq,"ts":r.get("ts"),"sender":r.get("from"),
              "official_referee":r.get("from")==REF,"from_leader":r.get("from")==LEADER,
              "type":d.get("type"),"request_id":d.get("request_id"),
              "status":d.get("status"),"reason":d.get("reason"),
              "room_generation":d.get("room_generation"),"poem_room":d.get("poem_room"),
              "target_is_maru":d.get("target_did")==MARU,
              "maru_in_members":MARU in members if members else False,
              "members":members if members else None,"text":d.get("text")
            },ensure_ascii=False,sort_keys=True))
        team=verified(TEAM)
        for r,d in team:
            if type(r.get("seq")) is int and r["seq"]>3:
                print("KOF_TEAM_UPDATE="+json.dumps({
                  "seq":r.get("seq"),"ts":r.get("ts"),"sender":r.get("from"),
                  "official_referee":r.get("from")==REF,"type":d.get("type"),
                  "request_id":d.get("request_id"),"status":d.get("status"),
                  "reason":d.get("reason"),"intake_seq":d.get("intake_seq"),
                  "version":d.get("version"),"word":d.get("word")
                },ensure_ascii=False,sort_keys=True))
        print_maru_authority()
        if time.monotonic()>=end:break
        time.sleep(10)
    print("KOF_FOLLOWUP_WATCH=COMPLETE_READ_ONLY")

if STATE.exists():
    try:prior=json.loads(STATE.read_text("utf-8"))
    except Exception:stop("state_file_invalid")
    if prior.get("request_id")!=REQUEST_ID:stop("state_request_id_conflict")
    if prior.get("state")=="posted":
        print("KOF_APPLICATION=ALREADY_POSTED seq="+str(prior.get("seq"))+" ts="+str(prior.get("ts")))
        print("REQUEST_ID="+REQUEST_ID)
        print("DO_NOT_RERUN_THIS_BLOCK=YES")
        raise SystemExit(0)
    stop("prior_attempt_state_"+str(prior.get("state","unknown")))

if oracle_signer.expected_did()!=MARU:stop("maru_expected_did_mismatch")
core.require_verified_did(MARU)
if not core.signer_matches_pinned():stop("signer_not_pinned")

require_team_open()
kind,existing,_=inspect_discovery()
print_maru_authority()
if kind=="existing":
    persist("posted",seq=existing.get("seq"),ts=existing.get("ts"),reconciled=True)
    print("KOF_APPLICATION=RECONCILED seq="+str(existing.get("seq"))+" ts="+str(existing.get("ts")))
    print("REQUEST_ID="+REQUEST_ID)
    print("DO_NOT_RERUN_THIS_BLOCK=YES")
    followup()
    raise SystemExit(0)

persist("preparing",started_at=datetime.now(UTC).isoformat())
nonce=core.make_nonce(DISCOVERY,MARU)
try:signed=sign_official(nonce)
except Exception:
    persist("sign_failed",failed_at=datetime.now(UTC).isoformat())
    stop("official_signer_failed")
if len(signed)!=2 or signed[0]!=MARU:
    persist("sign_output_invalid",failed_at=datetime.now(UTC).isoformat())
    stop("signer_output_invalid")
verify_signed_record(DISCOVERY,{"from":MARU,"nonce":nonce,"text":TEXT,"sig":signed[1]})

require_team_open()
kind,existing,_=inspect_discovery()
if kind=="existing":
    persist("posted",seq=existing.get("seq"),ts=existing.get("ts"),reconciled=True)
    print("KOF_APPLICATION=RECONCILED seq="+str(existing.get("seq"))+" ts="+str(existing.get("ts")))
    print("REQUEST_ID="+REQUEST_ID)
    print("DO_NOT_RERUN_THIS_BLOCK=YES")
    followup()
    raise SystemExit(0)

persist("attempting",attempted_at=datetime.now(UTC).isoformat())
try:
    response=core.httpx.post(
      f"{core.BASE_URL}/r/{DISCOVERY}?format=json",
      json={"did":MARU,"nonce":nonce,"text":TEXT,"sig":signed[1]},
      timeout=20,
    )
    response.raise_for_status()
    body=response.json()
    row=body.get("posted")
    if not isinstance(row,dict) or row.get("from")!=MARU or str(row.get("nonce"))!=nonce or row.get("text")!=TEXT or row.get("sig")!=signed[1] or type(row.get("seq")) is not int or not isinstance(row.get("ts"),str):
        raise RuntimeError("posted_receipt_mismatch")
    verify_signed_record(DISCOVERY,row)
except Exception:
    persist("ambiguous",ambiguous_at=datetime.now(UTC).isoformat())
    print("KOF_APPLICATION=STOP:submission_unknown")
    print("REQUEST_ID="+REQUEST_ID)
    print("NO_BLIND_RETRY=YES")
    print("DO_NOT_RERUN_THIS_BLOCK=YES")
    raise SystemExit(1)

persist("posted",seq=row["seq"],ts=row["ts"],completed_at=datetime.now(UTC).isoformat())
print("KOF_APPLICATION=PASS seq="+str(row["seq"])+" ts="+row["ts"])
print("REQUEST_ID="+REQUEST_ID)
print("TYPE=sonnet.application.v1")
print("BINDING_ROSTER_CONSENT=NO")
print("REGISTRATION_ACCEPTANCE_CLAIM=NO")
print("NEXT=READ_ONLY_KOF_RESPONSE_OR_ROSTER")
print("DO_NOT_RERUN_THIS_BLOCK=YES")
followup()
PY

chmod 0644 "$TMP"

sudo bash -c '
set -Eeuo pipefail
set -a
. /etc/technocore-safe-agent/signer.env
set +a
exec /usr/sbin/runuser   -u technocore-signer   -g technocore-signer   -G technocore-autopilot   -- /usr/bin/env -i   PATH=/usr/bin:/bin   FLOP_STATE_DIR=/var/lib/technocore-safe-agent   PYTHONPATH=/opt/technocore-safe-agent/src   OCI_VAULT_SECRET_OCID="$OCI_VAULT_SECRET_OCID"   TECHNOCORE_SIGNER_EXPECTED_DID="$TECHNOCORE_SIGNER_EXPECTED_DID"   /opt/technocore-safe-agent/.venv/bin/python "$1"
' _ "$TMP"

echo "KOF_HELPER=COMPLETE"
