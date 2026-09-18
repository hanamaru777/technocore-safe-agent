#!/usr/bin/env bash
set -Eeuo pipefail

REPO=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
EXPECTED_HEAD=b8dc6ef0b1ac689f1c45a0fb1451800c75dd5c1f
REQ=maru-rescue-team-request-20260918-1
SAFETY="$STATE/observer-safety.json"

stop() {
  trap - ERR
  echo "MARU_RESCUE_ROOM=STOP:$1"
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
a=float(sys.argv[1]); raise SystemExit(0 if 0 <= a <= 300 else 1)
PY
[[ "$EVENTS" == 117 && "$MESSAGES" == 5083155 ]] || stop "P0_core_changed:$EVENTS/$MESSAGES"
echo "MARU_RESCUE_ROOM_PREFLIGHT=PASS health=$HEALTH age=$AGE core=$EVENTS/$MESSAGES"

TMP=$(mktemp /tmp/maru-rescue-room.XXXXXX.py)
trap 'rm -f "$TMP"' EXIT

cat >"$TMP" <<'PY'
from __future__ import annotations
import hashlib,json,os,secrets,subprocess,sys,time
from datetime import UTC,datetime
from flop_agent import core,observer,oracle_signer
from flop_agent.public_record import verify_signed_record

MARU="did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
REF="did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
DISC="mb-sonnet-2-discovery"
REG="mb-sonnet-2-registration"
RESULTS="d-sonnet-2-results"
GAME="maru-rescue-1"
TEAM="d-sonnet-2-team-maru-rescue-1"
REQUEST_ID="maru-rescue-team-request-20260918-1"
STATE=core.STATE/"signer"/"sonnet-2-maru-rescue-team-request-20260918.json"

PAYLOAD={
  "type":"sonnet.team-request.v1",
  "contest_id":"sonnet-2",
  "game_id":GAME,
  "request_id":REQUEST_ID,
}
TEXT=json.dumps(PAYLOAD,sort_keys=True,separators=(",",":"),ensure_ascii=True)
TEXT_HASH=hashlib.sha256(TEXT.encode()).hexdigest()

def stop(reason):
    print("MARU_RESCUE_ROOM=STOP:"+reason)
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

def persist(state,**extra):
    observer.atomic_json_write(STATE,{
      "schema_version":1,"request_id":REQUEST_ID,"state":state,"text_hash":TEXT_HASH,**extra
    },compact=True,mode=0o600)

def inspect():
    team=verified(TEAM,50)
    if team:
        print("MARU_RESCUE_ROOM_ALREADY_EXISTS="+json.dumps([
          {"seq":r.get("seq"),"ts":r.get("ts"),"from":r.get("from"),"type":d.get("type"),
           "request_id":d.get("request_id"),"status":d.get("status"),"reason":d.get("reason"),
           "intake_seq":d.get("intake_seq"),"room_generation":d.get("room_generation")}
          for r,d in team
        ],ensure_ascii=False,sort_keys=True))
        stop("team_room_not_fresh")

    existing=None
    for r,d in verified(DISC):
        if d.get("request_id")==REQUEST_ID:
            if r.get("from")!=MARU:stop("request_id_collision")
            if d!=PAYLOAD or r.get("text")!=TEXT:stop("existing_request_payload_conflict")
            existing=r
        if d.get("type")=="sonnet.team-request.v1" and d.get("game_id")==GAME and d.get("request_id")!=REQUEST_ID:
            print("OTHER_TEAM_REQUEST="+json.dumps({
              "seq":r.get("seq"),"ts":r.get("ts"),"sender":r.get("from"),"request_id":d.get("request_id")
            },sort_keys=True))
            stop("game_id_already_requested")
    return existing

def print_current_maru_authority():
    for room in (REG,RESULTS):
        for r,d in verified(room):
            if r.get("from")!=REF:continue
            blob=json.dumps(d,ensure_ascii=False,sort_keys=True)
            if MARU in blob or "maru-sonnet2-writer-fresh-20260917-1" in blob:
                print("MARU_AUTHORITY="+json.dumps({
                  "room":room,"seq":r.get("seq"),"ts":r.get("ts"),"type":d.get("type"),
                  "request_id":d.get("request_id"),"status":d.get("status"),"reason":d.get("reason"),
                  "intake_seq":d.get("intake_seq"),"role":d.get("role")
                },ensure_ascii=False,sort_keys=True))

def sign_text(nonce):
    def op():
        p=subprocess.run([sys.executable,str(core.ROOT/"scripts"/"sign.py"),"say",DISC,nonce,TEXT],
                         cwd=core.ROOT,env=os.environ.copy(),text=True,capture_output=True,check=False)
        if p.returncode!=0:raise RuntimeError("official_signer_failed")
        return [x.strip() for x in p.stdout.splitlines() if x.strip()]
    return oracle_signer.with_vault_seed(op)

if STATE.exists():
    try:prior=json.loads(STATE.read_text("utf-8"))
    except Exception:stop("state_file_invalid")
    if prior.get("request_id")!=REQUEST_ID:stop("state_request_id_conflict")
    if prior.get("state")=="posted":
        print("MARU_RESCUE_ROOM=ALREADY_POSTED seq="+str(prior.get("seq"))+" ts="+str(prior.get("ts")))
        print("REQUEST_ID="+REQUEST_ID)
        print("DO_NOT_RERUN_THIS_BLOCK=YES")
        raise SystemExit(0)
    stop("prior_attempt_state_"+str(prior.get("state","unknown")))

if oracle_signer.expected_did()!=MARU:stop("maru_expected_did_mismatch")
core.require_verified_did(MARU)
if not core.signer_matches_pinned():stop("signer_not_pinned")

existing=inspect()
print_current_maru_authority()
if existing is not None:
    persist("posted",seq=existing.get("seq"),ts=existing.get("ts"),reconciled=True)
    print("MARU_RESCUE_ROOM=RECONCILED seq="+str(existing.get("seq"))+" ts="+str(existing.get("ts")))
    print("REQUEST_ID="+REQUEST_ID)
    print("DO_NOT_RERUN_THIS_BLOCK=YES")
    raise SystemExit(0)

persist("preparing",started_at=datetime.now(UTC).isoformat())
nonce=core.make_nonce(DISC,MARU)
try:signed=sign_text(nonce)
except Exception:
    persist("sign_failed",failed_at=datetime.now(UTC).isoformat())
    stop("official_signer_failed")
if len(signed)!=2 or signed[0]!=MARU:
    persist("sign_output_invalid",failed_at=datetime.now(UTC).isoformat())
    stop("signer_output_invalid")
verify_signed_record(DISC,{"from":MARU,"nonce":nonce,"text":TEXT,"sig":signed[1]})

existing=inspect()
if existing is not None:
    persist("posted",seq=existing.get("seq"),ts=existing.get("ts"),reconciled=True)
    print("MARU_RESCUE_ROOM=RECONCILED seq="+str(existing.get("seq"))+" ts="+str(existing.get("ts")))
    print("REQUEST_ID="+REQUEST_ID)
    print("DO_NOT_RERUN_THIS_BLOCK=YES")
    raise SystemExit(0)

persist("attempting",attempted_at=datetime.now(UTC).isoformat())
try:
    response=core.httpx.post(
      f"{core.BASE_URL}/r/{DISC}?format=json",
      json={"did":MARU,"nonce":nonce,"text":TEXT,"sig":signed[1]},
      timeout=20,
    )
    response.raise_for_status()
    body=response.json(); row=body.get("posted")
    if not isinstance(row,dict) or row.get("from")!=MARU or str(row.get("nonce"))!=nonce or row.get("text")!=TEXT or row.get("sig")!=signed[1] or type(row.get("seq")) is not int or not isinstance(row.get("ts"),str):
        raise RuntimeError("posted_receipt_mismatch")
    verify_signed_record(DISC,row)
except Exception:
    persist("ambiguous",ambiguous_at=datetime.now(UTC).isoformat())
    print("MARU_RESCUE_ROOM=STOP:submission_unknown")
    print("REQUEST_ID="+REQUEST_ID)
    print("NO_BLIND_RETRY=YES")
    print("DO_NOT_RERUN_THIS_BLOCK=YES")
    raise SystemExit(1)

persist("posted",seq=row["seq"],ts=row["ts"],completed_at=datetime.now(UTC).isoformat())
print("MARU_RESCUE_ROOM=PASS seq="+str(row["seq"])+" ts="+row["ts"])
print("REQUEST_ID="+REQUEST_ID)
print("TYPE=sonnet.team-request.v1")
print("BINDING_ROSTER_CONSENT=NO")
print("REGISTRATION_RETRY=NO")
print("DO_NOT_RERUN_THIS_BLOCK=YES")

start_seq=row["seq"]
end=time.monotonic()+300
seen=set()
while True:
    for r,d in verified(DISC):
        seq=r.get("seq")
        if not isinstance(seq,int) or seq<=start_seq:continue
        key=(seq,r.get("from"))
        if key in seen:continue
        relevant=(
          d.get("request_id")==REQUEST_ID or
          d.get("game_id")==GAME or
          (r.get("from")==REF and d.get("request_id")==REQUEST_ID)
        )
        if not relevant:continue
        seen.add(key)
        print("MARU_RESCUE_ROOM_FOLLOWUP="+json.dumps({
          "seq":seq,"ts":r.get("ts"),"sender":r.get("from"),
          "official_referee":r.get("from")==REF,"type":d.get("type"),
          "request_id":d.get("request_id"),"game_id":d.get("game_id"),
          "status":d.get("status"),"reason":d.get("reason"),
          "intake_seq":d.get("intake_seq"),"poem_room":d.get("poem_room"),
          "room_generation":d.get("room_generation"),"text":d.get("text")
        },ensure_ascii=False,sort_keys=True))
    team=verified(TEAM,50)
    if team:
        for r,d in team:
            key=("team",r.get("seq"))
            if key in seen:continue
            seen.add(key)
            print("MARU_RESCUE_TEAM_RECORD="+json.dumps({
              "seq":r.get("seq"),"ts":r.get("ts"),"sender":r.get("from"),
              "official_referee":r.get("from")==REF,"type":d.get("type"),
              "request_id":d.get("request_id"),"status":d.get("status"),
              "reason":d.get("reason"),"intake_seq":d.get("intake_seq"),
              "room_generation":d.get("room_generation")
            },ensure_ascii=False,sort_keys=True))
    print_current_maru_authority()
    if time.monotonic()>=end:break
    time.sleep(10)

print("MARU_RESCUE_ROOM_WATCH=COMPLETE_READ_ONLY")
PY

chmod 0644 "$TMP"

sudo bash -c '
set -Eeuo pipefail
set -a
. /etc/technocore-safe-agent/signer.env
set +a
exec /usr/sbin/runuser   -u technocore-signer   -g technocore-signer   -G technocore-autopilot   -- /usr/bin/env -i   PATH=/usr/bin:/bin   FLOP_STATE_DIR=/var/lib/technocore-safe-agent   PYTHONPATH=/opt/technocore-safe-agent/src   OCI_VAULT_SECRET_OCID="$OCI_VAULT_SECRET_OCID"   TECHNOCORE_SIGNER_EXPECTED_DID="$TECHNOCORE_SIGNER_EXPECTED_DID"   /opt/technocore-safe-agent/.venv/bin/python "$1"
' _ "$TMP"

echo "MARU_RESCUE_ROOM_HELPER=COMPLETE"
