#!/usr/bin/env bash
set -Eeuo pipefail

REPO=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
EXPECTED_HEAD=b8dc6ef0b1ac689f1c45a0fb1451800c75dd5c1f
SAFETY="$STATE/observer-safety.json"

pre_stop() {
  trap - ERR
  echo "MARU_ROSTER_V3=STOP_PRE_SIGN:$1"
  echo "REQUEST_CONSUMED=NO"
  exit 1
}
trap 'pre_stop unexpected_rc_$?' ERR

cd "$REPO"
OWNER=$(stat -c %U .git) || pre_stop git_owner_unreadable
HEAD=$(sudo -u "$OWNER" git -C "$REPO" rev-parse HEAD) || pre_stop git_head_unreadable
[[ "$HEAD" == "$EXPECTED_HEAD" ]] || pre_stop "unexpected_head:$HEAD"

for svc in   technocore-safe-agent-resident.service   technocore-safe-agent-lobby-capture.service   technocore-safe-agent-signer.service   technocore-safe-agent-discord.service   technocore-safe-agent-metadata-block.service
do
  systemctl is-active --quiet "$svc" || pre_stop "service_not_active:$svc"
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
) || pre_stop safety_unreadable

[[ "$HEALTH" == ok ]] || pre_stop "health_not_ok:$HEALTH"
python3 - "$AGE" <<'PY' || pre_stop safety_stale
import sys
a=float(sys.argv[1]); raise SystemExit(0 if 0 <= a <= 120 else 1)
PY
[[ "$EVENTS" == 117 && "$MESSAGES" == 5083155 ]] || pre_stop "P0_core_changed:$EVENTS/$MESSAGES"

echo "MARU_ROSTER_V3_PREFLIGHT=PASS health=$HEALTH age=$AGE core=$EVENTS/$MESSAGES"

TMP=$(mktemp /tmp/maru-roster-v3.XXXXXX.py)
trap 'rm -f "$TMP"' EXIT

cat >"$TMP" <<'PY'
from __future__ import annotations
import hashlib,json,os,secrets,subprocess,sys,time
from datetime import UTC,datetime
from flop_agent import core,observer,oracle_signer
from flop_agent.public_record import verify_signed_record

MARU="did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
REF="did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
GRID="did:key:z6Mkr1NYDRusR9wDgrXW65bQj4Vg39mfJXFmXTxd4PLfjxaj"
PUPH="did:key:z6MkmVhZbUKWmg3r6TTi3SVM3myYJ9BLbWYPSdc5iWPuPhb6"
WAKE="did:key:z6Mkr3hsA4hYbvrQeG61kSgKw51LTBo7d5TCHWyyQfjUmteK"

DISC="mb-sonnet-2-discovery"
TEAM="d-sonnet-2-team-maru-rescue-1"
GAME="maru-rescue-1"
GEN=1
BASELINE_LAST=149890
RID="maru-rescue-roster-20260918-3"
MEMBERS=[MARU,GRID,PUPH,WAKE]
PAYLOAD={
  "type":"sonnet.roster.v1",
  "contest_id":"sonnet-2",
  "game_id":GAME,
  "poem_room":TEAM,
  "room_generation":GEN,
  "members":MEMBERS,
  "request_id":RID,
}
STATE=core.STATE/"signer"/(RID+".json")
SIGNED_PHASE=False

def stop_pre(reason):
    if SIGNED_PHASE:
        raise RuntimeError("post_sign_gate:"+reason)
    print("MARU_ROSTER_V3=STOP_PRE_SIGN:"+reason)
    print("REQUEST_CONSUMED=NO")
    raise SystemExit(1)

def stop_terminal(reason,state="aborted_after_sign"):
    persist(state,reason=reason,ended_at=datetime.now(UTC).isoformat())
    print("MARU_ROSTER_V3=STOP_TERMINAL:"+reason)
    print("REQUEST_ID="+RID)
    print("DO_NOT_REUSE_REQUEST_ID=YES")
    raise SystemExit(1)

def persist(state,**extra):
    text=json.dumps(PAYLOAD,sort_keys=True,separators=(",",":"),ensure_ascii=True)
    observer.atomic_json_write(STATE,{
      "schema_version":1,
      "request_id":RID,
      "state":state,
      "text_hash":hashlib.sha256(text.encode()).hexdigest(),
      **extra,
    },compact=True,mode=0o600)

def get_room(room,since=0):
    try:
        r=core.httpx.get(
          f"{core.BASE_URL}/r/{room}",
          params={"format":"json","since":since,"limit":250,"wait":0},
          timeout=20,
        )
        r.raise_for_status()
        d=r.json()
    except Exception as e:
        print("ROOM_READ_ERROR="+type(e).__name__)
        raise
    if not isinstance(d,dict) or not isinstance(d.get("messages"),list):
        raise RuntimeError("bad_room_json")
    return d

def verified_rows(room,since=0):
    body=get_room(room,since)
    out=[]
    for r in body["messages"]:
        if not isinstance(r,dict):continue
        try:
            verify_signed_record(room,r)
        except Exception:
            continue
        try:d=json.loads(r.get("text",""))
        except Exception:d=None
        out.append((r,d))
    return body,out

def require_team_pristine():
    body,rows=verified_rows(TEAM,0)
    if body.get("generation")!=GEN:
        stop_pre("team_generation_changed:"+str(body.get("generation")))
    signed=[(r,d) for r,d in rows if isinstance(r.get("seq"),int)]
    if len(signed)!=1:
        stop_pre("team_not_pristine:message_count="+str(len(signed)))
    r,d=signed[0]
    if not (
      r.get("seq")==1 and r.get("from")==REF and isinstance(d,dict)
      and d.get("type")=="sonnet.room.v1" and d.get("contest_id")=="sonnet-2"
      and d.get("game_id")==GAME
    ):
        stop_pre("team_seq1_authority_mismatch")

def new_discovery_rows():
    body,rows=verified_rows(DISC,BASELINE_LAST)
    count=body.get("count")
    first=body.get("first_seq")
    if isinstance(count,int) and count>0:
        if not isinstance(first,int) or first>BASELINE_LAST+1:
            stop_pre("discovery_gap_after_approval:first="+str(first))
    return rows

def require_candidates_unchanged():
    rows=new_discovery_rows()
    for r,d in rows:
        seq=r.get("seq")
        sender=r.get("from")
        if not isinstance(seq,int) or seq<=BASELINE_LAST:
            continue
        if sender in MEMBERS[1:] and isinstance(d,dict):
            if d.get("type")=="sonnet.roster.v1":
                stop_pre("candidate_new_roster:"+sender+":"+str(seq))
            txt=str(d.get("text","")).lower()
            if any(x in txt for x in (
              "cannot join","not available","not free","live roster consent now taken",
              "must decline","already frozen","roster locked"
            )):
                stop_pre("candidate_unavailable:"+sender+":"+str(seq))
        if isinstance(d,dict) and d.get("type")=="sonnet.receipt.v1":
            sd=d.get("sender_did")
            if sd in MEMBERS[1:] and d.get("status")=="accepted":
                rr=str(d.get("request_id",""))
                if "roster" in rr or rr.startswith("cs-"):
                    stop_pre("candidate_referee_roster_receipt:"+sd+":"+str(seq))
    return rows

def require_no_maru_roster():
    _,rows=verified_rows(DISC,BASELINE_LAST)
    for r,d in rows:
        if isinstance(d,dict) and d.get("type")=="sonnet.roster.v1":
            mem=d.get("members")
            if isinstance(mem,list) and MARU in mem:
                stop_pre("maru_roster_already_present:"+str(r.get("seq")))

def reconcile_request():
    _,rows=verified_rows(DISC,BASELINE_LAST)
    for r,d in rows:
        if isinstance(d,dict) and d.get("request_id")==RID:
            if r.get("from")!=MARU or d!=PAYLOAD:
                stop_pre("request_id_collision")
            persist("posted",seq=r.get("seq"),ts=r.get("ts"),reconciled=True)
            print("MARU_ROSTER_V3=RECONCILED seq="+str(r.get("seq")))
            print("DO_NOT_RERUN=YES")
            raise SystemExit(0)

def sign_text(text,nonce):
    def op():
        p=subprocess.run(
          [sys.executable,str(core.ROOT/"scripts"/"sign.py"),"say",DISC,nonce,text],
          cwd=core.ROOT,env=os.environ.copy(),text=True,capture_output=True,check=False,
        )
        if p.returncode!=0:
            raise RuntimeError("official_signer_failed")
        return [x.strip() for x in p.stdout.splitlines() if x.strip()]
    return oracle_signer.with_vault_seed(op)

if STATE.exists():
    try:prior=json.loads(STATE.read_text("utf-8"))
    except Exception:stop_pre("state_file_invalid")
    print("MARU_ROSTER_V3=STOP_PRIOR_STATE:"+str(prior.get("state")))
    print("REQUEST_ID="+RID)
    print("DO_NOT_RERUN=YES")
    raise SystemExit(1)

if oracle_signer.expected_did()!=MARU:stop_pre("expected_did_mismatch")
core.require_verified_did(MARU)
if not core.signer_matches_pinned():stop_pre("signer_not_pinned")

require_team_pristine()
require_candidates_unchanged()
require_no_maru_roster()
reconcile_request()

text=json.dumps(PAYLOAD,sort_keys=True,separators=(",",":"),ensure_ascii=True)
persist("preparing",prepared_at=datetime.now(UTC).isoformat(),baseline_last=BASELINE_LAST)

nonce=core.make_nonce(DISC,MARU)
try:
    signed=sign_text(text,nonce)
except Exception:
    stop_terminal("official_signer_failed","sign_failed")
if len(signed)!=2 or signed[0]!=MARU:
    stop_terminal("signer_output_invalid","sign_output_invalid")
verify_signed_record(DISC,{"from":MARU,"nonce":nonce,"text":text,"sig":signed[1]})
persist("signed",nonce=nonce,signed_at=datetime.now(UTC).isoformat())
SIGNED_PHASE=True

# Binding payload is signed but not yet posted. Any state change now abandons RID.
try:
    require_team_pristine()
    require_candidates_unchanged()
    require_no_maru_roster()
except Exception as e:
    stop_terminal("state_changed_after_sign:"+type(e).__name__)

persist("attempting",nonce=nonce,attempted_at=datetime.now(UTC).isoformat())
try:
    response=core.httpx.post(
      f"{core.BASE_URL}/r/{DISC}?format=json",
      json={"did":MARU,"nonce":nonce,"text":text,"sig":signed[1]},
      timeout=20,
    )
    response.raise_for_status()
    body=response.json()
    row=body.get("posted")
    if not isinstance(row,dict):
        raise RuntimeError("missing_posted_row")
    if (
      row.get("from")!=MARU or str(row.get("nonce"))!=nonce
      or row.get("text")!=text or row.get("sig")!=signed[1]
      or type(row.get("seq")) is not int or not isinstance(row.get("ts"),str)
    ):
        raise RuntimeError("posted_receipt_mismatch")
    verify_signed_record(DISC,row)
except Exception:
    persist("ambiguous",nonce=nonce,ambiguous_at=datetime.now(UTC).isoformat())
    print("MARU_ROSTER_V3=STOP:submission_unknown")
    print("REQUEST_ID="+RID)
    print("NO_BLIND_RETRY=YES")
    print("DO_NOT_RERUN=YES")
    raise SystemExit(1)

persist("posted",nonce=nonce,seq=row["seq"],ts=row["ts"],completed_at=datetime.now(UTC).isoformat())
print("MARU_ROSTER_V3_POST=PASS seq="+str(row["seq"])+" request_id="+RID)
print("BINDING_ROSTER_CONSENT=YES")
print("WORD_SENT=NO")
print("X_POST=NO")
print("SUBMISSION_SENT=NO")
print("REGISTRATION_WRITE=NO")
print("DO_NOT_RERUN=YES")

deadline=time.monotonic()+180
seen=set()
receipt=None
while time.monotonic()<deadline:
    try:
        _,rows=verified_rows(DISC,row["seq"]-1)
    except Exception:
        time.sleep(5);continue
    for rr,d in rows:
        seq=rr.get("seq")
        if not isinstance(seq,int) or seq<=row["seq"] or seq in seen:
            continue
        seen.add(seq)
        if isinstance(d,dict):
            if d.get("type")=="sonnet.receipt.v1" and d.get("request_id")==RID and rr.get("from")==REF:
                receipt=(seq,d)
                print("MARU_ROSTER_V3_REFEREE="+json.dumps({
                  "seq":seq,"status":d.get("status"),"reason":d.get("reason"),
                  "roster_ready":d.get("roster_ready"),"intake_seq":d.get("intake_seq"),
                  "state_hash":d.get("state_hash")
                },sort_keys=True))
            if d.get("type")=="sonnet.roster.v1" and d.get("game_id")==GAME:
                print("MARU_ROSTER_V3_COUNTERSIGN="+json.dumps({
                  "seq":seq,"sender":rr.get("from"),"request_id":d.get("request_id"),
                  "members":d.get("members"),"room_generation":d.get("room_generation")
                },sort_keys=True))
            if d.get("type")=="sonnet.receipt.v1" and d.get("roster_ready") is True:
                print("MARU_ROSTER_V3_ROSTER_READY_RECEIPT="+json.dumps({
                  "seq":seq,"request_id":d.get("request_id"),"sender_did":d.get("sender_did"),
                  "status":d.get("status"),"state_hash":d.get("state_hash")
                },sort_keys=True))
    if receipt and receipt[1].get("status")!="accepted":
        break
    time.sleep(5)

if receipt is None:
    print("MARU_ROSTER_V3_WATCH=COMPLETE receipt_not_seen_yet")
else:
    print("MARU_ROSTER_V3_WATCH=COMPLETE")
PY

chmod 0644 "$TMP"

# Inner Python owns terminal/pre-sign classification from this point.
trap - ERR

sudo bash -c '
set -Eeuo pipefail
set -a
. /etc/technocore-safe-agent/signer.env
set +a
exec /usr/sbin/runuser   -u technocore-signer   -g technocore-signer   -G technocore-autopilot   -- /usr/bin/env -i   PATH=/usr/bin:/bin   FLOP_STATE_DIR=/var/lib/technocore-safe-agent   PYTHONPATH=/opt/technocore-safe-agent/src   OCI_VAULT_SECRET_OCID="$OCI_VAULT_SECRET_OCID"   TECHNOCORE_SIGNER_EXPECTED_DID="$TECHNOCORE_SIGNER_EXPECTED_DID"   /opt/technocore-safe-agent/.venv/bin/python "$1"
' _ "$TMP"

echo "MARU_ROSTER_V3_HELPER=COMPLETE"
