#!/usr/bin/env bash
set -Eeuo pipefail
REPO=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
EXPECTED_HEAD=b8dc6ef0b1ac689f1c45a0fb1451800c75dd5c1f
OBSERVER_STATE="$STATE/observer/observer-state.json"
stop(){ trap - ERR; echo "MARU_EXACT_FINAL=STOP:$1"; echo "DO_NOT_RERUN=YES"; exit 1; }
trap 'stop unexpected_rc_$?' ERR
cd "$REPO"
OWNER=$(stat -c %U .git) || stop git_owner_unreadable
HEAD=$(sudo -u "$OWNER" git -C "$REPO" rev-parse HEAD) || stop git_head_unreadable
[[ "$HEAD" == "$EXPECTED_HEAD" ]] || stop "unexpected_head:$HEAD"
for svc in technocore-safe-agent-resident.service technocore-safe-agent-lobby-capture.service technocore-safe-agent-signer.service technocore-safe-agent-discord.service technocore-safe-agent-metadata-block.service; do
  systemctl is-active --quiet "$svc" || stop "service_not_active:$svc"
done
read -r HEALTH EVENTS MESSAGES < <(
python3 - "$OBSERVER_STATE" <<'PY'
import json,sys
with open(sys.argv[1],encoding="utf-8") as f:d=json.load(f)
m=d.get("metrics",{})
print(d.get("health",{}).get("current","missing"),
      m.get("unrecoverable_core_gap_events","missing"),
      m.get("unrecoverable_core_gap_messages","missing"))
PY
) || stop observer_state_unreadable
[[ "$EVENTS" == 117 && "$MESSAGES" == 5083155 ]] || stop "P0_core_changed:$EVENTS/$MESSAGES"
[[ "$HEALTH" == ok || "$HEALTH" == degraded ]] || stop "health_not_allowed:$HEALTH"
echo "MARU_EXACT_FINAL_PREFLIGHT=PASS health=$HEALTH core=$EVENTS/$MESSAGES"

TMP=$(mktemp /tmp/maru-exact-final.XXXXXX.py)
trap 'rm -f "$TMP"' EXIT
cat >"$TMP" <<'PY'
from __future__ import annotations
import json,os,subprocess,sys
from flop_agent import core,observer,oracle_signer
from flop_agent.public_record import verify_signed_record

DISC="mb-sonnet-2-discovery"
TEAM="d-sonnet-2-team-maru-rescue-1"
GAME="maru-rescue-1"; GEN=1
REF="did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
MARU="did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
GRID="did:key:z6Mkr1NYDRusR9wDgrXW65bQj4Vg39mfJXFmXTxd4PLfjxaj"
PUPH="did:key:z6MkmVhZbUKWmg3r6TTi3SVM3myYJ9BLbWYPSdc5iWPuPhb6"
WAKE="did:key:z6Mkr3hsA4hYbvrQeG61kSgKw51LTBo7d5TCHWyyQfjUmteK"
MEMBERS=[MARU,GRID,PUPH,WAKE]
ROSTER_BASE={"type":"sonnet.roster.v1","contest_id":"sonnet-2","game_id":GAME,"poem_room":TEAM,"room_generation":GEN,"members":MEMBERS}
POEM_SHA="070aae5986ea533ef6aadc5f096e83b5c5e5082dacec9260d121bf4f88aea4bf"
GRID_WORDS="1:Amid 3:signals 5:pursue 9:distant 12:and 15:flame 19:preserves 21:gentle 24:false 31:In 33:lines 37:gentle 43:keep 45:passage 48:patient 58:measured 64:raise 66:gentle 71:A 74:may 76:remain 78:send 81:signal 87:earn 91:sustain 95:may 101:steady 103:begins"
PUPH_WORDS="4:we 6:the 8:The 10:keys 13:keep 20:the 29:true 35:seek 41:reply 44:the 47:With 49:steps 52:the 55:We 63:We 70:sky 73:truth 77:We 84:The 86:we 90:help 96:limit 99:view 104:the"
REQS=[
 ("gridonbtc",GRID,"maru-rescue-v3-exact-grid-20260918-1",GRID_WORDS,
  "You publicly confirmed at discovery seq150459 that you are registered, free, zero live roster consent, not frozen, and have no accepted word elsewhere."),
 ("PuPhb6",PUPH,"maru-rescue-v3-exact-puph-20260918-1",PUPH_WORDS,
  "You are still publishing WRITER AVAILABLE through discovery seq150467."),
]
ROSTER_STATE=core.STATE/"signer"/"maru-rescue-roster-20260918-3.json"
PLAN_STATE=core.STATE/"signer"/"maru-rescue-v3-plan-20260918-2.json"

def get_rows(room,since=0):
    r=core.httpx.get(f"{core.BASE_URL}/r/{room}",params={"format":"json","since":since,"limit":250,"wait":0},timeout=20)
    r.raise_for_status(); d=r.json(); rows=[]
    for row in d.get("messages",[]):
        if not isinstance(row,dict): continue
        try: verify_signed_record(room,row)
        except Exception: continue
        try:p=json.loads(row.get("text",""))
        except Exception:p=None
        rows.append((row,p))
    return d,rows

def die(x):
    print("MARU_EXACT_FINAL=STOP:"+x); print("DO_NOT_RERUN=YES"); raise SystemExit(1)

def require_state(path,seq):
    if not path.exists(): die("prior_state_missing:"+path.name)
    try:d=json.loads(path.read_text("utf-8"))
    except Exception: die("prior_state_invalid:"+path.name)
    if d.get("state")!="posted" or d.get("seq")!=seq: die("prior_state_unexpected:"+path.name)

def room_pristine():
    d,rows=get_rows(TEAM,0)
    if d.get("generation")!=GEN: die("team_generation_changed")
    signed=[r for r,p in rows if isinstance(r.get("seq"),int)]
    if len(signed)!=1 or signed[0].get("seq")!=1 or signed[0].get("from")!=REF: die("team_room_advanced")

def sign_text(text,nonce):
    def op():
        p=subprocess.run([sys.executable,str(core.ROOT/"scripts"/"sign.py"),"say",DISC,nonce,text],
          cwd=core.ROOT,env=os.environ.copy(),text=True,capture_output=True,check=False)
        if p.returncode!=0: raise RuntimeError("official_signer_failed")
        return [x.strip() for x in p.stdout.splitlines() if x.strip()]
    return oracle_signer.with_vault_seed(op)

if oracle_signer.expected_did()!=MARU: die("expected_did_mismatch")
core.require_verified_did(MARU)
if not core.signer_matches_pinned(): die("signer_not_pinned")
require_state(ROSTER_STATE,149959); require_state(PLAN_STATE,150265); room_pristine()

_,rows=get_rows(DISC,150402)
same=set(); conflicting=set(); ready=False
for row,p in rows:
    if not isinstance(p,dict): continue
    sender=row.get("from")
    if sender==REF and p.get("type")=="sonnet.receipt.v1" and p.get("roster_ready") is True and p.get("sender_did") in MEMBERS:
        ready=True
    if sender in (GRID,PUPH,WAKE) and p.get("type")=="sonnet.roster.v1":
        is_same=(p.get("contest_id")=="sonnet-2" and p.get("game_id")==GAME and p.get("poem_room")==TEAM and p.get("room_generation")==GEN and p.get("members")==MEMBERS)
        (same if is_same else conflicting).add(sender)
if ready:
    print("MARU_EXACT_FINAL=SKIP:roster_ready_already_true"); print("DO_NOT_RERUN=YES"); raise SystemExit(0)
if WAKE not in same: die("wakeup_countersign_not_visible")

posted=0
for label,target,rid,words,preface in REQS:
    if target in same:
        print("MARU_EXACT_FINAL_SKIP="+label+":already_countersigned"); continue
    if target in conflicting:
        print("MARU_EXACT_FINAL_SKIP="+label+":conflicting_roster_visible"); continue
    state=core.STATE/"signer"/(rid+".json")
    if state.exists(): die("prior_request_state:"+rid)
    frame=dict(ROSTER_BASE); frame["request_id"]="<YOUR_FRESH_REQUEST_ID>"
    text_body=(
      "URGENT EXACT MARU ROSTER FRAME. "+preface+" "
      "MARU exact roster consent is seq149959 and wakeupbeagent exact countersign is seq150403. "
      "Full validated plan is seq150265; poem SHA256="+POEM_SHA+". "
      "Your exact assigned positions/words are: "+words+". "
      "Sign this exact roster structure NOW if still free, replacing only request_id with your own fresh unique value: "
      +json.dumps(frame,separators=(",",":"),ensure_ascii=True)+". "
      "Do not write any poem word until pinned referee roster_ready=true. NON-BINDING coordination note only."
    )
    payload={"type":"sonnet.note.v1","contest_id":"sonnet-2","game_id":GAME,"target_did":target,"in_reply_to":150403,"request_id":rid,"text":text_body}
    text=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=True)
    nonce=core.make_nonce(DISC,MARU); signed=sign_text(text,nonce)
    if len(signed)!=2 or signed[0]!=MARU: die("sign_output_invalid:"+rid)
    verify_signed_record(DISC,{"from":MARU,"nonce":nonce,"text":text,"sig":signed[1]})
    observer.atomic_json_write(state,{"schema_version":1,"request_id":rid,"state":"signed","nonce":nonce},compact=True,mode=0o600)
    room_pristine()
    try:
        resp=core.httpx.post(f"{core.BASE_URL}/r/{DISC}?format=json",json={"did":MARU,"nonce":nonce,"text":text,"sig":signed[1]},timeout=20)
        resp.raise_for_status(); row=resp.json().get("posted")
        if not isinstance(row,dict) or row.get("from")!=MARU or row.get("text")!=text or row.get("sig")!=signed[1]: raise RuntimeError("posted_receipt_mismatch")
        verify_signed_record(DISC,row)
    except Exception:
        observer.atomic_json_write(state,{"schema_version":1,"request_id":rid,"state":"ambiguous","nonce":nonce},compact=True,mode=0o600)
        print("MARU_EXACT_FINAL=STOP:submission_unknown:"+rid); print("NO_BLIND_RETRY=YES"); print("DO_NOT_RERUN=YES"); raise SystemExit(1)
    observer.atomic_json_write(state,{"schema_version":1,"request_id":rid,"state":"posted","seq":row["seq"],"ts":row["ts"]},compact=True,mode=0o600)
    print("MARU_EXACT_FINAL_PASS="+label+" seq="+str(row["seq"])+" request_id="+rid); posted+=1

print("MARU_EXACT_FINAL=PASS posted="+str(posted))
print("NON_BINDING=YES ROSTER_WRITE=NO WORD=NO X=NO SUBMIT=NO REGISTRATION=NO")
print("DO_NOT_RERUN=YES")
PY

chmod 0644 "$TMP"
trap - ERR
sudo bash -c '
set -Eeuo pipefail
set -a
. /etc/technocore-safe-agent/signer.env
set +a
exec /usr/sbin/runuser -u technocore-signer -g technocore-signer -G technocore-autopilot -- /usr/bin/env -i \
PATH=/usr/bin:/bin FLOP_STATE_DIR=/var/lib/technocore-safe-agent PYTHONPATH=/opt/technocore-safe-agent/src \
OCI_VAULT_SECRET_OCID="$OCI_VAULT_SECRET_OCID" TECHNOCORE_SIGNER_EXPECTED_DID="$TECHNOCORE_SIGNER_EXPECTED_DID" \
/opt/technocore-safe-agent/.venv/bin/python "$1"
' _ "$TMP"
echo "MARU_EXACT_FINAL_HELPER=COMPLETE"
