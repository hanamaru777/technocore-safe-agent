#!/usr/bin/env bash
set -Eeuo pipefail
REPO=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
EXPECTED_HEAD=b8dc6ef0b1ac689f1c45a0fb1451800c75dd5c1f
OBSERVER_STATE="$STATE/observer/observer-state.json"

stop(){ trap - ERR; echo "MARU_WORD_WATCH=STOP:$1"; echo "DO_NOT_RERUN=YES"; exit 1; }
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
print(d.get("health",{}).get("current","missing"),m.get("unrecoverable_core_gap_events","missing"),m.get("unrecoverable_core_gap_messages","missing"))
PY
) || stop observer_state_unreadable
[[ "$EVENTS" == 117 && "$MESSAGES" == 5083155 ]] || stop "P0_core_changed:$EVENTS/$MESSAGES"
[[ "$HEALTH" == ok || "$HEALTH" == degraded ]] || stop "health_not_allowed:$HEALTH"
echo "MARU_WORD_WATCH_PREFLIGHT=PASS health=$HEALTH core=$EVENTS/$MESSAGES"

TMP=$(mktemp /tmp/maru-word-watch.XXXXXX.py)
trap 'rm -f "$TMP"' EXIT
cat >"$TMP" <<'PY'
from __future__ import annotations
import datetime,json,os,subprocess,sys,time
from pathlib import Path
from flop_agent import core,observer,oracle_signer,sonnet_preflight
from flop_agent.public_record import verify_signed_record

DISC="mb-sonnet-2-discovery"
TEAM="d-sonnet-2-team-maru-rescue-1"
GAME="maru-rescue-1"; GEN=1
REF="did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
MARU="did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
GRID="did:key:z6Mkr1NYDRusR9wDgrXW65bQj4Vg39mfJXFmXTxd4PLfjxaj"
PUPH="did:key:z6MkmVhZbUKWmg3r6TTi3SVM3myYJ9BLbWYPSdc5iWPuPhb6"
WAKE="did:key:z6Mkr3hsA4hYbvrQeG61kSgKw51LTBo7d5TCHWyyQfjUmteK"
FUKU="did:key:z6MkwLGfvY1ch5UsxgLpMwEdyT7kJjMiTpktNgPghsua6Vv2"
MEMBERS=[MARU,GRID,PUPH,WAKE]
LETTER={"M":MARU,"G":GRID,"P":PUPH,"W":WAKE}
CODE="GWGMGPWMGPGMGWGMWMGWGMGWMGWGPGMWGPGWGWGWGMGWGWPGPGWMGWGWMGMWMGPGMGMWMGWGPGWGMGWMGMPWGPGWGPGWGMGWMGPWGWGWGM"
POEM="""Amid weak signals we pursue the light
The distant keys align and keep a flame
A careful hand preserves the gentle night
A false claim may imitate a true name
In crowded lines we seek a distant shore
A clear reply can keep the passage free
With patient steps we guard a distant shore
We form each measured line across the sea
We raise a gentle aim toward the sky
A steady truth may quietly remain
We send a gentle signal climbing high
The trust we earn may surely help sustain
A quiet hand may limit what we view
A steady road begins the way anew"""
TOKENS=POEM.split()
EXPECTED_SHA="e9ac024e77f1961a24cc69b9b69ad296febee36689f3c693a8d07b7bf65f943e"
DEADLINE=datetime.datetime(2026,9,18,12,0,0,tzinfo=datetime.timezone.utc).timestamp()
ROSTER_STATE=core.STATE/"signer"/"maru-rescue-roster-20260918-3.json"

def die(x):
    print("MARU_WORD_WATCH=STOP:"+x); print("DO_NOT_RERUN=YES"); raise SystemExit(1)

def get_rows(room,since=0):
    r=core.httpx.get(f"{core.BASE_URL}/r/{room}",params={"format":"json","since":since,"limit":250,"wait":0},timeout=15)
    r.raise_for_status(); d=r.json(); rows=[]
    for row in d.get("messages",[]):
        if not isinstance(row,dict): continue
        try: verify_signed_record(room,row)
        except Exception: continue
        try:p=json.loads(row.get("text",""))
        except Exception:p=None
        rows.append((row,p))
    return d,rows

def sign_post(room,payload,rid):
    text=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=True)
    nonce=core.make_nonce(room,MARU)
    def op():
        p=subprocess.run([sys.executable,str(core.ROOT/"scripts"/"sign.py"),"say",room,nonce,text],
          cwd=core.ROOT,env=os.environ.copy(),text=True,capture_output=True,check=False)
        if p.returncode!=0: raise RuntimeError("official_signer_failed")
        return [x.strip() for x in p.stdout.splitlines() if x.strip()]
    signed=oracle_signer.with_vault_seed(op)
    if len(signed)!=2 or signed[0]!=MARU: die("sign_output_invalid:"+rid)
    verify_signed_record(room,{"from":MARU,"nonce":nonce,"text":text,"sig":signed[1]})
    state=core.STATE/"signer"/(rid+".json")
    if state.exists(): die("prior_request_state:"+rid)
    observer.atomic_json_write(state,{"schema_version":1,"request_id":rid,"state":"signed","nonce":nonce},compact=True,mode=0o600)
    try:
        resp=core.httpx.post(f"{core.BASE_URL}/r/{room}?format=json",json={"did":MARU,"nonce":nonce,"text":text,"sig":signed[1]},timeout=20)
        resp.raise_for_status(); row=resp.json().get("posted")
        if not isinstance(row,dict) or row.get("from")!=MARU or row.get("text")!=text or row.get("sig")!=signed[1]: raise RuntimeError("posted_receipt_mismatch")
        verify_signed_record(room,row)
    except Exception:
        observer.atomic_json_write(state,{"schema_version":1,"request_id":rid,"state":"ambiguous","nonce":nonce},compact=True,mode=0o600)
        print("MARU_WORD_WATCH=STOP:submission_unknown:"+rid); print("NO_BLIND_RETRY=YES"); print("DO_NOT_RERUN=YES"); raise SystemExit(1)
    observer.atomic_json_write(state,{"schema_version":1,"request_id":rid,"state":"posted","seq":row["seq"],"ts":row["ts"]},compact=True,mode=0o600)
    return row

def self_check():
    import hashlib
    if len(TOKENS)!=106 or len(CODE)!=106: die("plan_length")
    if hashlib.sha256(POEM.encode()).hexdigest()!=EXPECTED_SHA: die("poem_hash")
    if set(CODE)!={"M","G","P","W"}: die("code_members")
    if any(CODE[i]==CODE[i-1] for i in range(1,len(CODE))): die("adjacent_assignment")
    if CODE[-1]!="M" or TOKENS[-1]!="anew": die("final_not_maru")
    for t,c in zip(TOKENS,CODE):
        if not sonnet_preflight.did_can_write(LETTER[c],t): die("did_letter_violation:"+c+":"+t)
    counts={c:CODE.count(c) for c in "MGPW"}
    if counts!={"M":22,"G":44,"P":12,"W":28}: die("counts:"+str(counts))
    print("MARU_WORD_WATCH_SELF_CHECK=PASS tokens=106 counts=M22/G44/P12/W28 final=MARU")

def roster_local_ok():
    if not ROSTER_STATE.exists(): die("maru_roster_state_missing")
    d=json.loads(ROSTER_STATE.read_text("utf-8"))
    if d.get("state")!="posted" or d.get("seq")!=149959: die("maru_roster_state_changed")

def scan_discovery():
    _,rows=get_rows(DISC,150402)
    puph_rosters={}
    receipts={}
    fuku_reply=None
    for row,p in rows:
        if not isinstance(p,dict): continue
        if row.get("from")==PUPH and p.get("type")=="sonnet.roster.v1":
            same=(p.get("contest_id")=="sonnet-2" and p.get("game_id")==GAME and p.get("poem_room")==TEAM and p.get("room_generation")==GEN and p.get("members")==MEMBERS)
            if same and isinstance(p.get("request_id"),str): puph_rosters[p["request_id"]]=row["seq"]
        if row.get("from")==REF and p.get("type")=="sonnet.receipt.v1" and isinstance(p.get("request_id"),str):
            receipts[p["request_id"]]=(row,p)
        if row.get("from")==FUKU and (MARU in row.get("text","") or p.get("target_did")==MARU):
            fuku_reply=(row,p)
    for rid,seq in puph_rosters.items():
        rp=receipts.get(rid)
        if rp and rp[1].get("status")=="accepted" and rp[1].get("sender_did")==PUPH and rp[1].get("roster_ready") is True:
            return ("ready",rp[1].get("state_hash"),rid,seq,rp[0]["seq"],fuku_reply)
    return ("waiting",None,None,None,None,fuku_reply)

def accepted_state(initial_hash):
    d,rows=get_rows(TEAM,0)
    if d.get("generation")!=GEN: die("team_generation_changed")
    proposals={}
    accepted=[]
    for row,p in rows:
        if not isinstance(p,dict): continue
        if p.get("type")=="sonnet.word.v1" and isinstance(p.get("request_id"),str):
            proposals[p["request_id"]]=(row,p)
        if row.get("from")==REF and p.get("type")=="sonnet.receipt.v1" and p.get("status")=="accepted" and isinstance(p.get("version"),int):
            rid=p.get("request_id")
            if rid in proposals:
                accepted.append((p["version"],row,p,proposals[rid]))
    accepted.sort(key=lambda x:x[0])
    expected_version=0
    state_hash=initial_hash
    for version,rr,rp,(wr,wp) in accepted:
        if version!=expected_version+1: die("receipt_version_gap")
        idx=version-1
        if idx>=len(TOKENS): die("too_many_words")
        if wp.get("version")!=expected_version or wp.get("previous_state_hash")!=state_hash: die("accepted_chain_mismatch")
        if wp.get("word")!=TOKENS[idx]: die("accepted_word_diverged:"+str(version)+":"+str(wp.get("word")))
        if wr.get("from")!=LETTER[CODE[idx]]: die("accepted_contributor_diverged:"+str(version))
        state_hash=rp.get("state_hash")
        if not isinstance(state_hash,str): die("receipt_state_hash_missing")
        expected_version=version
    return expected_version,state_hash,accepted

if oracle_signer.expected_did()!=MARU: die("expected_did_mismatch")
core.require_verified_did(MARU)
if not core.signer_matches_pinned(): die("signer_not_pinned")
roster_local_ok(); self_check()
print("MARU_WORD_WATCH=WAITING_FOR_ROSTER_READY")

initial_hash=None
while time.time()<DEADLINE-5:
    status,h,rid,pseq,rseq,fuku=scan_discovery()
    if fuku is not None and status!="ready":
        row,p=fuku
        print("FUKUDESIGN_REPLY_SEEN=YES seq="+str(row["seq"]))
        print("FUKUDESIGN_REPLY_TEXT="+json.dumps(p,sort_keys=True,separators=(",",":"),ensure_ascii=True))
        print("MARU_WORD_WATCH=STOP:fukudesign_reply_before_roster_ready")
        print("DO_NOT_RERUN=YES")
        raise SystemExit(0)
    if status=="ready":
        initial_hash=h
        print("MARU_ROSTER_READY=YES puph_seq="+str(pseq)+" receipt_seq="+str(rseq)+" request_id="+rid+" state_hash="+str(h))
        break
    time.sleep(1)
if initial_hash is None:
    print("MARU_WORD_WATCH=STOP:deadline_without_roster_ready"); print("DO_NOT_RERUN=YES"); raise SystemExit(1)

while time.time()<DEADLINE-3:
    version,state_hash,accepted=accepted_state(initial_hash)
    if version==len(TOKENS):
        last=accepted[-1][2] if accepted else {}
        print("MARU_POEM_COMPLETE=YES version=106 state_hash="+state_hash)
        print("X_AND_SUBMIT=NOT_AUTHORIZED")
        print("NEED_X_AND_SUBMIT_AUTHORIZATION=YES")
        print("DO_NOT_RERUN=YES")
        raise SystemExit(0)
    idx=version
    expected=CODE[idx]
    if expected!="M":
        time.sleep(0.8); continue
    rid=f"maru-rescue-v3-corrected-w{idx+1:03d}-20260918-1"
    payload={"type":"sonnet.word.v1","contest_id":"sonnet-2","game_id":GAME,"room_generation":GEN,
             "version":version,"previous_state_hash":state_hash,"word":TOKENS[idx],"request_id":rid}
    row=sign_post(TEAM,payload,rid)
    print("MARU_WORD_POSTED position="+str(idx+1)+" word="+TOKENS[idx]+" seq="+str(row["seq"])+" request_id="+rid)
    deadline_wait=min(time.time()+35,DEADLINE-2)
    while time.time()<deadline_wait:
        nv,nh,na=accepted_state(initial_hash)
        if nv>version:
            if nv!=version+1: die("unexpected_version_advance")
            print("MARU_WORD_ACCEPTED position="+str(idx+1)+" version="+str(nv)+" state_hash="+nh)
            break
        time.sleep(0.8)
    else:
        print("MARU_WORD_WATCH=STOP:receipt_timeout_after_post:"+rid)
        print("NO_BLIND_RETRY=YES"); print("DO_NOT_RERUN=YES"); raise SystemExit(1)

print("MARU_WORD_WATCH=STOP:deadline")
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
echo "MARU_WORD_WATCH_HELPER=COMPLETE"
