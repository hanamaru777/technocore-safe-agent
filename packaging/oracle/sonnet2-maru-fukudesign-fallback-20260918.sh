#!/usr/bin/env bash
set -Eeuo pipefail

REPO=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
EXPECTED_HEAD=b8dc6ef0b1ac689f1c45a0fb1451800c75dd5c1f
REQ=maru-fukudesign-fallback-inquiry-20260918-1
SAFETY="$STATE/observer-safety.json"

stop(){ trap - ERR; echo "MARU_FUKU_FALLBACK=STOP:$1"; echo "REQUEST_ID=$REQ"; echo "DO_NOT_RERUN=YES"; exit 1; }
trap 'stop unexpected_rc_$?' ERR

cd "$REPO"
OWNER=$(stat -c %U .git) || stop git_owner_unreadable
HEAD=$(sudo -u "$OWNER" git -C "$REPO" rev-parse HEAD) || stop git_head_unreadable
[[ "$HEAD" == "$EXPECTED_HEAD" ]] || stop "unexpected_head:$HEAD"

for svc in technocore-safe-agent-resident.service technocore-safe-agent-lobby-capture.service technocore-safe-agent-signer.service technocore-safe-agent-discord.service technocore-safe-agent-metadata-block.service
do systemctl is-active --quiet "$svc" || stop "service_not_active:$svc"; done

read -r HEALTH AGE EVENTS MESSAGES < <(
python3 - "$SAFETY" <<'PY'
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
a=float(sys.argv[1]); raise SystemExit(0 if 0 <= a <= 120 else 1)
PY
[[ "$EVENTS" == 117 && "$MESSAGES" == 5083155 ]] || stop "P0_core_changed:$EVENTS/$MESSAGES"
echo "MARU_FUKU_FALLBACK_PREFLIGHT=PASS health=$HEALTH age=$AGE core=$EVENTS/$MESSAGES"

TMP=$(mktemp /tmp/maru-fuku-fallback.XXXXXX.py)
trap 'rm -f "$TMP"' EXIT
cat >"$TMP" <<'PY'
from __future__ import annotations
import json,os,subprocess,sys
from flop_agent import core,observer,oracle_signer
from flop_agent.public_record import verify_signed_record

DISC="mb-sonnet-2-discovery"
MARU_ROOM="d-sonnet-2-team-maru-rescue-1"
FUKU_ROOM="d-sonnet-2-team-fukudesign"
MARU_GAME="maru-rescue-1"
FUKU_GAME="fukudesign"
MARU="did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
REF="did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
FUKU_LEAD="did:key:z6MkwLGfvY1ch5UsxgLpMwEdyT7kJjMiTpktNgPghsua6Vv2"
RID="maru-fukudesign-fallback-inquiry-20260918-1"
STATE=core.STATE/"signer"/(RID+".json")
ROSTER_STATE=core.STATE/"signer"/"maru-rescue-roster-20260918-3.json"

TEXT=(
 "MARU fallback inquiry only. DID "+MARU+" / X https://x.com/MinerMaru73. "
 "I saw your latest fukudesign one-seat recruitment at discovery seq150294 and verified "
 "d-sonnet-2-team-fukudesign generation2 is referee-provisioned and still has no accepted word. "
 "MARU currently holds PRE-FREEZE roster consent on maru-rescue-1; its room remains generation1 "
 "with no word/freeze. I will NOT double-consent and I am NOT withdrawing in this message. "
 "Referee accepted MARU's role-gated team request for maru-rescue-1 at discovery seq148670 "
 "(intake869093), and MARU's current roster consent itself was referee-accepted at seq149985. "
 "If your last seat is still genuinely open and you are willing to include MARU immediately AFTER "
 "a verified withdrawal from maru-rescue-1, please reply with a conditional seat confirmation and "
 "the exact intended fukudesign roster members. I can then decide the safe switch once, without churn. "
 "This message is NON-BINDING: not sonnet.withdraw.v1, not roster consent, not a word, not X publication, "
 "not submission, not registration, and not a role change."
)
PAYLOAD={"type":"sonnet.application.v1","contest_id":"sonnet-2","game_id":FUKU_GAME,
         "did":MARU,"role":"writer","x_account_url":"https://x.com/MinerMaru73",
         "target_did":FUKU_LEAD,"request_id":RID,"text":TEXT}
PAYLOAD_TEXT=json.dumps(PAYLOAD,sort_keys=True,separators=(",",":"),ensure_ascii=True)

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

def hard_stop(reason):
    print("MARU_FUKU_FALLBACK=STOP:"+reason); print("REQUEST_ID="+RID); print("DO_NOT_RERUN=YES"); raise SystemExit(1)

def require_maru_state():
    if not ROSTER_STATE.exists(): hard_stop("maru_roster_state_missing")
    try:d=json.loads(ROSTER_STATE.read_text("utf-8"))
    except Exception: hard_stop("maru_roster_state_invalid")
    if d.get("state")!="posted" or d.get("seq")!=149959: hard_stop("maru_roster_state_changed")
    body,rows=get_rows(MARU_ROOM,0)
    if body.get("generation")!=1: hard_stop("maru_room_generation_changed")
    signed=[r for r,p in rows if isinstance(r.get("seq"),int)]
    if len(signed)!=1 or signed[0].get("seq")!=1 or signed[0].get("from")!=REF:
        hard_stop("maru_room_advanced")

def require_fuku_open():
    body,rows=get_rows(FUKU_ROOM,0)
    if body.get("generation")!=2: hard_stop("fuku_generation_changed")
    if any(isinstance(p,dict) and p.get("type")=="sonnet.word.v1" for r,p in rows):
        hard_stop("fuku_word_seen")
    setup=[(r,p) for r,p in rows if r.get("from")==REF and isinstance(p,dict) and p.get("type")=="sonnet.receipt.v1" and p.get("request_id")=="resetup-fukudesign-2" and p.get("status")=="accepted"]
    if not setup: hard_stop("fuku_setup_not_verified")

def already_ready():
    _,rows=get_rows(DISC,149959)
    for row,p in rows:
        if row.get("from")==REF and isinstance(p,dict) and p.get("type")=="sonnet.receipt.v1" and p.get("roster_ready") is True:
            if p.get("sender_did")==MARU: return True
    return False

def sign_text(nonce):
    def op():
        p=subprocess.run([sys.executable,str(core.ROOT/"scripts"/"sign.py"),"say",DISC,nonce,PAYLOAD_TEXT],
            cwd=core.ROOT,env=os.environ.copy(),text=True,capture_output=True,check=False)
        if p.returncode!=0: raise RuntimeError("official_signer_failed")
        return [x.strip() for x in p.stdout.splitlines() if x.strip()]
    return oracle_signer.with_vault_seed(op)

if STATE.exists(): hard_stop("prior_request_state")
if oracle_signer.expected_did()!=MARU: hard_stop("expected_did_mismatch")
core.require_verified_did(MARU)
if not core.signer_matches_pinned(): hard_stop("signer_not_pinned")
require_maru_state()
if already_ready():
    print("MARU_FUKU_FALLBACK=SKIP:maru_roster_ready_true"); print("DO_NOT_RERUN=YES"); raise SystemExit(0)
require_fuku_open()

nonce=core.make_nonce(DISC,MARU)
try:signed=sign_text(nonce)
except Exception: hard_stop("sign_failed")
if len(signed)!=2 or signed[0]!=MARU: hard_stop("sign_output_invalid")
verify_signed_record(DISC,{"from":MARU,"nonce":nonce,"text":PAYLOAD_TEXT,"sig":signed[1]})
observer.atomic_json_write(STATE,{"schema_version":1,"request_id":RID,"state":"signed","nonce":nonce},compact=True,mode=0o600)

require_maru_state(); require_fuku_open()
try:
    resp=core.httpx.post(f"{core.BASE_URL}/r/{DISC}?format=json",
        json={"did":MARU,"nonce":nonce,"text":PAYLOAD_TEXT,"sig":signed[1]},timeout=20)
    resp.raise_for_status(); body=resp.json(); row=body.get("posted")
    if not isinstance(row,dict) or row.get("from")!=MARU or row.get("text")!=PAYLOAD_TEXT or row.get("sig")!=signed[1]:
        raise RuntimeError("posted_receipt_mismatch")
    verify_signed_record(DISC,row)
except Exception:
    observer.atomic_json_write(STATE,{"schema_version":1,"request_id":RID,"state":"ambiguous","nonce":nonce},compact=True,mode=0o600)
    print("MARU_FUKU_FALLBACK=STOP:submission_unknown"); print("NO_BLIND_RETRY=YES"); print("DO_NOT_RERUN=YES"); raise SystemExit(1)

observer.atomic_json_write(STATE,{"schema_version":1,"request_id":RID,"state":"posted","seq":row["seq"],"ts":row["ts"]},compact=True,mode=0o600)
print("MARU_FUKU_FALLBACK=PASS seq="+str(row["seq"])+" request_id="+RID)
print("NON_BINDING=YES WITHDRAW=NO ROSTER_WRITE=NO WORD=NO X=NO SUBMIT=NO REGISTRATION=NO")
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
echo "MARU_FUKU_FALLBACK_HELPER=COMPLETE"
