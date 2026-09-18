#!/usr/bin/env bash
set -Eeuo pipefail

REPO=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
EXPECTED_HEAD=b8dc6ef0b1ac689f1c45a0fb1451800c75dd5c1f
REQ=maru-gguru1-apply-20260918-1
SAFETY="$STATE/observer-safety.json"

stop() {
  trap - ERR
  echo "GGURU1_APPLICATION=STOP:$1"
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
import datetime, json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d=json.load(f)
t=datetime.datetime.fromisoformat(d["updated_at"].replace("Z","+00:00"))
if t.tzinfo is None:
    t=t.replace(tzinfo=datetime.timezone.utc)
age=(datetime.datetime.now(datetime.timezone.utc)-t.astimezone(datetime.timezone.utc)).total_seconds()
print(d["health"], round(age,3), d["unrecoverable_core_gap_events"], d["unrecoverable_core_gap_messages"])
PY
) || stop safety_unreadable

[[ "$HEALTH" == ok || "$HEALTH" == degraded ]] || stop "health_not_allowed:$HEALTH"
python3 - "$AGE" <<'PY' || stop safety_stale
import sys
age=float(sys.argv[1])
raise SystemExit(0 if 0 <= age <= 300 else 1)
PY
[[ "$EVENTS" == 117 && "$MESSAGES" == 5083155 ]] || stop "P0_core_changed:$EVENTS/$MESSAGES"

echo "GGURU1_PREFLIGHT=PASS health=$HEALTH age=$AGE core=$EVENTS/$MESSAGES"

TMP=$(mktemp /tmp/maru-gguru1-deadline.XXXXXX.py)
trap 'rm -f "$TMP"' EXIT

cat >"$TMP" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta

from flop_agent import core, observer, oracle_signer
from flop_agent.public_record import verify_signed_record

DISCOVERY = "mb-sonnet-2-discovery"
TEAM = "d-sonnet-2-team-gguru1"
REG = "mb-sonnet-2-registration"
RESULTS = "d-sonnet-2-results"

MARU = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
LEADER = "did:key:z6MksGvoPh5Y6AsZEeMTBTxPW2PKTeBqGMTRBcYeZaaWWwn8"
REF = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
FRESH_REG = "maru-sonnet2-writer-fresh-20260917-1"

REQUEST_ID = "maru-gguru1-apply-20260918-1"
STATE = core.STATE / "signer" / "sonnet-2-gguru1-application-20260918.json"

PAYLOAD = {
    "type": "sonnet.application.v1",
    "contest_id": "sonnet-2",
    "game_id": "gguru1",
    "request_id": REQUEST_ID,
    "text": (
        MARU
        + " no_live_roster_consent:true. "
        + "Writer registration receipt is pending authoritative operator lookup; "
        + "I am not claiming acceptance. Ready for the exact generation-2 gguru1 "
        + "roster immediately if eligibility is confirmed."
    ),
}
TEXT = json.dumps(PAYLOAD, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
TEXT_HASH = hashlib.sha256(TEXT.encode()).hexdigest()

RECRUIT_MIN_SEQ = 147017
RECRUIT_MAX_AGE = timedelta(minutes=30)


def stop(reason: str) -> None:
    print(f"GGURU1_APPLICATION=STOP:{reason}")
    print("REQUEST_ID=" + REQUEST_ID)
    print("DO_NOT_RERUN_THIS_BLOCK=YES")
    raise SystemExit(1)


def read_room(room: str, limit: int = 200):
    try:
        payload = core.read_room(room, limit=limit, cache_buster=secrets.token_hex(16))
    except Exception as exc:
        print(f"READ_ERROR room={room} error={type(exc).__name__}")
        stop("room_read_failed")
    rows = payload if isinstance(payload, list) else payload.get("messages", []) if isinstance(payload, dict) else []
    if not isinstance(rows, list):
        stop("room_payload_invalid")
    return rows


def verified(room: str, limit: int = 200):
    out = []
    for row in read_room(room, limit):
        if not isinstance(row, dict):
            continue
        try:
            verify_signed_record(room, row)
            d = json.loads(row.get("text", ""))
        except Exception:
            continue
        if isinstance(d, dict):
            out.append((row, d))
    return out


def persist(state: str, **extra) -> None:
    observer.atomic_json_write(
        STATE,
        {
            "schema_version": 1,
            "request_id": REQUEST_ID,
            "state": state,
            "text_hash": TEXT_HASH,
            **extra,
        },
        compact=True,
        mode=0o600,
    )


def require_team_open() -> None:
    rows = verified(TEAM)
    room_ok = any(
        r.get("from") == REF
        and r.get("seq") == 2
        and d.get("type") == "sonnet.room.v1"
        and d.get("game_id") == "gguru1"
        for r, d in rows
    )
    setup_ok = any(
        r.get("from") == REF
        and r.get("seq") == 3
        and d.get("type") == "sonnet.receipt.v1"
        and d.get("request_id") == "resetup-gguru1-2"
        and d.get("status") == "accepted"
        and d.get("room_generation") == 2
        and d.get("intake_seq") == 395923
        for r, d in rows
    )
    if not room_ok or not setup_ok:
        stop("gguru1_authoritative_setup_changed")
    later = [r.get("seq") for r, _ in rows if type(r.get("seq")) is int and r["seq"] > 3]
    if later:
        print("GGURU1_TEAM_NEW_SEQS=" + ",".join(map(str, sorted(later))))
        stop("gguru1_team_already_advanced")


def inspect_discovery():
    rows = verified(DISCOVERY)
    now = datetime.now(UTC)
    latest_recruit = None
    existing = None

    for r, d in rows:
        seq = r.get("seq")
        sender = r.get("from")

        if d.get("request_id") == REQUEST_ID:
            if sender != MARU:
                stop("request_id_collision")
            if d != PAYLOAD or r.get("text") != TEXT:
                stop("existing_request_payload_conflict")
            existing = r

        if (
            d.get("type") == "sonnet.roster.v1"
            and d.get("game_id") == "gguru1"
            and isinstance(d.get("members"), list)
            and MARU in d["members"]
        ):
            print(
                "GGURU1_MARU_ROSTER_ALREADY_PRESENT="
                + json.dumps(
                    {
                        "seq": seq,
                        "ts": r.get("ts"),
                        "sender": sender,
                        "request_id": d.get("request_id"),
                        "room_generation": d.get("room_generation"),
                        "poem_room": d.get("poem_room"),
                        "members": d.get("members"),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            stop("maru_in_gguru1_roster_already")

        if (
            sender == LEADER
            and d.get("game_id") == "gguru1"
            and d.get("type") in ("sonnet.recruit.v1", "sonnet.note.v1")
            and isinstance(seq, int)
            and seq >= RECRUIT_MIN_SEQ
        ):
            text = str(d.get("text", ""))
            if "open writer seat" not in text.lower():
                continue
            ts = r.get("ts")
            try:
                when = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            except Exception:
                continue
            if now - when <= RECRUIT_MAX_AGE:
                if latest_recruit is None or seq > latest_recruit[0].get("seq", -1):
                    latest_recruit = (r, d)

    if existing is not None:
        return ("existing", existing, latest_recruit)

    if latest_recruit is None:
        stop("no_fresh_gguru1_open_seat_recruit")

    r, d = latest_recruit
    print(
        "GGURU1_RECRUIT_CONFIRMED="
        + json.dumps(
            {
                "seq": r.get("seq"),
                "ts": r.get("ts"),
                "sender": r.get("from"),
                "request_id": d.get("request_id"),
                "text": d.get("text"),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return ("none", None, latest_recruit)


def check_writer_authority() -> None:
    for room in (REG, RESULTS):
        for r, d in verified(room):
            if r.get("from") != REF:
                continue
            blob = json.dumps(d, ensure_ascii=False, sort_keys=True)
            if MARU in blob or FRESH_REG in blob:
                print(
                    "NEW_MARU_AUTHORITY="
                    + json.dumps(
                        {
                            "room": room,
                            "seq": r.get("seq"),
                            "ts": r.get("ts"),
                            "type": d.get("type"),
                            "request_id": d.get("request_id"),
                            "status": d.get("status"),
                            "reason": d.get("reason"),
                            "intake_seq": d.get("intake_seq"),
                            "role": d.get("role"),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                )


def sign_with_official_script(nonce: str):
    def operation():
        env = os.environ.copy()
        proc = subprocess.run(
            [
                sys.executable,
                str(core.ROOT / "scripts" / "sign.py"),
                "say",
                DISCOVERY,
                nonce,
                TEXT,
            ],
            cwd=core.ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError("official_signer_failed")
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return oracle_signer.with_vault_seed(operation)


def followup_watch() -> None:
    deadline = time.monotonic() + 100
    seen = set()
    material = False

    while True:
        for r, d in verified(DISCOVERY):
            seq = r.get("seq")
            if not isinstance(seq, int) or seq <= RECRUIT_MIN_SEQ:
                continue
            key = (seq, r.get("from"))
            if key in seen:
                continue

            members = d.get("members") if isinstance(d.get("members"), list) else []
            relevant = (
                d.get("game_id") == "gguru1"
                and (
                    r.get("from") == LEADER
                    or MARU in members
                    or MARU in json.dumps(d, ensure_ascii=False)
                    or r.get("from") == REF
                )
            )
            if not relevant:
                continue

            seen.add(key)
            out = {
                "seq": seq,
                "ts": r.get("ts"),
                "sender": r.get("from"),
                "official_referee": r.get("from") == REF,
                "from_leader": r.get("from") == LEADER,
                "type": d.get("type"),
                "request_id": d.get("request_id"),
                "status": d.get("status"),
                "reason": d.get("reason"),
                "game_id": d.get("game_id"),
                "room_generation": d.get("room_generation"),
                "poem_room": d.get("poem_room"),
                "target_is_maru": d.get("target_did") == MARU,
            }
            if members:
                out["members"] = members
                out["maru_in_members"] = MARU in members
            if isinstance(d.get("text"), str):
                out["text"] = d["text"]
            print("GGURU1_FOLLOWUP=" + json.dumps(out, ensure_ascii=False, sort_keys=True))

            if (
                d.get("type") == "sonnet.roster.v1"
                and MARU in members
                and d.get("room_generation") == 2
                and d.get("poem_room") == TEAM
            ):
                material = True
                print("GGURU1_MARU_ROSTER_CANDIDATE=YES")

        team = verified(TEAM)
        later = [
            (r, d)
            for r, d in team
            if type(r.get("seq")) is int and r["seq"] > 3
        ]
        if later:
            material = True
            for r, d in later:
                print(
                    "GGURU1_TEAM_UPDATE="
                    + json.dumps(
                        {
                            "seq": r.get("seq"),
                            "ts": r.get("ts"),
                            "official_referee": r.get("from") == REF,
                            "sender": r.get("from"),
                            "type": d.get("type"),
                            "request_id": d.get("request_id"),
                            "status": d.get("status"),
                            "reason": d.get("reason"),
                            "intake_seq": d.get("intake_seq"),
                            "version": d.get("version"),
                            "word": d.get("word"),
                            "state_hash": d.get("state_hash"),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                )

        check_writer_authority()

        if material or time.monotonic() >= deadline:
            break
        time.sleep(10)

    print("GGURU1_FOLLOWUP_WATCH=COMPLETE_READ_ONLY")


if STATE.exists():
    try:
        prior = json.loads(STATE.read_text("utf-8"))
    except Exception:
        stop("state_file_invalid")
    if prior.get("request_id") != REQUEST_ID:
        stop("state_request_id_conflict")
    if prior.get("state") == "posted":
        print(
            "GGURU1_APPLICATION=ALREADY_POSTED "
            f"seq={prior.get('seq')} ts={prior.get('ts')}"
        )
        print("REQUEST_ID=" + REQUEST_ID)
        print("DO_NOT_RERUN_THIS_BLOCK=YES")
        raise SystemExit(0)
    stop("prior_attempt_state_" + str(prior.get("state", "unknown")))

if oracle_signer.expected_did() != MARU:
    stop("maru_expected_did_mismatch")
core.require_verified_did(MARU)
if not core.signer_matches_pinned():
    stop("signer_not_pinned")

require_team_open()
kind, existing, _ = inspect_discovery()
check_writer_authority()

if kind == "existing":
    persist("posted", seq=existing.get("seq"), ts=existing.get("ts"), reconciled=True)
    print(
        "GGURU1_APPLICATION=RECONCILED "
        f"seq={existing.get('seq')} ts={existing.get('ts')}"
    )
    print("REQUEST_ID=" + REQUEST_ID)
    print("DO_NOT_RERUN_THIS_BLOCK=YES")
    followup_watch()
    raise SystemExit(0)

persist("preparing", started_at=datetime.now(UTC).isoformat())
nonce = core.make_nonce(DISCOVERY, MARU)

try:
    signed = sign_with_official_script(nonce)
except Exception:
    persist("sign_failed", failed_at=datetime.now(UTC).isoformat())
    stop("official_signer_failed")

if len(signed) != 2 or signed[0] != MARU:
    persist("sign_output_invalid", failed_at=datetime.now(UTC).isoformat())
    stop("signer_output_invalid")

verify_signed_record(
    DISCOVERY,
    {"from": MARU, "nonce": nonce, "text": TEXT, "sig": signed[1]},
)

# Final live recheck immediately before the one POST.
require_team_open()
kind, existing, _ = inspect_discovery()
if kind == "existing":
    persist("posted", seq=existing.get("seq"), ts=existing.get("ts"), reconciled=True)
    print(
        "GGURU1_APPLICATION=RECONCILED "
        f"seq={existing.get('seq')} ts={existing.get('ts')}"
    )
    print("REQUEST_ID=" + REQUEST_ID)
    print("DO_NOT_RERUN_THIS_BLOCK=YES")
    followup_watch()
    raise SystemExit(0)

persist("attempting", attempted_at=datetime.now(UTC).isoformat())

try:
    response = core.httpx.post(
        f"{core.BASE_URL}/r/{DISCOVERY}?format=json",
        json={"did": MARU, "nonce": nonce, "text": TEXT, "sig": signed[1]},
        timeout=20,
    )
    response.raise_for_status()
    body = response.json()
    row = body.get("posted")
    if (
        not isinstance(row, dict)
        or row.get("from") != MARU
        or str(row.get("nonce")) != nonce
        or row.get("text") != TEXT
        or row.get("sig") != signed[1]
        or type(row.get("seq")) is not int
        or not isinstance(row.get("ts"), str)
    ):
        raise RuntimeError("posted_receipt_mismatch")
    verify_signed_record(DISCOVERY, row)
except Exception:
    persist("ambiguous", ambiguous_at=datetime.now(UTC).isoformat())
    print("GGURU1_APPLICATION=STOP:submission_unknown")
    print("REQUEST_ID=" + REQUEST_ID)
    print("NO_BLIND_RETRY=YES")
    print("DO_NOT_RERUN_THIS_BLOCK=YES")
    raise SystemExit(1)

persist(
    "posted",
    seq=row["seq"],
    ts=row["ts"],
    completed_at=datetime.now(UTC).isoformat(),
)

print(
    "GGURU1_APPLICATION=PASS "
    f"seq={row['seq']} ts={row['ts']}"
)
print("REQUEST_ID=" + REQUEST_ID)
print("TYPE=sonnet.application.v1")
print("BINDING_ROSTER_CONSENT=NO")
print("NO_LIVE_ROSTER_CONSENT=TRUE")
print("NEXT=READ_ONLY_GGURU1_RESPONSE_OR_ROSTER")
print("DO_NOT_RERUN_THIS_BLOCK=YES")

followup_watch()
PY

chmod 0644 "$TMP"

sudo bash -c '
set -Eeuo pipefail
set -a
. /etc/technocore-safe-agent/signer.env
set +a

exec /usr/sbin/runuser   -u technocore-signer   -g technocore-signer   -G technocore-autopilot   -- /usr/bin/env -i   PATH=/usr/bin:/bin   FLOP_STATE_DIR=/var/lib/technocore-safe-agent   PYTHONPATH=/opt/technocore-safe-agent/src   OCI_VAULT_SECRET_OCID="$OCI_VAULT_SECRET_OCID"   TECHNOCORE_SIGNER_EXPECTED_DID="$TECHNOCORE_SIGNER_EXPECTED_DID"   /opt/technocore-safe-agent/.venv/bin/python "$1"
' _ "$TMP"

echo "GGURU1_HELPER=COMPLETE"
