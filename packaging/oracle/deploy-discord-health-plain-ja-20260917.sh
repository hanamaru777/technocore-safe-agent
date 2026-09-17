#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  trap - ERR
  echo "DISCORD_HEALTH_DEPLOY=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 1
}
trap 'fail unexpected_rc_$?' ERR

REPO=/opt/technocore-safe-agent
STATE=/var/lib/technocore-safe-agent
PRE=1b52b25fbfce15e77bd50efe6d684cf748db473a
TARGET=b8dc6ef0b1ac689f1c45a0fb1451800c75dd5c1f
SAFETY="$STATE/observer-safety.json"
RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service
META=technocore-safe-agent-metadata-block.service

cd "$REPO"
OWNER=$(stat -c %U .git) || fail git_owner_unreadable
gitx() { sudo -u "$OWNER" git -C "$REPO" "$@"; }
pid() { systemctl show "$1" -p MainPID --value; }
restarts() { systemctl show "$1" -p NRestarts --value; }

[[ "$(gitx symbolic-ref --short -q HEAD)" == main ]] || fail branch_not_main
[[ "$(gitx rev-parse HEAD)" == "$PRE" ]] || fail unexpected_pre_head
[[ -z "$(gitx status --porcelain=v1 --untracked-files=all)" ]] || fail dirty_tree
for svc in "$RES" "$CAP" "$SIG" "$DIS" "$META"; do
  systemctl is-active --quiet "$svc" || fail "service_not_active:$svc"
done

read -r HEALTH AGE EVENTS MESSAGES < <(
  timeout 5s python3 - "$SAFETY" <<'PY'
import datetime, json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d=json.load(f)
t=datetime.datetime.fromisoformat(d["updated_at"].replace("Z", "+00:00"))
if t.tzinfo is None:
    t=t.replace(tzinfo=datetime.timezone.utc)
age=(datetime.datetime.now(datetime.timezone.utc)-t.astimezone(datetime.timezone.utc)).total_seconds()
print(d["health"], round(age,3), d["unrecoverable_core_gap_events"], d["unrecoverable_core_gap_messages"])
PY
) || fail safety_snapshot_unavailable
[[ "$HEALTH" == ok || "$HEALTH" == degraded ]] || fail safety_health_not_allowed
python3 - "$AGE" <<'PY' || fail safety_stale
import sys
age=float(sys.argv[1])
raise SystemExit(0 if 0 <= age <= 300 else 1)
PY
[[ "$EVENTS" == 117 && "$MESSAGES" == 5083155 ]] || fail "P0_core_changed:$EVENTS/$MESSAGES"
echo "DISCORD_HEALTH_PREFLIGHT=PASS health=$HEALTH age=$AGE core=$EVENTS/$MESSAGES"

RES_PID=$(pid "$RES"); RES_NR=$(restarts "$RES")
CAP_PID=$(pid "$CAP"); CAP_NR=$(restarts "$CAP")
SIG_PID=$(pid "$SIG"); SIG_NR=$(restarts "$SIG")
META_PID=$(pid "$META"); META_NR=$(restarts "$META")
DIS_PID_BEFORE=$(pid "$DIS"); DIS_NR_BEFORE=$(restarts "$DIS")

timeout 30s sudo -u "$OWNER" git -C "$REPO" fetch --no-tags origin \
  refs/heads/main:refs/remotes/origin/main || fail origin_main_fetch_failed
[[ "$(gitx rev-parse refs/remotes/origin/main)" == "$TARGET" ]] || fail origin_main_not_target
[[ "$(gitx merge-base "$PRE" "$TARGET")" == "$PRE" ]] || fail target_not_descendant
ACTUAL=$(gitx diff --name-only "$PRE" "$TARGET" | LC_ALL=C sort)
EXPECTED=$(printf '%s\n' \
  src/flop_agent/discord_health_coalescing.py \
  tests/test_discord_health_coalescing.py | LC_ALL=C sort)
[[ "$ACTUAL" == "$EXPECTED" ]] || fail unexpected_target_delta

gitx merge --ff-only "$TARGET" || fail fast_forward_failed
[[ "$(gitx rev-parse HEAD)" == "$TARGET" ]] || fail head_after_fast_forward
[[ -z "$(gitx status --porcelain=v1 --untracked-files=all)" ]] || fail dirty_after_fast_forward

# Presentation-only smoke: no network, no signing, no Discord send, no state write.
PYTHONPATH="$REPO/src" "$REPO/.venv/bin/python" - <<'PY' || fail presentation_smoke_failed
from flop_agent import discord_health_coalescing as h
red=(
    "🔴 FLOP Agent 異常\n\n"
    "監視状態 degraded が5分以上継続しています。\n"
    "最終正常監視の確認: 1分前\n\n"
    "次にやること: /status"
)
yellow=(
    "🟡 FLOP Agent 通信欠落を複数検出\n\n"
    "未通知gap: +3\n"
    "最終監視: 1分前\n"
    "単発gapは6時間レポートへ集約し、連続時だけ通知しています。\n"
    "次にやること: /status"
)
green=(
    "🟢 FLOP Agent 監視復旧\n\n"
    "Observer監視状態が正常へ戻りました。\n"
    "結論: 対応不要。そのまま稼働中。"
)
r=h._humanize_notice(red)
y=h._humanize_notice(yellow)
g=h._humanize_notice(green)
assert r.startswith("🔴 監視が不安定") and "今やること: 基本は待機" in r and "degraded" not in r
assert y.startswith("🟡 通信抜けを複数検出") and "今回 3件" in y and "gap" not in y
assert g.startswith("🟢 監視復旧") and "今やること: なし" in g and "Observer" not in g
assert h._final_recovery_notice().startswith("🟢 監視復旧")
print("DISCORD_HEALTH_PRESENTATION_SMOKE=PASS")
PY

systemctl restart "$DIS" || fail discord_restart_failed
for _ in $(seq 1 20); do
  systemctl is-active --quiet "$DIS" && break
  sleep 1
done
systemctl is-active --quiet "$DIS" || fail discord_not_active
sleep 3

DIS_PID_AFTER=$(pid "$DIS"); DIS_NR_AFTER=$(restarts "$DIS")
[[ "$DIS_PID_AFTER" =~ ^[1-9][0-9]*$ ]] || fail discord_pid_invalid
[[ "$DIS_PID_AFTER" != "$DIS_PID_BEFORE" ]] || fail discord_pid_unchanged
[[ "$(pid "$RES")" == "$RES_PID" && "$(restarts "$RES")" == "$RES_NR" ]] || fail resident_changed
[[ "$(pid "$CAP")" == "$CAP_PID" && "$(restarts "$CAP")" == "$CAP_NR" ]] || fail capture_changed
[[ "$(pid "$SIG")" == "$SIG_PID" && "$(restarts "$SIG")" == "$SIG_NR" ]] || fail signer_changed
[[ "$(pid "$META")" == "$META_PID" && "$(restarts "$META")" == "$META_NR" ]] || fail metadata_changed
[[ "$(gitx rev-parse HEAD)" == "$TARGET" ]] || fail final_head_changed
[[ -z "$(gitx status --porcelain=v1 --untracked-files=all)" ]] || fail final_dirty_tree

read -r POST_EVENTS POST_MESSAGES < <(
  timeout 5s python3 - "$SAFETY" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d=json.load(f)
print(d["unrecoverable_core_gap_events"], d["unrecoverable_core_gap_messages"])
PY
) || fail post_safety_unavailable
[[ "$POST_EVENTS" == 117 && "$POST_MESSAGES" == 5083155 ]] || fail "P0_post_core_changed:$POST_EVENTS/$POST_MESSAGES"

echo 'DISCORD_HEALTH_DEPLOY=PASS'
echo "HEAD=$TARGET"
echo "PROTECTED_CORE=$POST_EVENTS/$POST_MESSAGES"
echo "DISCORD_RESTARTED=$DIS_PID_BEFORE->$DIS_PID_AFTER/NRestarts_before=$DIS_NR_BEFORE/NRestarts_after=$DIS_NR_AFTER"
echo "RESIDENT_PRESERVED=$RES_PID/NRestarts=$RES_NR"
echo "CAPTURE_PRESERVED=$CAP_PID/NRestarts=$CAP_NR"
echo "SIGNER_PRESERVED=$SIG_PID/NRestarts=$SIG_NR"
echo "METADATA_PRESERVED=$META_PID/NRestarts=$META_NR"

# One bounded read-only P0 audit after deploy. Failure here does not roll back or
# invite a deploy retry: the deploy result above is authoritative and consumed.
set +e
timeout 45s env PYTHONPATH="$REPO/src" "$REPO/.venv/bin/python" - <<'PY'
import json, secrets
from flop_agent import core
from flop_agent.public_record import verify_signed_record

MARU="did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
RISHI="did:key:z6MkhiRKcJjvdy1s4m6np8GgoLoqgVaRm5PmUVNKKiW9VpEZ"
REF="did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
FRESH="maru-sonnet2-writer-fresh-20260917-1"
APPLY_SEQ=133026


def read(room):
    payload=core.read_room(room, limit=200, cache_buster=secrets.token_hex(16))
    rows=payload if isinstance(payload, list) else payload.get("messages", [])
    return rows if isinstance(rows, list) else []


def audit(room):
    rows=read(room)
    verified=0
    relevant=[]
    for r in rows:
        if not isinstance(r, dict):
            continue
        try:
            verify_signed_record(room, r)
        except Exception:
            continue
        verified += 1
        try:
            d=json.loads(r.get("text", ""))
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        blob=json.dumps(d, ensure_ascii=False, sort_keys=True)
        seq=r.get("seq")
        if room == "d-sonnet-2-team-rishi-fire-1":
            keep=True
        elif room == "mb-sonnet-2-discovery":
            keep=(
                isinstance(seq, int) and seq > APPLY_SEQ and (
                    d.get("game_id") == "rishi-fire-1"
                    or MARU in blob
                    or r.get("from") == RISHI
                )
            )
        else:
            keep=(MARU in blob or FRESH in blob)
        if not keep:
            continue
        out={
            "seq": seq,
            "ts": r.get("ts"),
            "official_referee": r.get("from") == REF,
            "sender": r.get("from"),
        }
        for k in (
            "type", "status", "reason", "request_id", "contest_id", "game_id",
            "poem_room", "room_generation", "intake_seq", "word", "version",
            "previous_state_hash", "target_did", "participant_did", "role", "text"
        ):
            if k in d:
                out[k]=d[k]
        if isinstance(d.get("members"), list):
            out["members"]=d["members"]
            out["members_count"]=len(d["members"])
            out["maru_in_members"]=MARU in d["members"]
        relevant.append(out)
    first=rows[0].get("seq") if rows and isinstance(rows[0], dict) else None
    last=rows[-1].get("seq") if rows and isinstance(rows[-1], dict) else None
    print("P0_ROOM="+json.dumps({
        "room": room, "rows": len(rows), "verified": verified,
        "first_seq": first, "last_seq": last, "relevant_count": len(relevant)
    }, ensure_ascii=False, sort_keys=True))
    for out in relevant:
        print("P0_RELEVANT="+json.dumps(out, ensure_ascii=False, sort_keys=True))

for room in (
    "mb-sonnet-2-discovery",
    "d-sonnet-2-team-rishi-fire-1",
    "mb-sonnet-2-registration",
    "d-sonnet-2-results",
):
    audit(room)
print("P0_READ_ONLY_AUDIT=COMPLETE")
PY
AUDIT_RC=$?
set -e
if [[ "$AUDIT_RC" -ne 0 ]]; then
  echo "P0_READ_ONLY_AUDIT=UNAVAILABLE rc=$AUDIT_RC"
fi

trap - ERR
echo 'DO_NOT_RERUN=YES'
