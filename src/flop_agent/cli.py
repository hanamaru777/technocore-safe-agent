from __future__ import annotations

import argparse
import json
import sys

from . import core


def main() -> None:
    parser = argparse.ArgumentParser(prog="flop")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("status", "show-did", "activity-log", "sync-official", "doctor", "history-secret-scan"):
        sub.add_parser(command)
    room = sub.add_parser("read-room"); room.add_argument("room")
    new = sub.add_parser("read-new"); new.add_argument("room")
    post = sub.add_parser("post-signed"); post.add_argument("room"); post.add_argument("--text", required=True); post.add_argument("--confirm", action="store_true")
    plan = sub.add_parser("proof-plan"); plan.add_argument("--contribution-url", required=True); plan.add_argument("--room", default="lobby")
    create = sub.add_parser("create-proof"); create.add_argument("--plan-id", required=True); create.add_argument("--confirm", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "status":
            valid, count = core.verify_activity_log(); output = {"phase": "2 useful-agent foundation", "activity_log_valid": valid, "activity_count": count, "signer_matches_pinned_hash": core.signer_sha256() == core.SIGNER_SHA256}
        elif args.command == "show-did": output = {"did": core.current_did(), "did_note": dict(zip(("shard", "key", "fingerprint"), core.did_note_location(core.current_did()))), "warning": "DID Note は公開・world-writable の慣習であり認証ではありません。"}
        elif args.command == "read-room": output = core.read_room(args.room)
        elif args.command == "read-new": output = core.read_new(args.room)
        elif args.command == "post-signed": output = core.post_signed(args.room, args.text, args.confirm)
        elif args.command == "proof-plan": output = core.create_proof_plan(args.contribution_url, args.room)
        elif args.command == "create-proof": output = core.create_proof_bundle(args.plan_id, args.confirm)
        elif args.command == "activity-log": output = {"valid": core.verify_activity_log()[0], "path": str(core.STATE / "activities.jsonl")}
        elif args.command == "sync-official": output = core.sync_official()
        elif args.command == "doctor": output = core.doctor()
        elif args.command == "history-secret-scan":
            hits = core.history_secret_scan(); output = {"ok": not hits, "history_secret_scan_hits": hits}
        else:
            hits = core.secret_scan(); output = {"ok": not hits, "secret_scan_hits": hits, "signer_hash": core.signer_sha256(), "pinned_signer_hash": core.SIGNER_SHA256}
        print(json.dumps(output, ensure_ascii=False, indent=2))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
