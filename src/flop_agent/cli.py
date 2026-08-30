from __future__ import annotations

import argparse
import json
import sys

from . import core


def main() -> None:
    parser = argparse.ArgumentParser(prog="flop")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("status", "show-did", "activity-log", "sync-official", "doctor", "secret-scan", "history-secret-scan"):
        sub.add_parser(command)
    for command in ("observe", "observe-once", "agents", "opportunities", "observer-status", "discover-backfill", "intelligence", "resident-status", "top-agents", "candidates", "feedback-status", "reset-learning", "pause-resident", "resume-resident", "approved", "export-resident-state", "autopilot-status", "autopilot-queue", "autopilot-enable", "autopilot-disable", "autopilot-pause", "autopilot-resume"):
        sub.add_parser(command)
    compact = sub.add_parser("compact-observer-state"); compact.add_argument("--apply", action="store_true")
    agent = sub.add_parser("agent"); agent.add_argument("identifier")
    resident_candidate = sub.add_parser("candidate"); resident_candidate.add_argument("candidate_id")
    approve = sub.add_parser("approve"); approve.add_argument("candidate_id")
    reject = sub.add_parser("reject"); reject.add_argument("candidate_id"); reject.add_argument("reason")
    publish = sub.add_parser("publish-approved"); publish.add_argument("candidate_id"); publish.add_argument("--confirm", action="store_true")
    autopilot_publish = sub.add_parser("autopilot-publish"); autopilot_publish.add_argument("intent_id"); autopilot_publish.add_argument("--confirm", action="store_true")
    session = sub.add_parser("autopilot-session-once"); session.add_argument("--dry-run", action="store_true")
    session_publish = sub.add_parser("autopilot-session-publish"); session_publish.add_argument("intent_id")
    session_publish.add_argument("--did", required=True)
    sub.add_parser("autopilot-session-verify")
    sub.add_parser("autopilot-export")
    sub.add_parser("autopilot-ack")
    room = sub.add_parser("read-room"); room.add_argument("room")
    new = sub.add_parser("read-new"); new.add_argument("room")
    post = sub.add_parser("post-signed"); post.add_argument("room"); post.add_argument("--text", required=True); post.add_argument("--confirm", action="store_true"); post.add_argument("--did")
    plan = sub.add_parser("proof-plan"); plan.add_argument("--contribution-url", required=True); plan.add_argument("--room", default="lobby")
    create = sub.add_parser("create-proof"); create.add_argument("--plan-id", required=True); create.add_argument("--confirm", action="store_true")
    resume = sub.add_parser("resume-proof"); resume.add_argument("--plan-id", required=True); resume.add_argument("--confirm", action="store_true")
    show_plan = sub.add_parser("show-proof-plan"); show_plan.add_argument("--plan-id", required=True)
    verify = sub.add_parser("verify-did"); verify.add_argument("--expected-did", required=True)
    args = parser.parse_args()
    try:
        if args.command == "status":
            valid, count = core.verify_activity_log(); output = {"phase": "2 useful-agent foundation", "activity_log_valid": valid, "activity_count": count, "signer_matches_pinned_hash": core.signer_sha256() == core.SIGNER_SHA256}
        elif args.command == "show-did":
            did = core.current_did()
            output = {"did": did, "did_note": dict(zip(("shard", "key", "fingerprint"), core.did_note_location(did))), "warning": "DID Note は公開・world-writable の慣習であり認証ではありません。"}
        elif args.command == "verify-did":
            output = core.verify_did(args.expected_did)
        elif args.command == "read-room": output = core.read_room(args.room)
        elif args.command == "read-new": output = core.read_new(args.room)
        elif args.command == "post-signed": output = core.post_signed(args.room, args.text, args.confirm, did=args.did)
        elif args.command == "proof-plan": output = core.create_proof_plan(args.contribution_url, args.room)
        elif args.command == "create-proof": output = core.create_proof_bundle(args.plan_id, args.confirm)
        elif args.command == "resume-proof": output = core.resume_proof_bundle(args.plan_id, args.confirm)
        elif args.command == "show-proof-plan": output = core.show_proof_plan(args.plan_id)
        elif args.command == "observe":
            from . import observer
            observer.observe_forever(); return
        elif args.command == "observe-once":
            from . import observer
            output = observer.observe_once()
        elif args.command == "agents":
            from . import observer
            output = observer.list_agents()
        elif args.command == "agent":
            from . import observer
            output = observer.get_agent(args.identifier)
        elif args.command == "opportunities":
            from . import observer
            output = observer.opportunities()
        elif args.command == "observer-status":
            from . import observer
            output = observer.observer_status()
        elif args.command == "discover-backfill":
            from . import observer
            output = observer.discover_backfill()
        elif args.command == "compact-observer-state":
            from . import observer
            output = observer.compact_persisted_state(args.apply)
        elif args.command == "intelligence":
            from . import observer
            output = observer.intelligence_report()
        elif args.command in {"resident-status", "top-agents", "candidates", "candidate", "approve", "reject", "feedback-status", "reset-learning", "pause-resident", "resume-resident", "approved", "export-resident-state", "publish-approved", "autopilot-status", "autopilot-queue", "autopilot-enable", "autopilot-disable", "autopilot-pause", "autopilot-resume", "autopilot-publish", "autopilot-export", "autopilot-ack", "autopilot-session-once", "autopilot-session-verify", "autopilot-session-publish"}:
            from . import autopilot, autopilot_transport, observer, resident
            if args.command == "resident-status": output = resident.resident_status()
            elif args.command == "top-agents": output = {"agents": resident.refresh() and observer.intelligence_report()["interesting_agents"]}
            elif args.command == "candidates": output = resident.list_candidates()
            elif args.command == "candidate": output = resident.candidate(args.candidate_id)
            elif args.command == "approve": output = resident.feedback(args.candidate_id, "approved")
            elif args.command == "reject": output = resident.feedback(args.candidate_id, "rejected", args.reason)
            elif args.command == "feedback-status": output = resident.feedback_status()
            elif args.command == "reset-learning": output = resident.reset_learning()
            elif args.command == "pause-resident": output = resident.pause(True)
            elif args.command == "resume-resident": output = resident.pause(False)
            elif args.command == "approved": output = {"candidates": [item for item in resident.list_candidates()["candidates"] if item["status"] == "approved"]}
            elif args.command == "export-resident-state": output = {"export_path": resident.export_state()}
            elif args.command == "publish-approved": output = resident.publish_approved(args.candidate_id, args.confirm)
            elif args.command == "autopilot-status": output = autopilot.status()
            elif args.command == "autopilot-queue": output = autopilot.queue()
            elif args.command == "autopilot-enable": output = autopilot.enable()
            elif args.command == "autopilot-disable": output = autopilot.disable()
            elif args.command == "autopilot-pause": output = autopilot.pause(True)
            elif args.command == "autopilot-resume": output = autopilot.pause(False)
            elif args.command == "autopilot-publish": output = autopilot.publish(args.intent_id, args.confirm)
            elif args.command == "autopilot-export": output = autopilot.export_pending()
            elif args.command == "autopilot-ack": output = autopilot.acknowledge_export(json.load(sys.stdin))
            elif args.command == "autopilot-session-once": output = autopilot_transport.session_once(args.dry_run)
            elif args.command == "autopilot-session-verify": output = autopilot_transport.verify_session_did()
            else: output = autopilot_transport.publish_one(args.intent_id, args.did)
        elif args.command == "activity-log": output = {"valid": core.verify_activity_log()[0], "path": str(core.STATE / "activities.jsonl")}
        elif args.command == "sync-official": output = core.sync_official()
        elif args.command == "doctor": output = core.doctor()
        elif args.command == "history-secret-scan":
            hits = core.history_secret_scan(); output = {"ok": not hits, "history_secret_scan_hits": hits}
        else:
            hits = core.secret_scan(); output = {"ok": not hits, "secret_scan_hits": hits, "signer_hash": core.signer_sha256(), "pinned_signer_hash": core.SIGNER_SHA256}
        print(json.dumps(output, ensure_ascii=False, indent=2))
        if args.command == "verify-did" and not output["match"]:
            raise SystemExit(1)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
