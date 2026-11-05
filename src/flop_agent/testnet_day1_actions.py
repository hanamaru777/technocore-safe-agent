"""Local consent validation and durable OFFLINE reservations only.

No executor adapters, receipt algorithms, signer or transport are registered.
Existing Linux approval validators/journal are imported lazily. Pure status and
plan remain Windows-compatible and never inspect the production Action Inbox.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from datetime import UTC,datetime

from . import testnet_day1_release as release, testnet_budget as budget


def validate_plan(proposal, *, now):
    release.shape(proposal,"scope state reason payload canonical_payload_sha256 manifest_sha256 job budget official_limits actions created_at expires_at idempotency_key post_unknown_state wire_payload auto_renew live_permission")
    release.integer(proposal["created_at"]);release.integer(proposal["expires_at"])
    release.need(proposal.get("scope")=="T1150_LOCAL_FIRST_USE_PROPOSAL" and proposal.get("live_permission")=="NO" and
                 proposal.get("auto_renew") is False and proposal.get("created_at") <= now < proposal.get("expires_at"),"PLAN_INVALID_OR_EXPIRED")
    payload=proposal["payload"];job=proposal["job"]
    release.shape(payload,"scope action network release_sha256 chain_id genesis_sha256 did task_class data_class prompt max_test_units unit real_money_spend expires_at request_schema_sha256 signature_schema_sha256 protocol_nonce registration_required")
    release.need(type(payload["registration_required"]) is bool and
                 set(proposal["actions"])==({"registration","faucet","spend"} if payload["registration_required"] else {"faucet","spend"}) and
                 proposal["expires_at"]<=proposal["created_at"]+900 and payload["expires_at"]==proposal["expires_at"] and
                 payload["scope"]=="LOCAL_OFFLINE_PLAN_NOT_WIRE_REQUEST" and payload["network"]=="testnet" and
                 job["intent_id"]=="day1-"+release.sha({"did":payload["did"],"genesis":payload["genesis_sha256"]})[:40] and
                 job["utc_day"]==datetime.fromtimestamp(proposal["created_at"],UTC).date().isoformat(),"EXACT_PAYLOAD_REQUIRED")
    release.need(job["task_class"]==payload["task_class"]=="public_document_summary" and
                 job["data_class"]==payload["data_class"]=="PUBLIC","FIXED_PUBLIC_TASK_REQUIRED")
    release.need(payload["real_money_spend"]==0 and type(payload["real_money_spend"]) is int and
                 payload["protocol_nonce"] is None and payload["data_class"]=="PUBLIC" and
                 release.sha(payload)==proposal["canonical_payload_sha256"]==job["payload_sha256"] and
                 proposal["idempotency_key"]==job["intent_id"] and payload["max_test_units"]==job["max_test_units"],"EXACT_PAYLOAD_REQUIRED")
    from .testnet_day1 import PROMPT
    release.need(payload["prompt"]==PROMPT,"FIXED_PUBLIC_TASK_REQUIRED")
    budget.prepare(budget.new_ledger(),proposal["budget"],job)
    budget.caps(proposal["official_limits"])
    release.need(job["max_test_units"]<=proposal["official_limits"]["max_request_units"],"REQUEST_CAP_STOP")
    release.need(all(v==job["max_test_units"] and type(v) is int for v in proposal["budget"].values()),"ONE_FIRST_INFERENCE_CAP_REQUIRED")
    release.need(proposal["actions"]["spend"]["payload_sha256"]==job["payload_sha256"],"EXACT_PAYLOAD_REQUIRED")
    for action,row in proposal["actions"].items():
        release.need(action in ("registration","faucet","spend") and row["action_class"]==action and
                     release.sha(row["payload"])==row["payload_sha256"] and
                     row["payload"]["release_sha256"]==proposal["manifest_sha256"] and
                     row["payload"]["did"]==payload["did"] and row["payload"]["real_money_spend"]==0 and
                     row["payload"]["expires_at"]==proposal["expires_at"],"EXACT_PAYLOAD_REQUIRED")


def validate_consents(proposal, records, *, now):
    validate_plan(proposal,now=now)
    # Reuse production's exact approval hash, expiry and record validation;
    # never call its state loader/stager/consumer from this preparation layer.
    from . import airdrop_approval as approval
    release.need(type(records) is dict and set(records)==set(proposal["actions"]),"SEPARATE_OWNER_CONSENTS_REQUIRED")
    for action,expected in proposal["actions"].items():
        record=records[action]
        try:
            checked=approval._validate_record(record["request_id"],record)
            release.need(checked["status"]=="approved" and checked["action_class"]==action and
                         checked["payload_sha256"]==expected["payload_sha256"] and
                         checked["source_event_id"]==expected["source_event_id"] and
                         checked["expires_at"]==expected["expires_at"] and
                         approval._parse_utc(checked["expires_at"]).timestamp()>now and
                         approval._parse_utc(checked["decision_at"]).timestamp()<=now,"EXACT_OWNER_CONSENT_REQUIRED")
        except (approval.ApprovalInboxError,ValueError,KeyError,TypeError):
            raise release.Blocked("EXACT_OWNER_CONSENT_REQUIRED") from None
    return True


def journal_scope(path):
    # Explicit dedicated NEW local scope only, independent of FLOP_STATE_DIR.
    root=Path(__file__).resolve().parents[2]/"local-state/testnet-day1/journals"
    path=Path(path)
    try:
        release.need(path.is_absolute() and path.resolve(strict=True)==path and root in path.parents and
                     not any(p.is_symlink() or p.is_junction() for p in (path,*path.parents)),"DEDICATED_JOURNAL_SCOPE_REQUIRED")
    except OSError:raise release.Blocked("DEDICATED_JOURNAL_SCOPE_REQUIRED") from None
    return path


def reserve_offline(proposal,records,journal_dir,*,now):
    """A persisted PRE_SEND/UNKNOWN_POST fence, NOT permission to send.

    A reservation burns the one Day-1 attempt even if the process then dies.
    Existing R1064 directory flock/O_EXCL/fsync keeps budget+intent atomic.
    Never remove/rewrite entries or infer no-send from a network read miss.
    """
    validate_consents(proposal,records,now=now)
    from . import testnet_journal as journal
    path=journal_scope(journal_dir)
    current=journal.snapshot(path)
    release.need(not current["items"],"ONE_DAY1_ATTEMPT_ALREADY_RESERVED")
    # Even concurrent callers with the same proposal are rejected atomically by
    # reserve_unknown's shared directory lock and exact stable intent ID.
    result=journal.reserve_unknown(path,proposal["budget"],proposal["job"])
    return {**result,"scope":"OFFLINE_RESERVATION_NOT_EXECUTION","live_permission":"NO",
            "pre_send":"DURABLY_RESERVED","post_state":"UNKNOWN_POST","transport_invoked":False}


def receipt_report(proposal,raw,*,claimed_phase="unknown",now):
    """Untrusted delivery/acceptance/settlement hints NEVER establish finality."""
    validate_plan(proposal,now=now)
    release.need(type(raw) is bytes and 0<len(raw)<=65536,"RECEIPT_BOUND_REQUIRED")
    release.need(claimed_phase in ("unknown","delivered","accepted","settled","voucher"),"RECEIPT_PHASE_REQUIRED")
    return {"request_sha256":proposal["canonical_payload_sha256"],"unverified_receipt_sha256":hashlib.sha256(raw).hexdigest(),
            "claimed_phase_untrusted":claimed_phase,"transport":"UNVERIFIED","acceptance":"UNVERIFIED",
            "settlement":"UNVERIFIED","voucher":"UNVERIFIED","succeeded":False,"score":"NOT_PROVEN",
            "reason":"OFFICIAL_SETTLEMENT_VERIFIER_UNAVAILABLE","retry_allowed":False}


def verify_final_settlement(*args,**kwargs):
    # No registry escape hatch, invented wire format or caller's settled=true.
    # A published official rule + separately audited adapter are prerequisites.
    raise release.Blocked("OFFICIAL_SETTLEMENT_VERIFIER_UNAVAILABLE")
