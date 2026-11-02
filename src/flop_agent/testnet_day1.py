"""Offline FLOP Day-1 status and exact local first-use proposal. No execution.

Manifest/signature envelopes here are LOCAL review formats, never invented
chain request encodings. No core/production state, signing or adapter imports.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import os
from pathlib import Path
import re
import sys
import stat

from . import testnet_budget as budget
from . import testnet_day1_release as release

PROMPT = ("Summarize this public safety statement in one sentence: Use only official test tokens; "
          "do not reuse an inference request when its outcome is unknown.")
GATE_NAMES = (
    "official_source", "launch_release", "network_identity", "genesis", "rpc", "gateway",
    "original_existing_DID_public_binding", "audited_original_signer", "signature_wire_schema",
    "official_faucet_endpoint_terms_caps", "signed_inference_endpoint_request_caps",
    "authentic_final_settlement_receipt_rule", "test_token_budget", "explicit_owner_approvals",
    "duplicate_prevention_journal", "independent_real_live_observation", "safe_first_inference",
)
ROOT = Path(__file__).resolve().parents[2]
CODE_INPUTS = ("src/flop_agent/testnet_day1.py", "src/flop_agent/testnet_day1_release.py",
               "src/flop_agent/testnet_day1_actions.py", "src/flop_agent/testnet_budget.py",
               "src/flop_agent/testnet_journal.py", "src/flop_agent/public_record.py",
               "src/flop_agent/airdrop_approval.py", "src/flop_agent/airdrop_action_stager.py",
               "src/flop_agent/airdrop_executor.py", "src/flop_agent/airdrop_ledger.py",
               "packaging/testnet/r1057_offline_agent_launch_gate.py",
               "packaging/testnet/r1105_agent_public_readiness.py", "tests/test_testnet_day1.py")


def fingerprint():
    return release.sha({name:hashlib.sha256((ROOT/name).read_bytes().replace(b"\r\n",b"\n")).hexdigest() for name in CODE_INPUTS})


def code_evidence():
    path = ROOT/"docs/tasks/t1150_offline_verification.json"
    if not path.exists(): return {"state":"UNKNOWN","reason":"OFFLINE_TEST_EVIDENCE_NOT_RECORDED"}
    try:
        row = release.parse(path.read_bytes())
        release.shape(row,"scope source_sha256 targeted_passed targeted_skipped regressions_passed regressions_skipped failures platform ci")
        release.need(row["scope"] == "OFFLINE_CODE_ONLY" and row["source_sha256"] == fingerprint() and
                     row["failures"] == 0 and type(row["failures"]) is int, "CODE_EVIDENCE_BINDING")
        for k in ("targeted_passed","regressions_passed"):release.integer(row[k])
        for k in ("targeted_skipped","regressions_skipped"):release.integer(row[k],0)
        release.need(row["platform"] in ("WINDOWS","LINUX","WINDOWS_AND_LINUX") and row["ci"] in ("NOT_OBSERVED","PASS"), "CODE_EVIDENCE_SCOPE")
        return {"state":"VERIFIED","reason":"RECORDED_OFFLINE_TESTS_ONLY","scope":row["platform"],"ci":row["ci"],
                "skipped":row["targeted_skipped"]+row["regressions_skipped"]}
    except (OSError,ValueError,KeyError,TypeError):
        return {"state":"UNKNOWN","reason":"OFFLINE_TEST_EVIDENCE_INVALID_OR_STALE"}


def status(bundle=None, trust=None, *, now=None):
    now = int(datetime.now(UTC).timestamp()) if now is None else now
    gates = {name:{"state":"BLOCKED","reason":"WAIT_OFFICIAL_RELEASE"} for name in GATE_NAMES}
    for name,reason in (
        ("original_existing_DID_public_binding","ORIGINAL_PUBLIC_PROOF_NOT_SUPPLIED"),
        ("audited_original_signer","ORIGINAL_SIGNER_NOT_INSPECTED"),
        ("explicit_owner_approvals","SEPARATE_EXACT_CONSENTS_REQUIRED"),
        ("duplicate_prevention_journal","DEDICATED_PRE_SEND_JOURNAL_NOT_INITIALIZED"),
        ("independent_real_live_observation","NO_LIVE_OBSERVATION_PERFORMED"),
    ):gates[name]={"state":"UNKNOWN","reason":reason}
    manifest = None; error = None
    if bundle is not None:
        try:manifest = release.admit(bundle,trust,now=now)
        except (release.Blocked,budget.Stop) as blocked:error=str(blocked)
        except (ValueError,KeyError,TypeError):error="RELEASE_ADMISSION_FAILED"
        if error:
            gates["official_source"]={"state":"BLOCKED","reason":error}
        else:
            for name in ("official_source","network_identity","genesis","rpc","gateway","original_existing_DID_public_binding"):
                gates[name]={"state":"VERIFIED","reason":"PINNED_OFFLINE_REVIEW_NOT_LIVE_AUTHORITY"}
            gates["launch_release"]={"state":"UNKNOWN","reason":"REVIEWED_LIVE_DECLARATION_REQUIRES_INDEPENDENT_LIVE_PROOF"}
    for name in ("signature_wire_schema","official_faucet_endpoint_terms_caps","signed_inference_endpoint_request_caps"):
        gates[name]={"state":"BLOCKED","reason":"AUDITED_OFFICIAL_ACTION_ADAPTER_UNAVAILABLE"}
    gates["authentic_final_settlement_receipt_rule"]={"state":"BLOCKED","reason":"OFFICIAL_SETTLEMENT_VERIFIER_UNAVAILABLE"}
    if manifest:gates["test_token_budget"]={"state":"VERIFIED","reason":"REVIEWED_TEST_ONLY_LIMITS_REAL_MONEY_ZERO"}
    code=code_evidence()
    return {"schema_version":1,"task":"T1150","overall":"BLOCKED","next_action":"WAIT_OFFICIAL_RELEASE",
            "code_ready":code["state"],"code_evidence":code,"code_fingerprint":fingerprint(),"live_ready":"NO","gates":gates,
            "admission_error":error,"real_money_spend":0,"network_access":"NONE","live_actions":0,
            "airdrop_allocation":"NOT_PROVEN","target_date":"2026-11-03","target_date_confirmed":False}


def plan(bundle=None, trust=None, *, max_test_units=None, now=None):
    now = int(datetime.now(UTC).timestamp()) if now is None else now
    if bundle is None:
        return {"scope":"LOCAL_OFFLINE_PLAN_NOT_WIRE_REQUEST","state":"BLOCKED","reason":"WAIT_OFFICIAL_RELEASE",
                "task_class":"public_document_summary","data_class":"PUBLIC_FIXED_TEXT_ONLY","prompt":PROMPT,
                "network":"testnet","chain_id":None,"genesis_sha256":None,"did":None,
                "max_test_units":None,"real_money_spend":0,"auto_renew":False,"live_permission":"NO"}
    manifest=release.admit(bundle,trust,now=now)
    units=release.integer(max_test_units)
    lim=manifest["limits"]
    release.need(units <= lim["max_request_units"],"REQUEST_CAP_STOP")
    expires=min(now+lim["ttl_seconds"],release.timestamp(manifest["expires_at"]))
    release.need(now < expires,"PLAN_EXPIRED")
    payload={"scope":"LOCAL_OFFLINE_PLAN_NOT_WIRE_REQUEST","action":"inference","network":"testnet",
             "release_sha256":trust["manifest_sha256"],"chain_id":manifest["chain_id"],"genesis_sha256":manifest["genesis_sha256"],
             "did":trust["original_did"],"task_class":"public_document_summary","data_class":"PUBLIC",
             "prompt":PROMPT,"max_test_units":units,"unit":lim["unit"],"real_money_spend":0,
             "expires_at":expires,"request_schema_sha256":manifest["inference"]["schema_sha256"],
             "signature_schema_sha256":manifest["signature_schema_sha256"],"protocol_nonce":None}
    payload["registration_required"]=manifest["registration"]["required"]
    # Stable across regenerated plan TTLs. A new timestamp cannot bypass fence.
    intent="day1-"+release.sha({"did":trust["original_did"],"genesis":manifest["genesis_sha256"]})[:40]
    job={"intent_id":intent,"utc_day":datetime.fromtimestamp(now,UTC).date().isoformat(),
         "task_class":"public_document_summary","data_class":"PUBLIC","payload_sha256":release.sha(payload),"max_test_units":units}
    # One and only one first inference, stricter than the published upper caps.
    # This makes the existing journal's atomic global-budget lock sufficient
    # even when two processes race with different release/genesis proposals.
    policy={k:units for k in budget.CAP_FIELDS}
    budget.prepare(budget.new_ledger(),policy,job)
    actions={}
    for action in ("registration","faucet","spend"):
        if action=="registration" and not manifest["registration"]["required"]:continue
        bound=payload if action=="spend" else {"scope":"LOCAL_OFFLINE_ACTION_PROPOSAL","action":action,
            "release_sha256":trust["manifest_sha256"],"did":trust["original_did"],"genesis_sha256":manifest["genesis_sha256"],
            "endpoint":manifest[action]["url"],"schema_sha256":manifest[action]["schema_sha256"],
            "expires_at":expires,"real_money_spend":0,"max_test_units":0}
        actions[action]={"action_class":action,"payload_sha256":release.sha(bound),"payload":bound,
                         "source_event_id":"t1150-"+trust["manifest_sha256"][:24],"expires_at":datetime.fromtimestamp(expires,UTC).isoformat()}
    return {"scope":"T1150_LOCAL_FIRST_USE_PROPOSAL","state":"BLOCKED","reason":"AUDITED_PROTOCOL_SIGNER_AND_SETTLEMENT_REQUIRED",
            "payload":payload,"canonical_payload_sha256":release.sha(payload),"manifest_sha256":trust["manifest_sha256"],
            "job":job,"budget":policy,"official_limits":{k:lim[k] for k in budget.CAP_FIELDS},
            "actions":actions,"created_at":now,"expires_at":expires,
            "idempotency_key":intent,"post_unknown_state":"UNKNOWN_POST_NO_RETRY","wire_payload":"NOT_ENCODED",
            "auto_renew":False,"live_permission":"NO"}


def read_public(path):
    path=Path(path).absolute()
    release.need(".." not in path.parts and not any(re.search(r"seed|secret|credential|private.?key|wallet",p,re.I) for p in path.parts),"PUBLIC_FILE_ONLY")
    release.need(not any(p.is_symlink() or p.is_junction() for p in (path,*path.parents)),"PUBLIC_FILE_LINK_REFUSED")
    try:
        before=path.lstat()
        release.need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=release.MAX_BYTES,"PUBLIC_REGULAR_FILE_REQUIRED")
        fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_BINARY",0))
        with os.fdopen(fd,"rb") as stream:
            current=os.fstat(stream.fileno())
            release.need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==
                         (current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns),"PUBLIC_FILE_CHANGED")
            raw=stream.read(release.MAX_BYTES+1)
            after=os.fstat(stream.fileno())
            release.need((current.st_size,current.st_mtime_ns)==(after.st_size,after.st_mtime_ns),"PUBLIC_FILE_CHANGED")
            return release.parse(raw)
    except OSError:raise release.Blocked("PUBLIC_FILE_UNAVAILABLE") from None


def plan_summary(proposal):
    """One-screen public proposal; full exact bindings remain library objects."""
    if "payload" not in proposal:return proposal
    payload=proposal["payload"]
    return {"scope":proposal["scope"],"state":proposal["state"],"reason":proposal["reason"],
            "network":{k:payload[k] for k in ("network","chain_id","genesis_sha256","did")},
            "task":payload["prompt"],"data_class":"PUBLIC_FIXED_TEXT_ONLY","test_budget":proposal["budget"],
            "unit":payload["unit"],"expires_at":proposal["expires_at"],"real_money_spend":0,"auto_renew":False,
            "canonical_payload_sha256":proposal["canonical_payload_sha256"],"idempotency_key":proposal["idempotency_key"],
            "protocol_nonce":None,"wire_payload":"NOT_ENCODED","post_unknown_state":"UNKNOWN_POST_NO_RETRY",
            "separate_owner_consents":{k:v["payload_sha256"] for k,v in proposal["actions"].items()},"live_permission":"NO"}


class Parser(argparse.ArgumentParser):
    def error(self,message):raise release.Blocked("INVALID_ARGUMENTS")


def main(argv=None):
    try:
        parser=Parser(description="T1150 offline status/plan; never signs or sends.")
        parser.add_argument("command",choices=("status","plan","inspect-official"))
        parser.add_argument("--bundle");parser.add_argument("--reviewer-public-key")
        parser.add_argument("--manifest-sha256");parser.add_argument("--genesis-sha256")
        parser.add_argument("--original-did");parser.add_argument("--reference-sha256")
        parser.add_argument("--max-test-units",type=int);parser.add_argument("--network",action="store_true")
        args=parser.parse_args(argv)
        if args.command=="inspect-official":
            release.need(args.network and args.bundle is None,"EXPLICIT_PUBLIC_GET_REQUIRED")
            result=release.inspect_official()
            print(release.canonical(result).decode());return 3
        release.need(not args.network,"NO_NETWORK_FOR_STATUS_OR_PLAN")
        bundle=read_public(args.bundle) if args.bundle else None
        trust=None
        if bundle is not None:
            trust=dict(reviewer_public_hex=args.reviewer_public_key,manifest_sha256=args.manifest_sha256,
                genesis_sha256=args.genesis_sha256,original_did=args.original_did,reference_sha256=args.reference_sha256)
        result=status(bundle,trust) if args.command=="status" else plan_summary(plan(bundle,trust,max_test_units=args.max_test_units))
        print(release.canonical(result).decode())
        return 2 if result.get("admission_error") else 3
    except (release.Blocked,budget.Stop) as blocked:
        print(release.canonical({"task":"T1150","overall":"BLOCKED","live_ready":"NO","reason":str(blocked),"live_actions":0}).decode())
        return 2
    except (ValueError,KeyError,TypeError,OverflowError):
        print('{"task":"T1150","overall":"BLOCKED","live_ready":"NO","reason":"INVALID_OR_UNREVIEWED_LOCAL_INPUT","live_actions":0}')
        return 2


if __name__=="__main__":raise SystemExit(main())
