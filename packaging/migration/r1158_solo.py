"""Explicit v2 SOLO_OWNER consent; never an independent-human signature.

Consent is not machine evidence. Operational callers must still perform the
original host/UID/masks/egress/fd/SQLite/receipt checks. No cached JSON is GO.
"""
import hashlib
import importlib.util
from pathlib import Path
import re
import sys

sp=importlib.util.spec_from_file_location("r1158_contract",Path(__file__).with_name("r1107_contract.py"))
C=importlib.util.module_from_spec(sp);sys.modules[sp.name]=C;sp.loader.exec_module(C)
DOMAIN=b"FLOP-R1158-SOLO-OWNER-v2\0"
MACHINE_DOMAIN=b"FLOP-R1158-MACHINE-ONLY-v2\0"
MAX_SESSION=3600
MAX_OBSERVATION_AGE=30
LEVELS={
    "r1154-hold":"FLOP_APP_HOLD_KEEP_VM_SSH",
    "r1154-custody":"ORIGINAL_DID_ENCRYPTED_EXPORT",
    "r1154-preserve":"FULL_ENCRYPTED_DISARMED_RESTORE",
    "r1155-transfer":"FULL_ENCRYPTED_DISARMED_RESTORE",
    "r1154-permanent-no-replay":"PERMANENT_FIVE_ROUTE_NO_REPLAY",
    "r1155-activate":"NEW_ONLY_ACTIVATION",
    "r1155-new-request":"NEW_ONLY_FIXED_REPLY",
    "r1156-autonomy":"NEW_ONLY_ACTIVATION",
    "r1156-stage":"NEW_ONLY_ACTIVATION",
    "r1156-identities":"ISOLATED_LOCAL_SETUP",
    "r1155-recipient-init":"ORIGINAL_DID_ENCRYPTED_EXPORT",
    "r1154-rollback":"DISARMED_ROLLBACK_NO_OLD_POST_RELEASE",
    "r1158-machine-init":"ISOLATED_LOCAL_SETUP",
    "r1158-capacity":"EXISTING_HOST_ZERO_NEW_BILLING",
    "r1158-inventory":"FULL_ENCRYPTED_DISARMED_RESTORE",
    "r1158-monitor-session":"BOUNDED_MACHINE_MONITOR_SESSION",
}
ACK="ONE_HUMAN_NO_INDEPENDENT_REVIEW_CLAIM"
SAFE_CODES=frozenset(("SOLO_EXTRA_ROLE_REJECTED","SOLO_EXPLICIT_OPT_IN_REQUIRED","SOLO_EXACT_CONSENT_REQUIRED",
    "SOLO_MACHINE_ATTESTER_NOT_ENROLLED","SOLO_MACHINE_EVIDENCE_NOT_PROVEN","SOLO_SESSION_EXPIRED","SOLO_WATCHDOG_STOP_NO_RETRY",
    "SOLO_TARGET_UID_CONFLICT","SOLO_PROTECTED_RESERVE_STOP","SOLO_TARGET_RESOURCES_STOP","SOLO_ACTIVATION_NOT_PROVEN",
    "SOLO_G4_G5_NOT_PROVEN","SOLO_SOURCE_HOLD_NOT_PROVEN","SOLO_HOST_BOOT_STOP","SOLO_MACHINE_BINDING_STOP",
    "SOLO_TARGET_NO_REPLAY_NOT_PROVEN","SOLO_RESTORE_REQUIRES_DISARMED_TARGET","SOLO_LIVE_OS_CHECK_REQUIRED",
    "SOLO_INVENTORY_BINDING_STOP","SOLO_SOURCE_SIZE_STOP","SOLO_LEDGER_MEMORY_BOUND_STOP","SOLO_CUSTODY_RECEIPT_NOT_PROVEN",
    "SOLO_CUSTODY_ATTEMPT_EXISTS_NO_RETRY","SOLO_TRADEBOT_PROTECTION_CHANGED","SOLO_MEMORY_BUDGET_NOT_PROVEN",
    "SOLO_RECIPIENT_NOT_PROVEN","SOLO_SETUP_CONSENT_REQUIRED","SOLO_MULTIPLE_PUBLISHERS_STOP","SOLO_LATE_OR_REPLAYED_MACHINE_CHECK",
    "SOLO_ZERO_COST_CONSENT_REQUIRED","WARM_PROCESS_RACE_STOP","WARM_PROCESS_STILL_ALIVE","WARM_SCOPE_DRIFT_STOP","WARM_LAUNCHER_DRIFT_STOP"))


def solo(profile):
    return type(profile) is dict and profile.get("schema_version")==2 and profile.get("mode")=="SOLO_OWNER"


class Enrollment:
    def __init__(self,profile):
        C.shape(profile,"schema_version mode context keys source_key_ids source_did risk_ack machine_keys boots"+(" protected_tradebot" if "protected_tradebot" in profile else ""))
        C.need(type(profile["schema_version"]) is int and solo(profile) and profile["risk_ack"]==ACK,"SOLO_EXPLICIT_OPT_IN_REQUIRED")
        C.need(type(profile["keys"]) is list and len(profile["keys"])==1 and profile["keys"][0].get("role")=="owner","SOLO_EXTRA_ROLE_REJECTED")
        # Reuse the proven DID/context/excluded-key verification, with one
        # genuine owner key. Never enroll another role under the owner's key.
        base={k:v for k,v in profile.items() if k not in ("mode","risk_ack","machine_keys","boots","protected_tradebot")};base["schema_version"]=1
        checked=C.Enrollment(base)
        self.context=checked.context;self.keys=checked.keys;self.excluded=checked.excluded
        self.profile=C.decode(C.G.canonical(profile))
        if "protected_tradebot" in profile:
            C.shape(profile["protected_tradebot"],"unit")
            C.need(type(profile["protected_tradebot"]["unit"]) is str and re.fullmatch(r"(?i)tradebot[a-z0-9_-]*\.service",profile["protected_tradebot"]["unit"]),"SOLO_PROTECTED_UNIT_STOP")
        C.shape(profile["machine_keys"],"oci k137");C.shape(profile["boots"],"oci k137")
        for role in ("oci","k137"):
            C.digest(profile["boots"][role])
            if profile["machine_keys"][role] is not None:C.digest(profile["machine_keys"][role])
        present=[v for v in profile["machine_keys"].values() if v is not None]
        C.need(len(set(present))==len(present) and all(hashlib.sha256(bytes.fromhex(v)).hexdigest() not in self.keys|{k:None for k in self.excluded} for v in present),"SOLO_MACHINE_KEY_REUSE_STOP")

    def verify(self,packet,kind,role,now,*,age=900):
        C.need(role=="owner" and kind in LEVELS,"SOLO_ROLE_OR_OPERATION_REJECTED")
        C.shape(packet,"signer body signature");body=packet["body"]
        C.shape(body,"schema_version mode kind consent context authority_sha observed_at expires_at data")
        C.need(type(body["schema_version"]) is int and body["schema_version"]==2 and body["mode"]=="SOLO_OWNER" and
            body["kind"]==kind and body["consent"]==LEVELS[kind] and body["context"]==self.context and body["authority_sha"]==C.G.sha(self.profile),"SOLO_CONSENT_BINDING_STOP")
        # A separately specified v2 human session, NOT an extension of any v1
        # 30/900-second signature. Machine observations stay <=30 seconds.
        C.fresh(body["observed_at"],now,age=MAX_SESSION)
        C.need(now<C.integer(body["expires_at"],1)<=body["observed_at"]+MAX_SESSION,"SOLO_SESSION_EXPIRED")
        kid=C.digest(packet["signer"])
        C.need(kid in self.keys and kid not in self.excluded,"SOLO_OWNER_KEY_STOP")
        C.need(type(packet["signature"]) is str and re.fullmatch(r"[a-f0-9]{128}",packet["signature"]),"SOLO_SIGNATURE_STOP")
        try:C.G.Ed25519PublicKey.from_public_bytes(self.keys[kid][0]).verify(bytes.fromhex(packet["signature"]),DOMAIN+C.G.canonical(body))
        except (ValueError,C.G.InvalidSignature):raise C.Stop("SOLO_SIGNATURE_STOP") from None
        return C.decode(C.G.canonical(body["data"]))


def issue(profile,key,kind,data,*,now,seconds=1800,confirmation):
    authority=Enrollment(profile)
    C.need(kind in LEVELS and confirmation==LEVELS[kind],"SOLO_EXACT_CONSENT_REQUIRED")
    C.integer(seconds,1,MAX_SESSION)
    public=key.public_key().public_bytes_raw();kid=hashlib.sha256(public).hexdigest()
    C.need(authority.keys.get(kid)==(public,"owner"),"SOLO_OWNER_KEY_STOP")
    body=C.decode(C.G.canonical(dict(schema_version=2,mode="SOLO_OWNER",kind=kind,consent=confirmation,
        context=authority.context,authority_sha=C.G.sha(profile),observed_at=now,expires_at=now+seconds,data=data)))
    packet=dict(signer=kid,body=body,signature=key.sign(DOMAIN+C.G.canonical(body)).hex())
    authority.verify(packet,kind,"owner",now)
    return packet


def pair(authority,owner,witness,kind,now,*,age=900):
    if solo(authority.profile):
        C.need(witness is None,"SOLO_FAKE_WITNESS_REJECTED")
        return authority.trust.verify(owner,kind,"owner",now)
    left=authority.trust.verify(owner,kind,"owner",now,age=age)
    C.need(authority.trust.verify(witness,kind,"independent",now,age=age)==left,"PAIR_APPROVAL_STOP")
    return left


def destination(authority,packet,kind,now,*,age=900):
    if solo(authority.profile):
        C.need(kind=="r1154-permanent-no-replay","SOLO_DESTINATION_SIGNATURE_REJECTED")
        # Permission to quarantine, not a declaration that firewall rules have
        # already been installed. v2 live release must recheck installed rules.
        return authority.trust.verify(packet,kind,"owner",now)
    return authority.trust.verify(packet,kind,"destination",now,age=age)


def capacity(packet,now):
    C.shape(packet,"schema_version mode role observed_at data")
    C.need(type(packet["schema_version"]) is int and packet["schema_version"]==2 and
        packet["mode"]=="MACHINE_OBSERVATION" and packet["role"]=="k137","SOLO_MACHINE_OBSERVATION_REQUIRED")
    # Historical planning observation is NOT a current GO. Mandatory fresh
    # LiveChecks run separately at each execution boundary. Human review must
    # not require completing every local consent prompt within 30 seconds.
    C.fresh(packet["observed_at"],now,age=MAX_SESSION)
    return packet["data"]


def require_live_checks(live,operation,scope):
    """Fixed executable boundary, never a flag supplied by a plan document."""
    C.need(isinstance(live,LiveChecks),"SOLO_LIVE_OS_CHECK_REQUIRED")
    return live.check(operation,scope)


class LiveChecks:
    def __init__(self,authority,source,destination,*,clock):
        self.authority=authority;self.source=source;self.destination=destination;self.clock=clock

    def check(self,operation,scope):
        C.need(operation in ("hold","export","restore","activate","rollback"),"SOLO_ROLE_OR_OPERATION_REJECTED")
        # Injected only by a fixed authenticated carrier, not deserialized from
        # JSON. Test drivers exercise the same fail-closed contract.
        now=int(self.clock())
        source=machine_verify(self.authority,self.source(),"oci",scope,now)
        target=machine_verify(self.authority,self.destination(),"k137",scope,now)
        C.need(source.get("scope_sha")==C.G.sha(scope) and source.get("source_vm_running") is True and
            source.get("ssh_retained") is True,"SOLO_SOURCE_BINDING_STOP")
        if operation=="hold":C.need(source.get("scope_preflight_verified") is True,"SOLO_G4_G5_NOT_PROVEN")
        elif operation=="rollback":C.need(source.get("g5_quarantine_complete") is True and target.get("publisher_active") is False,"SOLO_ROLLBACK_NOT_DISARMED")
        else:C.need(source.get("g4_complete") is True and source.get("g5_quarantine_complete") is True,"SOLO_G4_G5_NOT_PROVEN")
        C.need(target.get("old_post_deny_verified") is True and target.get("single_writer_verified") is True,"SOLO_TARGET_NO_REPLAY_NOT_PROVEN")
        if operation in ("hold","export","restore","rollback"):
            C.need(target.get("publisher_active") is False,"SOLO_RESTORE_REQUIRES_DISARMED_TARGET")
        C.need(target.get("free_bytes",0)>20*C.R.GIB+target.get("remaining_bytes",0)+C.R.GIB,"SOLO_PROTECTED_RESERVE_STOP")
        if operation=="hold":
            C.need(target["free_bytes"]>=20*C.R.GIB+2*target["remaining_bytes"]+2*C.R.GIB,"SOLO_PROTECTED_RESERVE_STOP")
        C.need(target.get("memory_headroom_bytes",0)>=512*1024**2 and target.get("cpu_psi_milli",100000)<=5000 and
            target.get("io_psi_milli",100000)<=10000,"SOLO_TARGET_RESOURCES_STOP")
        if operation=="activate":C.need(target.get("tradebot_budget_verified") is True and target.get("same_did_restored") is True,"SOLO_ACTIVATION_NOT_PROVEN")
        return dict(source=source,target=target)


def machine_verify(authority,packet,role,scope,now):
    C.shape(packet,"body signature");body=packet["body"]
    C.shape(body,"schema_version mode role authority_sha scope_sha machine boot observed_at expires_at challenge seq data")
    profile=authority.profile;public=profile["machine_keys"][role]
    C.need(public is not None,"SOLO_MACHINE_ATTESTER_NOT_ENROLLED")
    expected=authority.trust.context["host" if role=="oci" else "destination"]
    C.need(type(body["schema_version"]) is int and body["schema_version"]==2 and body["mode"]=="MACHINE_ONLY_NO_HUMAN_INDEPENDENCE" and
        body["role"]==role and body["authority_sha"]==authority.pin and body["scope_sha"]==C.G.sha(scope) and body["machine"]==expected and
        body["boot"]==profile["boots"][role],"SOLO_MACHINE_BINDING_STOP")
    C.digest(body["challenge"]);C.integer(body["seq"],1);C.fresh(body["observed_at"],now,age=MAX_OBSERVATION_AGE)
    C.need(now<body["expires_at"]<=body["observed_at"]+MAX_OBSERVATION_AGE,"SOLO_MACHINE_LEASE_STOP")
    C.need(type(packet["signature"]) is str and re.fullmatch(r"[a-f0-9]{128}",packet["signature"]),"SOLO_MACHINE_SIGNATURE_STOP")
    try:C.G.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(bytes.fromhex(packet["signature"]),MACHINE_DOMAIN+C.G.canonical(body))
    except (ValueError,C.G.InvalidSignature):raise C.Stop("SOLO_MACHINE_SIGNATURE_STOP") from None
    C.shape(body["data"],"scope_sha source_vm_running ssh_retained scope_preflight_verified g4_complete g5_quarantine_complete old_post_deny_verified single_writer_verified publisher_active free_bytes remaining_bytes memory_headroom_bytes cpu_psi_milli io_psi_milli tradebot_budget_verified same_did_restored upstream_finality")
    for name,value in body["data"].items():
        if name in ("scope_sha","upstream_finality"):continue
        if name.endswith("_bytes") or name.endswith("_milli"):C.integer(value,0)
        else:C.need(type(value) is bool,"SOLO_MACHINE_SCHEMA_STOP")
    C.need(body["data"]["upstream_finality"]=="UNKNOWN_REMAINS_UNKNOWN","SOLO_FALSE_FINALITY_REJECTED")
    return body["data"]


def check_reader(reader,packet,now,scope):
    C.shape(packet,"mode owner evidence inventory_evidence")
    C.need(packet["mode"]=="SOLO_OWNER_MACHINE_RECHECK","SOLO_MACHINE_OBSERVATION_REQUIRED")
    C.shape(packet["evidence"],"oci k137")
    expected=dict(anchor_sha=C.G.sha(reader.anchor),generation_sha=reader.anchor["generation_sha"])
    C.need(reader.anchor["source_boot"]==reader.authority.profile["boots"]["oci"] and
        reader.anchor["target_boot"]==reader.authority.profile["boots"]["k137"],"SOLO_HOST_BOOT_STOP")
    if reader.boot is not None:
        C.need(reader.boot()==reader.anchor["source_boot" if reader.anchor["purpose"]=="archive" else "target_boot"],"SOLO_HOST_BOOT_STOP")
    C.need(reader.authority.trust.verify(packet["owner"],"r1156-autonomy","owner",now)==expected,"SOLO_SESSION_BINDING_STOP")
    operation="activate" if reader.anchor["purpose"]=="runtime" else "export"
    LiveChecks(reader.authority,lambda:packet["evidence"]["oci"],lambda:packet["evidence"]["k137"],clock=lambda:now).check(operation,scope)
    inventory=inventory_verify(reader.authority,packet["inventory_evidence"],scope,now)
    for field,source in (("manifest_sha","manifest_sha"),("epoch","epoch"),("ledger_sha","ledger_sha"),("hold_journal_sha","hold_journal_sha"),("nonce_file_sha","nonce_file_sha"),("nonce_state_sha","nonce_state_sha")):
        C.need(reader.anchor[field]==inventory[source],"SOLO_INVENTORY_BINDING_STOP")
    bodies=[packet["evidence"][r]["body"] for r in ("oci","k137")]
    seq=[b["seq"] for b in bodies];issued=max(b["observed_at"] for b in bodies);expires=min(b["expires_at"] for b in bodies)
    token=C.G.sha(packet);last=reader.journal.latest;owner_sha=C.G.sha(packet["owner"])
    if last is not None:
        fresh_owner=last.get("owner_sha")!=owner_sha and packet["owner"]["body"]["observed_at"]>last["expires"]
        C.need(last["anchor_sha"]==C.G.sha(reader.anchor) and all(x>=y for x,y in zip(seq,last["seq"])) and
            (token==last["packet_sha"] or any(x>y for x,y in zip(seq,last["seq"])) and
            (issued<=last["expires"] or fresh_owner)),"SOLO_LATE_OR_REPLAYED_MACHINE_CHECK")
    if last is None or token!=last["packet_sha"]:
        reader.journal.save(dict(anchor_sha=C.G.sha(reader.anchor),packet_sha=token,owner_sha=owner_sha,seq=seq,issued=issued,expires=expires))
    return dict(anchor_sha=C.G.sha(reader.anchor),seq=seq)


def inventory_verify(authority,packet,scope,now):
    C.shape(packet,"body signature");body=packet["body"]
    C.shape(body,"mode authority_sha scope_sha boot observed_at expires_at data")
    C.need(body["mode"]=="MACHINE_ONLY_FROZEN_INVENTORY" and body["authority_sha"]==authority.pin and
        body["scope_sha"]==C.G.sha(scope) and body["boot"]==authority.profile["boots"]["oci"],"SOLO_INVENTORY_BINDING_STOP")
    C.fresh(body["observed_at"],now,age=MAX_SESSION)
    C.need(now<body["expires_at"]<=body["observed_at"]+MAX_SESSION,"SOLO_SESSION_EXPIRED")
    public=authority.profile["machine_keys"]["oci"]
    C.need(public is not None and re.fullmatch(r"[a-f0-9]{128}",packet["signature"]),"SOLO_MACHINE_SIGNATURE_STOP")
    try:C.G.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(bytes.fromhex(packet["signature"]),MACHINE_DOMAIN+C.G.canonical(body))
    except (ValueError,C.G.InvalidSignature):raise C.Stop("SOLO_MACHINE_SIGNATURE_STOP") from None
    data=body["data"]
    C.shape(data,"inventory_sha ledger_sha epoch manifest_sha nonce_file_sha nonce_state_sha source_bytes hold_journal_sha")
    for field,value in data.items():C.integer(value,1) if field=="source_bytes" else C.digest(value)
    return data


def recipient_verify(authority,packet,now):
    C.shape(packet,"body signature");body=packet["body"]
    C.shape(body,"mode authority_sha machine boot did_sha recipient_public observed_at expires_at")
    C.need(body["mode"]=="MACHINE_ONLY_RECIPIENT" and body["authority_sha"]==authority.pin and
        body["machine"]==authority.trust.context["destination"] and body["boot"]==authority.profile["boots"]["k137"] and
        body["did_sha"]==authority.trust.context["did"],"SOLO_RECIPIENT_NOT_PROVEN")
    C.digest(body["recipient_public"]);C.fresh(body["observed_at"],now,age=MAX_SESSION)
    C.need(now<body["expires_at"]<=body["observed_at"]+MAX_SESSION,"SOLO_RECIPIENT_NOT_PROVEN")
    public=authority.profile["machine_keys"]["k137"]
    C.need(public is not None and re.fullmatch(r"[a-f0-9]{128}",packet["signature"]),"SOLO_RECIPIENT_NOT_PROVEN")
    try:C.G.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(bytes.fromhex(packet["signature"]),MACHINE_DOMAIN+C.G.canonical(body))
    except (ValueError,C.G.InvalidSignature):raise C.Stop("SOLO_RECIPIENT_NOT_PROVEN") from None
    return body["recipient_public"]
