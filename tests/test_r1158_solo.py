"""Dummy owner/DID/machine keys only. No hosts, services, credentials or POST."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
import test_r1155_warm as old

ROOT=Path(__file__).resolve().parents[1]
H=old.S.H;C=H.C;V=H.solo_module();case=old.case;h=old.old.h
O=C.legacy("r1158_owner.py");B=C.legacy("r1158_machine.py")


@pytest.fixture
def solo(case):
    machines={role:Ed25519PrivateKey.generate() for role in ("oci","k137")}
    profile=dict(schema_version=2,mode="SOLO_OWNER",context=case.f.context,source_did=case.f.did,
        keys=[dict(public_hex=case.f.keys["owner"].public_key().public_bytes_raw().hex(),role="owner")],
        source_key_ids=case.f.enrolled["source_key_ids"],risk_ack=V.ACK,
        machine_keys={role:key.public_key().public_bytes_raw().hex() for role,key in machines.items()},
        boots={role:h("boot "+role) for role in machines})
    a=H.Authority(profile,C.G.sha(profile))
    def issue(kind,data,at=None):return V.issue(profile,case.f.keys["owner"],kind,data,now=case.f.now if at is None else at,seconds=1800,confirmation=V.LEVELS[kind])
    scope=copy.deepcopy(case.scope);scope["version"]=2;scope["witness"]=None
    scope["surfaces"]={k:"MACHINE_RECHECK_REQUIRED_NO_HUMAN_INDEPENDENCE" for k in H.SURFACES}
    scope["destination"]=dict(schema_version=2,mode="MACHINE_OBSERVATION",role="k137",observed_at=case.f.now,data=case.scope["destination"]["body"]["data"])
    scope["quarantine"].update(inventory_sha=None,ledger_sha=None)
    binding=dict(scope_sha=C.G.sha({k:v for k,v in scope.items() if k not in ("owner","witness")}),downtime=True,keep_vm_running=True,keep_ssh=True,
        cost_cap="ZERO_NEW_BILLING",permanent_post_deny=True)
    scope["owner"]=issue("r1154-hold",binding)
    return SimpleNamespace(a=a,profile=profile,machines=machines,issue=issue,scope=scope)


def observation(solo,role,now,*,seq=1,scope=None):
    scope=scope or solo.scope
    data=dict(scope_sha=C.G.sha(scope),source_vm_running=role=="oci",ssh_retained=role=="oci",scope_preflight_verified=role=="oci",
        g4_complete=role=="oci",g5_quarantine_complete=role=="oci",old_post_deny_verified=role=="k137",single_writer_verified=role=="k137",
        publisher_active=False,
        free_bytes=64*1024**3,remaining_bytes=1024**3,memory_headroom_bytes=1024**3,cpu_psi_milli=0,io_psi_milli=0,
        tradebot_budget_verified=True,same_did_restored=True,upstream_finality="UNKNOWN_REMAINS_UNKNOWN")
    body=dict(schema_version=2,mode="MACHINE_ONLY_NO_HUMAN_INDEPENDENCE",role=role,authority_sha=solo.a.pin,
        scope_sha=C.G.sha(scope),machine=solo.profile["context"]["host" if role=="oci" else "destination"],boot=solo.profile["boots"][role],
        observed_at=now,expires_at=now+30,challenge=h("challenge "+role),seq=seq,data=data)
    return dict(body=body,signature=solo.machines[role].sign(V.MACHINE_DOMAIN+C.G.canonical(body)).hex())


def sign_observation(solo,role,packet):
    packet["signature"]=solo.machines[role].sign(V.MACHINE_DOMAIN+C.G.canonical(packet["body"])).hex()


def test_one_actual_owner_no_fake_independence_and_legacy_strict_remains(case,solo):
    assert H.validate_scope(solo.a,solo.scope,now=case.f.now)
    assert H.solo(solo.a) and solo.scope["witness"] is None
    assert not any(row[1]=="independent" for row in solo.a.trust.keys.values())
    # Fresh existing v1 style still requires its genuine independent key.
    assert old.old.M.validate_scope(case.a,case.scope,now=case.f.now)
    wrong=copy.deepcopy(case.scope);wrong["witness"]=None
    with pytest.raises(Exception):old.old.M.validate_scope(case.a,wrong,now=case.f.now)


@pytest.mark.parametrize("fault",["extra_role","reuse_owner_as_machine","original_did_key","missing_opt_in","fake_witness","wrong_level","stretched","expired","old_context","mutated_binding"])
def test_consent_fail_closed(case,solo,fault):
    if fault in ("extra_role","reuse_owner_as_machine","original_did_key","missing_opt_in"):
        p=copy.deepcopy(solo.profile)
        if fault=="extra_role":p["keys"].append(dict(public_hex=case.f.keys["independent"].public_key().public_bytes_raw().hex(),role="independent"))
        if fault=="reuse_owner_as_machine":p["machine_keys"]["oci"]=p["keys"][0]["public_hex"]
        if fault=="original_did_key":p["keys"][0]["public_hex"]=case.f.own.public_key().public_bytes_raw().hex()
        if fault=="missing_opt_in":p["risk_ack"]="pretend independent"
        with pytest.raises(ValueError):H.Authority(p,C.G.sha(p))
        return
    packet=copy.deepcopy(solo.scope["owner"])
    if fault=="fake_witness":
        with pytest.raises(ValueError,match="FAKE_WITNESS"):H.approval_pair(solo.a,packet,packet,"r1154-hold",case.f.now)
        return
    if fault=="wrong_level":packet["body"]["consent"]="NEW_ONLY_ACTIVATION"
    if fault=="stretched":packet["body"]["expires_at"]=case.f.now+3601
    if fault=="old_context":packet["body"]["context"]["generation"]+=1
    if fault=="mutated_binding":packet["body"]["data"]["keep_ssh"]=False
    with pytest.raises(ValueError):solo.a.trust.verify(packet,"r1154-hold","owner",case.f.now+1800 if fault=="expired" else case.f.now)


@pytest.mark.parametrize("role",["independent","destination","identity","upstream"])
def test_owner_never_verifies_as_another_role(case,solo,role):
    with pytest.raises(ValueError,match="ROLE_OR_OPERATION"):solo.a.trust.verify(solo.scope["owner"],"r1154-hold",role,case.f.now)


@pytest.mark.parametrize("fault",["cross_boot","expired","owner_forgery","different_machine","missing_g4","missing_g5","disk_floor","memory","unsigned","extra_field","false_ack","missing_source"])
def test_authenticated_machine_evidence_fail_closed(case,solo,fault):
    packets={r:observation(solo,r,case.f.now) for r in solo.machines}
    source=packets["oci"];target=packets["k137"]
    if fault=="cross_boot":source["body"]["boot"]=h("reboot")
    if fault=="expired":source["body"]["observed_at"]-=31;source["body"]["expires_at"]-=31
    if fault=="different_machine":target["body"]["machine"]=h("other host")
    if fault=="missing_g4":source["body"]["data"]["g4_complete"]=False
    if fault=="missing_g5":source["body"]["data"]["g5_quarantine_complete"]=False
    if fault=="disk_floor":target["body"]["data"].update(free_bytes=20*1024**3,remaining_bytes=0)
    if fault=="memory":target["body"]["data"]["memory_headroom_bytes"]=100
    if fault=="extra_field":target["body"]["data"]["execute"]="arbitrary shell"
    if fault=="false_ack":source["body"]["data"]["upstream_finality"]="ALL_ACKNOWLEDGED"
    for role,packet in packets.items():sign_observation(solo,role,packet)
    if fault=="owner_forgery":source["signature"]=case.f.keys["owner"].sign(V.MACHINE_DOMAIN+C.G.canonical(source["body"])).hex()
    if fault=="unsigned":source.pop("signature")
    if fault=="missing_source":source={}
    live=V.LiveChecks(solo.a,lambda:source,lambda:target,clock=lambda:case.f.now)
    with pytest.raises((ValueError,KeyError)):live.check("export",solo.scope)


def test_cached_scope_or_consent_alone_cannot_authorize_hold(case,solo):
    class Never:
        def identity(self,*_):pytest.fail("must not reach driver with cached consent only")
    with pytest.raises(ValueError,match="LIVE_OS_CHECK_REQUIRED"):H.Controller(solo.a,Never()).hold(solo.scope,now=case.f.now)


def test_machine_checks_are_not_automatic_human_reapproval(case,solo):
    before=C.G.canonical(solo.scope["owner"])
    live=V.LiveChecks(solo.a,lambda:observation(solo,"oci",case.f.now),lambda:observation(solo,"k137",case.f.now),clock=lambda:case.f.now)
    live.check("export",solo.scope);assert before==C.G.canonical(solo.scope["owner"])
    # No method has access to an owner private key; all rechecks use machines.
    assert set(live.__dict__)=={"authority","source","destination","clock"}


def test_solo_custody_uses_existing_exact_did_crypto_and_wipes_dummy(case,solo):
    _,binding,_,_=old.old.custody(case)
    body=dict(mode="MACHINE_ONLY_RECIPIENT",authority_sha=solo.a.pin,machine=solo.a.trust.context["destination"],boot=solo.profile["boots"]["k137"],
        did_sha=solo.a.trust.context["did"],recipient_public=binding["recipient_public"],observed_at=case.f.now,expires_at=case.f.now+1800)
    binding["recipient_evidence"]=dict(body=body,signature=solo.machines["k137"].sign(V.MACHINE_DOMAIN+C.G.canonical(body)).hex())
    owner=solo.issue("r1154-custody",binding)
    raw=bytearray(case.f.own.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
    envelope=old.S.K.encrypt(solo.a,binding,owner,None,raw,now=case.f.now)
    assert not any(raw) and envelope["binding"]==binding and "ciphertext" in envelope


def test_new_fixed_reply_keeps_no_retry_no_tclk_no_close1_and_no_null_receipt(case,solo):
    config=old.config(case);config["enrollment"]=solo.profile;config["enrollment_sha"]=solo.a.pin
    config["owner"]=solo.issue("r1155-activate",config["lease"]);config["witness"]=None
    req=old.request(case,config)
    data=dict(epoch=config["baseline"]["epoch"],activation_sha=C.G.sha(config["lease"]),request_sha=C.G.sha({k:v for k,v in req.items() if k not in ("owner","witness")}))
    req["owner"]=solo.issue("r1155-new-request",data);req["witness"]=None
    @contextlib.contextmanager
    def seed():
        buf=bytearray(case.f.own.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
        try:yield buf
        finally:buf[:]=b"\0"*len(buf)
    gate=lambda *_,**__:solo.a
    broker=old.S.Broker(config,seed,old.Journal(),gate=gate,clock=lambda:case.f.now)
    body=broker.sign(req,config["publisher_uid"])
    with pytest.raises(ValueError):broker.sign(req,config["publisher_uid"])
    calls=[];journal=old.Journal()
    def post(*args,**kwargs):
        calls.append(1);return SimpleNamespace(raise_for_status=lambda:None,json=lambda:dict(posted=None))
    with pytest.raises(ValueError):old.P.publish(config,req,journal,sign=lambda _:body,post=post,gate=gate,clock=lambda:case.f.now)
    with pytest.raises(ValueError):old.P.publish(config,req,journal,sign=lambda _:pytest.fail("no repeat"),post=post,gate=gate,clock=lambda:case.f.now)
    assert len(calls)==1 and journal.latest["phase"]=="UNKNOWN_NO_RETRY"
    for route in old.S.ROUTES[1:]:
        other=copy.deepcopy(req);other["route"]=route
        with pytest.raises(ValueError,match="NOT_ADMITTED"):old.S.render(other,case.f.did)


def test_existing_two_gib_scratch_and_no_vm_stop_surface():
    assert old.W.MAX_STAGE==2*1024**3
    source=(ROOT/"packaging/migration/r1158_machine.py").read_text(encoding="utf-8")
    for bad in ("poweroff","shutdown","/sbin/reboot","httpx.post","SIGN_SEED","get_secret_bundle"):
        assert bad not in source
    assert 'upstream_finality="UNKNOWN_REMAINS_UNKNOWN"' in source


def test_assemble_scope_is_one_owner_and_rejects_misbound_grant(case,solo):
    scope=copy.deepcopy(solo.scope);scope["owner"]=None
    artifact=dict(scope=scope,consent=dict(enrollment=solo.profile,enrollment_sha=solo.a.pin,
        kind="r1154-hold",binding=solo.scope["owner"]["body"]["data"],seconds=1800))
    result=O.assemble(dict(artifact=artifact,owner=solo.scope["owner"]),case.f.now)
    assert result==solo.scope and artifact["scope"]["owner"] is None
    artifact["scope"]["users"]["technocore"]+=1
    with pytest.raises(ValueError):O.assemble(dict(artifact=artifact,owner=solo.scope["owner"]),case.f.now)


def test_typed_consent_rejects_truthy_strings_and_boot_substitution(case,solo):
    wrong=copy.deepcopy(solo.scope["owner"]["body"]["data"]);wrong["keep_ssh"]="true"
    with pytest.raises(ValueError):O.validate_binding("r1154-hold",wrong,solo.profile)
    with pytest.raises(ValueError):O.validate_binding("r1158-machine-init",dict(role="oci",machine=solo.a.trust.context["host"],boot=h("fake")),solo.profile)
    cost=dict(destination=H.B.K137,upper=1024,units_sha=C.G.sha(solo.scope["units"]),existing_host_only=True,zero_new_billing=True)
    assert O.validate_binding("r1158-capacity",cost,solo.profile)==cost
    cost["zero_new_billing"]="verified"
    with pytest.raises(ValueError):O.validate_binding("r1158-capacity",cost,solo.profile)


def frozen(solo,now):
    data=dict(inventory_sha=h("inventory"),ledger_sha=h("ledger"),epoch=h("epoch"),manifest_sha=h("manifest"),
        nonce_file_sha=h("nonce bytes"),nonce_state_sha=h("nonce state"),source_bytes=1000,hold_journal_sha=h("hold"))
    body=dict(mode="MACHINE_ONLY_FROZEN_INVENTORY",authority_sha=solo.a.pin,scope_sha=C.G.sha(solo.scope),boot=solo.profile["boots"]["oci"],
        observed_at=now,expires_at=now+3600,data=data)
    return dict(body=body,signature=solo.machines["oci"].sign(V.MACHINE_DOMAIN+C.G.canonical(body)).hex())


def test_machine_monitor_over_900_seconds_no_human_resign_then_expiry(case,solo):
    inventory=frozen(solo,case.f.now);data=inventory["body"]["data"]
    anchor=dict(purpose="runtime",source_boot=solo.profile["boots"]["oci"],target_boot=solo.profile["boots"]["k137"],
        generation_sha=h("generation"),**{k:data[k] for k in ("manifest_sha","epoch","ledger_sha","hold_journal_sha","nonce_file_sha","nonce_state_sha")})
    owner=solo.issue("r1156-autonomy",dict(anchor_sha=C.G.sha(anchor),generation_sha=anchor["generation_sha"]))
    journal=old.Journal();reader=SimpleNamespace(authority=solo.a,anchor=anchor,journal=journal,boot=None)
    current=None
    for second in range(0,1001,10):
        now=case.f.now+second
        current=dict(mode="SOLO_OWNER_MACHINE_RECHECK",owner=owner,evidence={r:observation(solo,r,now,seq=second+1) for r in solo.machines},inventory_evidence=inventory)
        V.check_reader(reader,current,now,solo.scope)
    assert journal.latest["seq"]==[1001,1001] and current["owner"]==owner
    with pytest.raises(ValueError):V.check_reader(reader,current,case.f.now+1031,solo.scope)
    late=dict(current,evidence={r:observation(solo,r,case.f.now+1040,seq=1041) for r in solo.machines})
    with pytest.raises(ValueError,match="LATE_OR_REPLAYED"):V.check_reader(reader,late,case.f.now+1040,solo.scope)
    expired=dict(current,evidence={r:observation(solo,r,case.f.now+1800,seq=1801) for r in solo.machines})
    with pytest.raises(ValueError):V.check_reader(reader,expired,case.f.now+1800,solo.scope)
    renewed=dict(late,owner=solo.issue("r1156-autonomy",dict(anchor_sha=C.G.sha(anchor),generation_sha=anchor["generation_sha"]),at=case.f.now+1040))
    V.check_reader(reader,renewed,case.f.now+1040,solo.scope)


def test_active_target_is_not_a_disarmed_transfer_destination(case,solo):
    source=observation(solo,"oci",case.f.now);target=observation(solo,"k137",case.f.now)
    target["body"]["data"]["publisher_active"]=True;sign_observation(solo,"k137",target)
    live=V.LiveChecks(solo.a,lambda:source,lambda:target,clock=lambda:case.f.now)
    for operation in ("hold","export","restore","rollback"):
        with pytest.raises(ValueError):live.check(operation,solo.scope)
    live.check("activate",solo.scope)


@pytest.mark.parametrize("operation",["arbitrary-command","hold;id","delete","reboot"])
def test_fixed_rpc_rejects_unknown_operations_without_child(case,solo,operation):
    with pytest.raises(ValueError,match="OPERATION_REJECTED"):O.rpc({},"oci",operation,{},child=lambda *_:pytest.fail("no process"))


def test_source_probe_uses_actual_driver_and_does_not_claim_prehold_fencing(case,solo,tmp_path,monkeypatch):
    calls=[]
    class Driver:
        def identity(self,scope):calls.append("identity");assert scope==solo.scope
        def protected(self):calls.append("protected")
        def launchers(self):return solo.scope["launcher_sha"]
        def discovered(self):calls.append("discovered");return set(solo.scope["units"])
        def unit(self,name):calls.append(name);return solo.scope["units"][name]
    monkeypatch.setattr(B,"identity",lambda a,r:(solo.a.trust.context["host"],solo.profile["boots"][r]))
    monkeypatch.setattr(B.H,"Linux",Driver);monkeypatch.setattr(B.H,"WORK",tmp_path/"missing-hold")
    store=tmp_path/"technical";store.mkdir();monkeypatch.setattr(B,"STORE",store)
    monkeypatch.setattr(B,"time",SimpleNamespace(time=lambda:case.f.now))
    monkeypatch.setitem(sys.modules,"fcntl",SimpleNamespace(flock=lambda *_:None,LOCK_EX=1))
    packet=B.probe(solo.a,"oci",solo.scope,h("probe challenge"),key=solo.machines["oci"])
    evidence=V.machine_verify(solo.a,packet,"oci",solo.scope,case.f.now)
    assert evidence["scope_preflight_verified"] and not evidence["g4_complete"] and not evidence["g5_quarantine_complete"]
    assert {"identity","protected","discovered"}<=set(calls)
    assert packet["body"]["seq"]==1 and str(tmp_path) not in C.G.canonical(packet).decode()
    again=B.probe(solo.a,"oci",solo.scope,h("second probe"),key=solo.machines["oci"])
    assert again["body"]["seq"]==2


def test_solo_disabled_stage_marker_does_not_install_runtime(case,solo,monkeypatch):
    U=C.legacy("r1156_setup.py");calls=[]
    monkeypatch.setattr(U.N,"install_runtime",lambda *args:calls.append(args))
    U.initial_runtime(solo.a,{},dict(mode="SOLO_OWNER_AWAIT_FRESH_MACHINE_CHECK"))
    assert not calls
    for unsafe in ({"admitted":True},{"mode":"GO"},{}):
        with pytest.raises(ValueError):U.initial_runtime(solo.a,{},unsafe)
    U.initial_runtime(case.a,{"legacy":True},{"genuine":"legacy pair"});assert len(calls)==1


def test_watch_refresh_transports_machine_proof_without_owner_signing(case,solo):
    monitor=solo.issue("r1158-monitor-session",dict(scope_sha=C.G.sha(solo.scope),source_boot=solo.profile["boots"]["oci"],target_boot=solo.profile["boots"]["k137"]))
    calls=[]
    def request(control,role,operation,fields):
        calls.append((role,operation))
        if operation=="probe":
            packet=observation(solo,role,case.f.now);packet["body"]["challenge"]=fields["challenge"];sign_observation(solo,role,packet);return packet
        if operation=="runtime-check":assert fields["source"]["body"]["role"]=="oci"
        return dict(code="FIXED_SYNTHETIC_RESULT")
    control=dict(enrollment=solo.profile,enrollment_sha=solo.a.pin)
    watch=O.Watch(control,solo.scope,monitor,clock=lambda:case.f.now,request=request,runtime=dict(owner=monitor,inventory_evidence={}))
    before=C.G.canonical(monitor);watch.refresh();watch.check(case.f.now)
    assert calls==[("oci","probe"),("k137","probe"),("oci","publish-target-evidence"),("k137","runtime-check")]
    assert C.G.canonical(monitor)==before and watch.decorate(dict(operation="restore"))["evidence"]["oci"]["signature"]


def test_frozen_inventory_tamper_rejected_and_missing_proof_not_go(case,solo):
    packet=frozen(solo,case.f.now)
    assert V.inventory_verify(solo.a,packet,solo.scope,case.f.now)["nonce_file_sha"]==h("nonce bytes")
    packet["body"]["data"]["ledger_sha"]=h("forged ledger")
    with pytest.raises(ValueError):V.inventory_verify(solo.a,packet,solo.scope,case.f.now)
    with pytest.raises(ValueError):V.inventory_verify(solo.a,{},solo.scope,case.f.now)


def test_real_renewal_reader_dispatches_v2_and_checks_actual_boot(case,solo,monkeypatch):
    N=C.legacy("r1156_renewal.py");inventory=frozen(solo,case.f.now);d=inventory["body"]["data"]
    anchor=dict(purpose="runtime",authority_sha=solo.a.pin,source_machine=solo.a.trust.context["host"],target_machine=H.B.K137,
        source_boot=solo.profile["boots"]["oci"],target_boot=solo.profile["boots"]["k137"],source_head=C.G.SOURCE_HEAD,
        scope_sha=C.G.sha(solo.scope),did_sha=solo.a.trust.context["did"],capture_sha=h("preserve"),runtime_sha=h("runtime"),generation_sha=h("generation"),
        **{k:d[k] for k in ("hold_journal_sha","manifest_sha","epoch","ledger_sha","nonce_file_sha","nonce_state_sha")})
    grant=solo.issue("r1156-autonomy",dict(anchor_sha=C.G.sha(anchor),generation_sha=anchor["generation_sha"]))
    packet=dict(mode="SOLO_OWNER_MACHINE_RECHECK",owner=grant,evidence={r:observation(solo,r,case.f.now) for r in solo.machines},inventory_evidence=inventory)
    monkeypatch.setattr(N.S,"secured",lambda path,**_:solo.scope)
    reader=N.Reader(solo.a,anchor,lambda:packet,old.Journal(),boot=lambda:solo.profile["boots"]["k137"])
    assert reader.check(case.f.now)["seq"]==[1,1]
    reader.boot=lambda:h("rebooted")
    with pytest.raises(ValueError,match="HOST_BOOT"):reader.check(case.f.now)


def test_fixed_rpc_only_safe_stop_codes_and_executable_bootstrap(case,solo,monkeypatch):
    import ast,shlex
    monkeypatch.setattr(O.M,"endpoints_ok",lambda *_:None)
    monkeypatch.setattr(O,"roots",lambda *_:(["fixed-oci-ssh"],["fixed-k137-ssh"]))
    control=dict(enrollment=solo.profile,enrollment_sha=solo.a.pin,endpoints={})
    @contextlib.contextmanager
    def child(argv,**_):
        command=shlex.split(argv[-1]);assert command[:3]==["sudo","-n","/opt/technocore-safe-agent/.venv/bin/python"]
        ast.parse(command[-1]);assert "m.V.SAFE_CODES" in command[-1]
        class Sink(io.BytesIO):
            def close(self):pass
        yield SimpleNamespace(stdin=Sink(),stdout=io.BytesIO(C.G.canonical(dict(code="SOLO_TARGET_UID_CONFLICT",cutover="NO_GO"))),wait=lambda **_:0)
    with pytest.raises(ValueError,match="TARGET_UID_CONFLICT"):
        O.rpc(control,"oci","host-info",{},sources={"packaging/migration/public.py":"# synthetic"},child=child)


def test_owner_cannot_substitute_an_arbitrary_encryption_recipient(case,solo):
    _,binding,_,_=old.old.custody(case)
    binding["recipient_evidence"]={}
    with pytest.raises(ValueError):old.S.K.approved(solo.a,binding,solo.issue("r1154-custody",binding),None,now=case.f.now)


def test_solo_plan_binds_actual_frozen_evidence_and_reuses_existing_crypto(case,solo,tmp_path,monkeypatch):
    _,binding,_,_=old.old.custody(case)
    body=dict(mode="MACHINE_ONLY_RECIPIENT",authority_sha=solo.a.pin,machine=solo.a.trust.context["destination"],boot=solo.profile["boots"]["k137"],
        did_sha=solo.a.trust.context["did"],recipient_public=binding["recipient_public"],observed_at=case.f.now,expires_at=case.f.now+1800)
    binding["recipient_evidence"]=dict(body=body,signature=solo.machines["k137"].sign(V.MACHINE_DOMAIN+C.G.canonical(body)).hex())
    owner=solo.issue("r1154-custody",binding);raw=bytearray(case.f.own.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
    custody=dict(binding=binding,owner=owner,witness=None,envelope=old.S.K.encrypt(solo.a,binding,owner,None,raw,now=case.f.now))
    session=dict(enrollment=solo.profile,enrollment_sha=solo.a.pin,scope=solo.scope,inventory_evidence=frozen(solo,case.f.now),custody=custody,
        policy_sha=hashlib.sha256(H.boot_unit(solo.scope["users"].values(),solo.scope["units"])).hexdigest(),settings=dict(quota_bytes=solo.scope["destination"]["data"]["source_upper_bound_bytes"],offhost_parent=str(tmp_path)))
    preserve=O.build("preserve",session,case.f.now);policy=O.build("policy",session,case.f.now)
    session.update(preserve_owner=solo.issue(preserve["kind"],preserve["binding"]),destination_policy=solo.issue(policy["kind"],policy["binding"]))
    draft=O.build("plan",session,case.f.now)
    plan=O.assemble(dict(artifact=draft,owner=solo.issue("r1155-transfer",draft["consent"]["binding"])),case.f.now)
    assert O.T.admit(plan,case.f.now).pin==solo.a.pin and plan["witness"] is None and plan["preserve_witness"] is None
    assert not any(raw) and plan["custody"]["envelope"]["ciphertext"]
    # A valid v2 consent cannot accidentally enter the old unmonitored owner.
    monkeypatch.setattr(O.T,"time",SimpleNamespace(time=lambda:case.f.now))
    with pytest.raises(ValueError,match="VERSIONED_ENTRYPOINT"):O.T.owner(dict(plan=plan),b"x"*48)
    corrupt=copy.deepcopy(plan);corrupt["inventory_evidence"]["body"]["data"]["nonce_state_sha"]=h("tampered")
    with pytest.raises(ValueError):O.T.admit(corrupt,case.f.now)
    wrong=copy.deepcopy(plan);wrong["quota_bytes"]+=1
    with pytest.raises(ValueError):O.T.admit(wrong,case.f.now)


def test_consent_review_can_outlast_30s_but_not_replace_current_os_evidence(case,solo):
    assert H.validate_scope(solo.a,solo.scope,now=case.f.now+120)
    live=V.LiveChecks(solo.a,lambda:observation(solo,"oci",case.f.now),lambda:observation(solo,"k137",case.f.now),clock=lambda:case.f.now+120)
    with pytest.raises(ValueError):live.check("hold",solo.scope)


def test_immutable_pins_cover_all_solo_helpers():
    assert all("packaging/migration/"+leaf in O.T.bundle() for leaf in ("r1158_solo.py","r1158_machine.py","r1158_owner.py","r1157_operator.py","r1157_metadata.py"))
    text=(ROOT/"packaging/windows/r1158_solo_owner.ps1").read_text(encoding="utf-8")
    for term in ("-AsSecureString","Remove-R1027Custody","DIDTransferApproved","R987 V2","r1089_owner_control_pipe.cs"):
        assert term in text
    assert "InitRole" not in text and "READ_ONLY" in text


@pytest.mark.skipif(os.name!="nt",reason="native Windows PowerShell 5.1")
def test_ps51_solo_audit_never_prompts_for_credentials(case,solo,tmp_path):
    request=tmp_path/"solo-public.json"
    request.write_bytes(C.G.canonical(dict(enrollment=solo.profile,enrollment_sha=solo.a.pin,kind="r1154-hold",binding=solo.scope["owner"]["body"]["data"],seconds=1800)))
    O.M.protect_file(request)
    r=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",str(ROOT/"packaging/windows/r1158_solo_owner.ps1"),
        "-RequestFile",str(request),"-RequestSha256",hashlib.sha256(request.read_bytes()).hexdigest(),"-OutputDirectory",str(tmp_path/"public")],capture_output=True,timeout=60)
    assert r.returncode==0,r.stdout.decode(errors="replace")+r.stderr.decode(errors="replace")
    output=json.loads(r.stdout);assert output["code"]=="SOLO_CONSENT_DRAFT_ONLY" and output["cutover"]=="NO_GO" and not r.stderr
    assert b"recovery code" not in r.stdout and not (tmp_path/"public/approval.pem.enc").exists()
