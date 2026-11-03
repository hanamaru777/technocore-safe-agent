"""Fresh dummy approval keys/hosts only. No production SSH or DID custody."""
import base64
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import test_r1155_warm as old

ROOT=Path(__file__).resolve().parents[1]
def load(name,leaf):
    sp=importlib.util.spec_from_file_location(name,ROOT/"packaging/migration"/leaf)
    module=importlib.util.module_from_spec(sp);sys.modules[name]=module;sp.loader.exec_module(module);return module
M=load("r1157_operator_under_test","r1157_operator.py")
D=load("test_r1157_metadata","r1157_metadata.py")
case=old.case
h=old.old.h


@pytest.fixture
def session(case,tmp_path):
    descriptors={r:M.descriptor(case.f.keys[r],r,h("separate control "+r)) for r in M.ROLES}
    e=M.enroll(dict(context=case.f.context,source_did=case.f.did,source_key_ids=case.f.enrolled["source_key_ids"],descriptors=list(descriptors.values()),
        independent_key_id=M.validate_descriptor(descriptors["independent"])))
    sha=M.C.G.sha
    def endpoint(role):
        key=os.urandom(40);algorithm="ecdsa-sha2-nistp256" if role=="oci" else "ssh-ed25519"
        return dict(host="140.238.55.171" if role=="oci" else "8.8.8.8",user="ubuntu",host_key=algorithm+" "+base64.b64encode(key).decode(),
            host_key_sha256=hashlib.sha256(key).hexdigest(),credential_sha256=h("dummy credential "+role),
            identity_file="R987_V2_ESCROW" if role=="oci" else str(tmp_path/"dummy-ssh-file"),
            machine_sha256=case.f.context["host"] if role=="oci" else M.H.B.K137,uid=0 if role=="oci" else 1000,
            head=M.C.G.SOURCE_HEAD,cgroup_sha256=h("cgroup "+role),minimum_free_bytes=1024**3)
    ends=dict(schema_version=1,purpose="R1066_READONLY_PREFLIGHT",oci=endpoint("oci"),k137=endpoint("k137"))
    snapshots={}
    for role in ("oci","k137"):
        row=dict(version=1,role=role,challenge=h("challenge "+role),machine=ends[role]["machine_sha256"],boot=h("boot "+role),
            cgroup=ends[role]["cgroup_sha256"],uid=ends[role]["uid"],observed_at=case.f.now,memory_headroom_bytes=1024**3,
            cpu_psi_milli=0,io_psi_milli=0,writer_proof="NOT_PROVEN")
        if role=="oci":row.update(head=M.C.G.SOURCE_HEAD,source_bytes=10*1024**3,units=case.scope["units"],users=case.scope["users"],
            templates=case.scope["templates"],launcher_sha=case.scope["launcher_sha"],protected_sha=h("protected"),held=None)
        else:row["free_bytes"]=64*1024**3
        snapshots[role]=row
    review=dict(snapshots_sha=sha(snapshots),endpoints_sha=sha(ends),source_boot=snapshots["oci"]["boot"],destination_boot=snapshots["k137"]["boot"],
        surfaces={key:dict(complete=True,unknown=0,evidence_sha=h("independent actual evidence "+key)) for key in M.PROOF_FIELDS},
        route_evidence={r:dict(writer_scope_complete=True,evidence_sha=h(r),inventory_sha=case.scope["quarantine"]["inventory_sha"],
            ledger_sha=case.scope["quarantine"]["ledger_sha"]) for r in M.S.ROUTES},zero_cost_confirmed=True,disarmed_destination_confirmed=True)
    recipient=old.old.custody(case)[0]
    data=dict(enrollment=e,enrollment_sha=sha(e),endpoints=ends,snapshots=snapshots,review_data=review,
        settings=dict(run_id=case.scope["run_id"],known_hosts_sha=case.scope["known_hosts_sha"],offhost_parent=str(tmp_path),quota_bytes=11*1024**3,
            inventory_sha=case.scope["quarantine"]["inventory_sha"],ledger_sha=case.scope["quarantine"]["ledger_sha"],recipient_public=recipient.public_key().public_bytes_raw().hex(),challenge=h("custody challenge")))
    def sign(kind,role,now=None):return M.issue(kind,data,case.f.keys[role],descriptors[role],now=case.f.now if now is None else now)
    data["review"]=sign("review","independent");data["destination"]=sign("destination","destination")
    return SimpleNamespace(data=data,descriptors=descriptors,sign=sign)


def test_real_verifiers_accept_distinct_issuer_scope_and_custody(case,session):
    s=session;d=s.data
    # Different local signing times, same factual observation time; no fake
    # grants or use of another role's private key in the production path.
    packets={r:s.sign("scope",r,case.f.now+i) for i,r in enumerate(("owner","independent"))}
    scope=M.assemble("scope",d,packets,case.f.now+1)
    a=M.H.Authority(d["enrollment"],d["enrollment_sha"])
    assert M.H.validate_scope(a,scope,now=case.f.now+1)
    d["scope"]=scope
    req=M.assemble("custody",d,{r:s.sign("custody",r) for r in ("owner","independent")},case.f.now)
    M.K.approved(a,req["binding"],req["owner"],req["witness"],now=case.f.now)
    assert req["binding"]["recipient_public"]==d["settings"]["recipient_public"]


def test_complete_real_crypto_plan_and_renewal_match_existing_transport_and_reader(case,session):
    from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
    s=session;d=s.data;now=case.f.now
    def pair(kind):return M.assemble(kind,d,{r:s.sign(kind,r) for r in ("owner","independent")},case.f.now)
    d["scope"]=pair("scope");settings=d["settings"]
    d["held_data"]=dict(scope_sha=M.C.G.sha(d["scope"]),source_boot=d["snapshots"]["oci"]["boot"],hold_journal_sha=h("actual held journal"),
        manifest_sha=h("actual manifest"),nonce_file_sha=h("actual raw nonce file"),epoch=h("actual frozen epoch"),
        ledger_sha=settings["ledger_sha"],source_deny=True,target_deny=True)
    d["snapshots"]["oci"]["held"]=dict(M.H.result("HELD_VM_AND_SSH_UNCHANGED"),scope_sha=M.C.G.sha(d["scope"]),journal_sha=d["held_data"]["hold_journal_sha"])
    d["review_data"]["snapshots_sha"]=M.C.G.sha(d["snapshots"]);d["review"]=s.sign("review","independent")
    d["held"]=s.sign("held","independent")
    d["preserve_binding"]=dict(scope_sha=M.C.G.sha(d["scope"]),hold_journal_sha=d["held_data"]["hold_journal_sha"],roots_sha=M.C.G.sha(M.C.ROOTS),
        inventory_sha=settings["inventory_sha"],ledger_sha=settings["ledger_sha"],epoch=d["held_data"]["epoch"],source_cap_bytes=settings["quota_bytes"],
        destination_policy_sha=h("independently verified installed deny"),recovery_confirmed=True,cost_cap="ZERO_NEW_BILLING")
    d["preserve"]=pair("preserve");d["policy"]=s.sign("policy","destination")
    custody=pair("custody");a=M.H.Authority(d["enrollment"],d["enrollment_sha"])
    dummy=bytearray(case.f.own.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
    custody["envelope"]=M.K.encrypt(a,custody["binding"],custody["owner"],custody["witness"],dummy,now=now)
    d["custody"]={k:v for k,v in custody.items() if k not in ("enrollment","enrollment_sha")}
    held=d["held_data"]
    anchor=dict(purpose="archive",authority_sha=a.pin,source_machine=a.trust.context["host"],target_machine=M.H.B.K137,
        source_boot=held["source_boot"],target_boot=d["snapshots"]["k137"]["boot"],source_head=M.C.G.SOURCE_HEAD,
        scope_sha=held["scope_sha"],hold_journal_sha=held["hold_journal_sha"],manifest_sha=held["manifest_sha"],epoch=held["epoch"],
        did_sha=a.trust.context["did"],ledger_sha=held["ledger_sha"],nonce_file_sha=held["nonce_file_sha"],nonce_state_sha=h("canonical nonce state"),
        capture_sha=M.C.G.sha(d["preserve_binding"]),runtime_sha=None,generation_sha=None)
    metrics=dict(observed_at=now,source_running=True,ssh_retained=True,source_deny=True,target_deny=True,
        free_bytes=d["snapshots"]["k137"]["free_bytes"],remaining_bytes=settings["quota_bytes"],memory_headroom_bytes=1024**3,
        cpu_psi_milli=0,io_psi_milli=0,zero_cost=True)
    d["renewal"]=dict(anchor=anchor,metrics=metrics,previous=None)
    initial=pair("renewal");d["renewal"]["initial"]=initial
    plan=pair("transfer")
    assert M.T.admit(plan,now).pin==a.pin and plan["quota_bytes"]==settings["quota_bytes"]
    seen=SimpleNamespace(latest=None)
    seen.save=lambda value:setattr(seen,"latest",value)
    current=[initial];reader=M.N.Reader(a,anchor,lambda:current[0],seen);reader.check(now)
    for offset in (600,1200):
        case.f.now=now+offset
        for report in d["snapshots"].values():report["observed_at"]=case.f.now
        d["review_data"]["snapshots_sha"]=M.C.G.sha(d["snapshots"])
        d["review"]=s.sign("review","independent");d["held"]=s.sign("held","independent")
        d["renewal"]["previous"]=current[0];d["renewal"]["metrics"]["observed_at"]=case.f.now
        current[0]=pair("renewal");reader.check(case.f.now)
    assert seen.latest["seq"]==2
    with pytest.raises(ValueError):reader.check(now+2100)
    assert not any(dummy)


@pytest.mark.parametrize("fault",["missing","same_control","same_key","wrong_pin","tampered_consent","original_did_key"])
def test_independent_enrollment_fail_closed(case,session,fault):
    public=copy.deepcopy(list(session.descriptors.values()))
    if fault=="missing":public=[p for p in public if p["body"]["role"]!="independent"]
    if fault=="same_control":public=[M.descriptor(case.f.keys[r],r,h("same machine")) for r in M.ROLES]
    if fault=="same_key":public=[M.descriptor(case.f.keys["owner"],r,h(r)) for r in M.ROLES]
    if fault=="tampered_consent":public[0]["body"]["consent"]="no consent"
    if fault=="original_did_key":public=[M.descriptor(case.f.own,r,h(r)) if r=="independent" else session.descriptors[r] for r in M.ROLES]
    witness=next((M.validate_descriptor(p) for p in public if p["body"]["role"]=="independent"),h("missing")) if fault!="tampered_consent" else h("bad")
    with pytest.raises(Exception):M.enroll(dict(context=case.f.context,source_did=case.f.did,source_key_ids=case.f.enrolled["source_key_ids"],descriptors=public,independent_key_id=h("wrong") if fault=="wrong_pin" else witness))


@pytest.mark.parametrize("fault",["surface_missing","surface_unknown","route_missing","route_unknown","old_snapshot","host","boot","malicious_scope","low_disk","wrong_review_key","expired_grant","wrong_tool"])
def test_release_drafts_never_manufacture_missing_live_proof(case,session,fault):
    d=session.data
    if fault=="surface_missing":d["review_data"]["surfaces"].pop("manual")
    if fault=="surface_unknown":d["review_data"]["surfaces"]["processes"]["unknown"]=1
    if fault=="route_missing":d["review_data"]["route_evidence"].pop(M.S.ROUTES[0])
    if fault=="route_unknown":d["review_data"]["route_evidence"][M.S.ROUTES[0]]["writer_scope_complete"]=False
    if fault=="old_snapshot":d["snapshots"]["oci"]["observed_at"]-=901
    if fault=="host":d["snapshots"]["oci"]["machine"]=h("different host")
    if fault=="boot":d["snapshots"]["oci"]["boot"]=h("different boot")
    if fault=="malicious_scope":d["snapshots"]["oci"]["units"]["ssh.service"]=copy.deepcopy(next(iter(d["snapshots"]["oci"]["units"].values())))
    if fault=="low_disk":d["snapshots"]["k137"]["free_bytes"]=20*1024**3+1
    if fault=="wrong_review_key":d["review"]["signer"]=M.validate_descriptor(session.descriptors["owner"])
    now=case.f.now+901 if fault=="expired_grant" else case.f.now
    if fault=="wrong_tool":
        d["scope"]=dict(case.scope,tool_blob="0"*40)
        with pytest.raises(Exception):M.packet_spec("custody",d,now)
        return
    if fault=="malicious_scope":
        # An independent re-signature cannot permit protected service control.
        d["review_data"]["snapshots_sha"]=M.C.G.sha(d["snapshots"])
        d["review"]=session.sign("review","independent");d["destination"]=session.sign("destination","destination")
        with pytest.raises(Exception):M.assemble("scope",d,{r:session.sign("scope",r) for r in ("owner","independent")},now)
    else:
        with pytest.raises(Exception):M.packet_spec("scope",d,now)


def private_dir(path):
    path.mkdir(mode=0o700);M.protect_file(path);return path


def test_encrypted_approval_custody_no_plaintext_replacement_or_cross_role(case,session,tmp_path):
    folder=private_dir(tmp_path/"approval");buf=bytearray(os.urandom(48));password=bytes(buf)
    dummy=case.f.keys["owner"];public=M.init_key(folder,"owner",buf,key_factory=lambda:dummy,identity=lambda:h("local control"))
    assert not any(buf) and b"ENCRYPTED PRIVATE KEY" in (folder/"approval.pem.enc").read_bytes()
    with M.local_key(folder,bytearray(password),identity=lambda:h("local control")) as (key,record):assert record==public and key.public_key()==dummy.public_key()
    with pytest.raises(Exception):M.init_key(folder,"independent",bytearray(password),key_factory=lambda:case.f.keys["independent"])
    with pytest.raises(Exception):
        with M.local_key(folder,bytearray(b"wrong"*12),identity=lambda:h("local control")):pass
    with pytest.raises(Exception):
        with M.local_key(folder,bytearray(password),identity=lambda:h("different user")):pass


def test_logical_source_size_only_stat_no_contents_and_no_symlink_follow(tmp_path,monkeypatch):
    source=tmp_path/"state";source.mkdir();(source/"synthetic.env").write_bytes(b"x"*123)
    monkeypatch.setattr(Path,"read_bytes",lambda _:pytest.fail("metadata must not read file content"))
    assert D.logical_size([source])==123


def test_size_scan_bound_or_race_fail_closed(tmp_path):
    source=tmp_path/"state";source.mkdir();(source/"file").write_bytes(b"data")
    clock=iter((0,100,100,100))
    with pytest.raises(ValueError,match="SIZE_BOUND"):D.logical_size([source],clock=lambda:next(clock))


@pytest.mark.parametrize("role,held_mode",[("oci",False),("oci",True),("k137",False)])
def test_guest_reads_fixed_public_metadata_only(case,session,monkeypatch,tmp_path,role,held_mode):
    d=session.data;e=d["endpoints"][role]
    raw_machine=b"original" if role=="oci" else b"target placeholder"
    if role=="k137":
        # Fixed destination identity remains pinned; inject only the hash of
        # the synthetic read, not an actual machine identifier.
        original_hash=D.hashlib.sha256
        monkeypatch.setattr(D.hashlib,"sha256",lambda raw=b"":SimpleNamespace(hexdigest=lambda:M.H.B.K137)
            if raw==b"target placeholder" else original_hash(raw))
    raw={"/etc/machine-id":raw_machine,"/proc/sys/kernel/random/boot_id":("boot "+role).encode(),"/proc/self/cgroup":("cgroup "+role).encode()}
    if held_mode:
        work=tmp_path/"public-held";work.mkdir();path=work/"scope.json";path.write_bytes(M.C.G.canonical(case.scope))
        raw[path.as_posix()]=path.read_bytes();raw[Path(D.H.__file__).as_posix()]=Path(D.H.__file__).read_bytes()
        monkeypatch.setattr(D.H,"WORK",work)
        monkeypatch.setattr(D.H,"Controller",lambda *_:SimpleNamespace(verify=lambda:dict(M.H.result("HELD_VM_AND_SSH_UNCHANGED"),
            scope_sha=M.C.G.sha(case.scope),journal_sha=h("real verifier result"))))
    text={"/proc/meminfo":"MemAvailable: 1048576 kB\n","/proc/pressure/cpu":"some avg10=0.00 avg60=0.00\n","/proc/pressure/io":"some avg10=0.00 avg60=0.00\n"}
    monkeypatch.setattr(D.sys,"platform","linux");monkeypatch.setattr(D.os,"geteuid",lambda:e["uid"],raising=False)
    monkeypatch.setattr(Path,"read_bytes",lambda p:raw[p.as_posix()])
    monkeypatch.setattr(Path,"read_text",lambda p,**_:text[p.as_posix()])
    driver=SimpleNamespace(reader=SimpleNamespace(identity=lambda:dict(source_head=M.C.G.SOURCE_HEAD)),
        discovered=lambda:pytest.fail("must not rediscover masked units") if held_mode else set(case.scope["units"]),unit=lambda n:case.scope["units"][n],
        protected=lambda:dict(ssh="unchanged"),launchers=lambda:h("launchers"),identity=lambda scope:None)
    monkeypatch.setattr(D.H,"Linux",lambda:driver);monkeypatch.setattr(D,"logical_size",lambda _:10*1024**3)
    monkeypatch.setattr(D.shutil,"disk_usage",lambda _:SimpleNamespace(free=64*1024**3))
    monkeypatch.setitem(sys.modules,"pwd",SimpleNamespace(getpwnam=lambda n:SimpleNamespace(pw_uid=case.scope["users"][n])))
    report=D.peer(dict(enrollment=d["enrollment"],enrollment_sha=d["enrollment_sha"],operation="r1157-readonly-metadata",role=role,
        challenge=h("new challenge"),endpoint=e))
    assert report["writer_proof"]=="NOT_PROVEN" and report["challenge"]==h("new challenge")
    if role=="oci":
        assert report["source_bytes"]==10*1024**3 and report["users"]==case.scope["users"]
        assert (report["held"] is not None)==held_mode
    else:assert report["free_bytes"]==64*1024**3


def test_no_runtime_mutation_or_freeform_ssh_and_no_independent_auto_generation():
    text=(ROOT/"packaging/migration/r1157_metadata.py").read_text(encoding="utf-8")
    assert "def peer" in text and "writer_proof=\"NOT_PROVEN\"" in text
    for bad in (".post(",".hold(",".post_deny(",".stop(","sqlite3.connect","seed", "Vault"):
        assert bad not in text
    text=(ROOT/"packaging/migration/r1157_operator.py").read_text(encoding="utf-8")
    assert "StrictHostKeyChecking" not in text # inherited fixed ssh_base, no replacement
    assert 'T.bases(' in text and 'challenge=os.urandom(32)' in text


@pytest.mark.parametrize("fault",[None,"wrong_challenge","unknown_field","ssh_failure","timeout"])
def test_fixed_readonly_collector_authenticates_fresh_reply_no_network(case,session,monkeypatch,fault):
    d=session.data;commands=[]
    monkeypatch.setattr(M.T,"bases",lambda *_:[["fixed-oci-ssh"],["fixed-k137-ssh"]])
    class Input(io.BytesIO):
        def close(self):pass
    @contextlib.contextmanager
    def child(argv,**kwargs):
        commands.append(argv)
        if fault=="timeout":raise TimeoutError("synthetic secret error that must not be printed")
        stream=Input()
        class Output:
            def read(self,bound):
                stream.seek(0);control=M.C.R.frame_read(stream,M.C.R.MAGIC)
                req=control["request"];row=copy.deepcopy(d["snapshots"][req["role"]]);row["challenge"]=req["challenge"]
                if fault=="wrong_challenge":row["challenge"]=h("replay")
                if fault=="unknown_field":row["unsafe"]=True
                return M.C.G.canonical(row)
        yield SimpleNamespace(stdin=stream,stdout=Output(),wait=lambda **_:1 if fault=="ssh_failure" else 0)
    control=dict(enrollment=d["enrollment"],enrollment_sha=d["enrollment_sha"],endpoints=d["endpoints"],
        ssh="mock",oci_key="mock",oci_hosts="mock",k137_hosts="mock")
    if fault:
        with pytest.raises(Exception):M.collect(control,child=child)
    else:
        result=M.collect(control,child=child)
        assert set(result)=={"oci","k137"} and len(commands)==2
        assert "sudo -n /opt/technocore-safe-agent/.venv/bin/python" in commands[0][-1]
        assert "sudo" not in commands[1][-1].split("-c",1)[0]


def test_only_fixed_safe_error_from_missing_witness_and_no_stderr_secret(case,capsys,monkeypatch,tmp_path):
    data=dict(context=case.f.context,source_did=case.f.did,descriptors=[],independent_key_id=h("missing"))
    control=dict(operation="enroll",data=data,output=str(tmp_path),confirmation="CONFIRM_ENROLL")
    wire=io.BytesIO();M.C.R.frame_write(wire,M.C.R.MAGIC,control);wire.seek(0)
    monkeypatch.setattr(M.sys,"argv",["operator","--pipe"]);monkeypatch.setattr(M.sys,"stdin",SimpleNamespace(buffer=wire))
    assert M.main()==42
    output=capsys.readouterr()
    assert json.loads(output.out)["code"]=="OPERATOR_WITNESS_NOT_ENROLLED" and not output.err
    assert not list(tmp_path.iterdir())


def test_failed_private_custody_never_leaks_exception_and_wipes_pipe_password(case,session,capsys,monkeypatch,tmp_path):
    captured=[]
    @contextlib.contextmanager
    def denied(folder,password):
        captured.append(password)
        raise RuntimeError("PRIVATE_SYNTHETIC_ERROR_NOT_FOR_LOGS")
        yield
    monkeypatch.setattr(M,"local_key",denied)
    control=dict(operation="issue",data=dict(kind="scope",session=session.data),output=str(tmp_path),confirmation="CONFIRM_ISSUE")
    wire=io.BytesIO();M.C.R.frame_write(wire,M.C.R.MAGIC,control);wire.write(struct.pack(">I",48)+os.urandom(48));wire.seek(0)
    monkeypatch.setattr(M.sys,"argv",["operator","--pipe"]);monkeypatch.setattr(M.sys,"stdin",SimpleNamespace(buffer=wire))
    assert M.main()==42
    output=capsys.readouterr();assert json.loads(output.out)["code"]=="OPERATOR_PREPARATION_STOP"
    assert not output.err and "PRIVATE_SYNTHETIC" not in output.out and captured and not any(captured[0])
    assert not list(tmp_path.iterdir())


def test_enrollment_cli_exports_exact_public_endpoint_and_sha_files(case,session,capsys,monkeypatch,tmp_path):
    folder=private_dir(tmp_path/"public")
    data=dict(endpoints=session.data["endpoints"],source_did=case.f.did,source_key_ids=case.f.enrolled["source_key_ids"],
        descriptors=list(session.descriptors.values()),independent_key_id=M.validate_descriptor(session.descriptors["independent"]))
    control=dict(operation="enroll",data=data,output=str(folder),confirmation="CONFIRM_ENROLL")
    wire=io.BytesIO();M.C.R.frame_write(wire,M.C.R.MAGIC,control);wire.seek(0)
    monkeypatch.setattr(M.sys,"argv",["operator","--pipe"]);monkeypatch.setattr(M.sys,"stdin",SimpleNamespace(buffer=wire))
    assert M.main()==0
    reply=json.loads(capsys.readouterr().out);assert reply["cutover"]=="NO_GO"
    for leaf in ("enrollment.json","endpoints.json"):
        raw=(folder/leaf).read_bytes()
        assert (folder/(leaf+".sha256")).read_text().strip()==hashlib.sha256(raw).hexdigest()
    assert json.loads((folder/"endpoints.json").read_bytes())==data["endpoints"]


@pytest.mark.skipif(os.name!="nt",reason="native Windows PowerShell 5.1")
def test_ps51_default_audit_rejects_missing_witness_no_credential_prompt(tmp_path):
    # No key initialization/signing, SSH, or real credential reads in this test.
    request=tmp_path/"public-input.json";request.write_text('{"kind":"review","session":{}}',encoding="utf-8")
    M.protect_file(request)
    r=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",str(ROOT/"packaging/windows/r1157_operator.ps1"),
        "-RequestFile",str(request),"-RequestSha256",hashlib.sha256(request.read_bytes()).hexdigest(),"-OutputDirectory",str(tmp_path/"public")],
        capture_output=True,timeout=60)
    assert r.returncode==42
    assert b'"cutover":"NO_GO"' in r.stdout.replace(b" ",b"")
    assert not r.stderr and b"R987 V2 local recovery" not in r.stdout


@pytest.mark.skipif(os.name!="nt",reason="native Windows PowerShell 5.1")
def test_ps51_default_positive_public_plan_audit_never_opens_credential_or_key(case,session,tmp_path):
    request=tmp_path/"public-valid.json"
    request.write_bytes(M.C.G.canonical(dict(kind="scope",session=session.data)));M.protect_file(request)
    r=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",str(ROOT/"packaging/windows/r1157_operator.ps1"),
        "-RequestFile",str(request),"-RequestSha256",hashlib.sha256(request.read_bytes()).hexdigest(),"-OutputDirectory",str(tmp_path/"public")],
        capture_output=True,timeout=60)
    assert r.returncode==0,r.stdout.decode(errors="replace")+r.stderr.decode(errors="replace")
    result=json.loads(r.stdout);assert result["code"]=="OPERATOR_PUBLIC_DRAFT_CHECKED" and result["cutover"]=="NO_GO"
    assert result["kind"]=="r1154-hold" and not r.stderr


def test_ps51_pins_all_new_code_and_preserves_old_frozen_code():
    text=(ROOT/"packaging/windows/r1157_operator.ps1").read_text(encoding="utf-8")
    for leaf in ("operator","metadata"):
        path=ROOT/("packaging/migration/r1157_"+leaf+".py");raw=path.read_bytes().replace(b"\r\n",b"\n")
        blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        assert blob in text
    assert "-AsSecureString" in text and "Remove-R1027Custody" in text
    assert "DIDTransferApproved" in text and "STOP_FLOP_ONLY_KEEP_VM_AND_SSH" in text
    assert "r1154_warm_owner.ps1" in text and "r1155_warm_transfer.ps1" in text
