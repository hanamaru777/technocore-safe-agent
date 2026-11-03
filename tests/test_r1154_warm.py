"""Actual controller filesystem mutations on synthetic roots; NO real commands.

Fresh dummy signer/recipient keys only. Never call -Execute or Vault/SSH here.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
import sqlite3
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import test_r1107_readiness as old

ROOT=Path(__file__).resolve().parents[1]
def load(name,leaf):
    sp=importlib.util.spec_from_file_location(name,ROOT/"packaging/migration"/leaf)
    m=importlib.util.module_from_spec(sp);sys.modules[name]=m;sp.loader.exec_module(m);return m
M=load("test_r1154_hold","r1154_app_hold.py")
K=load("test_r1154_custody","r1154_custody.py")
O=load("test_r1154_owner","r1154_owner.py")
POSIX=pytest.mark.skipif(os.name!="posix",reason="POSIX private controller journal")
WIN=pytest.mark.skipif(os.name!="nt",reason="PowerShell 5.1")
def h(s):return hashlib.sha256(s.encode()).hexdigest()


@pytest.fixture
def case():
    f=old.Fixture(now=int(time.time()));f.context["destination"]=M.B.K137;a=M.Authority(f.enrolled,M.C.G.sha(f.enrolled))
    units={}
    for name in ("technocore-safe-agent-resident.service","lobby-capture.service","technocore-safe-agent-signer.service",
                 "technocore-safe-agent-tclk-accept@.service","technocore-safe-agent-tclk-accept@test.service",
                 "technocore-safe-agent-precontest-supervisor.service","technocore-safe-agent-precontest-supervisor.timer"):
        user="" if name.endswith(".timer") else "technocore-signer" if "signer" in name or "tclk" in name else "technocore"
        units[name]=dict(properties_sha=h(name),file_sha=h(name+"file"),user=user,
            targets=["technocore-safe-agent-precontest-supervisor.service"] if name.endswith(".timer") else [],stop_edges=[])
    scope=dict(version=1,run_id="c"*32,source=f.context,units=units,users={"technocore":1001,"technocore-signer":1002},
        surfaces={key:"INDEPENDENTLY_REVIEWED_NO_OUTSIDE_LAUNCHER" for key in M.SURFACES},
        templates={name:([name] if name in units else []) for name in M.C.U.EXPECTED},
        known_hosts_sha=h("known hosts"),launcher_sha=h("launchers"),tool_blob=M.tool_blob(),
        quarantine=dict(routes=list(M.P.ROUTES),inventory_sha=h("all exact original attempts"),ledger_sha=h("original nonce and receipts"),permanent=True,loss_accepted=True))
    scope["destination"]=f.signed("r1154-destination",dict(machine=M.B.K137,free_bytes=64*M.C.R.GIB,
        source_upper_bound_bytes=10*M.C.R.GIB,memory_headroom_bytes=M.C.R.GIB,cpu_psi_milli=0,io_psi_milli=0,
        disarmed_ready=True,publisher_disarmed=True,zero_cost_verified=True),"destination")
    result=SimpleNamespace(f=f,a=a,scope=scope)
    approve(result)
    return result


def approve(case):
    binding=M.C.G.sha({k:v for k,v in case.scope.items() if k not in ("owner","witness")})
    body=dict(scope_sha=binding,downtime=True,keep_vm_running=True,keep_ssh=True,cost_cap="ZERO_NEW_BILLING",permanent_post_deny=True)
    case.scope["owner"]=case.f.signed("r1154-hold",body,"owner")
    case.scope["witness"]=case.f.signed("r1154-hold",body,"independent")


def test_signed_scope_same_vm_ssh_and_all_five_routes(case):
    assert M.validate_scope(case.a,case.scope,now=case.f.now)
    assert len(case.scope["templates"])==27
    assert len(case.scope["quarantine"]["routes"])==5


@pytest.mark.parametrize("change",["ssh","metadata","agent","wrong_uid","unknown_cron","timer_target","stop_edge","template_missing","g5_missing","loss","signature"])
def test_scope_rejects_unsafe_unrelated_or_unproven(case,change):
    if change in ("ssh","metadata","agent"):
        name={"ssh":"ssh.service","metadata":"technocore-safe-agent-metadata-block.service","agent":"oracle-cloud-agent.service"}[change]
        case.scope["units"][name]=copy.deepcopy(next(iter(case.scope["units"].values())))
    if change=="wrong_uid":case.scope["users"]["technocore"]=1000
    if change=="unknown_cron":case.scope["surfaces"]["cron"]="UNKNOWN"
    if change=="timer_target":case.scope["units"]["technocore-safe-agent-precontest-supervisor.timer"]["targets"]=["unrelated.service"]
    if change=="stop_edge":case.scope["units"]["technocore-safe-agent-resident.service"]["stop_edges"]=["ssh.service"]
    if change=="template_missing":case.scope["templates"].pop(next(iter(case.scope["templates"])))
    if change=="g5_missing":case.scope["quarantine"]["routes"].pop()
    if change=="loss":case.scope["quarantine"]["loss_accepted"]=False
    approve(case)
    if change=="signature":case.scope["owner"]["signature"]="0"*128
    with pytest.raises(ValueError):M.validate_scope(case.a,case.scope,now=case.f.now)


class Fake:
    def __init__(self,case):self.scope=case.scope;self.events=[];self.denied=False;self.alive=False;self.extra=False
    def identity(self,scope):assert scope["source"]==self.scope["source"]
    def discovered(self):return set(self.scope["units"])|({"technocore-safe-agent-unknown.service"} if self.extra else set())
    def unit(self,name):return self.scope["units"][name]
    def launchers(self):return self.scope["launcher_sha"]
    def command(self,args):self.events.append(tuple(args));return SimpleNamespace(returncode=0,stdout=b"")
    def post_deny(self,users):self.denied=True;self.events.append(("DENY_UIDS",tuple(users.values())))
    def verify_deny(self,users):assert self.denied
    def stop(self,name):assert name not in M.PROTECTED;self.events.append(("STOP",name))
    def quiet(self,scope):
        self.verify_deny(scope["users"])
        M.need(not self.alive,"WARM_OUTSIDE_WRITER_STOP")
    def protected(self):return dict(ssh="same protected PID/state")
    def protected_unchanged(self,before):assert before==self.protected()


def roots(case,tmp_path,monkeypatch):
    units=tmp_path/"units";units.mkdir(mode=0o700);(units/"sysinit.target.wants").mkdir(mode=0o700)
    for name,row in case.scope["units"].items():
        data=("[Unit]\nDescription=Synthetic "+name+"\n").encode()
        (units/name).write_bytes(data);row["file_sha"]=hashlib.sha256(data).hexdigest()
    (units/"ssh.service").write_bytes(b"SSH PROTECTED")
    (units/"technocore-safe-agent-metadata-block.service").write_bytes(b"METADATA PROTECTED")
    monkeypatch.setattr(M,"UNITS",units);monkeypatch.setattr(M,"WORK",tmp_path/"hold")
    approve(case)
    return units


@POSIX
def test_real_masks_persisted_boot_deny_verify_and_safe_rollback(case,tmp_path,monkeypatch):
    units=roots(case,tmp_path,monkeypatch);before={p.name:p.read_bytes() for p in units.iterdir() if p.is_file()}
    fake=Fake(case);ctl=M.Controller(case.a,fake)
    result=ctl.hold(case.scope,now=case.f.now)
    assert result["code"]=="HELD_VM_AND_SSH_UNCHANGED" and result["cutover"]=="NO_GO"
    assert fake.events[0][0]=="DENY_UIDS"
    stopped=[event[1] for event in fake.events if event[0]=="STOP"]
    assert stopped[0].endswith(".timer") and "lobby-capture.service" in stopped
    assert any("@test.service" in n for n in stopped)
    for name in case.scope["units"]:assert os.readlink(units/name)=="/dev/null"
    assert ctl.verify()["code"]=="HELD_VM_AND_SSH_UNCHANGED"
    # Reboot path is a persistent root-only unit linked before every scoped unit.
    text=(units/M.GUARD).read_text()
    assert "--uid-owner 1001" in text and "--uid-owner 1002" in text and "--uid-owner 1000" not in text
    assert (units/"sysinit.target.wants"/M.GUARD).is_symlink()
    with pytest.raises(M.Stop):ctl.hold(case.scope,now=case.f.now)
    journal=M.J.UndoJournal(M.WORK/"records")
    bound=dict(journal_sha=journal.previous,scope_sha=M.C.G.sha(case.scope),aws_publishers_disabled=True,
        permanent_old_post_deny_retained=True,auto_restart=False)
    owner=case.f.signed("r1154-rollback",bound,"owner");witness=case.f.signed("r1154-rollback",bound,"independent")
    assert ctl.rollback(owner,witness,now=case.f.now)["code"]=="RESTORED_DISARMED_POST_DENY_RETAINED"
    assert {name:(units/name).read_bytes() for name in before}==before
    assert fake.denied and (units/M.GUARD).exists()
    assert not any("start" in args or "reboot" in args or "poweroff" in args for args in fake.events)


@POSIX
def test_unknown_scope_stops_before_mutation(case,tmp_path,monkeypatch):
    roots(case,tmp_path,monkeypatch);fake=Fake(case);fake.extra=True
    with pytest.raises(M.Stop,match="WARM_SCOPE_DRIFT_STOP"):M.Controller(case.a,fake).hold(case.scope,now=case.f.now)
    assert fake.events==[] and not M.WORK.exists()


@POSIX
def test_remaining_writer_disconnect_keeps_durable_unknown_no_repeat(case,tmp_path,monkeypatch):
    roots(case,tmp_path,monkeypatch);fake=Fake(case);fake.alive=True;ctl=M.Controller(case.a,fake)
    with pytest.raises(M.Stop,match="WARM_HOLD_INCOMPLETE_NO_AUTO_ROLLBACK"):ctl.hold(case.scope,now=case.f.now)
    state=M.J.UndoJournal(M.WORK/"records")
    assert state.latest["phase"]=="INCOMPLETE_HOLD_REVIEW_REQUIRED" and fake.denied
    with pytest.raises(M.Stop):ctl.verify()
    assert ctl.status()["code"]=="SOURCE_HOLD_STATUS_REQUIRES_VERIFY"
    with pytest.raises(M.Stop):ctl.hold(case.scope,now=case.f.now)


@POSIX
def test_rollback_never_grants_old_post_or_restarts_on_failed_approval(case,tmp_path,monkeypatch):
    roots(case,tmp_path,monkeypatch);fake=Fake(case);ctl=M.Controller(case.a,fake);ctl.hold(case.scope,now=case.f.now)
    packet=case.f.signed("r1154-rollback",dict(aws_publishers_disabled=False),"owner")
    with pytest.raises(ValueError):ctl.rollback(packet,packet,now=case.f.now)
    assert fake.denied and ctl.verify()["code"]=="HELD_VM_AND_SSH_UNCHANGED"


@POSIX
def test_missing_undo_evidence_never_claims_rollback_success(case,tmp_path,monkeypatch):
    roots(case,tmp_path,monkeypatch);fake=Fake(case);ctl=M.Controller(case.a,fake);ctl.hold(case.scope,now=case.f.now)
    (M.WORK/"saved"/next(iter(case.scope["units"]))).unlink()
    journal=M.J.UndoJournal(M.WORK/"records")
    bound=dict(journal_sha=journal.previous,scope_sha=M.C.G.sha(case.scope),aws_publishers_disabled=True,permanent_old_post_deny_retained=True,auto_restart=False)
    with pytest.raises(M.Stop,match="WARM_ROLLBACK_FAILED"):
        ctl.rollback(case.f.signed("r1154-rollback",bound,"owner"),case.f.signed("r1154-rollback",bound,"independent"),now=case.f.now)
    assert M.J.UndoJournal(M.WORK/"records").latest["phase"]=="ROLLBACK_FAILED_REVIEW_REQUIRED"


def test_bounded_bulk_scope_finds_nonprefixed_original_root_writer():
    names=["technocore-safe-agent-resident.service","unexpected-worker.service","ssh.service"]
    calls=[]
    def runner(args,**kwargs):
        calls.append(args)
        assert "stop" not in args and "start" not in args and kwargs["shell"] is False
        blocks=[]
        for name in names:
            cmd="/usr/sbin/sshd" if name=="ssh.service" else "/opt/technocore-safe-agent/run"
            blocks.append("Id="+name+"\nNames="+name+"\nLoadState=loaded\nExecStart="+cmd)
        return SimpleNamespace(returncode=0,stdout=("\n\n".join(blocks)+"\n").encode())
    driver=M.Linux(runner);driver.reader=SimpleNamespace(unit_files=lambda:names,loaded=lambda:names)
    assert driver.discovered()==set(names)-{"ssh.service"} and len(calls)==1


@pytest.mark.parametrize("bad",["host_action","root_stop","missing_property"])
def test_effective_stop_policy_refuses_host_or_privilege_actions(tmp_path,bad):
    fields={key:"" for key in M.STOP_PROPERTIES}
    fields.update(User="technocore",PermissionsStartOnly="no",NoNewPrivileges="yes",
        FailureAction="none",SuccessAction="none",StartLimitAction="none",JobTimeoutAction="none")
    if bad=="host_action":fields["FailureAction"]="poweroff"
    if bad=="missing_property":fields.pop("BoundBy")
    def runner(args,**kwargs):
        assert "stop" not in args and "start" not in args
        raw=b"ExecStop=+/usr/bin/mutator\n" if "cat" in args else ("\n".join(k+"="+v for k,v in fields.items())+"\n").encode()
        return SimpleNamespace(returncode=0,stdout=raw)
    driver=M.Linux(runner);driver.reader=SimpleNamespace(observed=lambda _: {"properties":{"ExecStart":"/opt/technocore-safe-agent/run"}})
    with pytest.raises(M.Stop):driver.unit("technocore-safe-agent-resident.service")


def test_protected_pid_change_is_not_reported_as_healthy():
    driver=M.Linux()
    before={"boot":h("same boot"),"units":{"ssh.service":{"LoadState":"loaded","ActiveState":"active","MainPID":"77"}}}
    after=copy.deepcopy(before);after["units"]["ssh.service"]["MainPID"]="78"
    driver.protected=lambda:after
    with pytest.raises(M.Stop,match="WARM_PROTECTED_STATE_CHANGED"):driver.protected_unchanged(before)


@pytest.mark.parametrize("field,value",[("free_bytes",20*1024**3),("publisher_disarmed",False),("zero_cost_verified",False),("memory_headroom_bytes",0)])
def test_fresh_k137_capacity_required_before_hold(case,field,value):
    data=copy.deepcopy(case.scope["destination"]["body"]["data"]);data[field]=value
    case.scope["destination"]=case.f.signed("r1154-destination",data,"destination");approve(case)
    with pytest.raises(ValueError):M.validate_scope(case.a,case.scope,now=case.f.now)


def test_ipv4_ipv6_post_deny_commands_only_dedicated_uids():
    calls=[]
    def runner(args,**kwargs):
        calls.append(args);assert kwargs["shell"] is False
        return SimpleNamespace(returncode=1 if "-C" in args else 0,stdout=b"")
    driver=M.Linux(runner);driver.post_deny({"technocore":1001,"technocore-signer":1002})
    assert len(calls)==8 and {args[0] for args in calls}=={"/usr/sbin/iptables","/usr/sbin/ip6tables"}
    assert not any("1000" in args or "sshd" in args for args in calls)
    assert all("FLOP_R1154" in args and "REJECT" in args for args in calls)


def capture_fixture(case,tmp_path,monkeypatch,wal=False):
    units=roots(case,tmp_path,monkeypatch);fake=Fake(case);ctl=M.Controller(case.a,fake);ctl.hold(case.scope,now=case.f.now)
    app=tmp_path/"application";state=tmp_path/"state";app.mkdir(mode=0o700);state.mkdir(mode=0o700)
    (state/"signer").mkdir(mode=0o700);(state/"autopilot").mkdir(mode=0o700)
    (app/"synthetic.py").write_bytes(b"# synthetic source")
    values={"verified-did.json":{"did":case.f.did},"nonces.json":{},"signer/oracle-signer-receipts.json":{"schema_version":1,"receipts":{}},"autopilot/autopilot-outbox.json":{"outbox":{}}}
    files={name:M.C.G.canonical(value) for name,value in values.items()}
    for name,data in files.items():(state/name).write_bytes(data)
    for name in M.C.G.DATABASES:
        connection=sqlite3.connect(state/name)
        connection.execute("CREATE TABLE messages(seq INTEGER PRIMARY KEY,text TEXT)")
        connection.execute("INSERT INTO messages VALUES (7,'synthetic')");connection.commit();connection.close()
    if wal:(state/(next(iter(M.C.G.DATABASES))+"-wal")).write_bytes(b"synthetic nonempty WAL")
    monkeypatch.setattr(M.C,"ROOTS",(str(app),str(state)))
    epoch=h("new app only held epoch")
    _,manifest,_=M.C.R.T._census_roots({"app":app,"state":state},M.C.G.SOURCE_HEAD,epoch="FROZEN:"+epoch)
    inventory={row["path"][6:]:row["sha256"] for row in manifest["entries"] if row["kind"]=="file" and row["path"].startswith("state/")}
    held=ctl.verify()
    binding=dict(scope_sha=held["scope_sha"],hold_journal_sha=held["journal_sha"],roots_sha=M.C.G.sha(M.C.ROOTS),
        inventory_sha=M.C.G.sha(M.P.original_attempts(files,case.f.did)),ledger_sha=M.P.ledger_digest(files,inventory),epoch=epoch,
        source_cap_bytes=64*1024**2,destination_policy_sha=h("installed exact permanent AWS no replay"),recovery_confirmed=True,cost_cap="ZERO_NEW_BILLING")
    owner=case.f.signed("r1154-preserve",binding,"owner");witness=case.f.signed("r1154-preserve",binding,"independent")
    policy=case.f.signed("r1154-permanent-no-replay",dict(policy_sha=binding["destination_policy_sha"],inventory_sha=binding["inventory_sha"],
        ledger_sha=binding["ledger_sha"],all_five_routes=True,survives_reboot=True,unknown_remains_unknown=True),"destination")
    return ctl,owner,witness,policy


@POSIX
def test_checkpointed_two_sqlite_without_wal_or_shm_real_encrypted_archive(case,tmp_path,monkeypatch):
    ctl,owner,witness,policy=capture_fixture(case,tmp_path,monkeypatch)
    key=os.urandom(48);wire=io.BytesIO()
    result=M.capture_checkpointed(ctl,owner,witness,policy,key,wire,clock=lambda:case.f.now)
    assert result["code"]=="ENCRYPTED_OFFHOST_RESTORE_UNPROVEN" and wire.getvalue().startswith(b"FLOPST01")
    target=tmp_path/"ciphertext"
    M.C.R.W.receive_offhost_ciphertext(io.BytesIO(wire.getvalue()),target,quota_bytes=64*1024**2)
    with M.C.R.LockedArchive(target) as archive:
        manifest,meta=archive.verify(key)
    assert meta["manifest_sha256"]==result["manifest_sha"]
    assert len([row for row in manifest["entries"] if row["path"].endswith("sqlite3")])==2
    assert not any(row["path"].endswith(("-wal","-shm")) for row in manifest["entries"])
    with pytest.raises(ValueError):M.capture_checkpointed(ctl,owner,witness,policy,key,io.BytesIO(),clock=lambda:case.f.now)


@POSIX
def test_nonempty_wal_is_not_silently_treated_as_checkpointed(case,tmp_path,monkeypatch):
    ctl,owner,witness,policy=capture_fixture(case,tmp_path,monkeypatch,wal=True);wire=io.BytesIO()
    with pytest.raises(M.Stop,match="WARM_NONEMPTY_WAL_REQUIRES_RO_WORKER"):
        M.capture_checkpointed(ctl,owner,witness,policy,os.urandom(48),wire,clock=lambda:case.f.now)
    assert not wire.getvalue()


def test_live_recipient_unseal_not_available_to_windows_or_other_users(case):
    recipient,binding,owner,witness=custody(case)
    with pytest.raises((ValueError,KeyError)):
        with K.unseal(case.a,binding,owner,witness,{},recipient,now=case.f.now):pytest.fail("not an enrolled isolated K137 receiver")


def custody(case):
    recipient=X25519PrivateKey.generate()
    continuity=K.S.request(case.a.trust,h("fresh approved transfer"),recipient.public_key().public_bytes_raw().hex())
    binding=dict(continuity=continuity,recipient_public=recipient.public_key().public_bytes_raw().hex(),
        source_head=K.C.G.SOURCE_HEAD,purpose="R1154_ONE_ORIGINAL_DID_ENCRYPTED_CUSTODY")
    owner=case.f.signed("r1154-custody",binding,"owner");witness=case.f.signed("r1154-custody",binding,"independent")
    return recipient,binding,owner,witness


def test_original_did_encrypted_only_and_independent_recipient_derivation(case):
    recipient,binding,owner,witness=custody(case)
    raw=case.f.own.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption());seed=bytearray(raw)
    envelope=K.encrypt(case.a,binding,owner,witness,seed,now=case.f.now)
    assert not any(seed) and raw.hex().encode() not in K.C.G.canonical(envelope)
    with K._unseal_memory(case.a,binding,owner,witness,envelope,recipient,now=case.f.now) as decoded:
        assert bytes(decoded)==raw
        observed=decoded
    assert not any(observed)


@pytest.mark.parametrize("change",["did","recipient","ciphertext","authority","binding"])
def test_custody_rejects_wrong_key_tamper_or_untrusted_approval(case,change):
    recipient,binding,owner,witness=custody(case)
    raw=case.f.own.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption());seed=bytearray(raw)
    if change=="did":
        with pytest.raises(ValueError):K.encrypt(case.a,binding,owner,witness,bytearray(os.urandom(32)),now=case.f.now)
        return
    if change=="authority":
        owner["signature"]="0"*128
        with pytest.raises(ValueError):K.encrypt(case.a,binding,owner,witness,seed,now=case.f.now)
        assert not any(seed);return
    envelope=K.encrypt(case.a,binding,owner,witness,seed,now=case.f.now)
    if change=="recipient":recipient=X25519PrivateKey.generate()
    if change=="ciphertext":
        value=bytearray.fromhex(envelope["ciphertext"]);value[0]^=1;envelope["ciphertext"]=value.hex()
    if change=="binding":binding["purpose"]="UNAPPROVED"
    with pytest.raises(Exception):
        with K._unseal_memory(case.a,binding,owner,witness,envelope,recipient,now=case.f.now):pytest.fail("must not unseal")


@POSIX
def test_provider_gate_wipes_and_never_refetches_after_attempt(case,tmp_path):
    recipient,binding,owner,witness=custody(case)
    root=tmp_path/"records";root.mkdir(mode=0o700);journal=K.H.J.UndoJournal(root)
    raw=bytearray(case.f.own.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()).hex().encode());calls=[]
    envelope=K.provider_once(case.a,binding,owner,witness,journal,lambda:(calls.append(1) or raw),now=case.f.now)
    assert not any(raw) and len(calls)==1
    with pytest.raises(ValueError):K.provider_once(case.a,binding,owner,witness,K.H.J.UndoJournal(root),lambda:pytest.fail("no second Vault access"),now=case.f.now)
    assert envelope["binding"]==binding


def request(case):
    return dict(enrollment=case.f.enrolled,enrollment_sha=case.a.pin,operation="hold",scope=case.scope,owner=None,witness=None)


def test_remote_command_fixed_and_hex_only_no_arbitrary_operation(case):
    req=request(case)
    args=O.fixed_command(["synthetic-ssh"],h("code"),case.a.pin,case.f.context["host"])
    assert len(args)==2 and "sudo -n /opt/technocore-safe-agent/.venv/bin/python -I -B -c" in args[1]
    with pytest.raises(ValueError):O.bootstrap("x;touch /tmp/BAD",case.a.pin,case.f.context["host"])
    req["operation"]="reboot"
    with pytest.raises(ValueError):M.peer(req)


@pytest.mark.parametrize("value",[b"UNTRUSTED-CONTROL",b'{"phase":"R1154","code":"HELD_VM_AND_SSH_UNCHANGED","vm_stop":"STOPPED"}'])
def test_no_raw_ssh_output_or_vm_shutdown_claim_accepted(value):
    with pytest.raises(ValueError):O.checked_result(value,0)


def test_custody_service_isolated_not_automatically_invoked():
    text=(ROOT/"packaging/oracle/r1154-custody.service").read_text()
    assert "User=technocore-signer" in text and "SupplementaryGroups=technocore-autopilot" in text
    assert "Group=technocore\n" not in text and "[Install]" not in text and "Restart=" not in text
    assert "InaccessiblePaths=/etc/technocore-safe-agent/env" in text
    source=Path(K.__file__).read_text()
    assert "get_secret_bundle" not in source  # unchanged original provider only
    assert "os.environ[" not in source and "SIGN_SEED" not in source


@WIN
def test_windows_default_no_credentials_or_ssh():
    result=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",str(ROOT/"packaging/windows/r1154_warm_owner.ps1")],capture_output=True,timeout=15)
    assert result.returncode==42 and result.stderr==b"" and json.loads(result.stdout)["code"]=="WARM_SIGNED_OWNER_REQUIRED"


@WIN
def test_windows_pinned_public_preflight_and_existing_custody_helpers(case,tmp_path):
    path=tmp_path/"request.json";path.write_bytes(M.C.G.canonical(request(case)))
    result=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",str(ROOT/"tests/windows/r1154_owner_contract.ps1"),
        "-RequestFile",str(path),"-RequestSha",hashlib.sha256(path.read_bytes()).hexdigest(),"-EnrollmentSha",case.a.pin],capture_output=True,timeout=45,cwd=ROOT)
    assert result.returncode==0,result.stdout.decode(errors="replace")+result.stderr.decode(errors="replace")
    assert result.stdout.strip()==b"R1154_PS51_OFFLINE=PASS"
