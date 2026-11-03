"""Synthetic only. NO hosts, Vault, real credentials, service commands or POST."""
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import time
import socket
import threading
from types import SimpleNamespace
from datetime import datetime,UTC,timedelta

import pytest
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
import test_r1154_warm as old

ROOT=Path(__file__).resolve().parents[1]
def load(name,leaf):
    sp=importlib.util.spec_from_file_location(name,ROOT/"packaging/migration"/leaf)
    m=importlib.util.module_from_spec(sp);sys.modules[name]=m;sp.loader.exec_module(m);return m
T=load("test_r1155_transfer","r1155_transfer.py")
S=load("test_r1155_signer","r1155_signer.py")
P=load("test_r1155_publisher","r1155_publisher.py")
A=load("test_r1155_activation","r1155_activation.py")
G=load("test_r1155_guard","r1155_guard_monitor.py")
W=T.WAL
POSIX=pytest.mark.skipif(os.name!="posix",reason="POSIX private census/journal")
WIN=pytest.mark.skipif(os.name!="nt",reason="native PS5.1")
case=old.case


class Journal:
    def __init__(self):self.latest=None;self.records=[]
    def save(self,value):self.latest=copy.deepcopy(value);self.records.append(copy.deepcopy(value))


def config(case):
    empty={r:[] for r in S.ROUTES}
    b=dict(epoch=old.h("held epoch"),did=case.f.did,inventory=empty,ledger_sha=old.h("ledger"),nonces={},old_ids=copy.deepcopy(empty),rate_history=[])
    lease=dict(baseline_sha=S.C.G.sha(b),destination=S.H.B.K137,boot_sha=old.h("boot"),source_hold_sha=old.h("hold"),
        restored_manifest_sha=old.h("restored"),custody_sha=old.h("envelope"),activated_at=case.f.now,
        original_post_deny=True,new_only=True,zero_cost=True,runtime_head="f"*40)
    lease.update(scope_sha=S.C.G.sha(case.scope),signer_uid=1101,publisher_uid=1102)
    value=dict(enrollment=case.f.enrolled,enrollment_sha=case.a.pin,baseline=b,baseline_sha=S.C.G.sha(b),lease=lease,
        signer_uid=1101,publisher_uid=1102)
    resign(case,value);return value


def resign(case,value):
    value["baseline_sha"]=S.C.G.sha(value["baseline"]);value["lease"]["baseline_sha"]=value["baseline_sha"]
    value["lease"].update(signer_uid=value["signer_uid"],publisher_uid=value["publisher_uid"])
    value["owner"]=case.f.signed("r1155-activate",value["lease"],"owner")
    value["witness"]=case.f.signed("r1155-activate",value["lease"],"independent")


def request(case,cfg,route=None):
    now=datetime.now(UTC)
    intent=dict(schema_version=1,intent_id="a"*20,source_fingerprint="b"*16,room="lobby",seq=1,category="specific_question",topic="nonce",
        public_knowledge_ids=["public-profile:1"],created_at=now.isoformat(),expires_at=(now+timedelta(hours=1)).isoformat(),safety_decision="concrete_public_technical_request")
    item=dict(route=route or S.ROUTES[0],id=intent["intent_id"],room="lobby",nonce="1770000000000",payload=dict(intent=intent))
    binding=dict(epoch=cfg["baseline"]["epoch"],activation_sha=S.C.G.sha(cfg["lease"]),request_sha=S.C.G.sha(item))
    item["owner"]=case.f.signed("r1155-new-request",binding,"owner")
    item["witness"]=case.f.signed("r1155-new-request",binding,"independent")
    return item


def gate(cfg,**kwargs):return S.activation(cfg,kwargs.get("now",int(time.time())))


def broker(case,cfg,journal=None):
    @contextlib.contextmanager
    def seed():
        material=bytearray(case.f.own.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
        try:yield material
        finally:material[:]=b"\0"*len(material)
    return S.Broker(cfg,seed,journal or Journal(),clock=lambda:case.f.now,gate=gate)


def test_same_did_canonical_signature_fixed_reply_and_peer_boundary(case):
    cfg=config(case);req=request(case,cfg);b=broker(case,cfg)
    with pytest.raises(ValueError):b.sign(req,9999)
    assert b.journal.latest is None
    body=b.sign(req,1102)
    S.C.V.verify_signed_record(req["room"],dict(body,**{"from":case.f.did}))
    assert body["did"]==case.f.did and "strictly increasing" in body["text"]
    assert "text" not in b.journal.latest["used"][S.ROUTES[0]+":"+req["id"]]
    with pytest.raises(ValueError,match="PERMANENT_NO_RETRY"):b.sign(req,1102)
    assert "SIGN_SEED" not in os.environ


def test_original_unicode_full_length_signature_no_truncation(case):
    official=S.K.S.original()
    seed=case.f.own.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
    key=official.Ed25519PrivateKey.from_private_bytes(seed)
    text="あ"*4096;preimage="lobby|1770000000000|"+text
    signature=official.signature(key,preimage)
    S.C.V.verify_did_signature(case.f.did,signature,preimage)
    with pytest.raises(ValueError):S.C.V.verify_did_signature(case.f.did,signature,preimage[:-1])


@POSIX
def test_real_unix_peer_credentials_and_bounded_protocol(case,tmp_path):
    cfg=config(case);cfg["publisher_uid"]=os.geteuid();resign(case,cfg)
    b=broker(case,cfg);req=request(case,cfg);path=tmp_path/"sign.sock";errors=[]
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(str(path));server.listen(1)
        def run():
            try:S.serve(b,server,once=True)
            except Exception as error:errors.append(type(error).__name__)
        thread=threading.Thread(target=run,daemon=True);thread.start()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(5);connection.connect(str(path))
            with connection.makefile("rwb",buffering=0) as stream:S.send_packet(stream,req);reply=S.read_packet(stream)
        thread.join(5)
    assert not errors and not thread.is_alive() and reply["did"]==case.f.did


def test_wrong_original_key_is_not_a_replacement_did(case):
    cfg=config(case);b=broker(case,cfg)
    @contextlib.contextmanager
    def wrong():yield bytearray(os.urandom(32))
    b.open_seed=wrong
    with pytest.raises(ValueError,match="DID_STOP"):b.sign(request(case,cfg),1102)
    assert b.journal.latest is None


def test_did_seed_exists_only_during_sign_and_is_wiped(case):
    cfg=config(case);b=broker(case,cfg);seen=[]
    @contextlib.contextmanager
    def material():
        raw=bytearray(case.f.own.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
        seen.append(raw);yield raw
    b.open_seed=material
    assert not hasattr(b,"seed") and not seen
    b.sign(request(case,cfg),1102)
    assert len(seen)==1 and not any(seen[0])


@pytest.mark.parametrize("route",S.ROUTES)
def test_all_five_old_attempts_are_denied_even_with_fresh_signed_request(case,route):
    cfg=config(case);cfg["baseline"]["old_ids"][route]=["a"*20];resign(case,cfg)
    b=broker(case,cfg);req=request(case,cfg,route)
    with pytest.raises(ValueError,match="OLD_REQUEST"):b.sign(req,1102)
    assert b.journal.latest is None


@pytest.mark.parametrize("field",["nonce","payload","room","authority","did","expiry"])
def test_wrong_binding_key_nonce_or_grant_fails_before_sign(case,field):
    cfg=config(case);req=request(case,cfg)
    if field=="nonce":cfg["baseline"]["nonces"][case.f.did+"|lobby"]=int(req["nonce"]);resign(case,cfg);req=request(case,cfg)
    if field=="payload":req["payload"]["intent"]["topic"]="arbitrary"
    if field=="room":req["room"]="p-private"
    if field=="authority":req["witness"]["signature"]="0"*128
    if field=="did":cfg["baseline"]["did"]="did:key:wrong";resign(case,cfg)
    if field=="expiry":case.f.now+=1000
    b=broker(case,cfg)
    with pytest.raises(Exception):b.sign(req,1102)
    assert b.journal.latest is None


def test_daily_rate_reuses_existing_policy_and_reserves_before_signature(case):
    cfg=config(case)
    cfg["baseline"]["rate_history"]=[dict(at=datetime.now(UTC).isoformat(),room="elsewhere",fingerprint="c"*16) for _ in range(6)]
    resign(case,cfg);b=broker(case,cfg)
    with pytest.raises(ValueError,match="RATE_STOP"):b.sign(request(case,cfg),1102)


@pytest.mark.parametrize("failure",["timeout","bad_receipt","accepted_then_crash"])
def test_unknown_post_permanent_fence_no_repost(case,failure):
    cfg=config(case);req=request(case,cfg);b=broker(case,cfg);j=Journal();calls=[]
    def post(url,**kw):
        calls.append((url,kw));assert "?format=json" in url and "sig=" not in url
        if failure=="timeout":raise TimeoutError("synthetic only")
        body=kw["json"]
        row=dict(**{"from":body["did"]},nonce=body["nonce"],text=body["text"],sig=body["sig"],seq=1,ts="2026-11-03T00:00:00Z")
        if failure=="bad_receipt":row["text"]="different"
        if failure=="accepted_then_crash":
            def save(value):raise OSError("synthetic disk failure")
            j.save=save
        return SimpleNamespace(raise_for_status=lambda:None,json=lambda:dict(posted=row))
    with pytest.raises(Exception):P.publish(cfg,req,j,sign=lambda r:b.sign(r,1102),post=post,gate=gate,clock=lambda:case.f.now)
    with pytest.raises(Exception):P.publish(cfg,req,j,sign=lambda _:pytest.fail("never sign again"),post=post,gate=gate,clock=lambda:case.f.now)
    assert len(calls)==1


def test_success_has_exact_record_durable_ack_and_never_reads_room(case):
    cfg=config(case);req=request(case,cfg);b=broker(case,cfg);j=Journal()
    def post(url,**kw):
        body=kw["json"];row=dict(**{"from":body["did"]},nonce=body["nonce"],text=body["text"],sig=body["sig"],seq=7,ts="2026-11-03T00:00:00Z")
        return SimpleNamespace(raise_for_status=lambda:None,json=lambda:dict(posted=row))
    result=P.publish(cfg,req,j,sign=lambda r:b.sign(r,1102),post=post,gate=gate,clock=lambda:case.f.now)
    assert result["code"]=="NEW_REQUEST_POSTED_ACKNOWLEDGED" and j.latest["record"]["seq"]==7


def wal_snapshot(tmp_path):
    app=tmp_path/"app";state=tmp_path/"state";app.mkdir(mode=0o700);state.mkdir(mode=0o700)
    # SQLite-generated real WAL and SHM copied while connections remain open;
    # all later tests read only frozen synthetic copies after closing writers.
    (app/"public.py").write_bytes(b"# public synthetic app")
    for name in sorted(W.C.G.DATABASES):
        original=tmp_path/("original-"+name)
        c=sqlite3.connect(original);c.execute("PRAGMA journal_mode=WAL");c.execute("PRAGMA wal_autocheckpoint=0")
        c.execute("CREATE TABLE messages(seq INTEGER PRIMARY KEY,text TEXT)");c.commit()
        c.execute("INSERT INTO messages VALUES (97,'synthetic WAL only')");c.commit()
        for suffix in ("","-wal","-shm"):shutil.copyfile(str(original)+suffix,str(state/name)+suffix)
        c.close()
    roots={"app":app,"state":state}
    _,manifest,ids=W.C.R.T._census_roots(roots,W.C.G.SOURCE_HEAD,epoch="FROZEN:"+old.h("same held epoch"))
    return roots,manifest,ids


@POSIX
def test_nonempty_two_wals_real_cursor_raw_evidence_unchanged(tmp_path):
    roots,manifest,ids=wal_snapshot(tmp_path);before={p:p.read_bytes() for p in roots["state"].iterdir()};calls=[]
    result=W.validate(roots,manifest,ids,lambda *args:calls.append(args),parent=tmp_path/"private")
    assert result==[(1,97),(1,97)] and calls
    assert all(p.read_bytes()==raw for p,raw in before.items())


@POSIX
@pytest.mark.parametrize("failure",["missing_shm","corrupt_wal","power_loss","changed_source","space"])
def test_wal_fail_closed_not_ignored(tmp_path,monkeypatch,failure):
    roots,manifest,ids=wal_snapshot(tmp_path)
    wal=next(roots["state"].glob("*-wal"));shm=Path(str(wal)[:-4]+"-shm")
    if failure=="missing_shm":
        shm.unlink();manifest["entries"]=[r for r in manifest["entries"] if r["path"]!="state/"+shm.name]
    if failure=="corrupt_wal":
        data=bytearray(wal.read_bytes());data[-20]^=1;wal.write_bytes(data)
    if failure=="power_loss":wal.write_bytes(wal.read_bytes()[:-10])
    if failure=="changed_source":next(roots["state"].glob("*.sqlite3")).write_bytes(b"modified")
    if failure=="space":monkeypatch.setattr(W.shutil,"disk_usage",lambda _:SimpleNamespace(free=0))
    with pytest.raises(Exception):W.validate(roots,manifest,ids,lambda *args:None,parent=tmp_path/"private")


@POSIX
def test_strict_wal_checksums_reject_rehashed_corrupt_copy(tmp_path):
    roots,manifest,ids=wal_snapshot(tmp_path);wal=next(roots["state"].glob("*-wal"))
    W.strict_wal(wal)
    raw=bytearray(wal.read_bytes());raw[-1]^=1;wal.write_bytes(raw)
    with pytest.raises(ValueError,match="CHECKSUM"):W.strict_wal(wal)


def test_real_sqlite_generated_wal_checksum_cross_platform(tmp_path):
    db=tmp_path/"dummy.sqlite3";c=sqlite3.connect(db)
    try:
        c.execute("PRAGMA journal_mode=WAL");c.execute("CREATE TABLE x(n)");c.commit()
        c.execute("INSERT INTO x VALUES(1)");c.commit()
        W.strict_wal(Path(str(db)+"-wal"))
    finally:c.close()


def transfer_plan(case,tmp_path,monkeypatch):
    old.roots(case,tmp_path,monkeypatch)
    source=tmp_path/"original";source.mkdir(mode=0o700)
    roots,_,_=wal_snapshot(source)
    state=roots["state"]
    (state/"signer").mkdir(mode=0o700);(state/"autopilot").mkdir(mode=0o700)
    values={"verified-did.json":dict(did=case.f.did),"nonces.json":{},
        "signer/oracle-signer-receipts.json":dict(schema_version=1,receipts={}),"autopilot/autopilot-outbox.json":dict(outbox={})}
    files={name:old.M.C.G.canonical(value) for name,value in values.items()}
    for name,data in files.items():(state/name).write_bytes(data)
    for module in (old.M.C,T.H.C,W.C):monkeypatch.setattr(module,"ROOTS",tuple(str(roots[k]) for k in ("app","state")))
    monkeypatch.setattr(T.H,"WORK",old.M.WORK);monkeypatch.setattr(W.H,"WORK",old.M.WORK)
    epoch=old.h("full WAL common held epoch")
    _,manifest,_=old.M.C.R.T._census_roots(roots,old.M.C.G.SOURCE_HEAD,epoch="FROZEN:"+epoch)
    hashes={r["path"][6:]:r["sha256"] for r in manifest["entries"] if r["kind"]=="file" and r["path"].startswith("state/")}
    inventory=old.M.C.G.sha(old.M.P.original_attempts(files,case.f.did));ledger=old.M.P.ledger_digest(files,hashes)
    case.scope["quarantine"].update(inventory_sha=inventory,ledger_sha=ledger);old.approve(case)
    ctl=old.M.Controller(case.a,old.Fake(case));held=ctl.hold(case.scope,now=case.f.now)
    binding=dict(scope_sha=held["scope_sha"],hold_journal_sha=held["journal_sha"],roots_sha=old.M.C.G.sha(old.M.C.ROOTS),
        inventory_sha=inventory,ledger_sha=ledger,epoch=epoch,source_cap_bytes=64*1024**2,
        destination_policy_sha=old.h("installed permanent deny"),recovery_confirmed=True,cost_cap="ZERO_NEW_BILLING")
    policy=case.f.signed("r1154-permanent-no-replay",dict(policy_sha=binding["destination_policy_sha"],inventory_sha=inventory,
        ledger_sha=ledger,all_five_routes=True,survives_reboot=True,unknown_remains_unknown=True),"destination")
    parent=tmp_path/"offhost";parent.mkdir(mode=0o700)
    recipient,custody_binding,custody_owner,custody_witness=old.custody(case)
    seed=bytearray(case.f.own.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
    envelope=old.K.encrypt(case.a,custody_binding,custody_owner,custody_witness,seed,now=case.f.now)
    custody=dict(binding=custody_binding,owner=custody_owner,witness=custody_witness,envelope=envelope)
    plan=dict(enrollment=case.f.enrolled,enrollment_sha=case.a.pin,run_id=case.scope["run_id"],scope=case.scope,
        preserve_owner=case.f.signed("r1154-preserve",binding,"owner"),preserve_witness=case.f.signed("r1154-preserve",binding,"independent"),
        destination_policy=policy,offhost_parent=str(parent),quota_bytes=64*1024**2,custody=custody)
    grant=dict(plan_sha=T.C.G.sha(plan),keep_source_vm_and_ssh=True,disarmed_restore_only=True,zero_new_billing=True)
    plan["owner"]=case.f.signed("r1155-transfer",grant,"owner");plan["witness"]=case.f.signed("r1155-transfer",grant,"independent")
    monkeypatch.setattr(T.H,"Controller",lambda _:ctl)
    return plan,roots,ctl


@POSIX
def test_connected_owner_stream_wal_aead_disarmed_restore_without_network(case,tmp_path,monkeypatch):
    plan,roots,ctl=transfer_plan(case,tmp_path,monkeypatch);calls=[];recovery=os.urandom(48)
    before={p:p.read_bytes() for p in roots["state"].iterdir() if p.is_file()}
    # Windows transport orchestration, real POSIX synthetic sink/AEAD/restore;
    # native PS5.1/NTFS is exercised independently by its existing regression.
    monkeypatch.setattr(T,"os",SimpleNamespace(name="nt",environ={"SystemRoot":str(tmp_path)}))
    monkeypatch.setattr(T,"bases",lambda *_:(["synthetic-source"],["synthetic-destination"]))
    monkeypatch.setattr(T,"bundle",lambda:{"packaging/migration/public.py":"# synthetic"})
    destination=tmp_path/"recipient";destination.mkdir(mode=0o700);disarmed=destination/"disarmed"
    monkeypatch.setattr(T.R.D,"ROOT",disarmed)
    monkeypatch.setattr(T.R.D,"evidence_gate",lambda parent,machine,uid:T.H.need(machine==T.H.B.K137 and uid==1000,"TEST_HOST_STOP"))
    class Pipe(io.BytesIO):
        def __init__(self,process):super().__init__();self.process=process
        def close(self):
            if self.closed:return
            incoming=io.BytesIO(self.getvalue());control=T.R.frame_read(incoming,T.R.MAGIC);req=control["request"];out=io.BytesIO()
            calls.append(req["operation"])
            if req["operation"] in ("source","verify"):T.peer(req,incoming,out)
            elif req["operation"]=="capacity":T.R.frame_write(out,T.R.META,dict(status="CAPACITY_VERIFIED_NOW",runtime_started=False))
            else:
                if not disarmed.exists():disarmed.mkdir(mode=0o700)
                meta=req["meta"]
                result=T.R.D.restore_stream(incoming,plan["run_id"],T.H.B.K137,1000,quota_bytes=plan["quota_bytes"],
                    expected_epoch=meta["epoch"],expected_manifest_sha256=meta["manifest_sha256"],expected_cursors=meta["sqlite_cursors"],
                    preserve_inert_links=True,resume=True)
                T.R.frame_write(out,T.R.META,result)
            self.process.stdout=io.BytesIO(out.getvalue());super().close()
    @contextlib.contextmanager
    def child(args,*,stdin=None,**kwargs):
        process=SimpleNamespace(stdout=io.BytesIO(),wait=lambda **_:0,poll=lambda:0,stderr=None)
        if stdin is None:process.stdin=Pipe(process)
        else:
            T.R.W.receive_offhost_ciphertext(stdin,Path(plan["offhost_parent"])/plan["run_id"],quota_bytes=plan["quota_bytes"])
            process.stdin=None;process.stdout=io.BytesIO(b'{"operation":"CIPHERTEXT_ONLY_NOT_AEAD_VERIFIED"}')
        yield process
    monkeypatch.setattr(T.R,"child",child)
    result=T.owner(dict(plan=plan),recovery)
    assert result["operation"]=="PRESERVED_AND_DISARMED_RESTORED" and calls==["capacity","verify","source","restore"]
    target=disarmed/plan["run_id"]/"state"
    assert all((target/p.name).read_bytes()==raw for p,raw in before.items())
    assert all(p.read_bytes()==raw for p,raw in before.items())
    assert (disarmed/plan["run_id"] / "DISARMED-STREAM-RECEIPT.json").is_file()
    # Re-enter only authenticates existing ciphertext and compares inert
    # restore prefixes. The source encryption is never performed twice.
    T.owner(dict(plan=plan),recovery)
    assert calls.count("source")==1


@POSIX
def test_interrupted_owner_capture_marker_prohibits_new_export(case,tmp_path,monkeypatch):
    plan,roots,ctl=transfer_plan(case,tmp_path,monkeypatch)
    marker=Path(plan["offhost_parent"])/("r1155-"+plan["run_id"]+".json")
    T.R.checkpoint(marker.parent,marker.name,dict(context=case.f.context,meta=None,phase="SOURCE_ATTEMPTING"))
    # None is not a valid completed meta; it cannot authorise a second export.
    with pytest.raises(Exception):T.meta_check(T.C.decode(marker.read_bytes())["meta"],plan)


def test_boot_lease_and_actual_source_hold_not_boolean_substitutes(case):
    cfg=config(case)
    with pytest.raises(Exception):S.local_gate(cfg,publisher=True,now=case.f.now)
    packet=case.f.signed("r1155-source-held",dict(hold_sha=cfg["lease"]["source_hold_sha"],all_scoped_units_masked=True,
        dual_stack_uid_deny=True,source_vm_running=True,ssh_retained=True,old_attempts_permanently_denied=True),"independent")
    A.source_hold(cfg,packet,case.f.now)
    with pytest.raises(Exception):A.source_hold(cfg,packet,case.f.now+31)


@POSIX
def test_guard_checks_real_masks_deny_and_reboot_not_installed_bool(case,tmp_path,monkeypatch):
    import pwd
    cfg=config(case);units=tmp_path/"units";units.mkdir();boot=tmp_path/"boot"
    boot.write_bytes(b"synthetic boot\n");cfg["lease"]["boot_sha"]=hashlib.sha256(b"synthetic boot").hexdigest();resign(case,cfg)
    monkeypatch.setattr(G,"UNITS",units);monkeypatch.setattr(G,"BOOT",boot)
    monkeypatch.setattr(pwd,"getpwnam",lambda n:SimpleNamespace(pw_uid=case.scope["users"][n]))
    for name in case.scope["units"]:os.symlink("/dev/null",units/name)
    calls=[];driver=SimpleNamespace(verify_deny=lambda users:calls.append(users))
    assert G.observe(cfg,case.scope,driver,now=case.f.now)["status"]=="READY" and calls
    (units/next(iter(case.scope["units"]))).unlink()
    with pytest.raises(ValueError,match="MASK_LOST"):G.observe(cfg,case.scope,driver,now=case.f.now)
    os.symlink("/dev/null",units/next(iter(case.scope["units"])));boot.write_bytes(b"rebooted")
    with pytest.raises(ValueError,match="BOOT_STOP"):G.observe(cfg,case.scope,driver,now=case.f.now)


def test_transport_remote_is_fixed_and_binary_stdin_only():
    public={"packaging/migration/public.py":"# synthetic"}
    args=T.command(["ssh.exe"],"restore",public,old.h("machine"),old.h("authority"))
    assert "systemd-run" in args[-1] and "MemoryMax=384M" in args[-1] and "ProtectSystem=strict" in args[-1]
    assert "sys.stdin.buffer" in args[-1] and "m.peer(request,sys.stdin.buffer" in args[-1]
    with pytest.raises(ValueError):T.command(["ssh.exe"],"reboot",public,old.h("machine"),old.h("authority"))


def test_isolated_services_no_vault_auto_start_or_original_paths():
    signer=(ROOT/"packaging/oracle/flop-r1155-signer.service").read_text()
    publisher=(ROOT/"packaging/oracle/flop-r1155-publisher.service").read_text()
    assert "RestrictAddressFamilies=AF_UNIX\n" in signer and "IPAddressDeny=any" in signer
    for text in (signer,publisher):
        assert "EnvironmentFile=" not in text and "[Install]" not in text and "Restart=" not in text
        assert "MemoryMax=128M" in text and "ProtectSystem=strict" in text
        assert "tradebot" in text and "ExecStart=/opt/flop-r1155-runtime/" in text


def test_source_public_config_requires_actual_dedicated_gid_before_writing(case,monkeypatch):
    Q=load("test_r1155_source_setup","r1155_custody_setup.py")
    _,binding,owner,witness=old.custody(case)
    request=dict(enrollment=case.f.enrolled,enrollment_sha=case.a.pin,binding=binding,owner=owner,witness=witness)
    monkeypatch.setattr(Q,"sys",SimpleNamespace(platform="linux",modules=sys.modules))
    monkeypatch.setattr(Q,"os",SimpleNamespace(geteuid=lambda:0,getgrouplist=lambda *args:[]))
    monkeypatch.setitem(sys.modules,"pwd",SimpleNamespace(getpwnam=lambda _:SimpleNamespace(pw_uid=1002,pw_gid=77,pw_name="technocore-signer")))
    monkeypatch.setitem(sys.modules,"grp",SimpleNamespace(getgrnam=lambda name:SimpleNamespace(gr_gid=88 if name=="technocore-signer" else 66)))
    monkeypatch.setattr(Q.H,"Linux",lambda:SimpleNamespace(reader=SimpleNamespace(identity=lambda:dict(host_digest=case.f.context["host"],source_head=Q.C.G.SOURCE_HEAD))))
    with pytest.raises(ValueError,match="SIGNER_GROUP_STOP"):Q.install_source_public(request,case.a.pin)


@WIN
def test_ps51_default_stop_and_parser():
    path=ROOT/"packaging/windows/r1155_warm_transfer.ps1"
    result=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",str(path)],capture_output=True,timeout=15)
    assert result.returncode==42 and result.stderr==b"" and json.loads(result.stdout)["cutover"]=="NO_GO"
    text=path.read_text();assert "-AsSecureString" in text and "OwnerPipe]::Run" in text and "Remove-R1027Custody" in text


@WIN
def test_native_ps51_signed_plan_positive_no_escrow_or_ssh(case,tmp_path):
    binding=dict(inventory_sha=case.scope["quarantine"]["inventory_sha"],ledger_sha=case.scope["quarantine"]["ledger_sha"],
        scope_sha=T.C.G.sha(case.scope),hold_journal_sha=old.h("actual held receipt in real use"),roots_sha=T.C.G.sha(T.C.ROOTS),
        epoch=old.h("held epoch"),source_cap_bytes=524288,destination_policy_sha=old.h("installed no replay"),
        recovery_confirmed=True,cost_cap="ZERO_NEW_BILLING")
    _,cb,co,cw=old.custody(case)
    seed=bytearray(case.f.own.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
    custody=dict(binding=cb,owner=co,witness=cw,envelope=old.K.encrypt(case.a,cb,co,cw,seed,now=case.f.now))
    plan=dict(enrollment=case.f.enrolled,enrollment_sha=case.a.pin,run_id=case.scope["run_id"],scope=case.scope,
        preserve_owner=case.f.signed("r1154-preserve",binding,"owner"),preserve_witness=case.f.signed("r1154-preserve",binding,"independent"),
        destination_policy=case.f.signed("r1154-permanent-no-replay",dict(policy_sha=binding["destination_policy_sha"],
            inventory_sha=binding["inventory_sha"],ledger_sha=binding["ledger_sha"],all_five_routes=True,survives_reboot=True,unknown_remains_unknown=True),"destination"),
        offhost_parent=str(tmp_path),quota_bytes=1048576,custody=custody)
    grant=dict(plan_sha=T.C.G.sha(plan),keep_source_vm_and_ssh=True,disarmed_restore_only=True,zero_new_billing=True)
    plan["owner"]=case.f.signed("r1155-transfer",grant,"owner");plan["witness"]=case.f.signed("r1155-transfer",grant,"independent")
    path=tmp_path/"public-plan.json";path.write_bytes(T.C.G.canonical(plan))
    args=["powershell.exe","-NoProfile","-NonInteractive","-File",str(ROOT/"tests/windows/r1155_transfer_contract.ps1"),
        "-PlanFile",str(path),"-PlanSha",hashlib.sha256(path.read_bytes()).hexdigest(),"-AuthoritySha",case.a.pin]
    result=subprocess.run(args,capture_output=True,cwd=ROOT,timeout=45)
    assert result.returncode==0,result.stdout.decode(errors="replace")+result.stderr.decode(errors="replace")
    assert b"R1155_PS51_OFFLINE=PASS" in result.stdout
