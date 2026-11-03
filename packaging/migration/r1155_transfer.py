"""Warm owner transport: real R1089 AEAD/NTFS -> R1086 DISARMED restore.

No original VM stop, publisher start, global-G4 substitute, or secret discovery.
Control/grants are public. Recovery travels only in binary pipe/SSH memory.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import struct
import stat
import sys
import time

def load(name,leaf):
    sp=importlib.util.spec_from_file_location(name,Path(__file__).with_name(leaf))
    m=importlib.util.module_from_spec(sp);sys.modules[name]=m;sp.loader.exec_module(m);return m
WAL=load("r1155_wal","r1155_wal.py");H=WAL.H;C=H.C;R=C.R
O=load("r1155_old_owner","r1154_owner.py")


def admit(plan,now):
    H.shape(plan,"enrollment enrollment_sha run_id scope preserve_owner preserve_witness destination_policy offhost_parent quota_bytes custody owner witness")
    a=H.Authority(plan["enrollment"],plan["enrollment_sha"])
    # The past HOLD grant is not renewed; fresh preservation/transfer grants
    # and the actual held journal are independently rechecked at acquisition.
    H.validate_scope(a,plan["scope"],now=plan["scope"]["owner"]["body"]["observed_at"])
    H.need(plan["run_id"]==plan["scope"]["run_id"] and type(plan["offhost_parent"]) is str and
        Path(plan["offhost_parent"]).is_absolute(),"TRANSFER_SCOPE_STOP")
    C.integer(plan["quota_bytes"],1,R.T.C.MAX_SOURCE_BYTES)
    preserved=plan["preserve_owner"]["body"]["data"]
    H.shape(preserved,"scope_sha hold_journal_sha roots_sha inventory_sha ledger_sha epoch source_cap_bytes destination_policy_sha recovery_confirmed cost_cap")
    for name in ("scope_sha","hold_journal_sha","roots_sha","inventory_sha","ledger_sha","epoch","destination_policy_sha"):C.digest(preserved[name])
    C.integer(preserved["source_cap_bytes"],1,plan["quota_bytes"])
    H.need(preserved["scope_sha"]==C.G.sha(plan["scope"]) and preserved["roots_sha"]==C.G.sha(C.ROOTS) and
        preserved["recovery_confirmed"] is True and preserved["cost_cap"]=="ZERO_NEW_BILLING","TRANSFER_PRESERVE_BINDING_STOP")
    H.need(a.verify(plan["preserve_owner"],"preserve","owner",now)==preserved and
        a.verify(plan["preserve_witness"],"preserve","independent",now)==preserved,"TRANSFER_PRESERVE_APPROVAL_STOP")
    H.need(preserved["inventory_sha"]==plan["scope"]["quarantine"]["inventory_sha"] and
        preserved["ledger_sha"]==plan["scope"]["quarantine"]["ledger_sha"],"TRANSFER_QUARANTINE_CONSENT_STOP")
    from importlib.util import spec_from_file_location,module_from_spec
    spec=spec_from_file_location("r1155_transfer_custody",Path(__file__).with_name("r1154_custody.py"))
    custody=module_from_spec(spec);spec.loader.exec_module(custody)
    doc=plan["custody"];H.shape(doc,"binding owner witness envelope")
    custody.approved(a,doc["binding"],doc["owner"],doc["witness"],now=doc["owner"]["body"]["observed_at"])
    H.need(doc["envelope"].get("binding")==doc["binding"] and len(C.G.canonical(doc))<=16384,"TRANSFER_CUSTODY_STOP")
    H.shape(doc["envelope"],"version binding ephemeral nonce ciphertext")
    policy=a.verify(plan["destination_policy"],"permanent-no-replay","destination",now)
    H.need(policy==dict(policy_sha=preserved["destination_policy_sha"],inventory_sha=preserved["inventory_sha"],
        ledger_sha=preserved["ledger_sha"],all_five_routes=True,survives_reboot=True,unknown_remains_unknown=True),"TRANSFER_NO_REPLAY_STOP")
    binding={k:v for k,v in plan.items() if k not in ("owner","witness")}
    for key,role in (("owner","owner"),("witness","independent")):
        H.need(a.trust.verify(plan[key],"r1155-transfer",role,now,age=900)==dict(plan_sha=C.G.sha(binding),
            keep_source_vm_and_ssh=True,disarmed_restore_only=True,zero_new_billing=True),"TRANSFER_APPROVAL_STOP")
    return a


def bundle():
    # Every reused source still has its immutable old pin. New files are
    # admitted by the PS5.1 root map; peers also bind the whole bundle SHA.
    result=O.sources()
    pins=C.decode(Path(__file__).with_name("r1155_source_pins.json").read_bytes())
    for name,pin in pins.items():
        raw=(H.ROOT/name).read_bytes().replace(b"\r\n",b"\n")
        H.need(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==pin,"TRANSFER_SOURCE_PIN_STOP")
        if name.endswith((".py",".json",".service")):
            result[name]=raw.decode()
    result["packaging/migration/r1155_source_pins.json"]=Path(__file__).with_name("r1155_source_pins.json").read_text().replace("\r\n","\n")
    H.need(len(C.G.canonical(result))<=R.LIMIT,"TRANSFER_BUNDLE_STOP")
    return result


def command(base,operation,sources,machine,enrollment):
    H.need(operation in ("source","capacity","restore","verify"),"TRANSFER_OPERATION_STOP")
    for value in (machine,enrollment):C.digest(value)
    # R1154's pinned, bounded staging/authentication, with a fixed streaming
    # dispatch. No EOF read before source/restore binary material.
    code=O.bootstrap(C.G.sha(sources),enrollment,machine)
    code=code.replace(" if sys.stdin.buffer.read(1)!=b'':raise ValueError()\n","")
    code=code.replace(" if os.geteuid()!=0 or", " if os.geteuid()!="+("0" if operation in ("source","verify") else "1000")+" or")
    code=code.replace("root/'packaging/migration/r1154_app_hold.py'","root/'packaging/migration/r1155_transfer.py'")
    code=code.replace("not name.startswith(('packaging/migration/','packaging/archive/','src/flop_agent/','scripts/'))",
        "not (name.startswith(('packaging/migration/','packaging/archive/','src/flop_agent/','scripts/','packaging/oracle/')) or name=='public-profile.json')")
    code=code.replace("  response=m.peer(request)\n  sys.stdout.buffer.write(canonical(response)+b'\\n');sys.stdout.buffer.flush()",
        "  m.peer(request,sys.stdin.buffer,sys.stdout.buffer)")
    H.need("response=m.peer(request)" not in code and "m.peer(request,sys.stdin.buffer" in code,"TRANSFER_BOOTSTRAP_STOP")
    if operation in ("source","verify"):
        args=["sudo","-n","/opt/technocore-safe-agent/.venv/bin/python","-I","-B","-c",code]
    else:
        args=["sudo","-n","/usr/bin/systemd-run","--quiet","--pipe","--wait","--collect",
            "--unit=flop-r1155-disarmed-restore.service","--property=User=ubuntu","--property=Group=ubuntu",
            "--property=MemoryMax=384M","--property=CPUQuota=50%","--property=TasksMax=32",
            "--property=NoNewPrivileges=yes","--property=ProtectSystem=strict","--property=ProtectHome=yes",
            "--property=PrivateTmp=yes","--property=PrivateDevices=yes","--property=CapabilityBoundingSet=",
            "--property=ReadWritePaths=/var/lib/flop-migration-r1066","/usr/bin/python3","-I","-B","-c",code]
    return [*base," ".join(shlex.quote(x) for x in args)]


def meta_check(meta,plan):
    H.shape(meta,"schema_version epoch manifest_sha256 files bytes symlinks sqlite_cursors ledger_sha256")
    binding=plan["preserve_owner"]["body"]["data"]
    H.need(meta["schema_version"]==1 and meta["epoch"]=="FROZEN:"+binding["epoch"] and
        0<meta["bytes"]<=min(plan["quota_bytes"],binding["source_cap_bytes"]),"TRANSFER_META_STOP")
    C.digest(meta["manifest_sha256"]);C.digest(meta["ledger_sha256"])
    C.integer(meta["files"],2,R.T.MAX_ARCHIVE_ENTRIES);C.integer(meta["symlinks"],0,meta["files"])
    H.need(type(meta["sqlite_cursors"]) is list and len(meta["sqlite_cursors"])==2,"TRANSFER_META_STOP")
    for row in meta["sqlite_cursors"]:
        H.need(type(row) is list and len(row)==2,"TRANSFER_META_STOP")
        for n in row:C.integer(n)


def peer(request,incoming,outgoing):
    H.shape(request,"enrollment enrollment_sha operation plan meta")
    plan=request["plan"];a=admit(plan,int(time.time()))
    sys.path.insert(0,str(H.ROOT/"src"))
    H.need(request["enrollment"]==plan["enrollment"] and request["enrollment_sha"]==a.pin,"TRANSFER_ENROLLMENT_STOP")
    mode=request["operation"]
    if mode in ("source","verify"):
        ctl=H.Controller(a);held=ctl.verify()
        H.need(held["scope_sha"]==C.G.sha(plan["scope"]),"TRANSFER_HOLD_STOP")
        if mode=="verify":R.frame_write(outgoing,R.META,held);return
        size=struct.unpack(">I",R.exact(incoming,4))[0];H.need(32<=size<=1024,"TRANSFER_RECOVERY_STOP")
        material=bytearray(R.exact(incoming,size))
        try:
            H.need(32<=len(material)<=1024 and incoming.read(1)==b"","TRANSFER_RECOVERY_STOP")
            H.capture_checkpointed(ctl,plan["preserve_owner"],plan["preserve_witness"],plan["destination_policy"],
                bytes(material),outgoing,sqlite_validator=WAL.validate,metadata=lambda x:R.frame_write(outgoing,R.META,x))
        finally:material[:]=b"\0"*len(material)
        return
    H.need(mode in ("capacity","restore"),"TRANSFER_OPERATION_STOP")
    H.need(sys.platform=="linux" and os.geteuid()==1000 and R.D.machine_digest()==a.trust.context["destination"],"TRANSFER_K137_STOP")
    parent=R.D.ROOT.parent
    for part in (parent,*parent.parents):H.need(not part.is_symlink(),"TRANSFER_SANDBOX_STOP")
    info=parent.lstat()
    H.need(stat.S_ISDIR(info.st_mode) and info.st_uid==1000 and stat.S_IMODE(info.st_mode)==0o700,"TRANSFER_SANDBOX_STOP")
    for path in R.T.BLOCKED_ROOTS[2:]:H.need(not os.access(path,os.W_OK),"TRANSFER_SANDBOX_STOP")
    # Actual CURRENT pressure; signed historical free space is not substituted.
    memory={k:int(v.split()[0]) for k,v in (x.split(":",1) for x in Path("/proc/meminfo").read_text().splitlines())}
    H.need(memory["MemAvailable"]>=512*1024,"TRANSFER_MEMORY_STOP")
    for name,limit in (("cpu",5),("io",10)):
        row=Path("/proc/pressure/"+name).read_text().splitlines()[0]
        from decimal import Decimal
        H.need(Decimal(dict(x.split("=",1) for x in row.split()[1:])["avg10"])<=limit,"TRANSFER_PRESSURE_STOP")
    upper=plan["preserve_owner"]["body"]["data"]["source_cap_bytes"]
    resumable=False
    if request["meta"] is not None:
        meta_check(request["meta"],plan)
        resumable=R.resume_present(dict(id=plan["run_id"],manifest_sha256=request["meta"]["manifest_sha256"]))
    needed=R.D.RESERVE+R.D.SQLITE_ALLOWANCE+(0 if resumable else upper)
    H.need(shutil.disk_usage(parent).free>=needed,"TRANSFER_CAPACITY_STOP")
    if mode=="capacity":R.frame_write(outgoing,R.META,dict(status="CAPACITY_VERIFIED_NOW",runtime_started=False));return
    meta=request["meta"];meta_check(meta,plan)
    if not R.D.ROOT.exists():R.D.ROOT.mkdir(mode=0o700)
    result=R.D.restore_stream(incoming,plan["run_id"],a.trust.context["destination"],1000,
        quota_bytes=upper,expected_epoch=meta["epoch"],expected_manifest_sha256=meta["manifest_sha256"],
        expected_cursors=meta["sqlite_cursors"],preserve_inert_links=True,resume=True)
    # Ciphertext-only custody companion outside the inert archive tree, so
    # the existing restorer's prefix/extras checks remain unchanged.
    companion=R.D.ROOT/(plan["run_id"]+"-custody.json");raw=C.G.canonical(plan["custody"])
    if companion.exists():H.need(not companion.is_symlink() and companion.read_bytes()==raw,"TRANSFER_CUSTODY_DRIFT_STOP")
    else:H.exclusive(companion,raw)
    R.frame_write(outgoing,R.META,result)


def bases(control,a):
    H.shape(control,"plan endpoints ssh oci_key oci_hosts k137_hosts")
    ends=control["endpoints"]
    H.need(ends["oci"]["machine_sha256"]==a.trust.context["host"] and ends["k137"]["machine_sha256"]==H.B.K137 and
        ends["k137"]["user"]=="ubuntu" and ends["k137"]["uid"]==1000,"TRANSFER_ENDPOINT_STOP")
    result=[]
    for role in ("oci","k137"):
        e=ends[role];known=Path(control[role+"_hosts"])
        H.need(not known.is_symlink() and known.is_file() and 0<known.stat().st_size<=4096,"TRANSFER_HOST_PIN_STOP")
        H.need(known.read_bytes()==(e["host"]+" "+e["host_key"]+"\n").encode("ascii"),"TRANSFER_HOST_PIN_STOP")
        key=control["oci_key"] if role=="oci" else e["identity_file"]
        path=Path(key);info=path.lstat()
        H.need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and 0<info.st_size<=65536,"TRANSFER_KEY_PIN_STOP")
        material=None
        try:
            with path.open("rb") as f:material=bytearray(f.read(65537))
            H.need(0<len(material)<=65536 and hashlib.sha256(material).hexdigest()==e["credential_sha256"],"TRANSFER_KEY_PIN_STOP")
        finally:
            if material is not None:material[:]=b"\0"*len(material)
        argv=R.SSH.ssh_base(control["ssh"],e["host"],e["user"],key,str(known),hashlib.sha256(known.read_bytes()).hexdigest(),source=role=="oci")
        algorithm=e["host_key"].split()[0]
        H.need(algorithm in ("ecdsa-sha2-nistp256","ssh-ed25519"),"TRANSFER_HOST_PIN_STOP")
        argv[1:1]=["-o","HostKeyAlgorithms="+algorithm,"-o","KnownHostsCommand=none"]
        # OpenSSH option parser requires quotes around Windows paths with spaces.
        for i,value in enumerate(argv):
            if value.startswith("UserKnownHostsFile="):
                path=value.split("=",1)[1].replace("\\","/")
                H.need(not any(c in path for c in ('"','\n','\r')),"TRANSFER_HOST_PIN_STOP")
                argv[i]='UserKnownHostsFile="'+path+'"'
        result.append(argv)
    return result


def owner(control,recovery):
    plan=control["plan"];a=admit(plan,int(time.time()))
    H.need(os.name=="nt","TRANSFER_WINDOWS_CUSTODY_REQUIRED")
    src,dst=bases(control,a);public=bundle();parent=Path(plan["offhost_parent"])
    archive=parent/plan["run_id"];record=parent/("r1155-"+plan["run_id"]+".json")
    ps=str(Path(os.environ["SystemRoot"])/"System32/WindowsPowerShell/v1.0/powershell.exe")
    request=dict(enrollment=plan["enrollment"],enrollment_sha=a.pin,operation="capacity",plan=plan,meta=None)
    if record.exists():
        H.need(record.stat().st_size<=16384 and not record.is_symlink(),"TRANSFER_CUSTODY_STOP")
        saved=C.decode(record.read_bytes());H.need(saved["context"]==a.trust.context,"TRANSFER_CUSTODY_STOP")
        meta_check(saved["meta"],plan);request["meta"]=saved["meta"]
    def rpc(mode,base,req):
        return command(base,mode,public,a.trust.context["host"] if mode in ("source","verify") else H.B.K137,a.pin)
    # Offline destination prepared FIRST. No source HOLD is manufactured here.
    with R.child(rpc("capacity",dst,request),timeout=90) as p:
        R.send_request(p,public,request);cap=R.frame_read(p.stdout,R.META)
        H.need(p.wait(timeout=15)==0 and cap==dict(status="CAPACITY_VERIFIED_NOW",runtime_started=False),"TRANSFER_CAPACITY_STOP")
    with R.child(rpc("verify",src,{**request,"operation":"verify"}),timeout=90) as p:
        R.send_request(p,public,{**request,"operation":"verify"});hold=R.frame_read(p.stdout,R.META)
        H.need(p.wait(timeout=15)==0 and hold["scope_sha"]==C.G.sha(plan["scope"]),"TRANSFER_HOLD_STOP")
    if record.exists():
        H.need(record.stat().st_size<=16384 and not record.is_symlink(),"TRANSFER_CUSTODY_STOP")
        saved=C.decode(record.read_bytes());H.need(saved["context"]==a.trust.context,"TRANSFER_CUSTODY_STOP")
        meta=saved["meta"];meta_check(meta,plan)
    else:
        H.need(not archive.exists(),"TRANSFER_UNKNOWN_NO_AUTO_RETRY")
        H.need(shutil.disk_usage(parent).free>=plan["quota_bytes"]+R.GIB,"TRANSFER_LOCAL_SPACE_STOP")
        request["operation"]="source"
        # Durable marker BEFORE remote invocation: absent result is UNKNOWN.
        R.checkpoint(parent,record.name,dict(context=a.trust.context,meta=None,phase="SOURCE_ATTEMPTING"))
        with R.child(rpc("source",src,request)) as p:
            R.send_request(p,public,request,recovery);meta=R.frame_read(p.stdout,R.META);meta_check(meta,plan)
            R.checkpoint(parent,record.name,dict(context=a.trust.context,meta=meta,phase="RECEIVING"))
            args=[ps,"-NoProfile","-NonInteractive","-File",str(Path(__file__).with_name("r1085_windows_offhost_sink.ps1")),
                "-ExistingPrivateNtfsParent",str(parent),"-NewArchiveFolder",plan["run_id"],"-QuotaBytes",str(plan["quota_bytes"]),"-AllowCiphertextOnly"]
            with R.child(args,stdin=p.stdout) as sink:
                received=R.bounded_result(sink)
                H.need(received["operation"]=="CIPHERTEXT_ONLY_NOT_AEAD_VERIFIED" and p.wait(timeout=30)==0,"TRANSFER_UNKNOWN_NO_AUTO_RETRY")
    with R.LockedArchive(archive,windows_validator=R.windows_custody) as held:
        manifest,proof=held.verify(recovery)
        H.need(all(meta[k]==v for k,v in proof.items()),"TRANSFER_AEAD_STOP")
        R.checkpoint(parent,record.name,dict(context=a.trust.context,meta=meta,phase="AEAD_VERIFIED"))
        # Fresh owner leases are checked again; no forged R1089 G4/G5 PASS.
        admit(plan,int(time.time()))
        request.update(operation="restore",meta=meta)
        with R.child(rpc("restore",dst,request)) as p:
            R.send_request(p,public,request);held.stream(recovery,p.stdin);p.stdin.close();p.stdin=None
            restored=R.frame_read(p.stdout,R.META)
            H.need(p.wait(timeout=30)==0 and p.stdout.read(1)==b"","TRANSFER_RESTORE_UNKNOWN")
        H.need(all(restored[k]==meta[k] for k in ("manifest_sha256","files","bytes","symlinks","sqlite_cursors")),"TRANSFER_RESTORE_STOP")
        R.checkpoint(parent,record.name,dict(context=a.trust.context,meta=meta,phase="DISARMED_RESTORED"))
    return dict(task="R1155",operation="PRESERVED_AND_DISARMED_RESTORED",cutover="NO_GO",oci_retirement="STRICT_NO_GO")


def main():
    recovery_bytes=bytearray()
    try:
        H.need(sys.argv[1:] in (["--owner"],["--check-plan"]),"TRANSFER_ARGUMENT_STOP")
        control=R.frame_read(sys.stdin.buffer,R.MAGIC)
        if sys.argv[1:]==["--check-plan"]:
            admit(control["plan"],int(time.time()));print('{"operation":"OWNER_SESSION_VERIFIED","cutover":"NO_GO"}');return 0
        n=struct.unpack(">I",R.exact(sys.stdin.buffer,4))[0];H.need(32<=n<=1024,"TRANSFER_RECOVERY_STOP")
        recovery_bytes.extend(R.exact(sys.stdin.buffer,n));H.need(sys.stdin.buffer.read(1)==b"","TRANSFER_INPUT_STOP")
        print(C.G.canonical(owner(control,bytes(recovery_bytes))).decode());return 0
    except Exception:
        print('{"task":"R1155","operation":"BLOCKED","code":"TRANSFER_STOP_UNKNOWN_NO_AUTO_RETRY","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}');return 42
    finally:recovery_bytes[:]=b"\0"*len(recovery_bytes)


if __name__=="__main__":raise SystemExit(main())
