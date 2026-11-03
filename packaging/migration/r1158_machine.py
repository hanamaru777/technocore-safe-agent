"""Root-only fixed-function machine evidence. NO human-witness role.

No DID key, Vault, arbitrary preimage/command, POST or source VM control.
Machine keys never leave their host. Setup/quarantine are explicit operations;
probes read the existing OS boundary and sign only the fixed safe schema.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import time
from decimal import Decimal

sp=importlib.util.spec_from_file_location("r1158_machine_transfer",Path(__file__).with_name("r1155_transfer.py"))
T=importlib.util.module_from_spec(sp);sys.modules[sp.name]=T;sp.loader.exec_module(T)
H=T.H;C=T.C;V=H.solo_module()
STORE=Path("/var/lib/flop-r1158-machine")
UNIT=H.UNITS/"flop-r1158-legacy-post-deny.service"


def identity(a,role,*,verify_boot=True):
    H.need(sys.platform=="linux" and os.geteuid()==0 and role in ("oci","k137"),"SOLO_ROOT_HOST_REQUIRED")
    machine=hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
    raw=Path("/proc/sys/kernel/random/boot_id").read_bytes()
    # Archive source uses the legacy raw-byte witness. Existing K137 runtime
    # uses stripped boot_id. Preserve both established contracts explicitly.
    boot=hashlib.sha256(raw if role=="oci" else raw.strip()).hexdigest()
    H.need(machine==a.trust.context["host" if role=="oci" else "destination"] and
        (not verify_boot or boot==a.profile["boots"][role]),"SOLO_HOST_BOOT_STOP")
    if role=="oci":H.need(H.Linux().reader.identity()["source_head"]==C.G.SOURCE_HEAD,"SOLO_SOURCE_HEAD_STOP")
    else:H.need(machine==H.B.K137,"SOLO_TARGET_HOST_STOP")
    return machine,boot


def machine_key(a,role,*,initialize=False,key_factory=None):
    identity(a,role)
    import resource
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption,load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    root=H.private_dir(STORE);path=root/"machine-only.pem"
    owner_id=next(iter(a.trust.keys))
    if initialize:
        H.need(not path.exists() and not (root/"owner.json").exists(),"SOLO_MACHINE_ALREADY_ENROLLED")
        key=(key_factory or Ed25519PrivateKey.generate)()
        H.exclusive(root/"owner.json",C.G.canonical(dict(owner_id=owner_id,context=a.trust.context,role=role)))
        H.exclusive(path,key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    owner=C.decode((root/"owner.json").read_bytes())
    H.need(owner==dict(owner_id=owner_id,context=a.trust.context,role=role),"SOLO_MACHINE_CUSTODY_STOP")
    info=path.lstat();H.need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_uid==0 and
        stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=4096,"SOLO_MACHINE_CUSTODY_STOP")
    key=load_pem_private_key(path.read_bytes(),password=None)
    H.need(isinstance(key,Ed25519PrivateKey),"SOLO_MACHINE_CUSTODY_STOP")
    if not initialize:H.need(key.public_key().public_bytes_raw().hex()==a.profile["machine_keys"][role],"SOLO_MACHINE_PIN_STOP")
    return key


def resources():
    import shutil
    raw=Path("/proc/meminfo").read_text()
    values={k:int(v.split()[0])*1024 for k,v in (line.split(":",1) for line in raw.splitlines())}
    metrics=dict(free_bytes=shutil.disk_usage("/var/lib").free,memory_headroom_bytes=values["MemAvailable"],
        total_memory_bytes=values["MemTotal"])
    for name in ("cpu","io"):
        fields=dict(x.split("=",1) for x in (Path("/proc/pressure")/name).read_text().splitlines()[0].split()[1:])
        metrics[name+"_psi_milli"]=int(Decimal(fields["avg10"])*1000)
    return metrics


def target_rules(a,scope,*,prepare=False,consent=None):
    identity(a,"k137");driver=H.Linux()
    expected=H.boot_unit(scope["users"].values(),scope["units"])
    if prepare:
        data=dict(scope_sha=C.G.sha(scope),policy_sha=hashlib.sha256(expected).hexdigest(),all_five_routes=True,
            unknown_remains_unknown=True,zero_cost=True)
        H.need(a.trust.verify(consent,"r1154-permanent-no-replay","owner",int(time.time()))==data,"SOLO_QUARANTINE_CONSENT_REQUIRED")
        # Never apply a UID rule to an existing unrelated account/process.
        import pwd
        H.need(not any(p.pw_uid in scope["users"].values() for p in pwd.getpwall()),"SOLO_TARGET_UID_CONFLICT")
        for path in Path("/proc").iterdir():
            if not path.name.isdigit():continue
            try:raw=(path/"status").read_bytes()
            except FileNotFoundError:raise H.Stop("SOLO_PROCESS_RACE_STOP") from None
            match=C.G.re.search(rb"^Uid:\s+(\d+)",raw,C.G.re.M)
            H.need(match is not None and int(match[1]) not in scope["users"].values(),"SOLO_TARGET_UID_CONFLICT")
        H.need(not UNIT.exists() and not UNIT.is_symlink(),"SOLO_QUARANTINE_ALREADY_ATTEMPTED")
        for name in scope["units"]:H.need(not (H.UNITS/name).exists() and not (H.UNITS/name).is_symlink(),"SOLO_EXISTING_TARGET_UNIT_STOP")
        H.exclusive(STORE/"QUARANTINE_ATTEMPTING",C.G.canonical(data))
        driver.post_deny(scope["users"])
        H.exclusive(UNIT,expected);os.chmod(UNIT,0o644)
        os.symlink("../"+UNIT.name,H.UNITS/"sysinit.target.wants"/UNIT.name)
        H.sync(H.UNITS/"sysinit.target.wants");H.sync(H.UNITS)
    H.need(UNIT.is_file() and not UNIT.is_symlink() and UNIT.read_bytes()==expected and
        os.readlink(H.UNITS/"sysinit.target.wants"/UNIT.name)=="../"+UNIT.name,"SOLO_TARGET_NO_REPLAY_NOT_PROVEN")
    driver.verify_deny(scope["users"])
    return True


def target_activation(a,scope,r):
    """Read-only actual restore/one-writer/cgroup budget, never guessed peaks."""
    S=C.legacy("r1155_signer.py");driver=H.Linux()
    # All fixed new writers must have actual bounded units. Unknown memory.max
    # or an unidentified protected TradeBot is NOT zero consumption.
    protected=a.profile.get("protected_tradebot")
    if not protected:return False,False
    H.shape(protected,"unit")
    H.need(type(protected["unit"]) is str and C.G.re.fullmatch(r"(?i)tradebot[a-z0-9_-]*\.service",protected["unit"]),"SOLO_PROTECTED_UNIT_STOP")
    roles=["flop-r1155-signer.service","flop-r1155-publisher.service","flop-r1155-guard-monitor.service","flop-r1156-resident.service","flop-r1156-capture.service"]
    caps=[];pub_pid=0
    for unit in [protected["unit"],*roles]:
        raw=driver.command(["/usr/bin/systemctl","show","--no-pager","--property=LoadState,MemoryMax,MemoryCurrent,MainPID","--",unit]).stdout
        fields=dict(line.split("=",1) for line in raw.decode("ascii","strict").splitlines())
        if fields.get("MainPID")=="0" and fields.get("MemoryCurrent")=="[not set]":fields["MemoryCurrent"]="0"
        H.need(set(fields)=={"LoadState","MemoryMax","MemoryCurrent","MainPID"} and fields["LoadState"]=="loaded" and
            all(fields[k].isdigit() for k in ("MemoryMax","MemoryCurrent","MainPID")),"SOLO_MEMORY_BUDGET_NOT_PROVEN")
        caps.append((int(fields["MemoryMax"]),int(fields["MemoryCurrent"])))
        if unit==roles[1]:pub_pid=int(fields["MainPID"])
    maximum,current=caps[0]
    H.need(maximum>=1200*1024**2,"SOLO_TRADEBOT_PROTECTION_CHANGED")
    required=max(0,maximum-current)+sum(max(0,cap-used) for cap,used in caps[1:])+256*1024**2
    fits=r["memory_headroom_bytes"]>=required
    config=S.secured(S.CONFIG);S.activation(config,config["owner"]["body"]["observed_at"])
    H.need(config["enrollment_sha"]==a.pin,"SOLO_ACTIVATION_BINDING_STOP")
    actors=[]
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():continue
        try:raw=(path/"status").read_bytes()
        except FileNotFoundError:raise H.Stop("SOLO_PROCESS_RACE_STOP") from None
        match=C.G.re.search(rb"^Uid:\s+(\d+)",raw,C.G.re.M)
        H.need(match is not None,"SOLO_PROCESS_RACE_STOP")
        if int(match[1])==config["publisher_uid"]:actors.append(int(path.name))
    H.need(actors==([pub_pid] if pub_pid else []),"SOLO_MULTIPLE_PUBLISHERS_STOP")
    restored=C.R.D.ROOT/scope["run_id"]
    receipt=C.decode((restored/"DISARMED-STREAM-RECEIPT.json").read_bytes())
    did=restored/"state/verified-did.json"
    H.need(not did.is_symlink() and did.stat().st_size<=4096,"SOLO_DID_RESTORE_NOT_PROVEN")
    same=(C.decode(did.read_bytes()).get("did")==a.profile["source_did"] and receipt["runtime_started"] is False and
        receipt["manifest_sha256"]==config["lease"]["restored_manifest_sha"] and receipt["source_epoch"]=="FROZEN:"+config["baseline"]["epoch"])
    return fits,same


def probe(a,role,scope,challenge,*,key=None):
    machine,boot=identity(a,role);C.digest(challenge)
    key=key or machine_key(a,role)
    # Historical HOLD consent proves the stop was authorized. Read-only OS
    # observation doesn't renew it; current write/export consent is separate.
    at=scope["owner"]["body"]["observed_at"];H.validate_scope(a,scope,now=at)
    data=dict(scope_sha=C.G.sha(scope),source_vm_running=False,ssh_retained=False,scope_preflight_verified=False,g4_complete=False,
        g5_quarantine_complete=False,old_post_deny_verified=False,single_writer_verified=False,publisher_active=False,free_bytes=0,remaining_bytes=0,
        memory_headroom_bytes=0,cpu_psi_milli=0,io_psi_milli=0,tradebot_budget_verified=False,same_did_restored=False,
        upstream_finality="UNKNOWN_REMAINS_UNKNOWN")
    if role=="oci":
        driver=H.Linux();driver.identity(scope);driver.protected()
        H.need(driver.launchers()==scope["launcher_sha"],"SOLO_LAUNCHER_DRIFT_STOP")
        if H.WORK.exists():
            try:
                H.Controller(a,driver).verify() # actual masks, UID deny, namespaces/fds
                data.update(g4_complete=True,g5_quarantine_complete=True)
            except ValueError:
                # Partial-HOLD evidence permits disarmed rollback only.
                H.Controller(a,driver).status();driver.verify_deny(scope["users"])
                data.update(g4_complete=False,g5_quarantine_complete=True)
            H.need(C.decode((H.WORK/"scope.json").read_bytes())==scope,"SOLO_SCOPE_DRIFT_STOP")
        else:
            H.need(driver.discovered()==set(scope["units"]) and all(driver.unit(n)==v for n,v in scope["units"].items()),"SOLO_SCOPE_DRIFT_STOP")
        data.update(source_vm_running=True,ssh_retained=True,scope_preflight_verified=True)
    else:
        target_rules(a,scope);r=resources()
        data.update(old_post_deny_verified=True,single_writer_verified=True,**{k:v for k,v in r.items() if k!="total_memory_bytes"})
        data["remaining_bytes"]=scope["destination"]["data"]["source_upper_bound_bytes"]
        # Before activation no existing new publisher may be active. For
        # activation, separately measure its UID/process and protected budget.
        active=H.Linux().command(["/usr/bin/systemctl","is-active","flop-r1155-publisher.service"],allowed=(0,3,4)).returncode==0
        data["publisher_active"]=active
        if active:data["single_writer_verified"]=False
        try:
            data["tradebot_budget_verified"],data["same_did_restored"]=target_activation(a,scope,r)
            data["single_writer_verified"]=True
        except (ValueError,OSError,KeyError):pass
    import fcntl
    with (STORE/"seq.lock").open("ab") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        seqfile=STORE/"seq.json";seq=1
        if seqfile.exists():seq=C.decode(seqfile.read_bytes())["seq"]+1
        C.R.checkpoint(STORE,seqfile.name,dict(seq=seq))
        now=int(time.time());body=dict(schema_version=2,mode="MACHINE_ONLY_NO_HUMAN_INDEPENDENCE",role=role,
            authority_sha=a.pin,scope_sha=C.G.sha(scope),machine=machine,boot=boot,observed_at=now,
            expires_at=now+V.MAX_OBSERVATION_AGE,challenge=challenge,seq=seq,data=data)
        return dict(body=body,signature=key.sign(V.MACHINE_DOMAIN+C.G.canonical(body)).hex())


def peer(request,incoming=None,outgoing=None):
    """Staged ONLY by the pinned carrier; no untrusted operation/path/env."""
    a=H.Authority(request["enrollment"],request["enrollment_sha"])
    H.need(H.solo(a),"SOLO_VERSION_REQUIRED")
    operation=request["operation"]
    if operation in ("source","capacity","restore","verify"):
        H.need(incoming is not None and outgoing is not None,"SOLO_STREAM_REQUIRED")
        envelope=request["evidence"];clean={k:v for k,v in request.items() if k!="evidence"}
        H.shape(envelope,"oci k137")
        role="oci" if operation in ("source","verify") else "k137"
        scope=request["plan"]["scope"]
        if role=="oci":
            identity(a,role);live=live_source(a,scope)
        else:
            H.need(sys.platform=="linux" and os.geteuid()==1000 and C.R.D.machine_digest()==H.B.K137,"SOLO_TARGET_HOST_STOP")
            live=V.LiveChecks(a,lambda:envelope["oci"],lambda:envelope["k137"],clock=time.time)
        live.check("export" if role=="oci" else "restore",scope)
        return T.peer(clean,incoming,outgoing,controller_factory=lambda authority:H.Controller(authority,live=live))
    role=request["role"]
    if operation=="host-info":
        H.shape(request,"enrollment enrollment_sha operation role")
        machine,boot=identity(a,role,verify_boot=False)
        return dict(code="PINNED_READ_ONLY_BOOT_BINDING",role=role,machine=machine,boot=boot,cutover="NO_GO")
    identity(a,role);operation=request["operation"]
    H.need(operation in ("machine-init","machine-public","recipient-proof","initial-capacity","probe","inventory","prepare-quarantine","publish-target-evidence","hold","rollback","runtime-check","prepare-identities","stage-runtime","source-custody-once","source-custody-read"),"SOLO_OPERATION_REJECTED")
    extra={"machine-init":"owner","machine-public":"","recipient-proof":"","initial-capacity":"upper units owner",
        "probe":"scope challenge","inventory":"scope owner","prepare-quarantine":"scope owner",
        "publish-target-evidence":"scope packet owner","hold":"scope","rollback":"scope owner",
        "runtime-check":"challenge owner source inventory_evidence","prepare-identities":"request","stage-runtime":"request",
        "source-custody-once":"request","source-custody-read":"request"}[operation]
    H.shape(request,"enrollment enrollment_sha operation role "+extra)
    if operation in ("prepare-identities","stage-runtime"):
        H.need(role=="k137","SOLO_ROLE_OR_OPERATION_REJECTED")
        U=C.legacy("r1156_setup.py");document=request["request"]
        profile=document if operation=="prepare-identities" else document["config"]
        H.need(profile["enrollment_sha"]==a.pin and profile["enrollment"]==a.profile,"SOLO_SETUP_CONSENT_REQUIRED")
        return U.identities(document) if operation=="prepare-identities" else U.stage(document)
    if operation in ("source-custody-once","source-custody-read"):
        H.need(role=="oci","SOLO_ROLE_OR_OPERATION_REJECTED")
        U=C.legacy("r1155_custody_setup.py");K=U.K;document=request["request"]
        H.shape(document,"enrollment enrollment_sha binding owner witness")
        H.need(document["enrollment"]==a.profile and document["enrollment_sha"]==a.pin,"SOLO_SETUP_CONSENT_REQUIRED")
        at=int(time.time()) if operation=="source-custody-once" else document["owner"]["body"]["observed_at"]
        K.approved(a,document["binding"],document["owner"],document["witness"],now=at)
        if operation=="source-custody-once":
            H.need(not K.STATE.exists(),"SOLO_CUSTODY_ATTEMPT_EXISTS_NO_RETRY")
            driver=H.Linux();driver.protected()
            U.install_source_public(document,a.pin)
            H.exclusive(STORE/"CUSTODY_LAUNCH_ATTEMPTING",C.G.canonical(dict(binding_sha=C.G.sha(document["binding"]))))
            # The existing isolated oneshot alone retrieves/uses/wipes the
            # original seed. Root/Windows receive only its encrypted envelope.
            driver.command(["/usr/bin/systemctl","start","r1154-custody.service"])
        import pwd
        uid=pwd.getpwnam("technocore-signer").pw_uid;path=K.STATE/"recipient-envelope.json";info=path.lstat()
        H.need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_uid==uid and info.st_nlink==1 and
            stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=16384,"SOLO_CUSTODY_RECEIPT_NOT_PROVEN")
        envelope=C.decode(path.read_bytes());H.shape(envelope,"version binding ephemeral nonce ciphertext")
        H.need(envelope["binding"]==document["binding"],"SOLO_CUSTODY_RECEIPT_NOT_PROVEN")
        return dict(binding=document["binding"],owner=document["owner"],witness=None,envelope=envelope)
    if operation=="machine-public":
        H.need(STORE.is_dir() and not STORE.is_symlink(),"SOLO_MACHINE_ATTESTER_NOT_ENROLLED")
        owner=C.decode((STORE/"owner.json").read_bytes())
        H.need(owner==dict(owner_id=next(iter(a.trust.keys)),context=a.trust.context,role=role),"SOLO_MACHINE_CUSTODY_STOP")
        value=C.decode((STORE/"public.json").read_bytes())
        return dict(code="MACHINE_ONLY_PUBLIC_KEY",role=role,public_hex=value["public_hex"],boot=a.profile["boots"][role],cutover="NO_GO")
    if operation=="recipient-proof":
        H.need(role=="k137","SOLO_ROLE_OR_OPERATION_REJECTED")
        S=C.legacy("r1155_signer.py")
        import pwd
        uid=pwd.getpwnam("technocore-signer").pw_uid
        path=S.STORE/"recipient-public.json";info=path.lstat()
        H.need(uid>1000 and stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_uid==uid and
            info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=4096,"SOLO_RECIPIENT_NOT_PROVEN")
        public=C.decode(path.read_bytes());H.shape(public,"recipient_public plaintext_persisted")
        H.need(public["plaintext_persisted"] is False,"SOLO_RECIPIENT_NOT_PROVEN");C.digest(public["recipient_public"])
        now=int(time.time());body=dict(mode="MACHINE_ONLY_RECIPIENT",authority_sha=a.pin,machine=a.trust.context["destination"],boot=a.profile["boots"][role],
            did_sha=a.trust.context["did"],recipient_public=public["recipient_public"],observed_at=now,expires_at=now+V.MAX_SESSION)
        return dict(body=body,signature=machine_key(a,role).sign(V.MACHINE_DOMAIN+C.G.canonical(body)).hex())
    if operation=="initial-capacity":
        H.need(role=="k137","SOLO_ROLE_OR_OPERATION_REJECTED")
        C.integer(request["upper"],1,C.R.T.C.MAX_SOURCE_BYTES);r=resources();driver=H.Linux()
        H.need(len(request["units"])<=128 and all(H.J.NAME.fullmatch(n) and n not in H.PROTECTED for n in request["units"]),"SOLO_SCOPE_DRIFT_STOP")
        expected=dict(destination=a.trust.context["destination"],upper=request["upper"],units_sha=C.G.sha(request["units"]),existing_host_only=True,zero_new_billing=True)
        H.need(a.trust.verify(request["owner"],"r1158-capacity","owner",int(time.time()))==expected,"SOLO_ZERO_COST_CONSENT_REQUIRED")
        ready=all(driver.command(["/usr/bin/systemctl","is-active",name],allowed=(0,3,4)).returncode in (3,4)
            for name in ("flop-r1155-publisher.service",*request["units"]))
        data=dict(machine=H.B.K137,free_bytes=r["free_bytes"],source_upper_bound_bytes=request["upper"],memory_headroom_bytes=r["memory_headroom_bytes"],
            cpu_psi_milli=r["cpu_psi_milli"],io_psi_milli=r["io_psi_milli"],disarmed_ready=ready,publisher_disarmed=ready,zero_cost_verified=True)
        body=dict(mode="MACHINE_ONLY_INITIAL_CAPACITY",authority_sha=a.pin,boot=a.profile["boots"][role],observed_at=int(time.time()),data=data)
        return dict(body=body,signature=machine_key(a,role).sign(V.MACHINE_DOMAIN+C.G.canonical(body)).hex())
    if operation=="probe":return probe(a,role,request["scope"],request["challenge"])
    if operation=="inventory":
        H.need(role=="oci","SOLO_ROLE_OR_OPERATION_REJECTED")
        return frozen_inventory(a,request["scope"],request["owner"])
    if operation in ("hold","rollback"):
        H.need(role=="oci","SOLO_ROLE_OR_OPERATION_REJECTED")
        live=live_source(a,request["scope"]);controller=H.Controller(a,live=live)
        if operation=="hold":return controller.hold(request["scope"],now=int(time.time()))
        return controller.rollback(request["owner"],None,now=int(time.time()))
    if operation=="runtime-check":
        H.need(role=="k137","SOLO_ROLE_OR_OPERATION_REJECTED")
        N=C.legacy("r1156_renewal.py");config=N.S.secured(N.S.CONFIG)
        scope=C.decode(N.S.CONFIG.with_name("scope.json").read_bytes())
        target=probe(a,"k137",scope,request["challenge"])
        packet=dict(mode="SOLO_OWNER_MACHINE_RECHECK",owner=request["owner"],evidence=dict(oci=request["source"],k137=target),inventory_evidence=request["inventory_evidence"])
        return N.install_runtime(config,packet)
    # Serialize key/counter/CAS changes; process crash releases the OS lock.
    root=H.private_dir(STORE)
    import fcntl
    with (root/"lock").open("ab") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if operation=="machine-init":
            expected=dict(role=role,machine=a.trust.context["host" if role=="oci" else "destination"],boot=a.profile["boots"][role])
            H.need(a.trust.verify(request["owner"],"r1158-machine-init","owner",int(time.time()))==expected,"SOLO_SETUP_CONSENT_REQUIRED")
            key=machine_key(a,role,initialize=True)
            H.exclusive(STORE/"public.json",C.G.canonical(dict(public_hex=key.public_key().public_bytes_raw().hex())))
            return dict(code="MACHINE_ONLY_KEY_INITIALIZED",role=role,public_hex=key.public_key().public_bytes_raw().hex(),boot=a.profile["boots"][role],cutover="NO_GO")
        key=machine_key(a,role)
        if operation=="prepare-quarantine":
            H.need(role=="k137","SOLO_ROLE_OR_OPERATION_REJECTED")
            target_rules(a,request["scope"],prepare=True,consent=request["owner"])
            return dict(code="LEGACY_FIVE_ROUTE_QUARANTINE_INSTALLED",cutover="NO_GO")
        if operation=="publish-target-evidence":
            H.need(role=="oci","SOLO_ROLE_OR_OPERATION_REJECTED")
            consent=request["owner"]
            H.need(a.trust.verify(consent,"r1158-monitor-session","owner",int(time.time()))==
                dict(scope_sha=C.G.sha(request["scope"]),source_boot=a.profile["boots"]["oci"],target_boot=a.profile["boots"]["k137"]),"SOLO_MONITOR_CONSENT_REQUIRED")
            packet=request["packet"];V.machine_verify(a,packet,"k137",request["scope"],int(time.time()))
            path=root/(C.G.sha(request["scope"])+".json")
            if path.exists():
                old=C.decode(path.read_bytes());prior=old["packet"]
                reset=C.G.sha(consent)!=C.G.sha(old["owner"]) and consent["body"]["observed_at"]>prior["body"]["expires_at"]
                H.need(packet==prior or packet["body"]["seq"]>prior["body"]["seq"] and
                    (packet["body"]["observed_at"]<=prior["body"]["expires_at"] or reset),"SOLO_LATE_OR_REPLAYED_MACHINE_CHECK")
            C.R.checkpoint(root,path.name,dict(owner=consent,packet=packet))
            return dict(code="MACHINE_CHECK_INSTALLED",cutover="NO_GO")
        return probe(a,role,request["scope"],request["challenge"],key=key)


def live_source(a,scope):
    def destination():
        value=C.decode((STORE/(C.G.sha(scope)+".json")).read_bytes())
        H.need(a.trust.verify(value["owner"],"r1158-monitor-session","owner",int(time.time()))==dict(scope_sha=C.G.sha(scope),
            source_boot=a.profile["boots"]["oci"],target_boot=a.profile["boots"]["k137"]),"SOLO_MONITOR_CONSENT_REQUIRED")
        return value["packet"]
    return V.LiveChecks(a,lambda:probe(a,"oci",scope,os.urandom(32).hex()),destination,clock=time.time)


def frozen_inventory(a,scope,owner):
    identity(a,"oci");key=machine_key(a,"oci")
    data=a.trust.verify(owner,"r1158-inventory","owner",int(time.time()))
    H.shape(data,"scope_sha source_cap_bytes encrypted_only keep_vm_and_ssh")
    H.need(data["scope_sha"]==C.G.sha(scope) and data["encrypted_only"] is True and data["keep_vm_and_ssh"] is True,"SOLO_INVENTORY_CONSENT_REQUIRED")
    C.integer(data["source_cap_bytes"],1,C.R.T.C.MAX_SOURCE_BYTES)
    controller=H.Controller(a);held=controller.verify()
    H.need(held["scope_sha"]==C.G.sha(scope),"SOLO_SCOPE_DRIFT_STOP")
    epoch=C.G.sha(dict(scope_sha=held["scope_sha"],journal_sha=held["journal_sha"],run_id=scope["run_id"]))
    roots=dict(zip(("app","state"),(Path(p) for p in C.ROOTS)))
    roots,manifest,ids=C.R.T._census_roots(roots,C.G.SOURCE_HEAD,epoch="FROZEN:"+epoch)
    hashes={r["path"][6:]:r["sha256"] for r in manifest["entries"] if r["kind"]=="file" and r["path"].startswith("state/")}
    files={};total=0
    for name,digest in hashes.items():
        if name.startswith(("signer/","autopilot/","close1/")) or name in ("verified-did.json","nonces.json","activities.jsonl"):
            row=next(r for r in manifest["entries"] if r["path"]=="state/"+name)
            total+=row["size"];H.need(row["size"]<=16*1024**2 and total<=64*1024**2,"SOLO_LEDGER_MEMORY_BOUND_STOP")
            files[name]=b"".join(C.R.T.read_blocks(roots["state"]/name,ids["state/"+name]))
    H.need(C.decode(files["verified-did.json"])["did"]==a.profile["source_did"],"SOLO_DID_CONTINUITY_STOP")
    T.WAL.validate(roots,manifest,ids,lambda *_:controller.verify())
    H.need(C.R.T._census_roots(roots,C.G.SOURCE_HEAD,epoch="FROZEN:"+epoch)[1]==manifest,"SOLO_SOURCE_EPOCH_DRIFT_STOP")
    count=sum(row["size"] for row in manifest["entries"])
    H.need(count<=data["source_cap_bytes"],"SOLO_SOURCE_SIZE_STOP")
    inventory=C.G.sha(H.P.original_attempts(files,a.profile["source_did"]))
    value=dict(inventory_sha=inventory,ledger_sha=H.P.ledger_digest(files,hashes),epoch=epoch,manifest_sha=C.G.sha(manifest),
        nonce_file_sha=hashes["nonces.json"],nonce_state_sha=C.G.sha(C.decode(files["nonces.json"])),source_bytes=count,hold_journal_sha=held["journal_sha"])
    now=int(time.time());expires=min(owner["body"]["expires_at"],now+V.MAX_SESSION)
    body=dict(mode="MACHINE_ONLY_FROZEN_INVENTORY",authority_sha=a.pin,scope_sha=C.G.sha(scope),boot=a.profile["boots"]["oci"],
        observed_at=now,expires_at=expires,data=value)
    return dict(body=body,signature=key.sign(V.MACHINE_DOMAIN+C.G.canonical(body)).hex())
