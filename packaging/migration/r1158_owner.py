"""Solo Windows operator: explicit consent, fixed RPC, existing R1155 stream.

No witness private key, no direct Technocore client, no implicit activation.
Machine watchdogs cannot create/extend a human consent signature.
"""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import struct
import sys
import threading
import time

sp=importlib.util.spec_from_file_location("r1158_old_operator",Path(__file__).with_name("r1157_operator.py"))
M=importlib.util.module_from_spec(sp);sys.modules[sp.name]=M;sp.loader.exec_module(M)
H=M.H;C=M.C;T=M.T;V=H.solo_module()


def profile_from_public(data):
    H.shape(data,"endpoints source_did source_key_ids owner_public boots machine_keys"+(" protected_tradebot" if "protected_tradebot" in data else ""))
    kid=M.validate_descriptor(data["owner_public"]);public=data["owner_public"]["body"]
    H.need(public["role"]=="owner","SOLO_OWNER_KEY_STOP")
    endpoints=data["endpoints"]
    context=dict(campaign=C.G.sha(dict(purpose="R1158_SOLO_OWNER",endpoints=endpoints,owner=kid,did=data["source_did"])),
        host=endpoints["oci"]["machine_sha256"],destination=H.B.K137,did=hashlib.sha256(data["source_did"].encode()).hexdigest(),
        source_head=C.G.SOURCE_HEAD,generation=1)
    profile=dict(schema_version=2,mode="SOLO_OWNER",risk_ack=V.ACK,context=context,source_did=data["source_did"],
        source_key_ids=data["source_key_ids"],keys=[dict(public_hex=public["public_hex"],role="owner")],boots=data["boots"],machine_keys=data["machine_keys"])
    if "protected_tradebot" in data:profile["protected_tradebot"]=data["protected_tradebot"]
    a=H.Authority(profile,C.G.sha(profile));M.endpoints_ok(endpoints,a)
    return profile


def validate_binding(kind,data,profile):
    """Only existing exact fixed-function approval kinds, never free signing."""
    fields={
        "r1154-hold":"scope_sha downtime keep_vm_running keep_ssh cost_cap permanent_post_deny",
        "r1154-custody":"continuity recipient_public source_head purpose recipient_evidence",
        "r1154-preserve":"scope_sha hold_journal_sha roots_sha inventory_sha ledger_sha epoch source_cap_bytes destination_policy_sha recovery_confirmed cost_cap",
        "r1154-permanent-no-replay":"policy_sha inventory_sha ledger_sha all_five_routes survives_reboot unknown_remains_unknown",
        "r1155-transfer":"plan_sha keep_source_vm_and_ssh disarmed_restore_only zero_new_billing",
        "r1155-activate":"baseline_sha destination boot_sha source_hold_sha restored_manifest_sha custody_sha activated_at original_post_deny new_only zero_cost runtime_head scope_sha signer_uid publisher_uid",
        "r1155-new-request":"epoch activation_sha request_sha",
        "r1156-autonomy":"anchor_sha generation_sha",
        "r1156-stage":"document_sha no_start zero_cost",
        "r1156-identities":"document_sha no_start zero_cost",
        "r1155-recipient-init":"destination run_id purpose",
        "r1154-rollback":"journal_sha scope_sha aws_publishers_disabled permanent_old_post_deny_retained auto_restart",
        "r1158-machine-init":"role machine boot",
        "r1158-capacity":"destination upper units_sha existing_host_only zero_new_billing",
        "r1158-inventory":"scope_sha source_cap_bytes encrypted_only keep_vm_and_ssh",
        "r1158-monitor-session":"scope_sha source_boot target_boot",
    }
    H.need(kind in fields,"SOLO_OPERATION_REJECTED")
    if kind=="r1154-permanent-no-replay" and set(data)=={"scope_sha","policy_sha","all_five_routes","unknown_remains_unknown","zero_cost"}:
        shape="scope_sha policy_sha all_five_routes unknown_remains_unknown zero_cost"
    else:shape=fields[kind]
    H.shape(data,shape)
    boolean_fields={"downtime","keep_vm_running","keep_ssh","permanent_post_deny","recovery_confirmed","all_five_routes","survives_reboot",
        "unknown_remains_unknown","keep_source_vm_and_ssh","disarmed_restore_only","zero_new_billing","original_post_deny","new_only","zero_cost",
        "no_start","aws_publishers_disabled","permanent_old_post_deny_retained","auto_restart","encrypted_only","keep_vm_and_ssh","existing_host_only"}
    for key,value in data.items():
        if key.endswith("_sha") or key in ("scope_sha","epoch","machine","boot","recipient_public","source_boot","target_boot","destination"):
            C.digest(value)
        if key in ("source_cap_bytes",):C.integer(value,1,C.R.T.C.MAX_SOURCE_BYTES)
        if key=="upper":C.integer(value,1,C.R.T.C.MAX_SOURCE_BYTES)
        if key in boolean_fields:H.need(value is (False if key=="auto_restart" else True),"SOLO_CONSENT_BINDING_STOP")
    if kind=="r1154-custody":
        a=H.Authority(profile,C.G.sha(profile))
        H.need(data["continuity"]==M.K.S.request(a.trust,data["continuity"]["challenge"],data["recipient_public"]) and
            data["source_head"]==C.G.SOURCE_HEAD and data["purpose"]=="R1154_ONE_ORIGINAL_DID_ENCRYPTED_CUSTODY","SOLO_CONSENT_BINDING_STOP")
        H.need(V.recipient_verify(a,data["recipient_evidence"],int(time.time()))==data["recipient_public"],"SOLO_RECIPIENT_NOT_PROVEN")
    if "cost_cap" in data:H.need(data["cost_cap"]=="ZERO_NEW_BILLING","SOLO_CONSENT_BINDING_STOP")
    if kind=="r1158-machine-init":
        H.need(data["role"] in ("oci","k137") and data["machine"]==profile["context"]["host" if data["role"]=="oci" else "destination"] and
            data["boot"]==profile["boots"][data["role"]],"SOLO_CONSENT_BINDING_STOP")
    if kind=="r1158-monitor-session":
        H.need(data["source_boot"]==profile["boots"]["oci"] and data["target_boot"]==profile["boots"]["k137"],"SOLO_CONSENT_BINDING_STOP")
    if kind=="r1158-capacity":H.need(data["destination"]==profile["context"]["destination"],"SOLO_CONSENT_BINDING_STOP")
    return data


def roots(control,a):
    return T.bases(dict(plan={},endpoints=control["endpoints"],ssh=control["ssh"],oci_key=control["oci_key"],
        oci_hosts=control["oci_hosts"],k137_hosts=control["k137_hosts"]),a)


def build(kind,session,now):
    """Derive protocol artifacts from actual machine results, never fake grants."""
    a=H.Authority(session["enrollment"],session["enrollment_sha"]);H.need(H.solo(a),"SOLO_VERSION_REQUIRED")
    if kind=="custody":
        proof=session["recipient_evidence"];public=V.recipient_verify(a,proof,now)
        binding=dict(continuity=M.K.S.request(a.trust,os.urandom(32).hex(),public),recipient_public=public,
            source_head=C.G.SOURCE_HEAD,purpose="R1154_ONE_ORIGINAL_DID_ENCRYPTED_CUSTODY",recipient_evidence=proof)
        return dict(request=dict(enrollment=a.profile,enrollment_sha=a.pin,binding=binding,owner=None,witness=None),
            consent=dict(enrollment=a.profile,enrollment_sha=a.pin,kind="r1154-custody",binding=binding,seconds=1800))
    if kind=="scope":
        source=session["snapshots"]["oci"];settings=session["settings"]
        H.shape(settings,"run_id known_hosts_sha offhost_parent quota_bytes")
        C.fresh(source["observed_at"],now,age=900);H.need(source["machine"]==a.trust.context["host"] and source["boot"]==a.profile["boots"]["oci"],"SOLO_SOURCE_BINDING_STOP")
        H.need(C.G.re.fullmatch(r"[a-f0-9]{32}",settings["run_id"]),"SOLO_CONSENT_BINDING_STOP");C.digest(settings["known_hosts_sha"])
        proof=session["capacity_evidence"];body=proof["body"]
        H.shape(body,"mode authority_sha boot observed_at data")
        H.need(body["mode"]=="MACHINE_ONLY_INITIAL_CAPACITY" and body["authority_sha"]==a.pin and body["boot"]==a.profile["boots"]["k137"],"SOLO_MACHINE_BINDING_STOP")
        C.fresh(body["observed_at"],now,age=30)
        C.G.Ed25519PublicKey.from_public_bytes(bytes.fromhex(a.profile["machine_keys"]["k137"])).verify(bytes.fromhex(proof["signature"]),V.MACHINE_DOMAIN+C.G.canonical(body))
        H.need(body["data"]["source_upper_bound_bytes"]>=source["source_bytes"] and settings["quota_bytes"]==body["data"]["source_upper_bound_bytes"],"SOLO_SOURCE_SIZE_STOP")
        scope=dict(version=2,run_id=settings["run_id"],source=a.trust.context,units=source["units"],users=source["users"],
            surfaces={k:"MACHINE_RECHECK_REQUIRED_NO_HUMAN_INDEPENDENCE" for k in H.SURFACES},
            templates=source["templates"],known_hosts_sha=settings["known_hosts_sha"],launcher_sha=source["launcher_sha"],tool_blob=H.tool_blob(),
            destination=dict(schema_version=2,mode="MACHINE_OBSERVATION",role="k137",observed_at=body["observed_at"],data=body["data"]),
            quarantine=dict(routes=list(M.S.ROUTES),inventory_sha=None,ledger_sha=None,permanent=True,loss_accepted=True),owner=None,witness=None)
        binding=dict(scope_sha=C.G.sha({k:v for k,v in scope.items() if k not in ("owner","witness")}),downtime=True,keep_vm_running=True,keep_ssh=True,
            cost_cap="ZERO_NEW_BILLING",permanent_post_deny=True)
        return dict(scope=scope,consent=dict(enrollment=a.profile,enrollment_sha=a.pin,kind="r1154-hold",binding=binding,seconds=1800))
    scope=session["scope"]
    H.validate_scope(a,scope,now=scope["owner"]["body"]["observed_at"])
    if kind in ("preserve","policy","plan"):
        policy_sha=hashlib.sha256(H.boot_unit(scope["users"].values(),scope["units"])).hexdigest()
        H.need(session["policy_sha"]==policy_sha,"SOLO_QUARANTINE_POLICY_BINDING_STOP")
    if kind=="monitor":
        return dict(enrollment=a.profile,enrollment_sha=a.pin,kind="r1158-monitor-session",seconds=1800,
            binding=dict(scope_sha=C.G.sha(scope),source_boot=a.profile["boots"]["oci"],target_boot=a.profile["boots"]["k137"]))
    if kind in ("preserve","policy"):
        inventory=V.inventory_verify(a,session["inventory_evidence"],scope,now);settings=session["settings"]
        if kind=="preserve":
            binding=dict(scope_sha=C.G.sha(scope),hold_journal_sha=inventory["hold_journal_sha"],roots_sha=C.G.sha(C.ROOTS),
                inventory_sha=inventory["inventory_sha"],ledger_sha=inventory["ledger_sha"],epoch=inventory["epoch"],source_cap_bytes=settings["quota_bytes"],
                destination_policy_sha=session["policy_sha"],recovery_confirmed=True,cost_cap="ZERO_NEW_BILLING")
        else:binding=dict(policy_sha=session["policy_sha"],inventory_sha=inventory["inventory_sha"],ledger_sha=inventory["ledger_sha"],
            all_five_routes=True,survives_reboot=True,unknown_remains_unknown=True)
        return dict(enrollment=a.profile,enrollment_sha=a.pin,kind="r1154-preserve" if kind=="preserve" else "r1154-permanent-no-replay",binding=binding,seconds=1800)
    if kind=="plan":
        evidence=session["inventory_evidence"];inventory=V.inventory_verify(a,evidence,scope,now)
        settings=session["settings"];C.integer(settings["quota_bytes"],inventory["source_bytes"],C.R.T.C.MAX_SOURCE_BYTES)
        H.need(settings["quota_bytes"]==scope["destination"]["data"]["source_upper_bound_bytes"],"SOLO_SOURCE_SIZE_STOP")
        custody=session["custody"];M.K.approved(a,custody["binding"],custody["owner"],None,now=custody["owner"]["body"]["observed_at"])
        H.need(custody["witness"] is None and custody["envelope"]["binding"]==custody["binding"],"SOLO_FAKE_WITNESS_REJECTED")
        preserved=dict(scope_sha=C.G.sha(scope),hold_journal_sha=inventory["hold_journal_sha"],roots_sha=C.G.sha(C.ROOTS),
            inventory_sha=inventory["inventory_sha"],ledger_sha=inventory["ledger_sha"],epoch=inventory["epoch"],source_cap_bytes=settings["quota_bytes"],
            destination_policy_sha=session["policy_sha"],recovery_confirmed=True,cost_cap="ZERO_NEW_BILLING")
        policy=dict(policy_sha=session["policy_sha"],inventory_sha=inventory["inventory_sha"],ledger_sha=inventory["ledger_sha"],
            all_five_routes=True,survives_reboot=True,unknown_remains_unknown=True)
        plan=dict(enrollment=a.profile,enrollment_sha=a.pin,run_id=scope["run_id"],scope=scope,preserve_owner=session["preserve_owner"],
            preserve_witness=None,destination_policy=session["destination_policy"],offhost_parent=settings["offhost_parent"],quota_bytes=settings["quota_bytes"],
            custody=custody,owner=None,witness=None,inventory_evidence=evidence)
        H.need(a.verify(plan["preserve_owner"],"preserve","owner",now)==preserved and
            H.destination_approval(a,plan["destination_policy"],"r1154-permanent-no-replay",now)==policy,"SOLO_CONSENT_BINDING_STOP")
        grant=dict(plan_sha=C.G.sha({k:v for k,v in plan.items() if k not in ("owner","witness")}),keep_source_vm_and_ssh=True,disarmed_restore_only=True,zero_new_billing=True)
        return dict(plan=plan,consent=dict(enrollment=a.profile,enrollment_sha=a.pin,kind="r1155-transfer",binding=grant,seconds=1800))
    raise H.Stop("SOLO_OPERATION_REJECTED")


def assemble(data,now):
    """Attach exactly the reviewed owner grant; never fill a witness slot."""
    H.shape(data,"artifact owner")
    artifact=C.decode(C.G.canonical(data["artifact"]));request=artifact["consent"]
    H.shape(request,"enrollment enrollment_sha kind binding seconds")
    a=H.Authority(request["enrollment"],request["enrollment_sha"])
    H.need(H.solo(a) and a.trust.verify(data["owner"],request["kind"],"owner",now)==request["binding"],"SOLO_CONSENT_BINDING_STOP")
    if set(artifact)=={"scope","consent"}:
        result=artifact["scope"];H.need(result["owner"] is None and result["witness"] is None,"SOLO_FAKE_WITNESS_REJECTED")
        result["owner"]=data["owner"];H.validate_scope(a,result,now=now)
    elif set(artifact)=={"plan","consent"}:
        result=artifact["plan"];H.need(result["owner"] is None and result["witness"] is None,"SOLO_FAKE_WITNESS_REJECTED")
        result["owner"]=data["owner"];T.admit(result,now)
    else:
        H.shape(artifact,"request consent");result=artifact["request"]
        H.need(result["owner"] is None and result["witness"] is None and result["enrollment_sha"]==a.pin,"SOLO_FAKE_WITNESS_REJECTED")
        result["owner"]=data["owner"];M.K.approved(a,result["binding"],result["owner"],None,now=now)
    return result


def rpc(control,role,operation,fields,*,sources=None,child=None):
    H.need(role in ("oci","k137") and operation in ("host-info","machine-init","machine-public","recipient-proof","initial-capacity","probe","inventory","prepare-quarantine","publish-target-evidence","hold","rollback","runtime-check","prepare-identities","stage-runtime","source-custody-once","source-custody-read"),"SOLO_OPERATION_REJECTED")
    a=H.Authority(control["enrollment"],control["enrollment_sha"]);M.endpoints_ok(control["endpoints"],a)
    base=roots(control,a)[0 if role=="oci" else 1];sources=sources or T.bundle()
    code=T.O.bootstrap(C.G.sha(sources),a.pin,a.trust.context["host"] if role=="oci" else H.B.K137)
    code=code.replace("root/'packaging/migration/r1154_app_hold.py'","root/'packaging/migration/r1158_machine.py'")
    code=code.replace("not name.startswith(('packaging/migration/','packaging/archive/','src/flop_agent/','scripts/'))",
        "not (name.startswith(('packaging/migration/','packaging/archive/','src/flop_agent/','scripts/','packaging/oracle/')) or name=='public-profile.json')")
    H.need(code.count("  response=m.peer(request)")==1,"SOLO_TRANSPORT_CONFIG_STOP")
    code=code.replace("  response=m.peer(request)","  try:response=m.peer(request)\n  except ValueError as failure:\n   if str(failure) not in m.V.SAFE_CODES:raise\n   response={'code':str(failure),'cutover':'NO_GO'}")
    python="/opt/technocore-safe-agent/.venv/bin/python" if role=="oci" else "/usr/bin/python3"
    argv=[*base," ".join(shlex.quote(v) for v in ("sudo","-n",python,"-I","-B","-c",code))]
    request=dict(fields,enrollment=a.profile,enrollment_sha=a.pin,operation=operation,role=role)
    with (child or C.R.child)(argv,timeout=300 if operation=="inventory" else 90) as process:
        C.R.send_request(process,sources,request)
        raw=process.stdout.read(65537);H.need(len(raw)<=65536 and process.wait(timeout=10)==0,"SOLO_FIXED_RPC_STOP")
        value=C.decode(raw)
        if value.get("code") in V.SAFE_CODES:raise H.Stop(value["code"])
        H.need(value.get("code")!="WARM_REMOTE_STOP_UNKNOWN","SOLO_MACHINE_EVIDENCE_NOT_PROVEN")
        return value


class Watch:
    """Bounded machine rechecks only. No owner key/passphrase/signing callback."""
    def __init__(self,control,scope,monitor,*,clock=time.time,request=rpc,runtime=None):
        self.control=control;self.scope=scope;self.monitor=monitor;self.clock=clock;self.request=request
        self.a=H.Authority(control["enrollment"],control["enrollment_sha"])
        self.stop=threading.Event();self.failed=threading.Event();self.active=None;self.thread=None;self.evidence=None
        self.lock=threading.RLock()
        self.runtime=runtime

    def refresh(self):
        now=int(self.clock())
        H.need(self.a.trust.verify(self.monitor,"r1158-monitor-session","owner",now)==dict(scope_sha=C.G.sha(self.scope),
            source_boot=self.a.profile["boots"]["oci"],target_boot=self.a.profile["boots"]["k137"]),"SOLO_MONITOR_CONSENT_REQUIRED")
        values={}
        for role in ("oci","k137"):
            challenge=os.urandom(32).hex()
            value=self.request(self.control,role,"probe",dict(scope=self.scope,challenge=challenge))
            H.need(value["body"]["challenge"]==challenge,"SOLO_MACHINE_REPLAY_STOP")
            V.machine_verify(self.a,value,role,self.scope,int(self.clock()));values[role]=value
        self.request(self.control,"oci","publish-target-evidence",dict(scope=self.scope,packet=values["k137"],owner=self.monitor))
        if self.runtime is not None:
            H.shape(self.runtime,"owner inventory_evidence")
            self.request(self.control,"k137","runtime-check",dict(challenge=os.urandom(32).hex(),owner=self.runtime["owner"],
                inventory_evidence=self.runtime["inventory_evidence"],source=values["oci"]))
        with self.lock:self.evidence=values

    def check(self,now):
        H.need(not self.failed.is_set() and self.evidence is not None,"SOLO_WATCHDOG_STOP_NO_RETRY")
        self.a.trust.verify(self.monitor,"r1158-monitor-session","owner",now)
        with self.lock:
            for role in ("oci","k137"):V.machine_verify(self.a,self.evidence[role],role,self.scope,now)

    def start(self,*_):
        if self.thread is not None:return
        self.refresh()
        def loop():
            try:
                while not self.stop.wait(10):self.refresh()
            except Exception:
                self.failed.set()
                if self.active is not None and self.active.poll() is None:self.active.kill()
        self.thread=threading.Thread(target=loop,daemon=True);self.thread.start()

    def attach(self,process):
        self.active=process
        if self.failed.is_set() and process.poll() is None:process.kill()

    def decorate(self,request):
        self.check(int(self.clock()))
        with self.lock:return dict(request,evidence=C.decode(C.G.canonical(self.evidence)))

    def __enter__(self):return self
    def __exit__(self,*_):
        self.stop.set()
        if self.thread is not None:self.thread.join(120);H.need(not self.thread.is_alive(),"SOLO_WATCHDOG_CLEANUP_STOP")


def main():
    password=bytearray()
    try:
        H.need(sys.argv[1:]==["--pipe"],"SOLO_PS51_ENTRY_REQUIRED")
        control=C.R.frame_read(sys.stdin.buffer,C.R.MAGIC)
        H.shape(control,"operation data output confirmation"+(" connection" if "connection" in control else ""))
        operation=control["operation"];data=control["data"]
        H.need(operation in ("audit","init","enroll","build","assemble","consent","collect","rpc","transfer","monitor"),"SOLO_OPERATION_REJECTED")
        if operation in ("init","consent","transfer"):
            size=struct.unpack(">I",C.R.exact(sys.stdin.buffer,4))[0];H.need(32<=size<=1024,"SOLO_PASSWORD_STOP")
            password.extend(C.R.exact(sys.stdin.buffer,size))
        H.need(sys.stdin.buffer.read(1)==b"","SOLO_INPUT_STOP")
        if operation in ("collect","rpc","transfer","monitor"):
            connection=control["connection"];H.shape(connection,"endpoints ssh oci_key oci_hosts k137_hosts")
            target=data if operation=="collect" else data["transport"]
            H.need(not set(target).intersection(set(connection)-{"endpoints"}) and
                ("endpoints" not in target or target["endpoints"]==connection["endpoints"]),"SOLO_TRANSPORT_CONFIG_STOP")
            target.update(connection)
        else:H.need("connection" not in control,"SOLO_NETWORK_NOT_REQUESTED")
        now=int(time.time());folder=Path(control["output"])
        if operation=="init":
            H.shape(data,"role");H.need(data["role"]=="owner" and control["confirmation"]=="INIT_OWNER_ONLY","SOLO_OWNER_KEY_STOP")
            result=M.init_key(M.store_path(),"owner",password);name="owner-public.json"
        elif operation=="enroll":
            H.need(control["confirmation"]==V.ACK,"SOLO_EXPLICIT_OPT_IN_REQUIRED")
            result=profile_from_public(data);name="solo-profile.json"
        elif operation=="build":
            H.need(control["confirmation"]=="BUILD_PUBLIC_ONLY","SOLO_EXACT_CONSENT_REQUIRED")
            H.shape(data,"kind session");result=build(data["kind"],data["session"],now);name=data["kind"]+"-public.json"
        elif operation=="assemble":
            H.need(control["confirmation"]=="ASSEMBLE_REVIEWED_OWNER_GRANT","SOLO_EXACT_CONSENT_REQUIRED")
            result=assemble(data,now);name="assembled-public.json"
        elif operation=="collect":
            H.need(control["confirmation"]=="READ_ONLY_FIXED_HOSTS","SOLO_EXACT_CONSENT_REQUIRED")
            result=dict(snapshots=M.collect(data),boot_bindings={r:rpc(data,r,"host-info",{}) for r in ("oci","k137")});name="machine-metadata.json"
        elif operation in ("audit","consent"):
            H.shape(data,"enrollment enrollment_sha kind binding seconds")
            a=H.Authority(data["enrollment"],data["enrollment_sha"]);H.need(H.solo(a),"SOLO_VERSION_REQUIRED")
            validate_binding(data["kind"],data["binding"],a.profile);C.integer(data["seconds"],1,V.MAX_SESSION)
            if operation=="audit":
                H.need(control["confirmation"]=="READ_ONLY","SOLO_EXACT_CONSENT_REQUIRED")
                print(C.G.canonical(dict(code="SOLO_CONSENT_DRAFT_ONLY",consent=V.LEVELS[data["kind"]],human_independence=False,
                    machine_evidence="REQUIRED_AT_EXECUTION",cutover="NO_GO")).decode());return 0
            H.need(control["confirmation"]==V.LEVELS[data["kind"]],"SOLO_EXACT_CONSENT_REQUIRED")
            with M.local_key(M.store_path(),password) as (key,public):
                H.need(public["body"]["role"]=="owner","SOLO_OWNER_KEY_STOP")
                result=V.issue(a.profile,key,data["kind"],data["binding"],now=now,seconds=data["seconds"],confirmation=control["confirmation"])
            name=data["kind"]+"-owner.json"
        elif operation=="rpc":
            H.need(control["confirmation"]=="EXECUTE_FIXED_"+data["operation"].upper(),"SOLO_EXACT_CONSENT_REQUIRED")
            result=rpc(data["transport"],data["role"],data["operation"],data["fields"]);name=data["operation"]+"-"+data["role"]+".json"
        elif operation=="monitor":
            H.need(control["confirmation"]=="BOUNDED_MACHINE_MONITOR_SESSION","SOLO_EXACT_CONSENT_REQUIRED")
            H.shape(data,"transport scope monitor runtime")
            with Watch(data["transport"],data["scope"],data["monitor"],runtime=data["runtime"]) as watch:
                watch.start()
                while not watch.failed.wait(5):watch.check(int(time.time()))
                raise H.Stop("SOLO_WATCHDOG_STOP_NO_RETRY")
        else:
            H.need(control["confirmation"]=="FULL_ENCRYPTED_DISARMED_RESTORE","SOLO_EXACT_CONSENT_REQUIRED")
            plan=data["transport"]["plan"];a=T.admit(plan,now)
            data["transport"]["enrollment"]=a.profile;data["transport"]["enrollment_sha"]=a.pin
            with Watch(data["transport"],plan["scope"],data["monitor"]) as watch:
                # Old transport receives ONLY its exact existing control keys.
                old_control={k:v for k,v in data["transport"].items() if k not in ("enrollment","enrollment_sha")}
                commands=lambda *args,**kwargs:T.command(*args,**kwargs,peer_leaf="r1158_machine.py")
                result=T.owner(old_control,bytes(password),session=watch,commands=commands)
            name="disarmed-transfer-result.json"
        M.output(folder,name,result)
        print(C.G.canonical(dict(code="SOLO_PUBLIC_ARTIFACT_CREATED",artifact=name,sha256=C.G.sha(result),cutover="NO_GO")).decode());return 0
    except Exception as error:
        code=str(error) if isinstance(error,ValueError) and str(error) in V.SAFE_CODES else "SOLO_STOP_NO_AUTO_RETRY"
        print(C.G.canonical(dict(code=code,cutover="NO_GO",oci_retirement="STRICT_NO_GO")).decode());return 42
    finally:password[:]=b"\0"*len(password)


if __name__=="__main__":raise SystemExit(main())
