"""Offline approval issuer and fixed, opt-in READ ONLY metadata carrier.

No DID key/provider, POST, HOLD, restore, service control or automatic renewal.
Only an explicitly consenting local operator can unlock their approval key.
Missing independent evidence never becomes a locally manufactured PASS.
"""
import contextlib
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,BestAvailableEncryption,load_pem_private_key

ROOT=Path(__file__).resolve().parents[2]
sp=importlib.util.spec_from_file_location("r1157_renewal",Path(__file__).with_name("r1156_renewal.py"))
N=importlib.util.module_from_spec(sp);sys.modules[sp.name]=N;sp.loader.exec_module(N)
S=N.S;H=N.H;C=N.C
T=C.legacy("r1155_transfer.py");K=S.K
DOMAIN=b"FLOP-R1157-LOCAL-APPROVAL-CUSTODY-v1\0"
ROLES={"owner","independent","destination"}
KINDS={"review","destination","scope","custody","transfer","renewal","recipient","held","preserve","policy"}
PROOF_FIELDS=H.SURFACES|{"processes","fd_aliases","five_route_writers"}


def secure_path(path,*,directory=False):
    """Caller-created private directory; refuse links/ACL inheritance."""
    path=Path(path).absolute()
    for parent in (path,*path.parents):
        H.need(not parent.is_symlink() and not (hasattr(parent,"is_junction") and parent.is_junction()),"OPERATOR_PATH_STOP")
    info=path.lstat();H.need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),"OPERATOR_PATH_STOP")
    if os.name=="posix":
        H.need(info.st_uid==os.geteuid() and not info.st_mode&0o077,"OPERATOR_PERMISSIONS_STOP")
    else:
        # Use the pinned old ACL guard, never arbitrary helper input or script
        # entrypoints. Only a path crosses stdin; no key/passphrase/environment.
        import subprocess
        code=r'''$ErrorActionPreference='Stop';[Console]::InputEncoding=[Text.Encoding]::UTF8;$p=[Console]::In.ReadToEnd()
$a=if([IO.Directory]::Exists($p)){[IO.Directory]::GetAccessControl($p)}else{[IO.File]::GetAccessControl($p)}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if(-not $a.AreAccessRulesProtected){exit 42}
foreach($r in $a.Access){if($r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -cne $sid){exit 42}}
if($a.Owner -ne [Security.Principal.WindowsIdentity]::GetCurrent().Name -and $a.Owner -cne $sid){exit 42}'''
        r=subprocess.run([str(Path(os.environ.get("SystemRoot","C:/Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe"),
            "-NoProfile","-NonInteractive","-Command",code],input=str(path).encode(),stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,timeout=15,shell=False)
        H.need(r.returncode==0,"OPERATOR_PERMISSIONS_STOP")
    return path


def control_identity():
    """Local custody boundary, not proof that two humans are independent."""
    if os.name=="nt":
        import subprocess
        r=subprocess.run([str(Path(os.environ.get("SystemRoot","C:/Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe"),
            "-NoProfile","-NonInteractive","-Command",
            "[Console]::Write([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"],
            capture_output=True,timeout=15,shell=False)
        H.need(r.returncode==0 and re.fullmatch(rb"S-[0-9-]{5,180}",r.stdout),"OPERATOR_IDENTITY_STOP")
        return hashlib.sha256(r.stdout).hexdigest()
    return hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()+b"|"+str(os.geteuid()).encode()).hexdigest()


def store_path():
    if os.name=="nt":
        import ctypes
        buf=ctypes.create_unicode_buffer(32768)
        H.need(ctypes.windll.shell32.SHGetFolderPathW(None,28,None,0,buf)==0,"OPERATOR_STORE_STOP")
        return Path(buf.value)/"FLOP-R1157-approval"
    return Path.home()/".local/share/flop-r1157-approval"


def protect_file(path):
    if os.name=="posix":os.chmod(path,0o700 if path.is_dir() else 0o600);return
    import subprocess
    code=r'''$ErrorActionPreference='Stop';[Console]::InputEncoding=[Text.Encoding]::UTF8;$p=[Console]::In.ReadToEnd()
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$dir=[IO.Directory]::Exists($p)
$a=if($dir){New-Object Security.AccessControl.DirectorySecurity}else{New-Object Security.AccessControl.FileSecurity}
$a.SetOwner($sid);$a.SetAccessRuleProtection($true,$false)
$a.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow')))
if($dir){[IO.Directory]::SetAccessControl($p,$a)}else{[IO.File]::SetAccessControl($p,$a)}'''
    r=subprocess.run([str(Path(os.environ.get("SystemRoot","C:/Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe"),
        "-NoProfile","-NonInteractive","-Command",code],input=str(path).encode(),stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,timeout=15,shell=False)
    H.need(r.returncode==0,"OPERATOR_PERMISSIONS_STOP")


def descriptor(key,role,control):
    H.need(role in ROLES,"OPERATOR_ROLE_STOP");C.digest(control)
    body=dict(version=1,role=role,public_hex=key.public_key().public_bytes_raw().hex(),control=control,
        consent="SEPARATELY_CONTROLLED_WITNESS" if role=="independent" else "LOCAL_APPROVAL_ONLY_NOT_DID")
    return dict(body=body,signature=key.sign(DOMAIN+C.G.canonical(body)).hex())


def validate_descriptor(value):
    H.shape(value,"body signature");body=value["body"]
    H.shape(body,"version role public_hex control consent")
    H.need(type(body["version"]) is int and body["version"]==1 and body["role"] in ROLES,"OPERATOR_ROLE_STOP")
    C.digest(body["public_hex"]);C.digest(body["control"])
    H.need(body["consent"]==("SEPARATELY_CONTROLLED_WITNESS" if body["role"]=="independent" else "LOCAL_APPROVAL_ONLY_NOT_DID"),"OPERATOR_CONSENT_STOP")
    H.need(type(value["signature"]) is str and re.fullmatch(r"[a-f0-9]{128}",value["signature"]),"OPERATOR_SIGNATURE_STOP")
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(body["public_hex"])).verify(bytes.fromhex(value["signature"]),DOMAIN+C.G.canonical(body))
    return hashlib.sha256(bytes.fromhex(body["public_hex"])).hexdigest()


def init_key(folder,role,password,*,key_factory=Ed25519PrivateKey.generate,identity=control_identity):
    """Runtime opt-in only. Tests inject freshly generated dummy keys."""
    secure_path(folder,directory=True)
    H.need(type(password) is bytearray and 32<=len(password)<=1024 and role in ROLES,"OPERATOR_PASSWORD_STOP")
    H.need(not any(folder.iterdir()),"OPERATOR_KEY_ALREADY_ENROLLED")
    try:
        key=key_factory();public=descriptor(key,role,identity())
        encrypted=key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,BestAvailableEncryption(bytes(password)))
        # If the second write fails, leave the first encrypted file in place:
        # no silent key replacement/re-generation on the next invocation.
        local_write(folder/"approval.pem.enc",encrypted)
        local_write(folder/"public.json",C.G.canonical(public))
        protect_file(folder/"approval.pem.enc");protect_file(folder/"public.json")
        secure_path(folder/"approval.pem.enc");secure_path(folder/"public.json")
        return public
    finally:password[:]=b"\0"*len(password)


@contextlib.contextmanager
def local_key(folder,password,*,identity=control_identity):
    encrypted=None;key=None
    try:
        secure_path(folder,directory=True);secure_path(folder/"approval.pem.enc");secure_path(folder/"public.json")
        public=read_public(folder/"public.json");validate_descriptor(public)
        expected_cipher=require_control(folder,public,identity=identity)
        H.need(type(password) is bytearray and 32<=len(password)<=1024,"OPERATOR_PASSWORD_STOP")
        H.need((folder/"approval.pem.enc").stat().st_size<=16384,"OPERATOR_KEY_BOUND_STOP")
        encrypted=bytearray((folder/"approval.pem.enc").read_bytes())
        if expected_cipher is not None:H.need(hashlib.sha256(encrypted).hexdigest()==expected_cipher,"OPERATOR_KEY_MISMATCH")
        key=load_pem_private_key(bytes(encrypted),bytes(password))
        H.need(isinstance(key,Ed25519PrivateKey) and key.public_key().public_bytes_raw().hex()==public["body"]["public_hex"],"OPERATOR_KEY_MISMATCH")
        yield key,public
    finally:
        password[:]=b"\0"*len(password);key=None
        if encrypted is not None:encrypted[:]=b"\0"*len(encrypted)


def require_control(folder,public,*,identity=control_identity):
    """Original SID or same-key signed continuity; never rewrite descriptor."""
    if public["body"]["control"]==identity() and not (folder/"host-binding.json").exists():return None
    name="flop_r1160_owner_continuity"
    if name not in sys.modules:
        sp=importlib.util.spec_from_file_location(name,Path(__file__).with_name("r1160_owner_continuity.py"))
        module=importlib.util.module_from_spec(sp);sys.modules[name]=module;sp.loader.exec_module(module)
    try:return sys.modules[name].verify_local(folder,public,sys.modules[__name__],control=identity())
    except Exception:raise H.Stop("OPERATOR_CUSTODY_HOST_STOP") from None


def enroll(value):
    H.need(type(value) is dict and type(value.get("descriptors")) is list and len(value["descriptors"])==3,"OPERATOR_WITNESS_NOT_ENROLLED")
    if "endpoints" in value:
        H.shape(value,"endpoints source_did source_key_ids descriptors independent_key_id")
        ends=value["endpoints"]
        context=dict(campaign=C.G.sha(dict(purpose="R1157_OFFLINE_AUTHORITY",endpoints=ends,source_did=value["source_did"])),
            host=ends["oci"]["machine_sha256"],destination=ends["k137"]["machine_sha256"],
            did=hashlib.sha256(value["source_did"].encode()).hexdigest(),source_head=C.G.SOURCE_HEAD,generation=1)
    else:
        H.shape(value,"context source_did source_key_ids descriptors independent_key_id");context=value["context"]
    rows={};controls={}
    H.need(type(value["descriptors"]) is list and len(value["descriptors"])==3,"OPERATOR_WITNESS_NOT_ENROLLED")
    for public in value["descriptors"]:
        kid=validate_descriptor(public);body=public["body"]
        H.need(body["role"] not in rows,"OPERATOR_DUPLICATE_ROLE_STOP")
        rows[body["role"]]=dict(public_hex=body["public_hex"],role=body["role"]);controls[body["role"]]=body["control"]
        if body["role"]=="independent":H.need(kid==value["independent_key_id"],"OPERATOR_WITNESS_PIN_STOP")
    H.need(set(rows)==ROLES and len(set(controls.values()))==3,"OPERATOR_WITNESS_NOT_INDEPENDENT")
    result=dict(schema_version=1,context=context,source_did=value["source_did"],source_key_ids=value["source_key_ids"],keys=[rows[r] for r in sorted(rows)])
    a=H.Authority(result,C.G.sha(result))
    if "endpoints" in value:endpoints_ok(value["endpoints"],a)
    return result


def read_public(path):
    path=Path(path);H.need(not path.is_symlink() and path.is_file() and 0<path.stat().st_size<=1024**2,"OPERATOR_PUBLIC_FILE_STOP")
    return C.decode(path.read_bytes())


def endpoints_ok(ends,authority):
    H.shape(ends,"schema_version purpose oci k137")
    H.need(type(ends["schema_version"]) is int and ends["schema_version"]==1 and ends["purpose"]=="R1066_READONLY_PREFLIGHT","OPERATOR_ENDPOINT_STOP")
    fields="host user host_key host_key_sha256 credential_sha256 identity_file machine_sha256 uid head cgroup_sha256 minimum_free_bytes"
    import base64,ipaddress
    for role in ("oci","k137"):
        e=ends[role];H.shape(e,fields)
        ip=ipaddress.ip_address(e["host"])
        H.need(ip.version==4 and str(ip)==e["host"] and ip.is_global,"OPERATOR_ENDPOINT_STOP")
        H.need(e["user"]=="ubuntu" and type(e["uid"]) is int and e["uid"]==(0 if role=="oci" else 1000),"OPERATOR_ENDPOINT_STOP")
        for k in ("host_key_sha256","credential_sha256","machine_sha256","cgroup_sha256"):C.digest(e[k])
        H.need(re.fullmatch(r"[a-f0-9]{40}",e["head"]),"OPERATOR_HEAD_STOP")
        H.need(type(e["host_key"]) is str and re.fullmatch(r"(?:ssh-ed25519|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]{40,1024}",e["host_key"]),"OPERATOR_HOST_KEY_STOP")
        H.need(hashlib.sha256(base64.b64decode(e["host_key"].split()[1],validate=True)).hexdigest()==e["host_key_sha256"],"OPERATOR_HOST_KEY_STOP")
        C.integer(e["minimum_free_bytes"],1024**3,2**50)
        if role=="oci":
            H.need(e["host"]=="140.238.55.171" and e["identity_file"]=="R987_V2_ESCROW" and e["head"]==C.G.SOURCE_HEAD and
                e["host_key"].startswith("ecdsa-sha2-nistp256 ") and e["machine_sha256"]==authority.trust.context["host"],"OPERATOR_OCI_BINDING_STOP")
        else:
            H.need(e["machine_sha256"]==H.B.K137 and type(e["identity_file"]) is str and
                not any(x in e["identity_file"] for x in ('"','\n','\r')),"OPERATOR_K137_BINDING_STOP")
    for key in ("host","machine_sha256","host_key_sha256","credential_sha256"):
        H.need(ends["oci"][key]!=ends["k137"][key],"OPERATOR_HOST_SEPARATION_STOP")


def metadata_ok(report,role,authority,ends,now):
    common="version role challenge machine boot cgroup uid observed_at memory_headroom_bytes cpu_psi_milli io_psi_milli writer_proof"
    H.shape(report,common+(" head units users templates launcher_sha protected_sha source_bytes held" if role=="oci" else " free_bytes"))
    e=ends[role];H.need(type(report["version"]) is int and report["version"]==1 and report["role"]==role and
        report["machine"]==e["machine_sha256"] and report["uid"]==e["uid"] and report["cgroup"]==e["cgroup_sha256"] and report["writer_proof"]=="NOT_PROVEN","OPERATOR_HOST_EVIDENCE_STOP")
    C.digest(report["boot"]);C.digest(report["challenge"]);C.fresh(report["observed_at"],now,age=900 if role=="oci" else 30)
    for field in ("memory_headroom_bytes","cpu_psi_milli","io_psi_milli"):C.integer(report[field])
    if role=="oci":
        H.need(report["head"]==C.G.SOURCE_HEAD,"OPERATOR_HEAD_STOP")
        C.integer(report["source_bytes"],1,C.R.T.C.MAX_SOURCE_BYTES);C.digest(report["launcher_sha"]);C.digest(report["protected_sha"])
        if report["held"] is not None:
            T.O.checked_result(C.G.canonical(report["held"]),0)
            H.need(report["held"]["code"]=="HELD_VM_AND_SSH_UNCHANGED","OPERATOR_HOLD_NOT_PROVEN")
    else:C.integer(report["free_bytes"])


def review_data(session,now):
    """Explicit independent proof, NEVER derived from a metadata success flag."""
    allowed={"enrollment","enrollment_sha","endpoints","snapshots","review_data","review","settings","destination","scope",
        "held_data","held","preserve_binding","preserve","policy","custody","renewal"}
    H.need(type(session) is dict and set(session)<=allowed,"OPERATOR_SESSION_STOP")
    H.shape(session["snapshots"],"oci k137")
    a=H.Authority(session["enrollment"],session["enrollment_sha"]);ends=session["endpoints"]
    endpoints_ok(ends,a)
    for role in ("oci","k137"):metadata_ok(session["snapshots"][role],role,a,ends,now)
    data=session["review_data"]
    H.shape(data,"snapshots_sha endpoints_sha source_boot destination_boot surfaces route_evidence zero_cost_confirmed disarmed_destination_confirmed")
    H.need(data["snapshots_sha"]==C.G.sha(session["snapshots"]) and data["endpoints_sha"]==C.G.sha(ends) and
        data["source_boot"]==session["snapshots"]["oci"]["boot"] and data["destination_boot"]==session["snapshots"]["k137"]["boot"],"OPERATOR_REVIEW_BINDING_STOP")
    H.need(type(data["surfaces"]) is dict and set(data["surfaces"])==PROOF_FIELDS,"G4_NOT_PROVABLE")
    for row in data["surfaces"].values():
        H.shape(row,"complete unknown evidence_sha");C.digest(row["evidence_sha"])
        H.need(row["complete"] is True and type(row["unknown"]) is int and row["unknown"]==0,"G4_NOT_PROVABLE")
    H.need(type(data["route_evidence"]) is dict and set(data["route_evidence"])==set(S.ROUTES),"G5_NOT_PROVABLE")
    for row in data["route_evidence"].values():
        H.shape(row,"writer_scope_complete evidence_sha inventory_sha ledger_sha")
        H.need(row["writer_scope_complete"] is True,"G5_NOT_PROVABLE")
        for field in ("evidence_sha","inventory_sha","ledger_sha"):C.digest(row[field])
    H.need(data["zero_cost_confirmed"] is True and data["disarmed_destination_confirmed"] is True,"OPERATOR_DESTINATION_NOT_ADMITTED")
    return a,data


def admitted(session,now):
    a,data=review_data(session,now)
    H.need(a.trust.verify(session["review"],"r1157-reviewed-scope","independent",now,age=900)==data,"OPERATOR_INDEPENDENT_PROOF_STOP")
    return a


def scope_draft(session,now):
    a=admitted(session,now);source=session["snapshots"]["oci"];target=session["snapshots"]["k137"]
    settings=session["settings"]
    H.shape(settings,"run_id known_hosts_sha offhost_parent quota_bytes inventory_sha ledger_sha recipient_public challenge")
    H.need(re.fullmatch(r"[a-f0-9]{32}",settings["run_id"]),"OPERATOR_RUN_STOP")
    for field in ("known_hosts_sha","inventory_sha","ledger_sha","recipient_public","challenge"):C.digest(settings[field])
    for row in session["review_data"]["route_evidence"].values():
        H.need(row["inventory_sha"]==settings["inventory_sha"] and row["ledger_sha"]==settings["ledger_sha"],"G5_BINDING_STOP")
    C.integer(settings["quota_bytes"],source["source_bytes"],C.R.T.C.MAX_SOURCE_BYTES)
    H.need(Path(settings["offhost_parent"]).is_absolute(),"OPERATOR_OFFHOST_STOP")
    H.need(target["free_bytes"]>=20*C.R.GIB+2*settings["quota_bytes"]+2*C.R.GIB and target["memory_headroom_bytes"]>=512*1024**2 and
        target["cpu_psi_milli"]<=5000 and target["io_psi_milli"]<=10000,"OPERATOR_K137_CAPACITY_STOP")
    H.need(a.trust.verify(session["destination"],"r1154-destination","destination",now,age=30)==destination_data(session,now),"OPERATOR_DESTINATION_STOP")
    return dict(version=1,run_id=settings["run_id"],source=a.trust.context,units=source["units"],users=source["users"],
        surfaces={key:"INDEPENDENTLY_REVIEWED_NO_OUTSIDE_LAUNCHER" for key in H.SURFACES},
        templates=source["templates"],known_hosts_sha=settings["known_hosts_sha"],launcher_sha=source["launcher_sha"],
        destination=session["destination"],tool_blob=H.tool_blob(),
        quarantine=dict(routes=list(S.ROUTES),inventory_sha=settings["inventory_sha"],ledger_sha=settings["ledger_sha"],permanent=True,loss_accepted=True))


def destination_data(session,now):
    review_data(session,now);source=session["snapshots"]["oci"];target=session["snapshots"]["k137"]
    return dict(machine=H.B.K137,free_bytes=target["free_bytes"],source_upper_bound_bytes=source["source_bytes"],
        memory_headroom_bytes=target["memory_headroom_bytes"],cpu_psi_milli=target["cpu_psi_milli"],io_psi_milli=target["io_psi_milli"],
        disarmed_ready=True,publisher_disarmed=True,zero_cost_verified=True)


def packet_spec(kind,session,now):
    H.need(kind in KINDS,"OPERATOR_KIND_STOP")
    if kind=="review":a,data=review_data(session,now);return a,"r1157-reviewed-scope",data,{"independent"},900
    a=admitted(session,now)
    if kind=="destination":return a,"r1154-destination",destination_data(session,now),{"destination"},30
    if kind=="scope":
        draft=scope_draft(session,now)
        return a,"r1154-hold",dict(scope_sha=C.G.sha(draft),downtime=True,keep_vm_running=True,keep_ssh=True,
            cost_cap="ZERO_NEW_BILLING",permanent_post_deny=True),{"owner","independent"},900
    scope=session["scope"]
    # Original admission is immutable history; current source/boot/proof is
    # independently re-admitted above. Never stretch old signatures.
    at=max(scope[k]["body"]["observed_at"] for k in ("owner","witness"));C.integer(at,1,now)
    H.validate_scope(a,scope,now=at)
    H.need(scope["source"]==a.trust.context and scope["run_id"]==session["settings"]["run_id"] and
        scope["known_hosts_sha"]==session["settings"]["known_hosts_sha"] and
        scope["quarantine"]["ledger_sha"]==session["settings"]["ledger_sha"] and
        scope["quarantine"]["inventory_sha"]==session["settings"]["inventory_sha"],"OPERATOR_SCOPE_CHANGED")
    if kind=="custody":
        settings=session["settings"]
        binding=dict(continuity=K.S.request(a.trust,settings["challenge"],settings["recipient_public"]),recipient_public=settings["recipient_public"],
            source_head=C.G.SOURCE_HEAD,purpose="R1154_ONE_ORIGINAL_DID_ENCRYPTED_CUSTODY")
        return a,"r1154-custody",binding,{"owner","independent"},900
    if kind=="recipient":return a,"r1155-recipient-init",dict(destination=H.B.K137,run_id=scope["run_id"],purpose="ENCRYPTED_RECIPIENT_ONLY_NOT_NEW_DID"),{"owner","independent"},900
    if kind=="held":
        data=session["held_data"]
        H.shape(data,"scope_sha source_boot hold_journal_sha manifest_sha nonce_file_sha epoch ledger_sha source_deny target_deny")
        H.need(data["scope_sha"]==C.G.sha(scope) and data["source_boot"]==session["snapshots"]["oci"]["boot"] and
            data["source_deny"] is True and data["target_deny"] is True,"OPERATOR_HOLD_NOT_PROVEN")
        observed=session["snapshots"]["oci"]["held"]
        H.need(observed is not None and observed["scope_sha"]==data["scope_sha"] and
            observed["journal_sha"]==data["hold_journal_sha"],"OPERATOR_HOLD_NOT_PROVEN")
        for field in ("hold_journal_sha","manifest_sha","nonce_file_sha","epoch","ledger_sha"):C.digest(data[field])
        # This is an explicit independent attestation, NOT a proof manufactured
        # from inventory metadata. The reviewer must supply its external facts.
        return a,"r1157-held-evidence",data,{"independent"},30
    if kind in ("preserve","policy"):
        held=admit_held(session,a,now)
        if kind=="preserve":return a,"r1154-preserve",held,{"owner","independent"},900
        return a,"r1154-permanent-no-replay",dict(policy_sha=held["destination_policy_sha"],inventory_sha=held["inventory_sha"],
            ledger_sha=held["ledger_sha"],all_five_routes=True,survives_reboot=True,unknown_remains_unknown=True),{"destination"},900
    if kind=="transfer":
        plan=transfer_draft(session,a,now)
        # The encrypted custody envelope and held archive bindings MUST already
        # exist from the original separately approved operations. Never mint.
        stripped={k:v for k,v in plan.items() if k not in ("owner","witness")}
        H.need(stripped["scope"]==scope and stripped["enrollment"]==session["enrollment"] and stripped["enrollment_sha"]==a.pin and
            stripped["run_id"]==scope["run_id"] and stripped["offhost_parent"]==session["settings"]["offhost_parent"] and
            stripped["quota_bytes"]==session["settings"]["quota_bytes"],"OPERATOR_PLAN_BINDING_STOP")
        # Validate every old transport grant before issuing a new outer grant.
        held=admit_held(session,a,now)
        H.need(stripped["preserve_owner"]["body"]["data"]==held,"OPERATOR_PRESERVE_STOP")
        K.approved(a,stripped["custody"]["binding"],stripped["custody"]["owner"],stripped["custody"]["witness"],now=now)
        H.need(stripped["custody"]["envelope"]["binding"]==stripped["custody"]["binding"],"OPERATOR_CUSTODY_STOP")
        return a,"r1155-transfer",dict(plan_sha=C.G.sha(stripped),keep_source_vm_and_ssh=True,disarmed_restore_only=True,zero_new_billing=True),{"owner","independent"},900
    anchor=session["renewal"]["anchor"];N.anchor_ok(a,anchor)
    held=admit_held(session,a,now)
    H.need(anchor["capture_sha"]==C.G.sha(held) and anchor["scope_sha"]==C.G.sha(scope) and anchor["hold_journal_sha"]==held["hold_journal_sha"] and
        anchor["source_boot"]==session["snapshots"]["oci"]["boot"] and anchor["target_boot"]==session["snapshots"]["k137"]["boot"],"OPERATOR_RENEWAL_BINDING_STOP")
    observed=session["held"]["body"]["data"]
    H.need(anchor["manifest_sha"]==observed["manifest_sha"] and anchor["nonce_file_sha"]==observed["nonce_file_sha"] and
        anchor["epoch"]==observed["epoch"] and anchor["ledger_sha"]==observed["ledger_sha"],"OPERATOR_RENEWAL_BINDING_STOP")
    metrics=session["renewal"]["metrics"];C.fresh(metrics["observed_at"],now,age=30)
    # Reuse the real Reader to validate full metrics/CAS after both signatures.
    previous=session["renewal"]["previous"];seq=0
    if previous is not None:
        N.peek(a,anchor,previous,now);seq=previous["owner"]["body"]["data"]["seq"]+1
    return a,"r1156-renewal",dict(anchor_sha=C.G.sha(anchor),seq=seq,previous=C.G.sha(previous) if previous else None,metrics=metrics),{"owner","independent"},900


def admit_held(session,a,now):
    value=a.trust.verify(session["held"],"r1157-held-evidence","independent",now,age=30)
    H.shape(value,"scope_sha source_boot hold_journal_sha manifest_sha nonce_file_sha epoch ledger_sha source_deny target_deny")
    H.need(value["scope_sha"]==C.G.sha(session["scope"]) and value["source_boot"]==session["snapshots"]["oci"]["boot"] and
        value["source_deny"] is True and value["target_deny"] is True,"OPERATOR_HOLD_NOT_PROVEN")
    for field in ("hold_journal_sha","manifest_sha","nonce_file_sha","epoch","ledger_sha"):C.digest(value[field])
    # Existing preserve binding fields, with measured sizes, not guessed bytes.
    preserved=session["preserve_binding"]
    H.shape(preserved,"scope_sha hold_journal_sha roots_sha inventory_sha ledger_sha epoch source_cap_bytes destination_policy_sha recovery_confirmed cost_cap")
    for field in ("scope_sha","hold_journal_sha","roots_sha","inventory_sha","ledger_sha","epoch","destination_policy_sha"):C.digest(preserved[field])
    H.need(preserved["scope_sha"]==C.G.sha(session["scope"]) and preserved["roots_sha"]==C.G.sha(C.ROOTS) and
        preserved["inventory_sha"]==session["settings"]["inventory_sha"] and preserved["ledger_sha"]==session["settings"]["ledger_sha"] and
        preserved["hold_journal_sha"]==value["hold_journal_sha"] and preserved["epoch"]==value["epoch"] and
        preserved["ledger_sha"]==value["ledger_sha"] and preserved["source_cap_bytes"]==session["settings"]["quota_bytes"] and
        preserved["source_cap_bytes"]>=session["snapshots"]["oci"]["source_bytes"] and preserved["recovery_confirmed"] is True and
        preserved["cost_cap"]=="ZERO_NEW_BILLING","OPERATOR_HOLD_CHANGED")
    return preserved


def issue(kind,session,key,public,*,now):
    a,wire,data,roles,ttl=packet_spec(kind,session,now);kid=validate_descriptor(public)
    H.need(public["body"]["role"] in roles and a.trust.keys.get(kid)==(key.public_key().public_bytes_raw(),public["body"]["role"]),"OPERATOR_ISSUER_ROLE_STOP")
    # Shared factual observation time allows independently issued packets to
    # satisfy the frozen verifier's historical timestamp checks. Issuing later
    # never extends that factual window or renews the old grants.
    at=max(session["snapshots"][r]["observed_at"] for r in ("oci","k137"));C.fresh(at,now,age=ttl)
    body=C.decode(C.G.canonical(dict(kind=wire,context=a.trust.context,observed_at=at,expires_at=at+ttl,data=data)))
    packet=dict(signer=kid,body=body,signature=key.sign(C.DOMAIN+C.G.canonical(body)).hex())
    a.trust.verify(packet,wire,public["body"]["role"],now,age=ttl)
    return packet


def transfer_draft(session,a,now):
    settings=session["settings"];preserve=session["preserve"]
    held=admit_held(session,a,now)
    H.need(preserve["binding"]==held,"OPERATOR_PRESERVE_STOP")
    for key,role in (("owner","owner"),("witness","independent")):
        H.need(a.verify(preserve[key],"preserve",role,now)==held,"OPERATOR_PRESERVE_STOP")
    policy=session["policy"]
    expected=dict(policy_sha=held["destination_policy_sha"],inventory_sha=held["inventory_sha"],ledger_sha=held["ledger_sha"],
        all_five_routes=True,survives_reboot=True,unknown_remains_unknown=True)
    H.need(a.trust.verify(policy,"r1154-permanent-no-replay","destination",now,age=900)==expected,"OPERATOR_DENY_POLICY_STOP")
    custody=session["custody"]
    K.approved(a,custody["binding"],custody["owner"],custody["witness"],now=custody["owner"]["body"]["observed_at"])
    H.need(custody["envelope"]["binding"]==custody["binding"] and custody["binding"]["recipient_public"]==settings["recipient_public"],"OPERATOR_CUSTODY_STOP")
    result=dict(enrollment=a.profile,enrollment_sha=a.pin,run_id=settings["run_id"],scope=session["scope"],
        preserve_owner=preserve["owner"],preserve_witness=preserve["witness"],destination_policy=policy,
        offhost_parent=settings["offhost_parent"],quota_bytes=settings["quota_bytes"],custody=custody)
    if "initial" in session.get("renewal",{}):
        N.peek(a,session["renewal"]["anchor"],session["renewal"]["initial"],now)
        result["renewal"]=dict(anchor=session["renewal"]["anchor"],initial=session["renewal"]["initial"])
    return result


def assemble(kind,session,packets,now):
    a,wire,data,roles,ttl=packet_spec(kind,session,now)
    H.need(set(packets)==roles,"OPERATOR_WITNESS_NOT_ENROLLED")
    for role,packet in packets.items():H.need(a.trust.verify(packet,wire,role,now,age=ttl)==data,"OPERATOR_PACKET_CHANGED")
    if kind in ("review","destination","held","policy"):return next(iter(packets.values()))
    if kind=="scope":
        result=dict(scope_draft(session,now),owner=packets["owner"],witness=packets["independent"]);H.validate_scope(a,result,now=now);return result
    if kind=="custody":return dict(enrollment=a.profile,enrollment_sha=a.pin,binding=data,owner=packets["owner"],witness=packets["independent"])
    if kind=="recipient":return dict(enrollment=a.profile,enrollment_sha=a.pin,run_id=session["scope"]["run_id"],owner=packets["owner"],witness=packets["independent"])
    if kind=="preserve":return dict(binding=data,owner=packets["owner"],witness=packets["independent"])
    if kind=="transfer":
        result=dict(transfer_draft(session,a,now),owner=packets["owner"],witness=packets["independent"]);T.admit(result,now);return result
    result=dict(owner=packets["owner"],witness=packets["independent"])
    class Journal:
        latest=None
        def save(self,value):self.latest=value
    journal=Journal();previous=session["renewal"]["previous"]
    if previous:
        body=previous["owner"]["body"]
        journal.latest=dict(anchor_sha=data["anchor_sha"],packet_sha=C.G.sha(previous),seq=data["seq"]-1,issued=body["observed_at"],expires=body["expires_at"])
    N.Reader(a,session["renewal"]["anchor"],lambda:result,journal).check(now);return result


def collect(control,*,child=None):
    """Only invoked by PS -ReadOnlyCollect; uses existing R987/K137 pins."""
    a=H.Authority(control["enrollment"],control["enrollment_sha"]);ends=control["endpoints"];endpoints_ok(ends,a)
    bases=T.bases(dict(plan={},endpoints=ends,ssh=control["ssh"],oci_key=control["oci_key"],oci_hosts=control["oci_hosts"],k137_hosts=control["k137_hosts"]),a)
    sources=T.bundle();name="packaging/migration/r1157_metadata.py"
    sources[name]=(ROOT/name).read_text(encoding="utf-8").replace("\r\n","\n")
    results={};child=child or C.R.child
    for role,base in zip(("oci","k137"),bases):
        challenge=os.urandom(32).hex()
        request=dict(enrollment=a.profile,enrollment_sha=a.pin,operation="r1157-readonly-metadata",role=role,challenge=challenge,endpoint=ends[role])
        code=T.O.bootstrap(C.G.sha(sources),a.pin,ends[role]["machine_sha256"])
        code=code.replace("root/'packaging/migration/r1154_app_hold.py'","root/'packaging/migration/r1157_metadata.py'")
        code=code.replace(" if os.geteuid()!=0 or"," if os.geteuid()!="+("0" if role=="oci" else "1000")+" or")
        # Bundle includes the already-pinned public units/profile from R1156.
        code=code.replace("not name.startswith(('packaging/migration/','packaging/archive/','src/flop_agent/','scripts/'))",
            "not (name.startswith(('packaging/migration/','packaging/archive/','src/flop_agent/','scripts/','packaging/oracle/')) or name=='public-profile.json')")
        import shlex
        interpreter="/opt/technocore-safe-agent/.venv/bin/python" if role=="oci" else "/usr/bin/python3"
        argv=[*base," ".join(shlex.quote(x) for x in (["sudo","-n"] if role=="oci" else [])+[interpreter,"-I","-B","-c",code])]
        with child(argv,timeout=180) as proc:
            C.R.send_request(proc,sources,request);raw=proc.stdout.read(1024**2+1)
            H.need(len(raw)<=1024**2 and proc.wait(timeout=5)==0,"OPERATOR_METADATA_TRANSPORT_STOP")
            value=C.decode(raw);H.need(value["challenge"]==challenge,"OPERATOR_METADATA_REPLAY_STOP")
            metadata_ok(value,role,a,ends,int(time.time()));results[role]=value
    return results


def output(folder,name,value):
    secure_path(folder,directory=True)
    path=folder/name;H.need(not path.exists() and not path.is_symlink(),"OPERATOR_OUTPUT_EXISTS_STOP")
    raw=C.G.canonical(value);local_write(path,raw)
    # Public hashes only, no credentials/endpoint contents in console.
    local_write(folder/(name+".sha256"),hashlib.sha256(raw).hexdigest().encode()+b"\n")


def local_write(path,raw):
    # CREATE_NEW/O_EXCL: never replace an existing approval or follow a final
    # link. Parent custody is current-user-only; junction ancestors are refused.
    secure_path(path.parent,directory=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    with os.fdopen(fd,"wb") as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    protect_file(path);secure_path(path)


def main():
    password=bytearray()
    try:
        H.need(sys.argv[1:]==["--pipe"],"OPERATOR_PS51_ENTRY_REQUIRED")
        control=C.R.frame_read(sys.stdin.buffer,C.R.MAGIC)
        H.shape(control,"operation data output confirmation")
        op=control["operation"];data=control["data"];now=int(time.time())
        H.need(op in ("init","enroll","audit","draft","issue","assemble","collect"),"OPERATOR_OPERATION_STOP")
        # OwnerPipe sends the SecureString only for init/issue. Other modes
        # reject any secret segment; no argv/env/log/files carry passwords.
        if op in ("init","issue"):
            size=struct.unpack(">I",C.R.exact(sys.stdin.buffer,4))[0]
            H.need(32<=size<=1024,"OPERATOR_PASSWORD_STOP")
            password.extend(C.R.exact(sys.stdin.buffer,size))
        H.need(sys.stdin.buffer.read(1)==b"","OPERATOR_INPUT_STOP")
        H.need(control["confirmation"]==("READ_ONLY" if op=="audit" else "CONFIRM_"+op.upper()),"OPERATOR_CONSENT_STOP")
        folder=Path(control["output"])
        if op=="init":
            H.shape(data,"role");result=init_key(store_path(),data["role"],password);name="public-"+data["role"]+".json"
        elif op=="enroll":result=enroll(data);name="enrollment.json"
        elif op=="collect":result=collect(data);name="snapshots.json"
        else:
            H.need(type(data) is dict and set(data) in ({"kind","session"},{"kind","session","packets"}),"OPERATOR_DATA_STOP")
            kind=data["kind"];session=data["session"]
            if op=="audit":
                _,wire,_,roles,ttl=packet_spec(kind,session,now)
                print(C.G.canonical(dict(code="OPERATOR_PUBLIC_DRAFT_CHECKED",kind=wire,roles=sorted(roles),ttl_seconds=ttl,
                    request_sha=C.G.sha(data),unit_count=len(session["snapshots"]["oci"]["units"]),
                    source_bytes=session["snapshots"]["oci"]["source_bytes"],destination_free_bytes=session["snapshots"]["k137"]["free_bytes"],
                    protected_reserve_bytes=20*C.R.GIB,cutover="NO_GO")).decode());return 0
            if op=="draft":
                a,wire,binding,roles,ttl=packet_spec(kind,session,now)
                result=scope_draft(session,now) if kind=="scope" else transfer_draft(session,a,now) if kind=="transfer" else binding
                name=kind+"-draft.json"
            elif op=="issue":
                packet_spec(kind,session,now) # validate BEFORE opening private custody
                with local_key(store_path(),password) as (key,public):result=issue(kind,session,key,public,now=now)
                name=kind+"-"+public["body"]["role"]+".json"
            else:result=assemble(kind,session,data["packets"],now);name=kind+".json"
        output(folder,name,result)
        if op=="enroll" and "endpoints" in data:output(folder,"endpoints.json",data["endpoints"])
        if op=="assemble" and data["kind"]=="scope":
            output(folder,"hold-request.json",dict(enrollment=data["session"]["enrollment"],enrollment_sha=data["session"]["enrollment_sha"],
                operation="hold",scope=result,owner=None,witness=None))
        print(C.G.canonical(dict(code="OPERATOR_PUBLIC_ARTIFACT_CREATED",artifact=name,sha256=C.G.sha(result),cutover="NO_GO")).decode());return 0
    except Exception as error:
        allowed={"OPERATOR_WITNESS_NOT_ENROLLED","OPERATOR_WITNESS_NOT_INDEPENDENT","G4_NOT_PROVABLE","G5_NOT_PROVABLE",
            "OPERATOR_K137_CAPACITY_STOP","OPERATOR_PASSWORD_STOP","OPERATOR_CUSTODY_HOST_STOP","OPERATOR_PERMISSIONS_STOP","OPERATOR_CONSENT_STOP"}
        code=str(error) if type(error) is H.Stop and str(error) in allowed else "OPERATOR_PREPARATION_STOP"
        print(C.G.canonical(dict(code=code,cutover="NO_GO",oci_retirement="STRICT_NO_GO")).decode());return 42
    finally:password[:]=b"\0"*len(password)


if __name__=="__main__":raise SystemExit(main())
