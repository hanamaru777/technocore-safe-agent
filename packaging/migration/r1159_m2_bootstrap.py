"""M2 first-use public endpoint bootstrap. No enrollment, signing or mutation.

Only the reviewed PS5.1 entry uses this helper. Its guest is sent on SSH stdin;
existing R1066 read-only primitives and the public DID decoder are reused.
"""
import ast
import base64
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

HOSTS={"oci":"140.238.55.171","k137":"52.198.96.243"}
K137_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIyiNgOHH+g+6CnwWoVfeJIWcWpQxTsPVH7eAtsGtHTE"
K137_MACHINE=("e2692bd8b11c4021e3ddaebe9e5d49e28" "3ac00584737bc5b7145e657f438d514")
TRADEBOT="k137q-public-k58.service"
SAFE=frozenset(("OCI_INDEPENDENT_TRUST_REQUIRED","OCI_HOST_TRUST_MISMATCH","KNOWN_HOSTS_AMBIGUOUS",
    "KNOWN_HOSTS_INVALID","K137_HOST_TRUST_MISMATCH","M2_SCHEMA_STOP","M2_UID_MISMATCH","M2_MACHINE_MISMATCH",
    "M2_BOOT_CHANGED","M2_CGROUP_CHANGED","M2_CGROUP_MEMBERSHIP_UNVERIFIED","K137_LOGIN_CGROUP_UNBOUNDED",
    "M2_HEAD_MISMATCH","M2_PUBLIC_DID_UNVERIFIED","M2_PUBLIC_DID_CHANGED","M2_DISK_INSUFFICIENT",
    "M2_TRADEBOT_METADATA_UNVERIFIED","M2_TRADEBOT_CAP_CHANGED","M2_SOURCE_PIN_MISMATCH","M2_CHALLENGE_MISMATCH",
    "M2_CLOCK_UNVERIFIED","M2_INPUT_BOUND","M2_OUTPUT_EXISTS","M2_OWNER_PUBLIC_UNVERIFIED"))


def need(ok,code="M2_SCHEMA_STOP"):
    if not ok:raise ValueError(code)


def strict(raw):
    need(type(raw) is bytes and 0<len(raw)<=32768,"M2_INPUT_BOUND")
    def pairs(rows):
        result={}
        for k,v in rows:need(k not in result);result[k]=v
        return result
    return json.loads(raw.decode("utf-8","strict"),object_pairs_hook=pairs,parse_constant=lambda _:need(False))


def shape(value,fields):need(type(value) is dict and set(value)==set(fields.split()))
def integer(value,low=0,high=2**60):need(type(value) is int and low<=value<=high);return value
def digest(value):need(type(value) is str and re.fullmatch(r"[a-f0-9]{64}",value));return value
def canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def blob(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()


def host_key(value,algorithm):
    need(type(value) is str and len(value)<=1024,"KNOWN_HOSTS_INVALID")
    parts=value.split(" ");need(len(parts)==2 and parts[0]==algorithm,"KNOWN_HOSTS_INVALID")
    try:raw=base64.b64decode(parts[1],validate=True)
    except ValueError:raise ValueError("KNOWN_HOSTS_INVALID") from None
    offset=0
    def string():
        nonlocal offset
        need(offset+4<=len(raw),"KNOWN_HOSTS_INVALID");n=int.from_bytes(raw[offset:offset+4],"big");offset+=4
        need(0<n<=1024 and offset+n<=len(raw),"KNOWN_HOSTS_INVALID");v=raw[offset:offset+n];offset+=n;return v
    need(string()==algorithm.encode(),"KNOWN_HOSTS_INVALID")
    if algorithm=="ssh-ed25519":need(len(string())==32,"KNOWN_HOSTS_INVALID")
    else:need(string()==b"nistp256" and len(point:=string())==65 and point[0]==4,"KNOWN_HOSTS_INVALID")
    need(offset==len(raw),"KNOWN_HOSTS_INVALID")
    return sha(raw)


def trust_plan(request):
    shape(request,"oracle_key_sha256 oracle_trust_reference known_hosts")
    pin=request["oracle_key_sha256"];reference=request["oracle_trust_reference"]
    need(type(pin) is str and re.fullmatch(r"[a-f0-9]{64}",pin) and type(reference) is str and len(reference)<=180 and
        re.fullmatch(r"https://github\.com/hanamaru777/technocore-safe-agent/issues/[0-9]+#issuecomment-[0-9]+",reference),"OCI_INDEPENDENT_TRUST_REQUIRED")
    text=request["known_hosts"];need(type(text) is str and 0<len(text.encode())<=16384,"KNOWN_HOSTS_INVALID")
    found={r:[] for r in HOSTS}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):continue
        parts=line.split();need(3<=len(parts)<=16,"KNOWN_HOSTS_INVALID")
        if parts[0].startswith("@"):
            need(not any(h in parts[1].split(",") for h in HOSTS.values()) and not parts[1].startswith("|"),"KNOWN_HOSTS_INVALID")
            continue
        hosts=parts[0]
        for role,host in HOSTS.items():
            match=host in hosts.split(",")
            if hosts.startswith("|1|"):
                try:
                    _,version,salt,value=hosts.split("|")
                    salt=base64.b64decode(salt,validate=True);value=base64.b64decode(value,validate=True)
                    need(len(salt)==20 and len(value)==20,"KNOWN_HOSTS_INVALID")
                    match=hmac.compare_digest(hmac.new(salt,host.encode(),hashlib.sha1).digest(),value)
                except ValueError:raise ValueError("KNOWN_HOSTS_INVALID") from None
            if match:
                algorithm="ecdsa-sha2-nistp256" if role=="oci" else "ssh-ed25519"
                if parts[1]==algorithm:found[role].append(parts[1]+" "+parts[2])
    need(len(found["oci"])==1 and len(found["k137"])<=1,"KNOWN_HOSTS_AMBIGUOUS")
    need(host_key(found["oci"][0],"ecdsa-sha2-nistp256")==pin,"OCI_HOST_TRUST_MISMATCH")
    need(not found["k137"] or found["k137"][0]==K137_KEY,"K137_HOST_TRUST_MISMATCH")
    return dict(schema_version=1,purpose="R1159_TRUST_ONLY_NOT_ENDPOINTS",oracle_trust_reference=reference,oracle_key_sha256=pin,
        oci=dict(host=HOSTS["oci"],user="ubuntu",host_key=found["oci"][0]),
        k137=dict(host=HOSTS["k137"],user="ubuntu",host_key=K137_KEY))


def public_did(raw,decode):
    value=strict(raw);shape(value,"did verified_at")
    need(type(value["verified_at"]) is str and re.fullmatch(r"[0-9T:+.Z-]{20,64}",value["verified_at"]),"M2_PUBLIC_DID_UNVERIFIED")
    return did_identity(value["did"],decode)


def did_identity(did,decode):
    need(type(did) is str and re.fullmatch(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}",did),"M2_PUBLIC_DID_UNVERIFIED")
    decoded=decode(did[9:]);need(len(decoded)==34 and decoded[:2]==b"\xed\x01","M2_PUBLIC_DID_UNVERIFIED")
    return did,[sha(decoded[2:])]


def public_file(path,allowed_uids):
    for parent in path.parents:need(not parent.is_symlink(),"M2_PUBLIC_DID_UNVERIFIED")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd);need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid in allowed_uids and
            not info.st_mode&0o022 and 0<info.st_size<=1024,"M2_PUBLIC_DID_UNVERIFIED")
        raw=os.read(fd,1025);after=os.fstat(fd)
        need((info.st_ino,info.st_size,info.st_mtime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns) and len(raw)==info.st_size,"M2_PUBLIC_DID_CHANGED")
        return raw
    finally:os.close(fd)


def cgroup_evidence(R,role):
    raw=R.read_small("/proc/self/cgroup");text=raw.decode("ascii").strip()
    need(text.startswith("0::/") and "\n" not in text,"M2_CGROUP_MEMBERSHIP_UNVERIFIED")
    relative=text[4:]
    need(len(relative)<=512 and (not relative or re.fullmatch(r"[A-Za-z0-9_.@:/-]+",relative) and
        all(p not in ("",".","..") for p in relative.split("/"))),"M2_CGROUP_MEMBERSHIP_UNVERIFIED")
    root="/sys/fs/cgroup/"+relative;R.directory(root)
    members=R.read_small(root+"/cgroup.procs",65536).splitlines()
    need(members and all(p.isdigit() for p in members) and str(os.getpid()).encode() in members,"M2_CGROUP_MEMBERSHIP_UNVERIFIED")
    if role=="k137":
        try:R.resources(sha(text.encode()))
        except Exception:raise ValueError("K137_LOGIN_CGROUP_UNBOUNDED") from None
    def limit(name):
        value=R.read_small(root+"/"+name,32).strip();need(value==b"max" or value.isdigit(),"M2_CGROUP_MEMBERSHIP_UNVERIFIED")
        return None if value==b"max" else int(value)
    cpu=R.read_small(root+"/cpu.max",64).split();need(len(cpu)==2 and cpu[1].isdigit() and (cpu[0]==b"max" or cpu[0].isdigit()),"M2_CGROUP_MEMBERSHIP_UNVERIFIED")
    return dict(raw_sha256=sha(raw),normalized_sha256=sha(text.encode()),memory_max=limit("memory.max"),pids_max=limit("pids.max"),
        cpu_quota=None if cpu[0]==b"max" else int(cpu[0]),cpu_period=int(cpu[1]))


def tradebot_evidence(R):
    r=R.subprocess.run(["/usr/bin/systemctl","show","--no-pager","--property=LoadState,ActiveState,MemoryHigh,MemoryMax,ControlGroup","--",TRADEBOT],
        stdin=R.subprocess.DEVNULL,capture_output=True,timeout=5,check=False,env={"PATH":"/usr/bin:/bin","LANG":"C"})
    need(r.returncode==0 and len(r.stdout)<=2048 and not r.stderr,"M2_TRADEBOT_METADATA_UNVERIFIED")
    rows=r.stdout.decode("ascii").splitlines();d={}
    for line in rows:
        k,v=line.split("=",1);need(k not in d,"M2_TRADEBOT_METADATA_UNVERIFIED");d[k]=v
    shape(d,"LoadState ActiveState MemoryHigh MemoryMax ControlGroup")
    need(d["LoadState"]=="loaded" and d["ActiveState"]=="active" and d["MemoryHigh"].isdigit() and d["MemoryMax"].isdigit(),"M2_TRADEBOT_METADATA_UNVERIFIED")
    need(int(d["MemoryHigh"])==1000*1024**2 and int(d["MemoryMax"])==1200*1024**2,"M2_TRADEBOT_CAP_CHANGED")
    path=d["ControlGroup"];need(re.fullmatch(r"/[A-Za-z0-9_./@:-]{1,512}",path) and all(p not in ("",".","..") for p in path[1:].split("/")),"M2_TRADEBOT_METADATA_UNVERIFIED")
    R.directory("/sys/fs/cgroup"+path)
    need(R.read_small("/sys/fs/cgroup"+path+"/memory.max",32).strip()==d["MemoryMax"].encode(),"M2_TRADEBOT_CAP_CHANGED")
    return dict(unit=TRADEBOT,active=True,memory_high=int(d["MemoryHigh"]),memory_max=int(d["MemoryMax"]),cgroup_sha256=sha(path.encode()))


def probe(role,challenge,R,decode,source_blobs):
    need(role in HOSTS and sys.platform=="linux");digest(challenge)
    uid=os.geteuid();need(uid==(0 if role=="oci" else 1000),"M2_UID_MISMATCH")
    machine=R.read_small("/etc/machine-id",64).strip();need(re.fullmatch(rb"[a-f0-9]{32}",machine),"M2_MACHINE_MISMATCH")
    machine=sha(machine)
    if role=="k137":need(machine==K137_MACHINE,"M2_MACHINE_MISMATCH")
    boot=R.read_small("/proc/sys/kernel/random/boot_id",64)
    need(re.fullmatch(rb"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\n?",boot),"M2_BOOT_CHANGED")
    cg=cgroup_evidence(R,role)
    if role=="oci":
        R.directory(R.APP);R.directory(R.STATE);head=R.git_head(R.APP);need(head==R.HEAD,"M2_HEAD_MISMATCH")
        import pwd
        path=Path(R.STATE)/"verified-did.json";allowed={0,pwd.getpwnam("technocore").pw_uid}
        public=public_file(path,allowed);did,keys=public_did(public,decode);target=None;disk=R.STATE
    else:
        for p in R.PROTECTED:R.directory(p);need(not os.access(p,os.W_OK),"M2_TRADEBOT_METADATA_UNVERIFIED")
        R.directory(R.K137_STAGE);head=R.git_head(R.K137_STAGE);need(head==R.K137_STAGE_SHA,"M2_HEAD_MISMATCH")
        info=R.directory(R.LANDING);need(info.st_uid==1000 and stat.S_IMODE(info.st_mode)==0o700 and os.access(R.LANDING,os.R_OK|os.W_OK|os.X_OK),"M2_CGROUP_MEMBERSHIP_UNVERIFIED")
        did=None;keys=None;target=tradebot_evidence(R);disk=R.LANDING
    space=os.statvfs(disk);free=space.f_bavail*space.f_frsize
    need(free>=(1 if role=="oci" else 21)*1024**3,"M2_DISK_INSUFFICIENT")
    need(R.read_small("/proc/sys/kernel/random/boot_id",64)==boot,"M2_BOOT_CHANGED")
    need(sha(R.read_small("/proc/self/cgroup"))==cg["raw_sha256"],"M2_CGROUP_CHANGED")
    need(cgroup_evidence(R,role)==cg,"M2_CGROUP_CHANGED")
    if role=="oci":need(public_file(path,allowed)==public,"M2_PUBLIC_DID_CHANGED")
    return dict(schema_version=1,role=role,challenge=challenge,observed_at=int(time.time()),source_blobs=source_blobs,
        machine_sha256=machine,boot_raw_sha256=sha(boot),boot_runtime_sha256=sha(boot if role=="oci" else boot.strip()),
        uid=uid,head=head,cgroup=cg,free_bytes=free,source_did=did,source_key_ids=keys,tradebot=target,
        read_only=True,cutover="NO_GO",oci_retirement="STRICT_NO_GO")


def sources():
    root=Path(__file__).resolve().parents[2]
    paths={"bootstrap":Path(__file__),"preflight":root/"packaging/migration/r1066_preflight_readonly.py","public_record":root/"src/flop_agent/public_record.py"}
    raw={k:p.read_bytes().replace(b"\r\n",b"\n") for k,p in paths.items()}
    return root,raw,{k:blob(v) for k,v in raw.items()}


def decoder_source(raw):
    tree=ast.parse(raw.decode());wanted={"B58","B58_INDEX"};parts=[]
    for n in tree.body:
        if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in wanted for t in n.targets):parts.append(ast.get_source_segment(raw.decode(),n))
        if isinstance(n,ast.FunctionDef) and n.name=="_b58decode":parts.append(ast.get_source_segment(raw.decode(),n))
    need(len(parts)==3,"M2_SOURCE_PIN_MISMATCH");return "\n".join(parts)


def guest_source(role,challenge):
    need(role in HOSTS);digest(challenge);_,raw,pins=sources()
    wanted={"need","strict","shape","integer","digest","canonical","sha","blob","public_did","did_identity","public_file","cgroup_evidence","tradebot_evidence","probe"}
    tree=ast.parse(raw["bootstrap"].decode());parts=[ast.get_source_segment(raw["bootstrap"].decode(),n) for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in wanted]
    need(len(parts)==len(wanted),"M2_SOURCE_PIN_MISMATCH")
    header="import os,sys,re,json,stat,hashlib,time,types\nfrom pathlib import Path\n"
    header+="R=types.ModuleType('pinned_r1066');exec(compile("+repr(raw["preflight"].decode())+",'<pinned-r1066>','exec'),R.__dict__)\n"
    header+="HOSTS="+repr(HOSTS)+"\nK137_MACHINE="+repr(K137_MACHINE)+"\nTRADEBOT="+repr(TRADEBOT)+"\n"
    code=header+decoder_source(raw["public_record"])+"\n"+"\n\n".join(parts)
    code+="\ntry:\n result=probe("+repr(role)+","+repr(challenge)+",R,_b58decode,"+repr(pins)+")\n print(canonical(result).decode())\nexcept Exception as error:\n code=str(error) if type(error) is ValueError and str(error) in "+repr(sorted(SAFE))+" else 'M2_GUEST_UNVERIFIED'\n print(json.dumps({'code':code,'cutover':'NO_GO'}));sys.exit(42)\n"
    need(len(code.encode())<=16384,"M2_INPUT_BOUND");compile(code,"<r1159-guest>","exec");return code.encode()


def validate_report(value,role,challenge,pins,R,decode,now):
    shape(value,"schema_version role challenge observed_at source_blobs machine_sha256 boot_raw_sha256 boot_runtime_sha256 uid head cgroup free_bytes source_did source_key_ids tradebot read_only cutover oci_retirement")
    need(type(value["schema_version"]) is int and value["schema_version"]==1 and value["role"]==role)
    need(value["challenge"]==challenge,"M2_CHALLENGE_MISMATCH");need(value["source_blobs"]==pins,"M2_SOURCE_PIN_MISMATCH")
    need(type(value["observed_at"]) is int and now-180<=value["observed_at"]<=now+5,"M2_CLOCK_UNVERIFIED")
    for k in ("machine_sha256","boot_raw_sha256","boot_runtime_sha256"):digest(value[k])
    need(value["uid"]==(0 if role=="oci" else 1000) and type(value["uid"]) is int,"M2_UID_MISMATCH")
    need(value["head"]==(R.HEAD if role=="oci" else R.K137_STAGE_SHA),"M2_HEAD_MISMATCH")
    need(value["read_only"] is True and value["cutover"]=="NO_GO" and value["oci_retirement"]=="STRICT_NO_GO")
    need(integer(value["free_bytes"])>=(1 if role=="oci" else 21)*1024**3,"M2_DISK_INSUFFICIENT")
    cg=value["cgroup"];shape(cg,"raw_sha256 normalized_sha256 memory_max pids_max cpu_quota cpu_period")
    digest(cg["raw_sha256"]);digest(cg["normalized_sha256"])
    integer(cg["cpu_period"],1,1000000)
    for k in ("memory_max","pids_max","cpu_quota"):
        if cg[k] is not None:integer(cg[k],1)
    if role=="k137":
        need(value["machine_sha256"]==K137_MACHINE,"M2_MACHINE_MISMATCH")
        need(cg["memory_max"] is not None and cg["memory_max"]<=256*1024**2 and cg["pids_max"] is not None and cg["pids_max"]<=64 and
            cg["cpu_quota"] is not None and cg["cpu_quota"]<=cg["cpu_period"],"K137_LOGIN_CGROUP_UNBOUNDED")
        t=value["tradebot"];shape(t,"unit active memory_high memory_max cgroup_sha256")
        need(t["unit"]==TRADEBOT and t["active"] is True and t["memory_high"]==1000*1024**2 and t["memory_max"]==1200*1024**2,"M2_TRADEBOT_CAP_CHANGED");digest(t["cgroup_sha256"])
        need(value["source_did"] is None and value["source_key_ids"] is None)
    else:
        did,keys=did_identity(value["source_did"],decode)
        need(value["source_key_ids"]==keys and value["tradebot"] is None and value["boot_runtime_sha256"]==value["boot_raw_sha256"],"M2_PUBLIC_DID_UNVERIFIED")
    return value


def finish(control,M,*,now=None,owner_public=None):
    shape(control,"plan reports challenges credential_hashes k137_identity_file output")
    plan=control["plan"];shape(plan,"schema_version purpose oracle_trust_reference oracle_key_sha256 oci k137")
    need(type(plan["schema_version"]) is int and plan["schema_version"]==1 and plan["purpose"]=="R1159_TRUST_ONLY_NOT_ENDPOINTS")
    need(type(plan["oracle_trust_reference"]) is str and re.fullmatch(r"https://github\.com/hanamaru777/technocore-safe-agent/issues/[0-9]+#issuecomment-[0-9]+",plan["oracle_trust_reference"]),"OCI_INDEPENDENT_TRUST_REQUIRED")
    shape(control["reports"],"oci k137");shape(control["challenges"],"oci k137");shape(control["credential_hashes"],"oci k137")
    _,raw,pins=sources();R=types.ModuleType("pinned_preflight");exec(compile(raw["preflight"],"<r1066>","exec"),R.__dict__)
    decoder={};exec(decoder_source(raw["public_record"]),decoder)
    endpoints=dict(schema_version=1,purpose="R1066_READONLY_PREFLIGHT")
    for role in HOSTS:
        e=plan[role];shape(e,"host user host_key");need(e["host"]==HOSTS[role] and e["user"]=="ubuntu")
        if role=="k137":need(e["host_key"]==K137_KEY,"K137_HOST_TRUST_MISMATCH")
        key_sha=host_key(e["host_key"],"ecdsa-sha2-nistp256" if role=="oci" else "ssh-ed25519")
        if role=="oci":need(key_sha==plan["oracle_key_sha256"],"OCI_HOST_TRUST_MISMATCH")
        digest(control["challenges"][role]);digest(control["credential_hashes"][role])
        report=validate_report(control["reports"][role],role,control["challenges"][role],pins,R,decoder["_b58decode"],int(time.time()) if now is None else now)
        endpoints[role]=dict(**e,host_key_sha256=key_sha,credential_sha256=control["credential_hashes"][role],
            identity_file="R987_V2_ESCROW" if role=="oci" else control["k137_identity_file"],machine_sha256=report["machine_sha256"],uid=report["uid"],
            head=report["head"],cgroup_sha256=report["cgroup"]["raw_sha256"],minimum_free_bytes=(1 if role=="oci" else 21)*1024**3)
    need(endpoints["oci"]["credential_sha256"]!=endpoints["k137"]["credential_sha256"],"M2_SCHEMA_STOP")
    need(endpoints["oci"]["machine_sha256"]!=endpoints["k137"]["machine_sha256"],"M2_MACHINE_MISMATCH")
    # Existing Init is CONSUMED. Only its public descriptor is read, never the
    # approval PEM or passphrase, and no signatures/keys are created here.
    public=owner_public if owner_public is not None else M.read_public(M.store_path()/"public.json")
    M.validate_descriptor(public);need(public["body"]["role"]=="owner" and public["body"]["control"]==M.control_identity(),"M2_OWNER_PUBLIC_UNVERIFIED")
    source=control["reports"]["oci"]
    enroll=dict(endpoints=endpoints,source_did=source["source_did"],source_key_ids=source["source_key_ids"],owner_public=public,
        boots={r:control["reports"][r]["boot_runtime_sha256"] for r in HOSTS},machine_keys={r:None for r in HOSTS},protected_tradebot=dict(unit=TRADEBOT))
    # Exact existing R1158 admission, but do NOT enroll or save any authority.
    spec=importlib.util.spec_from_file_location("r1159_review_r1158",Path(__file__).with_name("r1158_owner.py"))
    legacy=importlib.util.module_from_spec(spec);sys.modules[spec.name]=legacy;spec.loader.exec_module(legacy)
    legacy.profile_from_public(enroll)
    folder=Path(control["output"]);M.secure_path(folder,directory=True)
    files={"endpoints.json":endpoints,"host-evidence.json":dict(reports=control["reports"],trust_reference=plan["oracle_trust_reference"],
        key_ids_basis="SHA256_OBSERVED_ED25519_PUBLIC_KEY",enrollment="NOT_DONE",cutover="NO_GO",oci_retirement="STRICT_NO_GO"),"enroll-input.json":enroll}
    need(not any((folder/n).exists() or (folder/(n+".sha256")).exists() for n in files),"M2_OUTPUT_EXISTS")
    need(not (folder/"M2-result.json").exists(),"M2_OUTPUT_EXISTS")
    for n,value in files.items():M.output(folder,n,value)
    M.output(folder,"M2-result.json",dict(code="M2_AUTHENTICATED_PUBLIC_ARTIFACTS_ONLY",artifacts={n:sha(canonical(v)) for n,v in files.items()},
        source_blobs=pins,enrollment="NOT_DONE",cutover="NO_GO",oci_retirement="STRICT_NO_GO"))
    return dict(code="M2_AUTHENTICATED_PUBLIC_ARTIFACTS_ONLY",enrollment="NOT_DONE",cutover="NO_GO",oci_retirement="STRICT_NO_GO")


def main():
    try:
        need(sys.argv[1:] and sys.argv[1] in ("--prepare","--guest","--finish"))
        if sys.argv[1]=="--guest":need(len(sys.argv)==4);sys.stdout.buffer.write(guest_source(sys.argv[2],sys.argv[3]));return 0
        need(len(sys.argv)==2);value=strict(sys.stdin.buffer.read(32769))
        if sys.argv[1]=="--prepare":result=trust_plan(value)
        else:
            shape(value,"plan report_bytes challenges credential_hashes k137_identity_file output")
            shape(value["report_bytes"],"oci k137")
            reports={}
            for role in HOSTS:
                encoded=value["report_bytes"][role];need(type(encoded) is str and len(encoded)<=8192,"M2_INPUT_BOUND")
                raw=base64.b64decode(encoded,validate=True);need(len(raw)<=4096,"M2_INPUT_BOUND")
                reports[role]=strict(raw)
            value={k:v for k,v in value.items() if k!="report_bytes"};value["reports"]=reports
            sp=importlib.util.spec_from_file_location("r1159_existing_public_output",Path(__file__).with_name("r1157_operator.py"))
            M=importlib.util.module_from_spec(sp);sys.modules[sp.name]=M;sp.loader.exec_module(M)
            result=finish(value,M)
        sys.stdout.buffer.write(canonical(result));return 0
    except Exception as error:
        code=str(error) if type(error) is ValueError and str(error) in SAFE else "M2_UNVERIFIED_STOP"
        print(json.dumps(dict(code=code,cutover="NO_GO",oci_retirement="STRICT_NO_GO")));return 42


if __name__=="__main__":raise SystemExit(main())
