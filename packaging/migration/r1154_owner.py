"""Fixed original-host HOLD/VERIFY/ROLLBACK transport, not a generic SSH RPC.

Windows supplies only R987's short-lived identity-file PATH via binary stdin.
No private key bytes, seed, arbitrary remote command, room or signing input.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sp=importlib.util.spec_from_file_location("r1154_owner_hold",Path(__file__).with_name("r1154_app_hold.py"))
H=importlib.util.module_from_spec(sp);sys.modules[sp.name]=H;sp.loader.exec_module(H)
C,R=H.C,H.C.R


def sources():
    pins=json.loads(Path(__file__).with_name("r1154_source_pins.json").read_bytes())
    result={}
    for name,pin in pins.items():
        raw=(ROOT/name).read_bytes().replace(b"\r\n",b"\n")
        H.need(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==pin,"WARM_SOURCE_PIN_STOP")
        if name.endswith((".py",".json")) and (name.startswith(("packaging/migration/","packaging/archive/","src/flop_agent/","scripts/"))):
            result[name]=raw.decode("utf8")
    H.need(len(C.G.canonical(result))<=R.LIMIT,"WARM_SOURCE_BOUND_STOP")
    return result


def bootstrap(source_sha,enrollment_sha,machine_sha):
    for value in (source_sha,enrollment_sha,machine_sha):C.digest(value)
    # Only validated hex interpolates into shell code. Trusted enrollment is
    # independently pinned in this immutable invocation, never adopted from a
    # source reply. Staged files are PUBLIC code only, not grants or secrets.
    return '''import sys,struct,json,hashlib,tempfile,pathlib,os,importlib.util
def exact(n):
 b=bytearray()
 while len(b)<n:
  x=sys.stdin.buffer.read(n-len(b))
  if not x: raise ValueError()
  b.extend(x)
 return bytes(b)
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def sha(x):return hashlib.sha256(canonical(x)).hexdigest()
def pairs(items):
 out={}
 for k,v in items:
  if k in out:raise ValueError()
  out[k]=v
 return out
try:
 if exact(8)!=b'FLOPR189':raise ValueError()
 n=struct.unpack('>I',exact(4))[0]
 if not 0<n<=4194304:raise ValueError()
 control=json.loads(exact(n),object_pairs_hook=pairs);request=control['request'];sources=control['sources']
 if sys.stdin.buffer.read(1)!=b'':raise ValueError()
 if sha(sources)!='''+repr(source_sha)+''':raise ValueError()
 if sha(request['enrollment'])!='''+repr(enrollment_sha)+''' or request['enrollment_sha']!='''+repr(enrollment_sha)+''':raise ValueError()
 if os.geteuid()!=0 or hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes().strip()).hexdigest()!='''+repr(machine_sha)+''':raise ValueError()
 with tempfile.TemporaryDirectory(prefix='flop-r1154-public-') as temporary:
  root=pathlib.Path(temporary)
  for name,text in sources.items():
   p=pathlib.PurePosixPath(name)
   if p.is_absolute() or '..' in p.parts or not name.startswith(('packaging/migration/','packaging/archive/','src/flop_agent/','scripts/')):raise ValueError()
   target=root/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);target.write_text(text,encoding='utf8')
  spec=importlib.util.spec_from_file_location('r1154_peer',root/'packaging/migration/r1154_app_hold.py')
  m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
  response=m.peer(request)
  sys.stdout.buffer.write(canonical(response)+b'\\n');sys.stdout.buffer.flush()
except Exception:
 sys.stdout.write('{"phase":"R1154","code":"WARM_REMOTE_STOP_UNKNOWN","vm_stop":"NOT_IMPLEMENTED","source_archive":"NO_GO","aws_publisher":"DISARMED","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}\\n')
 sys.exit(42)
'''


def fixed_command(base,source_sha,enrollment_sha,machine_sha):
    code=bootstrap(source_sha,enrollment_sha,machine_sha)
    return [*base," ".join(shlex.quote(x) for x in ("sudo","-n","/opt/technocore-safe-agent/.venv/bin/python","-I","-B","-c",code))]


def checked_result(raw,exit_code):
    value=C.decode(raw)
    required={"phase","code","vm_stop","source_archive","aws_publisher","cutover","oci_retirement"}
    H.need(type(value) is dict and required<=set(value)<=required|{"scope_sha","journal_sha"},"WARM_RESPONSE_STOP")
    H.need(value["phase"]=="R1154" and value["vm_stop"]=="NOT_IMPLEMENTED" and value["source_archive"]=="NO_GO" and
        value["aws_publisher"]=="DISARMED" and value["cutover"]=="NO_GO" and value["oci_retirement"]=="STRICT_NO_GO" and
        value["code"] in ("HELD_VM_AND_SSH_UNCHANGED","RESTORED_DISARMED_POST_DENY_RETAINED","SOURCE_HOLD_STATUS_REQUIRES_VERIFY","WARM_REMOTE_STOP_UNKNOWN"),"WARM_RESPONSE_STOP")
    for key in ("scope_sha","journal_sha"):
        if key in value:C.digest(value[key])
    H.need(exit_code==0 and value["code"]!="WARM_REMOTE_STOP_UNKNOWN","WARM_REMOTE_UNKNOWN_NO_AUTO_RETRY")
    return value


def check_request(control):
    H.shape(control,"request expected_enrollment_sha ssh identity known_hosts known_hosts_sha")
    request=control["request"];H.shape(request,"enrollment enrollment_sha operation scope owner witness")
    authority=H.Authority(request["enrollment"],request["enrollment_sha"])
    H.need(authority.pin==C.digest(control["expected_enrollment_sha"]),"WARM_ENROLLMENT_STOP")
    H.need(request["operation"] in ("hold","verify","rollback","status"),"WARM_OPERATION_STOP")
    at=int(time.time()) if request["operation"]=="hold" else request["scope"]["owner"]["body"]["observed_at"]
    H.validate_scope(authority,request["scope"],now=at)
    H.need(control["known_hosts_sha"]==request["scope"]["known_hosts_sha"],"WARM_HOST_PIN_STOP")
    return authority


def owner(control):
    authority=check_request(control);request=control["request"]
    for key in ("ssh","identity","known_hosts"):
        H.need(type(control[key]) is str and Path(control[key]).is_absolute(),"WARM_LOCAL_PATH_STOP")
    known=Path(control["known_hosts"])
    H.need(known.stat().st_size<=1048576 and not known.is_symlink(),"WARM_HOST_PIN_STOP")
    raw=known.read_bytes()
    H.need(hashlib.sha256(raw).hexdigest()==C.digest(control["known_hosts_sha"]),"WARM_HOST_PIN_STOP")
    rows=[row for row in raw.decode("ascii").splitlines() if row.startswith("140.238.55.171 ecdsa-sha2-nistp256 ")]
    H.need(len(rows)==1,"WARM_HOST_PIN_STOP")
    # Public single-host material only, under the R987 private custody parent.
    single=Path(control["identity"]).parent/"r1154-known-hosts"
    fd=os.open(single,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as f:f.write((rows[0]+"\n").encode());f.flush();os.fsync(f.fileno())
    try:
        base=R.SSH.ssh_base(control["ssh"],"140.238.55.171","ubuntu",control["identity"],str(single),
            hashlib.sha256(single.read_bytes()).hexdigest(),source=True)
        base[1:1]=["-o","HostKeyAlgorithms=ecdsa-sha2-nistp256","-o","KnownHostsCommand=none"]
        public=sources()
        args=fixed_command(base,C.G.sha(public),authority.pin,authority.trust.context["host"])
        with R.child(args,timeout=600) as process:
            R.send_request(process,public,request)
            out=process.stdout.read(65537)
            H.need(len(out)<=65536,"WARM_RESPONSE_STOP")
            return checked_result(out,process.wait(timeout=15))
    finally:
        single.unlink()


def main():
    try:
        H.need(sys.argv[1:] in (["--owner"],["--check"]),"WARM_SIGNED_OWNER_REQUIRED")
        control=R.frame_read(sys.stdin.buffer,R.MAGIC)
        H.need(sys.stdin.buffer.read(1)==b"","WARM_INPUT_STOP")
        if sys.argv[1:]==["--check"]:
            check_request(control);print(C.G.canonical(H.result("PUBLIC_REQUEST_CHECKED_NO_SSH")).decode());return 42
        reply=owner(control)
        print(C.G.canonical(reply).decode());return 0
    except Exception:
        print(C.G.canonical(H.result("WARM_OWNER_STOP_UNKNOWN_NO_AUTO_RETRY")).decode());return 42


if __name__=="__main__":raise SystemExit(main())
