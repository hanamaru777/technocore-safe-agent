#!/usr/bin/env bash
# R1071: AWS CloudShell read-only bounded transient cgroup probe on K137.
# No permanent service, no owner files/data modifications. Temporary systemd unit only.
set -Eeuo pipefail
umask 077
die() { printf '{"phase":"R1071","result":"STOP","code":"%s","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}\n' "$1"; exit 42; }
# Never modify the host without this exact, deliberate owner opt-in.
[[ "$#" -eq 0 ]] || die ARGUMENTS_STOP
for command_name in aws python3 ssh ssh-keygen mktemp; do
  command -v "$command_name" >/dev/null 2>&1 || die TOOL_UNAVAILABLE
done
d="$(mktemp -d /tmp/flop-r1067.XXXXXXXX)" || die TEMP_STOP
cleanup() {
    rm -f -- "$d/access.json" "$d/identity" "$d/identity-cert.pub" "$d/known_hosts" "$d/metadata.json"
    rmdir -- "$d" 2>/dev/null || :
}
trap cleanup EXIT
# Private AWS-issued credentials never printed and never leave the temporary directory.
if ! aws lightsail get-instance-access-details \
    --instance-name tradebot-k137 --protocol ssh --region ap-northeast-1 \
    --output json >"$d/access.json" 2>/dev/null; then
    die AWS_AUTH_OR_INSTANCE_STOP
fi
export R1067_DIR="$d"
if ! python3 -I -B - <<'PY'
import base64
import datetime
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import struct
import subprocess
import sys
import time

class Reject(Exception):
    pass

def require(ok, code):
    if not ok:
        raise Reject(code)

def read_ssh_host_key(record):
    require(type(record) is dict, "HOSTKEY_SCHEMA_STOP")
    algorithm=record.get("algorithm")
    require(algorithm in ("ssh-ed25519","ecdsa-sha2-nistp256","ssh-rsa"), "HOSTKEY_ALGORITHM_STOP")
    value=record.get("publicKey")
    require(type(value) is str and len(value)<=4096, "HOSTKEY_BLOB_STOP")
    parts=value.strip().split()
    if len(parts)==2:
        require(parts[0]==algorithm, "HOSTKEY_ALGORITHM_STOP")
        value=parts[1]
    else:
        require(len(parts)==1, "HOSTKEY_BLOB_STOP")
        value=parts[0]
    require(bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}",value)), "HOSTKEY_BLOB_STOP")
    raw=base64.b64decode(value,validate=True)
    require(40<=len(raw)<=2048, "HOSTKEY_BLOB_STOP")
    n=struct.unpack(">I",raw[:4])[0]
    require(0<n<=64 and len(raw)>=4+n, "HOSTKEY_BLOB_STOP")
    require(raw[4:4+n].decode("ascii")==algorithm, "HOSTKEY_ALGORITHM_STOP")
    sha="SHA256:"+base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    require(record.get("fingerprintSHA256")==sha, "HOSTKEY_FINGERPRINT_STOP")
    return algorithm,value

try:
    d=pathlib.Path(os.environ["R1067_DIR"])
    response=json.loads((d/"access.json").read_text(encoding="utf-8"))
    require(type(response) is dict and type(response.get("accessDetails")) is dict,
            "RESPONSE_SCHEMA_STOP")
    a=response["accessDetails"]
    require(a.get("instanceName")=="tradebot-k137" and a.get("protocol")=="ssh",
            "INSTANCE_IDENTITY_STOP")
    ip=ipaddress.IPv4Address(a.get("ipAddress"))
    require(ip.is_global and str(ip)==a["ipAddress"], "INSTANCE_IP_STOP")
    user=a.get("username")
    require(type(user) is str and bool(re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}",user))
            and user!="root", "INSTANCE_USER_STOP")
    private=a.get("privateKey")
    require(type(private) is str and bool(private.strip()), "TEMP_PRIVATE_KEY_MISSING_STOP")
    # Do not presume AWS's private-key serialization. Let the installed
    # OpenSSH parser validate the actual unencrypted credential under 0600
    # ephemeral custody, without echoing key text, logs or derived pubkey.
    require(len(private)<=65536 and private.isascii() and "\x00" not in private,
            "TEMP_PRIVATE_KEY_BOUND_STOP")
    cert=a.get("certKey")
    require(type(cert) is str and cert.startswith((
        "ssh-ed25519-cert-v01@openssh.com ",
        "ssh-rsa-cert-v01@openssh.com ",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com ")),
        "TEMP_CERTIFICATE_FORMAT_STOP")
    # AWS CLI documents expiresAt, but the user's authenticated Lightsail
    # response may omit/null it. Absence is NOT proof of validity: OpenSSH
    # independently validates the short-lived certificate at SSH login.
    # If the service supplies an expiration, reject definitely expired values.
    expiry=a.get("expiresAt")
    if expiry not in (None, ""):
        if type(expiry) in (int, float):
            end=float(expiry)
        elif type(expiry) is str:
            try:
                end=datetime.datetime.fromisoformat(
                    expiry.strip().replace("Z","+00:00")
                ).timestamp()
            except (ValueError, OverflowError):
                raise Reject("TEMP_CREDENTIAL_EXPIRY_SCHEMA_STOP")
        else:
            raise Reject("TEMP_CREDENTIAL_EXPIRY_SCHEMA_STOP")
        require(end > time.time()+10 and end < time.time()+7*86400,
                "TEMP_CREDENTIAL_EXPIRED_OR_INVALID_STOP")
    keys=a.get("hostKeys")
    require(type(keys) is list, "HOSTKEY_SCHEMA_STOP")
    selected=None
    # Never fall back from an advertised ed25519 key with a bad fingerprint.
    for algorithm in ("ssh-ed25519","ecdsa-sha2-nistp256","ssh-rsa"):
        matches=[k for k in keys if type(k) is dict and k.get("algorithm")==algorithm]
        require(len(matches)<=1, "HOSTKEY_DUPLICATE_STOP")
        if matches:
            selected=read_ssh_host_key(matches[0])
            break
    require(selected is not None,"HOSTKEY_SUPPORTED_ALGORITHM_MISSING")
    algorithm,public_blob=selected
    def put(name,value):
        fd=os.open(d/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w",encoding="ascii",newline="\n") as stream:
            stream.write(value)
    put("identity",private.strip()+"\n")
    try:
        parsed=subprocess.run(
            ["/usr/bin/ssh-keygen","-y","-P","","-f",str(d/"identity")],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,timeout=10,check=False,
            env={"PATH":"/usr/bin:/bin","HOME":"/nonexistent"})
    except (OSError,subprocess.TimeoutExpired):
        raise Reject("TEMP_PRIVATE_KEY_PARSER_STOP")
    require(parsed.returncode==0,"TEMP_PRIVATE_KEY_PARSE_STOP")
    put("identity-cert.pub",cert.strip()+"\n")
    put("known_hosts",str(ip)+" "+algorithm+" "+public_blob+"\n")
    put("metadata.json",json.dumps({"ip":str(ip),"user":user,
                                    "algorithm":("rsa-sha2-512,rsa-sha2-256" if algorithm=="ssh-rsa" else algorithm)},separators=(",",":")))
except Reject as error:
    # Fixed allow-listed status only. Never show privateKey, certKey or AWS JSON.
    print(json.dumps({"phase":"R1069","result":"STOP","code":str(error),
                      "cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}))
    sys.exit(42)
except Exception:
    print('{"phase":"R1069","result":"STOP","code":"RESPONSE_PARSE_OR_CUSTODY_STOP","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}')
    sys.exit(42)
PY
then
    exit 42
fi
read -r k137_ip k137_user k137_algorithm < <(python3 -I -B -c 'import json,os;d=json.load(open(os.environ["R1067_DIR"]+"/metadata.json"));print(d["ip"],d["user"],d["algorithm"])') || die METADATA_STOP
if ! ssh -F /dev/null -T -i "$d/identity" \
    -o "CertificateFile=$d/identity-cert.pub" \
    -o "UserKnownHostsFile=$d/known_hosts" \
    -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes \
    -o "HostKeyAlgorithms=$k137_algorithm" \
    -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes \
    -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
    -o GSSAPIAuthentication=no -o HostbasedAuthentication=no \
    -o UpdateHostKeys=no -o ForwardAgent=no -o ForwardX11=no \
    -o ClearAllForwardings=yes -o ProxyCommand=none -o ProxyJump=none \
    -o PermitLocalCommand=no -o ConnectTimeout=10 \
    -o ConnectionAttempts=1 -o ServerAliveInterval=10 \
    -o ServerAliveCountMax=2 "$k137_user@$k137_ip" \
    "sudo -n /usr/bin/systemd-run --system --quiet --pipe --collect --unit=flop-r1071-scope-probe.service --property=User=ubuntu --property=Group=ubuntu --property=MemoryMax=256M --property=TasksMax=64 --property=CPUQuota=50% --property=NoNewPrivileges=yes --property=ProtectSystem=strict --property=ProtectHome=yes --property=PrivateTmp=yes /usr/bin/python3 -I -B -" 2>/dev/null <<'PY'
import hashlib,json,os,pathlib,re,stat,sys
P=pathlib.Path("/var/lib/flop-migration-r1066")
S="/opt/flop-shadow/releases/3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e"
def guard(v):
    if not v: raise ValueError("SCOPE_UNVERIFIED")
try:
    guard(sys.platform=="linux" and os.geteuid()==1000)
    a=P.lstat()
    guard(stat.S_ISDIR(a.st_mode) and not stat.S_ISLNK(a.st_mode)
          and stat.S_IMODE(a.st_mode)==0o700 and a.st_uid==1000)
    guard(pathlib.Path(S).is_dir())
    c=pathlib.Path("/proc/self/cgroup").read_text("ascii",errors="strict").strip()
    guard(c.startswith("0::/") and len(c)<=512 and "\\n" not in c)
    rel=c[4:]
    guard(bool(rel) and re.fullmatch("[A-Za-z0-9_.@:/-]+",rel)
          and all(x not in ("",".","..") for x in rel.split("/")))
    root=pathlib.Path("/sys/fs/cgroup")/rel
    mem=(root/"memory.max").read_text("ascii").strip()
    pids=(root/"pids.max").read_text("ascii").strip()
    cpu=(root/"cpu.max").read_text("ascii").split()
    guard(mem.isdecimal() and pids.isdecimal()
          and len(cpu)==2 and all(x.isdecimal() for x in cpu))
    guard(0<int(mem)<=268435456 and 0<int(pids)<=64
          and 0<int(cpu[0])<=int(cpu[1])<=1000000)
    print(json.dumps({"phase":"R1071_K137_BOUNDED_SCOPE","result":"BOUNDED_SCOPE_OBSERVED",
        "uid":1000,"landing":"PRIVATE_0700",
        "cgroup_sha256":hashlib.sha256(c.encode("ascii")).hexdigest(),
        "memory_max_bytes":int(mem),"pids_max":int(pids),
        "cpu_quota":int(cpu[0]),"cpu_period":int(cpu[1]),
        "archive":"NOT_PRESENT","source_backup":"NOT_CREATED",
        "cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"},
        sort_keys=True,separators=(",",":")))
except Exception:
    print('{"phase":"R1071_K137_BOUNDED_SCOPE","result":"STOP","code":"SCOPE_UNVERIFIED","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}')
    raise SystemExit(42)
PY
then
    die SSH_OR_REMOTE_BOUNDED_SCOPE_STOP
fi
