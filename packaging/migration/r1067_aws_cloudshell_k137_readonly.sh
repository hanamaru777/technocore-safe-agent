#!/usr/bin/env bash
# R1067: AWS CloudShell owner-invoked K137 ONLY read-only provenance.
# The Lightsail API generates temporary SSH keys. Explicit owner approval required.
set -Eeuo pipefail
umask 077
die() { printf '{"phase":"R1067","result":"STOP","code":"%s","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}\n' "$1"; exit 42; }
for command_name in aws python3 ssh mktemp; do
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
import base64,hashlib,ipaddress,json,os,pathlib,re,sys
try:
    d=pathlib.Path(os.environ["R1067_DIR"])
    a=json.loads((d/"access.json").read_text(encoding="utf-8"))["accessDetails"]
    assert a["instanceName"]=="tradebot-k137" and a["protocol"]=="ssh"
    ip=ipaddress.IPv4Address(a["ipAddress"])
    assert ip.is_global and str(ip)==a["ipAddress"]
    user=a["username"]
    assert re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}",user) and user!="root"
    assert a["privateKey"].startswith(("-----BEGIN OPENSSH PRIVATE KEY-----",
                                              "-----BEGIN RSA PRIVATE KEY-----"))
    assert a["certKey"].startswith(("ssh-ed25519-cert-v01@openssh.com ","ssh-rsa-cert-v01@openssh.com "))
    assert a.get("expiresAt")
    candidates=[h for h in a["hostKeys"] if h.get("algorithm")=="ssh-ed25519"]
    assert len(candidates)==1
    h=candidates[0]
    key=base64.b64decode(h["publicKey"],validate=True)
    sha=base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip("=")
    assert h["fingerprintSHA256"]=="SHA256:"+sha and 32<=len(key)<=2048
    def put(name,value):
        fd=os.open(d/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w",encoding="ascii",newline="\n") as f:
            f.write(value)
    put("identity",a["privateKey"].strip()+"\n")
    put("identity-cert.pub",a["certKey"].strip()+"\n")
    put("known_hosts",str(ip)+" ssh-ed25519 "+h["publicKey"]+"\n")
    put("metadata.json",json.dumps({"ip":str(ip),"user":user},separators=(",",":")))
except Exception:
    sys.exit(42)
PY
then
    die AWS_RESPONSE_AUTHORITY_STOP
fi
read -r k137_ip k137_user < <(python3 -I -B -c 'import json,os;d=json.load(open(os.environ["R1067_DIR"]+"/metadata.json"));print(d["ip"],d["user"])') || die METADATA_STOP
if ! ssh -F /dev/null -T -i "$d/identity" \
    -o "CertificateFile=$d/identity-cert.pub" \
    -o "UserKnownHostsFile=$d/known_hosts" \
    -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes \
    -o HostKeyAlgorithms=ssh-ed25519 \
    -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes \
    -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
    -o GSSAPIAuthentication=no -o HostbasedAuthentication=no \
    -o UpdateHostKeys=no -o ForwardAgent=no -o ForwardX11=no \
    -o ClearAllForwardings=yes -o ProxyCommand=none -o ProxyJump=none \
    -o PermitLocalCommand=no -o ConnectTimeout=10 \
    -o ConnectionAttempts=1 -o ServerAliveInterval=10 \
    -o ServerAliveCountMax=2 "$k137_user@$k137_ip" \
    "/usr/bin/python3 -I -B -" 2>/dev/null <<'PY'
import json,os,pathlib,pwd,stat,subprocess,sys
try:
    assert sys.platform=="linux" and os.geteuid()!=0
    def entry(path):
        p=pathlib.Path(path)
        try:
            s=p.lstat()
            return {"exists":True,"directory":stat.S_ISDIR(s.st_mode),
                    "symlink":stat.S_ISLNK(s.st_mode),
                    "same_uid":s.st_uid==os.geteuid(),
                    "mode":stat.S_IMODE(s.st_mode)}
        except FileNotFoundError:
            return {"exists":False}
    stage="/opt/flop-shadow/releases/3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e"
    roots={"shadow":"/opt/flop-shadow","stage":stage,
           "landing":"/var/lib/flop-migration-r1066",
           "tradebot":"/opt/tradebot-k137",
           "tradebot_private":"/opt/tradebot-k137-private"}
    paths={k:entry(v) for k,v in roots.items()}
    git_head="UNCONFIRMED"
    if paths["stage"].get("directory") and not paths["stage"].get("symlink"):
        try:
            p=subprocess.run(["/usr/bin/git","-c","safe.directory="+stage,
                             "-C",stage,"rev-parse","--verify","HEAD"],
                    capture_output=True,timeout=5,
                    env={"PATH":"/usr/bin:/bin","HOME":"/nonexistent",
                         "GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null",
                         "GIT_OPTIONAL_LOCKS":"0"})
            if p.returncode==0 and len(p.stdout)==41:
                git_head="MATCH" if p.stdout.strip()==b"3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e" else "MISMATCH"
        except (OSError,subprocess.TimeoutExpired):
            pass
    st=os.statvfs("/")
    available=st.f_bavail*st.f_frsize
    total=st.f_blocks*st.f_frsize
    mem={}
    for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
        if line.startswith(("MemAvailable:","MemTotal:")):
            k,v=line.split(":",1);mem[k]=int(v.strip().split()[0])*1024
    try:
        shadow=pwd.getpwnam("flop-shadow")
        user={"exists":True,"login_shell":shadow.pw_shell.rsplit("/",1)[-1],
              "uid":shadow.pw_uid}
    except KeyError:
        user={"exists":False}
    cgroup="UNCONFIRMED"
    try:
        line=pathlib.Path("/proc/self/cgroup").read_text().strip()
        if line.startswith("0::/"): cgroup="CGROUP_V2_PRESENT_LIMIT_NOT_ASSESSED"
    except (OSError,UnicodeError):
        pass
    print(json.dumps({"phase":"R1067_K137_READONLY","result":"HOST_AUTHENTICATED",
        "filesystem_free_bytes":available,"filesystem_total_bytes":total,
        "mem_available_bytes":mem.get("MemAvailable",0),
        "mem_total_bytes":mem.get("MemTotal",0),
        "uid":os.geteuid(),"shadow_identity":user,"paths":paths,
        "stage_git_head":git_head,"cgroup":cgroup,
        "tradebot_execution_impact":"NOT_ASSESSED",
        "original_oci_archive":"NOT_ASSESSED",
        "cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"},
        separators=(",",":"),sort_keys=True))
except Exception:
    print('{"phase":"R1067_K137_READONLY","result":"STOP","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}')
    raise SystemExit(42)
PY
then
    die SSH_OR_REMOTE_READONLY_STOP
fi
