"""Synthetic host snapshots/keys only. Never select real local credentials."""
import ast
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec,ed25519
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import test_r1157_operator as prior

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/"packaging/migration/r1159_m2_bootstrap.py"
PS=ROOT/"packaging/windows/r1159_authenticated_m2_bootstrap.ps1"
sp=importlib.util.spec_from_file_location("r1159_test",PATH);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
sp=importlib.util.spec_from_file_location("r1159_dummy_official_signer",ROOT/"scripts/sign.py");official=importlib.util.module_from_spec(sp);sp.loader.exec_module(official)
WINDOWS=pytest.mark.skipif(os.name!="nt",reason="native PS5.1 synthetic-only contract")


@pytest.fixture
def fixture(tmp_path,monkeypatch):
    # Fresh disposable DID/host/owner keys. No key is read from the machine.
    did_key=ed25519.Ed25519PrivateKey.generate();did=official.did_of(did_key)
    host=ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(Encoding.OpenSSH,PublicFormat.OpenSSH).decode()
    plan=m.trust_plan(dict(oracle_key_sha256=m.host_key(host,"ecdsa-sha2-nistp256"),
        oracle_trust_reference="https://github.com/hanamaru777/technocore-safe-agent/issues/765#issuecomment-1",known_hosts=m.HOSTS["oci"]+" "+host))
    now=int(time.time());pins=m.sources()[2];reports={}
    for role in m.HOSTS:
        reports[role]=dict(schema_version=1,role=role,challenge=m.sha(role.encode()),observed_at=now,source_blobs=pins,
            machine_sha256=m.sha(b"synthetic oci") if role=="oci" else m.K137_MACHINE,
            boot_raw_sha256=m.sha((role+" raw boot").encode()),boot_runtime_sha256=m.sha((role+" raw boot").encode()) if role=="oci" else m.sha(b"runtime boot"),
            uid=0 if role=="oci" else 1000,head="ec4bc4892d40cdd2a03e102faa44d72c89e01b99" if role=="oci" else "3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e",
            cgroup=dict(raw_sha256=m.sha(b"cgroup raw"),normalized_sha256=m.sha(b"cgroup normalized"),memory_max=128*1024**2,pids_max=32,cpu_quota=10000,cpu_period=100000),
            free_bytes=64*1024**3,source_did=did if role=="oci" else None,source_key_ids=[m.sha(did_key.public_key().public_bytes_raw())] if role=="oci" else None,
            tradebot=None if role=="oci" else dict(unit=m.TRADEBOT,active=True,memory_high=1000*1024**2,memory_max=1200*1024**2,cgroup_sha256=m.sha(b"protected group")),
            read_only=True,cutover="NO_GO",oci_retirement="STRICT_NO_GO")
    output=tmp_path/"public";output.mkdir(mode=0o700);prior.M.protect_file(output)
    control=dict(plan=plan,reports=reports,challenges={r:v["challenge"] for r,v in reports.items()},credential_hashes={r:m.sha((r+" credential").encode()) for r in reports},
        k137_identity_file=str(tmp_path/"synthetic.pem"),output=str(output))
    owner=ed25519.Ed25519PrivateKey.generate();identity=m.sha(b"dummy local owner")
    descriptor=prior.M.descriptor(owner,"owner",identity);monkeypatch.setattr(prior.M,"control_identity",lambda:identity)
    monkeypatch.setattr(prior.M,"store_path",lambda:tmp_path/"synthetic-approval-only")
    _,raw,_=m.sources();decoder={};exec(m.decoder_source(raw["public_record"]),decoder)
    R=SimpleNamespace(HEAD=reports["oci"]["head"],K137_STAGE_SHA=reports["k137"]["head"])
    return SimpleNamespace(control=control,public=descriptor,now=now,decode=decoder["_b58decode"],R=R,host=host,output=output)


def test_success_public_artifacts_only_no_owner_key_init(fixture,monkeypatch):
    monkeypatch.setattr(prior.M,"init_key",lambda *_:pytest.fail("Init is consumed"))
    monkeypatch.setattr(prior.M,"local_key",lambda *_:pytest.fail("never unlock owner"))
    result=m.finish(fixture.control,prior.M,now=fixture.now,owner_public=fixture.public)
    assert result["code"]=="M2_AUTHENTICATED_PUBLIC_ARTIFACTS_ONLY" and result["enrollment"]=="NOT_DONE"
    endpoints=json.loads((fixture.output/"endpoints.json").read_bytes())
    assert endpoints["purpose"]=="R1066_READONLY_PREFLIGHT" and endpoints["k137"]["uid"]==1000
    assert endpoints["oci"]["identity_file"]=="R987_V2_ESCROW" and endpoints["k137"]["cgroup_sha256"]==fixture.control["reports"]["k137"]["cgroup"]["raw_sha256"]
    enroll=json.loads((fixture.output/"enroll-input.json").read_bytes())
    assert enroll["owner_public"]==fixture.public and enroll["machine_keys"]==dict(oci=None,k137=None)
    assert "witness" not in enroll and not (fixture.output/"approval.pem.enc").exists()
    for name in ("endpoints.json","host-evidence.json","enroll-input.json","M2-result.json"):
        assert (fixture.output/(name+".sha256")).read_text().strip()==m.sha((fixture.output/name).read_bytes())
    with pytest.raises(ValueError,match="OUTPUT_EXISTS"):m.finish(fixture.control,prior.M,now=fixture.now,owner_public=fixture.public)


@pytest.mark.parametrize("fault",["unknown","challenge","pin","uid","machine","head","cgroup","memory","pids","cpu","clock","floor","tradebot","DID","migration_go"])
def test_forged_or_incomplete_snapshot_never_writes_endpoints(fixture,fault):
    c=copy.deepcopy(fixture.control);v=c["reports"]["k137"]
    if fault=="unknown":v["body"]="untrusted"
    if fault=="challenge":v["challenge"]=m.sha(b"old challenge")
    if fault=="pin":v["source_blobs"]["bootstrap"]="f"*40
    if fault=="uid":v["uid"]=0
    if fault=="machine":v["machine_sha256"]=m.sha(b"other machine")
    if fault=="head":v["head"]="a"*40
    if fault=="cgroup":v.pop("cgroup")
    if fault=="memory":v["cgroup"]["memory_max"]=None
    if fault=="pids":v["cgroup"]["pids_max"]=65
    if fault=="cpu":v["cgroup"]["cpu_quota"]=200000
    if fault=="clock":v["observed_at"]-=181
    if fault=="floor":v["free_bytes"]=20*1024**3
    if fault=="tradebot":v["tradebot"]["unit"]="other.service"
    if fault=="DID":c["reports"]["oci"]["source_key_ids"]=[m.sha(b"invented key")]
    if fault=="migration_go":v["cutover"]="GO"
    with pytest.raises(ValueError):m.finish(c,prior.M,now=fixture.now,owner_public=fixture.public)
    assert not list(fixture.output.iterdir())


def test_host_trust_is_separate_not_tofu_and_hashed_known_hosts(fixture):
    pin=m.host_key(fixture.host,"ecdsa-sha2-nistp256")
    request=dict(oracle_key_sha256=pin,oracle_trust_reference=fixture.control["plan"]["oracle_trust_reference"],known_hosts=m.HOSTS["oci"]+" "+fixture.host)
    for key in ("oracle_key_sha256","oracle_trust_reference"):
        wrong=dict(request);wrong[key]=""
        with pytest.raises(ValueError,match="INDEPENDENT_TRUST"):m.trust_plan(wrong)
    with pytest.raises(ValueError,match="TRUST_MISMATCH"):m.trust_plan(dict(request,oracle_key_sha256=m.sha(b"changed")))
    with pytest.raises(ValueError,match="AMBIGUOUS"):m.trust_plan(dict(request,known_hosts=request["known_hosts"]+"\n"+request["known_hosts"]))
    import hmac
    salt=os.urandom(20);hashed="|1|"+base64.b64encode(salt).decode()+"|"+base64.b64encode(hmac.new(salt,m.HOSTS["oci"].encode(),hashlib.sha1).digest()).decode()
    assert m.trust_plan(dict(request,known_hosts=hashed+" "+fixture.host))["oci"]["host_key"]==fixture.host
    fake=ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH,PublicFormat.OpenSSH).decode()
    with pytest.raises(ValueError,match="K137_HOST"):m.trust_plan(dict(request,known_hosts=request["known_hosts"]+"\n"+m.HOSTS["k137"]+" "+fake))


@pytest.fixture
def guest(fixture,monkeypatch):
    raw={"/etc/machine-id":b"a"*32,"/proc/sys/kernel/random/boot_id":b"12345678-1234-1234-1234-123456789abc\n",
        "/proc/self/cgroup":b"0::/bounded.scope\n","/sys/fs/cgroup/bounded.scope/cgroup.procs":str(os.getpid()).encode(),
        "/sys/fs/cgroup/bounded.scope/memory.max":b"134217728","/sys/fs/cgroup/bounded.scope/pids.max":b"32","/sys/fs/cgroup/bounded.scope/cpu.max":b"10000 100000"}
    public=m.canonical(dict(did=fixture.control["reports"]["oci"]["source_did"],verified_at="2026-11-04T00:00:00Z"))
    monkeypatch.setattr(m.sys,"platform","linux");monkeypatch.setattr(m.os,"geteuid",lambda:0,raising=False)
    monkeypatch.setattr(m,"public_file",lambda *_:public);monkeypatch.setitem(sys.modules,"pwd",SimpleNamespace(getpwnam=lambda _:SimpleNamespace(pw_uid=1001)))
    monkeypatch.setattr(m.os,"statvfs",lambda _:SimpleNamespace(f_bavail=64*1024**3,f_frsize=1),raising=False)
    R=SimpleNamespace(APP="/fixed-app",STATE="/fixed-state",HEAD=fixture.R.HEAD,read_small=lambda p,*_:raw[p],directory=lambda p:None,git_head=lambda p:fixture.R.HEAD)
    return R,raw


def test_guest_source_current_boot_and_cgroup_change_fail_closed(fixture,guest):
    R,raw=guest;report=m.probe("oci",fixture.control["challenges"]["oci"],R,fixture.decode,m.sources()[2])
    assert report["boot_raw_sha256"]==m.sha(raw["/proc/sys/kernel/random/boot_id"]) and report["source_did"]==fixture.control["reports"]["oci"]["source_did"]
    original=R.read_small;seen={}
    def read(path,*args):
        seen[path]=seen.get(path,0)+1
        if path=="/proc/sys/kernel/random/boot_id" and seen[path]>1:return b"other boot"
        return original(path,*args)
    R.read_small=read
    with pytest.raises(ValueError,match="BOOT_CHANGED"):m.probe("oci","a"*64,R,fixture.decode,m.sources()[2])
    R.read_small=original;raw["/sys/fs/cgroup/bounded.scope/cgroup.procs"]=b"99999999"
    with pytest.raises(ValueError,match="MEMBERSHIP"):m.probe("oci","a"*64,R,fixture.decode,m.sources()[2])


def test_guest_unbounded_k137_stops_without_service_changes(fixture,guest,monkeypatch):
    R,raw=guest;monkeypatch.setattr(m.os,"geteuid",lambda:1000,raising=False);monkeypatch.setattr(m,"K137_MACHINE",m.sha(b"a"*32))
    def fail(_):raise ValueError("max")
    R.resources=fail
    with pytest.raises(ValueError,match="LOGIN_CGROUP_UNBOUNDED"):m.probe("k137","b"*64,R,fixture.decode,m.sources()[2])


def test_actual_guest_k137_healthy_path_reuses_resource_guard(fixture,guest,monkeypatch):
    _,raw=guest;R=__import__('types').ModuleType("synthetic_preflight")
    exec(compile(m.sources()[1]["preflight"],"<pinned-r1066>","exec"),R.__dict__)
    monkeypatch.setattr(m.os,"geteuid",lambda:1000,raising=False);monkeypatch.setattr(m,"K137_MACHINE",m.sha(b"a"*32))
    monkeypatch.setattr(m.os,"access",lambda p,f:p==R.LANDING)
    monkeypatch.setattr(R,"read_small",lambda p,*_:raw[p])
    monkeypatch.setattr(R,"directory",lambda p:SimpleNamespace(st_uid=1000 if p==R.LANDING else 0,st_mode=stat.S_IFDIR|0o700))
    monkeypatch.setattr(R,"git_head",lambda p:R.K137_STAGE_SHA)
    body=b"LoadState=loaded\nActiveState=active\nMemoryHigh=1048576000\nMemoryMax=1258291200\nControlGroup=/system.slice/k137q-public-k58.service\n"
    calls=[]
    def command(argv,**kwargs):
        calls.append(argv);assert argv[:2]==["/usr/bin/systemctl","show"] and "--" in argv
        assert "shell" not in kwargs;return SimpleNamespace(returncode=0,stdout=body,stderr=b"")
    monkeypatch.setattr(R.subprocess,"run",command)
    raw["/sys/fs/cgroup/system.slice/k137q-public-k58.service/memory.max"]=b"1258291200"
    report=m.probe("k137","b"*64,R,fixture.decode,m.sources()[2])
    assert report["tradebot"]["unit"]==m.TRADEBOT and report["source_did"] is None and report["uid"]==1000
    assert report["cgroup"]["memory_max"]==128*1024**2 and len(calls)==1
    raw["/sys/fs/cgroup/bounded.scope/memory.max"]=b"max"
    with pytest.raises(ValueError,match="LOGIN_CGROUP_UNBOUNDED"):m.probe("k137","b"*64,R,fixture.decode,m.sources()[2])


def test_guest_cgroup_move_during_read_is_explicit_stop(fixture,guest):
    R,raw=guest
    def changed_head(_):raw["/proc/self/cgroup"]=b"0::/changed.scope\n";return R.HEAD
    R.git_head=changed_head
    with pytest.raises(ValueError,match="CGROUP_CHANGED"):m.probe("oci","a"*64,R,fixture.decode,m.sources()[2])


def test_guest_payload_is_bounded_readonly_and_does_not_import_owner_keys():
    code=m.guest_source("oci","a"*64);assert len(code)<16384
    tree=ast.parse(code);calls={ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n,ast.Call)}
    assert not calls.intersection({"os.system","os.unlink","os.rename","os.chmod","os.mkdir","sqlite3.connect","socket.socket"})
    for forbidden in ("vault_seed","init_key","approval.pem","systemctl stop","systemctl start","httpx","urllib","shell=True"):
        assert forbidden not in code.decode()
    with pytest.raises(ValueError):m.guest_source("oci;id","a"*64)
    with pytest.raises(ValueError):m.guest_source("oci","a"*63+";")


def test_strict_json_missing_or_duplicate_and_nonsecret_error(monkeypatch,capsys):
    with pytest.raises(ValueError):m.strict(b'{"role":1,"role":2}')
    with pytest.raises(ValueError):m.strict(b" "*32769)
    monkeypatch.setattr(m.sys,"argv",["helper","--prepare"])
    monkeypatch.setattr(m.sys,"stdin",SimpleNamespace(buffer=__import__('io').BytesIO(b'{}')))
    assert m.main()==42
    text=capsys.readouterr();assert 'NO_GO' in text.out and not text.err and "/" not in text.out


@pytest.mark.parametrize("bad",[None,b'{"uid":0,"uid":1000}',b'not JSON'])
def test_wire_preserves_exact_ssh_bytes_and_rejects_duplicate_keys(fixture,monkeypatch,capsys,bad):
    import io
    control=copy.deepcopy(fixture.control)
    reports=control.pop("reports");control["report_bytes"]={r:base64.b64encode(m.canonical(v)).decode() for r,v in reports.items()}
    if bad is not None:control["report_bytes"]["k137"]=base64.b64encode(bad).decode()
    calls=[]
    def finish(value,M):
        calls.append(value)
        return dict(code="M2_AUTHENTICATED_PUBLIC_ARTIFACTS_ONLY",cutover="NO_GO")
    monkeypatch.setattr(m,"finish",finish)
    monkeypatch.setattr(m.sys,"argv",["helper","--finish"])
    monkeypatch.setattr(m.sys,"stdin",SimpleNamespace(buffer=io.BytesIO(m.canonical(control))))
    result=m.main();output=capsys.readouterr()
    if bad is None:assert result==0 and calls[0]["reports"]==reports
    else:assert result==42 and not calls and "AUTHENTICATED_PUBLIC" not in output.out
    assert not list(fixture.output.iterdir()) and not output.err


def test_source_pins_and_frozen_functions_are_reused_not_invoked():
    text=PS.read_text(encoding="utf-8")
    for p in (PATH,ROOT/"packaging/migration/r1066_preflight_readonly.py",ROOT/"packaging/migration/r1155_source_pins.json",ROOT/"packaging/migration/r1066_owner_workflow.ps1",ROOT/"packaging/windows/r1138_lightsail_pem_single_acl_and_readonly_ssh.ps1"):
        assert m.blob(p.read_bytes().replace(b"\r\n",b"\n")) in text
    for name in ("Get-R1066Arguments","Unprotect-R1027","Remove-R1027Custody","Get-R1138ExactPem","-AsSecureString"):
        assert name in text
    for forbidden in ("Invoke-R1138","Set-R1138SinglePemAcl","r1158_solo_owner.ps1","-Operation Init","ssh-keyscan","StrictHostKeyChecking=no"):
        assert forbidden not in text
    original=(ROOT/"packaging/windows/r1136_k137_readonly_ssh_diagnostic.ps1").read_text(encoding="utf-8")
    assert m.K137_KEY in original and "$reports[$role]=[Convert]::ToBase64String($r.Output)" in text


@WINDOWS
@pytest.mark.parametrize("args,code",[([],"EXPLICIT_READONLY_EXECUTION_REQUIRED"),(["-Execute"],"OCI_INDEPENDENT_TRUST_REQUIRED")])
def test_native_ps51_never_reads_credentials_without_public_trust(args,code):
    p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",str(PS),*args],capture_output=True,timeout=20)
    assert p.returncode==42 and json.loads(p.stdout)["code"]==code and not p.stderr
    assert b"recovery code" not in p.stdout


def native(body):
    # Definition-only imports. No consumed script entrypoint, credential
    # selector or real SSH command is executed by this synthetic harness.
    import test_r1066_preflight as audited
    code=audited.ps_script("")+"\n"
    code+="$a=[Management.Automation.Language.Parser]::ParseFile('"+str(PS).replace("'","''")+"',[ref]$null,[ref]$null)\n"
    code+="foreach($n in $a.FindAll({param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){\n"
    code+="$p=@($n.Parameters|Where-Object {$null -ne $_}|ForEach-Object {$_.Extent.Text}) -join ',';$b=$n.Body.Extent.Text\n"
    code+="if($n.Name -ceq 'Read-R1159Code'){$b=$b.Replace('$PSScriptRoot',\"'"+str(PS.parent).replace("'","''")+"'\")}\n"
    code+="Set-Item ('Function:'+$n.Name) ([scriptblock]::Create(('param('+$p+\")`n\"+$b.Substring(1,$b.Length-2))))}\n"
    return code+body


@WINDOWS
def test_native_cleanup_and_missing_auth_never_finalize():
    code=native(r'''
$calls=0
function Invoke-R1159Local { $script:calls++;throw 'must not be called' }
foreach($case in @(@($true,$false),@($false,$true))) {
    $caught=$false
    try {$null=Complete-R1159 $case[0] $case[1] ([byte[]]@())} catch {$caught=$true}
    if(-not $caught -or $calls -ne 0){throw 'FALSE_GREEN'}
}
[Console]::Write('SYNTHETIC_CLEANUP_GATE_PASS')
''')
    r=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",code],capture_output=True,timeout=20)
    assert r.returncode==0 and r.stdout==b"SYNTHETIC_CLEANUP_GATE_PASS" and not r.stderr


@WINDOWS
def test_native_private_file_acl_readonly_validation_no_repair(tmp_path):
    p=tmp_path/"dummy.pem";p.write_bytes(os.urandom(96));prior.M.protect_file(p)
    code=native("Initialize-R1066\n$path='"+str(p).replace("'","''")+"'\n"+r'''
Assert-R1159ExistingFile $path 64 32768
$acl=[IO.File]::GetAccessControl($path)
$sid=New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'Read','Allow')
$acl.AddAccessRule($rule);[IO.File]::SetAccessControl($path,$acl)
$caught=$false
try {Assert-R1159ExistingFile $path 64 32768}catch{$caught=$true}
if(-not $caught){throw 'BAD_ACL_ACCEPTED'}
if(@(([IO.File]::GetAccessControl($path)).Access | Where-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -ceq 'S-1-1-0'}).Count -ne 1){throw 'UNAUTHORIZED_ACL_REPAIR'}
[Console]::Write('SYNTHETIC_ACL_PASS')
''')
    r=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",code],capture_output=True,timeout=30)
    assert r.returncode==0,r.stderr.decode(errors="replace")
    assert r.stdout==b"SYNTHETIC_ACL_PASS"


@WINDOWS
def test_native_selector_single_and_multiple_files_only_in_synthetic_home(tmp_path):
    home=tmp_path/"home";downloads=home/"Downloads";desktop=home/"Desktop";downloads.mkdir(parents=True);desktop.mkdir()
    (downloads/"LightsailDefaultPrivateKey-ap-northeast-1.pem").write_bytes(os.urandom(80))
    name="FLOP_NEW_SSH_20261018_AES256_V2.enc";(downloads/name).write_bytes(os.urandom(48))
    code=native("$script:fake='"+str(home).replace("'","''")+"'\nSet-Location -LiteralPath $script:fake\n"+r'''
$old=[IO.File]::ReadAllText((Join-Path $script:R1066Root '..\windows\r1062_writer_attribution_one_shot_readonly.ps1'))
$new=[IO.File]::ReadAllText((Join-Path $script:R1066Root '..\windows\r1138_lightsail_pem_single_acl_and_readonly_ssh.ps1'))
foreach($x in @(@($old,'Find-R1027Backup'),@($new,'Get-R1138ExactPem'))) {
    $source=$x[0].Replace("[Environment]::GetFolderPath('UserProfile')",'$script:fake').Replace("[Environment]::GetFolderPath('DesktopDirectory')","(Join-Path `$script:fake 'Desktop')")
    Import-R1159Function $source $x[1]
}
$null=Find-R1027Backup;$null=Get-R1138ExactPem
[IO.File]::WriteAllBytes((Join-Path $script:fake 'Downloads\LightsailDefaultPrivateKey-ap-northeast-1 (2).pem'),(New-Object byte[] 80))
[IO.File]::WriteAllBytes((Join-Path $script:fake 'Desktop\FLOP_NEW_SSH_20261018_AES256_V2.enc'),(New-Object byte[] 48))
$count=0
try {$null=Find-R1027Backup}catch{$count++}
try {$null=Get-R1138ExactPem}catch{$count++}
if($count -ne 2){throw 'AMBIGUOUS_CREDENTIAL_ACCEPTED'}
[Console]::Write('SYNTHETIC_SELECTORS_PASS')
''')
    r=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",code],capture_output=True,timeout=20)
    assert r.returncode==0,r.stderr.decode(errors="replace")
    assert r.stdout==b"SYNTHETIC_SELECTORS_PASS"


@WINDOWS
def test_native_carrier_interrupted_and_timeout_no_stderr_leak():
    code=native(r'''
Initialize-R1066
$source=[IO.File]::ReadAllText((Join-Path $script:R1066Root 'r1079_profile_ssh_transport.cs'))
Add-Type -TypeDefinition $source
$exe=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
$command="-NoProfile -NonInteractive -Command `"[Console]::Error.WriteLine('Permission denied (publickey). PRIVATE_CANARY');exit 255`""
$r=[FlopR1079.Transport]::Run($exe,$command,([byte[]]@()),10000)
if($r.ExitCode -ne 255 -or $r.FailureKind -cne 'SSH_PUBLIC_KEY_REJECTED' -or $r.Output.Length -ne 0){throw 'BAD_FAILURE_CLASS'}
$timed=$false
try {$null=[FlopR1079.Transport]::Run($exe,'-NoProfile -NonInteractive -Command "[Threading.Thread]::Sleep(3000)"',([byte[]]@()),100)}catch{$timed=$true}
if(-not $timed){throw 'TIMEOUT_NOT_STOPPED'}
[Console]::Write('SYNTHETIC_CARRIER_PASS')
''')
    r=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",code],capture_output=True,timeout=25)
    assert r.returncode==0,r.stderr.decode(errors="replace")
    assert r.stdout==b"SYNTHETIC_CARRIER_PASS" and not r.stderr and b"PRIVATE_CANARY" not in r.stdout


@WINDOWS
def test_native_reused_escrow_crypto_corruption_and_wrong_recovery(tmp_path):
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
    from cryptography.hazmat.primitives.serialization import PrivateFormat,NoEncryption
    dummy=ed25519.Ed25519PrivateKey.generate().private_bytes(Encoding.PEM,PrivateFormat.OpenSSH,NoEncryption())
    password=b"synthetic-only-recovery-code";salt=os.urandom(8)
    material=hashlib.pbkdf2_hmac("sha256",password,salt,600000,48)
    pad=padding.PKCS7(128).padder();padded=pad.update(dummy)+pad.finalize()
    cipher=Cipher(algorithms.AES(material[:32]),modes.CBC(material[32:])).encryptor()
    encrypted=b"Salted__"+salt+cipher.update(padded)+cipher.finalize()
    file=tmp_path/"synthetic.enc";file.write_bytes(encrypted)
    code=native("Initialize-R1066\n$data=[IO.File]::ReadAllBytes('"+str(file).replace("'","''")+"')\n"+
        "$expected='"+m.sha(encrypted)+"';$plainHash='"+m.sha(dummy)+"'\n"+r'''
$right=New-Object Security.SecureString
$wrong=New-Object Security.SecureString
foreach($c in 'synthetic-only-recovery-code'.ToCharArray()){$right.AppendChar($c)}
foreach($c in 'incorrect-synthetic-code'.ToCharArray()){$wrong.AppendChar($c)}
try {
    $plain=[FlopR1062.Guards]::Decrypt($data,$expected,$right)
    if([FlopR1062.Guards]::Sha256($plain) -cne $plainHash){throw 'SYNTHETIC_DECRYPT_MISMATCH'}
    [FlopR1062.Guards]::Clear($plain)
    $stops=0
    try {$bad=[FlopR1062.Guards]::Decrypt($data,$expected,$wrong);[FlopR1062.Guards]::Clear($bad)}catch{$stops++}
    $data[$data.Length-1]=$data[$data.Length-1] -bxor 1
    try {$bad=[FlopR1062.Guards]::Decrypt($data,$expected,$null);[FlopR1062.Guards]::Clear($bad)}catch{$stops++}
    if($stops -ne 2){throw 'UNVERIFIED_CIPHER_ACCEPTED'}
} finally {$right.Dispose();$wrong.Dispose();[FlopR1062.Guards]::Clear($data)}
[Console]::Write('SYNTHETIC_ESCROW_PASS')
''')
    r=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",code],capture_output=True,timeout=70)
    assert r.returncode==0,r.stderr.decode(errors="replace")
    assert r.stdout==b"SYNTHETIC_ESCROW_PASS" and dummy not in r.stdout and not r.stderr


@WINDOWS
def test_native_real_local_helper_pipe_no_ssh_or_credential_reads(fixture):
    request=dict(oracle_key_sha256=m.host_key(fixture.host,"ecdsa-sha2-nistp256"),oracle_trust_reference=fixture.control["plan"]["oracle_trust_reference"],known_hosts=m.HOSTS["oci"]+" "+fixture.host)
    payload=base64.b64encode(m.canonical(request)).decode()
    root=str(PS.parent).replace("'","''")
    code=native("$PSScriptRoot='"+root+"'\n$script:R1159Python='"+str(ROOT/".venv/Scripts/python.exe").replace("'","''")+"'\n"+
        "$script:R1159Program='"+str(PATH).replace("'","''")+"'\n$wire=[Convert]::FromBase64String('"+payload+"')\n"+r'''
Initialize-R1066
Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:R1066Root 'r1079_profile_ssh_transport.cs')))
$plan=[Text.Encoding]::UTF8.GetString((Invoke-R1159Local '--prepare' $wire))|ConvertFrom-Json
if($plan.purpose -cne 'R1159_TRUST_ONLY_NOT_ENDPOINTS'){throw 'BAD_LOCAL_PLAN'}
$challenge='a'*64
$guest=Invoke-R1159Local '--guest' ([byte[]]@()) 'oci' $challenge
if($guest.Length -gt 16384 -or $guest.Length -lt 1000){throw 'BAD_GUEST_LENGTH'}
[Console]::Write('SYNTHETIC_LOCAL_PIPE_PASS')
''')
    r=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",code],capture_output=True,timeout=30)
    assert r.returncode==0,r.stderr.decode(errors="replace")
    assert r.stdout==b"SYNTHETIC_LOCAL_PIPE_PASS" and not r.stderr
