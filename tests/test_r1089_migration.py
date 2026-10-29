"""Real AES-GCM -> binary wire -> Windows NTFS -> plaintext interoperability.

Only synthetic data/ephemeral attesters. No production credentials or SSH.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import time

import pytest

ROOT=Path(__file__).resolve().parents[1]
PKG=ROOT/"packaging/migration"
spec=importlib.util.spec_from_file_location("r1089_test",PKG/"r1089_migration.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
spec2=importlib.util.spec_from_file_location("r1089_synthetic",ROOT/"tests/test_r1063_release_gates.py")
synth=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(synth)
WIN=pytest.mark.skipif(os.name!="nt",reason="native PS5.1 and NTFS")
LINUX=pytest.mark.skipif(sys.platform!="linux" or (hasattr(os,"geteuid") and os.geteuid()==0),reason="nonroot Linux restore")


def serialized(rows, contents):
    manifest={"version":1,"source_head":m.T.HEAD,"epoch":"FROZEN:"+"b"*64,"entries":rows}
    raw=m.G.canonical(manifest)
    return manifest,len(raw).to_bytes(8,"big")+raw+b"".join(contents[r["path"]] for r in rows if r["kind"]=="file")


@pytest.fixture
def data(tmp_path,monkeypatch):
    rows=[];contents={};connections=[]
    def add(name,kind="file",value=b"",target=None):
        row=dict(path=name,mode=0o700 if kind=="directory" else 0o600,uid=1000,gid=1000,
                 mtime_ns=1000000000,kind=kind,size=len(value) if kind=="file" else 0,
                 sha256=hashlib.sha256(value).hexdigest() if kind=="file" else None,target=target)
        rows.append(row)
        if kind=="file": contents[name]=value
    add("app","directory");add("state","directory")
    add("app/binary",value=bytes(range(256))*8500)
    add("app/hard","hardlink",target="app/binary")
    for i in range(28):
        add("app/link%02d"%i,"symlink",target=("/opt/flop-shadow/DO-NOT-FOLLOW" if i==0 else
            "../state/nonces.json" if i==1 else "binary"))
    for n in m.G.DATABASES:
        p=tmp_path/n
        c=sqlite3.connect(p);connections.append(c)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("CREATE TABLE messages(seq INTEGER PRIMARY KEY, text TEXT)")
        c.execute("INSERT INTO messages VALUES (7,'synthetic text')");c.commit()
        for suffix in ("","-wal","-shm"):
            add("state/"+n+suffix,value=Path(str(p)+suffix).read_bytes())
    add("state/nonces.json",value=b'{"synthetic":19}')
    add("state/verified-did.json",value=b'{"did":"synthetic-public-only"}')
    add("state/oracle-signer-receipts.json",value=b'{"receipts":{"synthetic":"ambiguous"}}')
    manifest,plain=serialized(rows,contents)
    # Actual frozen encryption implementation; only the source FD inventory is
    # substituted with synthetic serialized records (no real source access).
    def blocks(*a,**k):
        for at in range(0,len(plain),733733): yield plain[at:at+733733]
    monkeypatch.setattr(m.W.T,"pack",blocks)
    key=os.urandom(48)
    wire=io.BytesIO()
    m.W.seal_manifest_to_stream({},manifest,{},key,wire)
    yield tmp_path,manifest,plain,key,wire.getvalue(),contents
    for c in connections: c.close()


def receive_posix(data):
    root,_,_,_,wire,_=data
    os.chmod(root,0o700)
    archive=root/"ciphertext"
    m.W.receive_offhost_ciphertext(io.BytesIO(wire),archive,quota_bytes=1024**3)
    return archive


def test_signed_plan_requires_every_independent_post_gate_and_did():
    f=synth.Synthetic()
    trust={"context":f.context,"keys":[{"public_hex":raw.hex(),"roles":list(roles)}
            for raw,roles in f.trust.keys.values()],"source_key_ids":list(f.trust.source_key_ids)}
    def plan_for(f):
        plan={"schema_version":1,"run_id":"c"*32,"offhost_parent":"C:\\synthetic", "quota_bytes":6*m.GIB,
              "expected_did":"did:key:z6Mk"+"1"*42,"trust":copy.deepcopy(trust),
              "packets":[p for p in f.bundle()["packets"] if p["body"]["gate"] in ("G0","G1","G2","G4","G5")]}
        plan["approval"]=f.approval("preserve_restore",m.G.sha(plan),at=synth.NOW)
        return plan
    f.context["did"]=hashlib.sha256(("did:key:z6Mk"+"1"*42).encode()).hexdigest()
    for route in f.e["G5"]["routes"].values():
        for record in route["attempts"]: record["did"]=f.context["did"]
    trust["context"]=f.context
    plan=plan_for(f)
    _,e=m.authorizations(plan,synth.NOW)
    assert set(e)=={"G0","G1","G2","G4","G5"}
    for mode in ("absent","ambiguous","wrong_did","bad_owner","duplicate"):
        bad=copy.deepcopy(plan)
        if mode=="absent": bad["packets"]=[p for p in bad["packets"] if p["body"]["gate"]!="G5"]
        if mode=="ambiguous":
            f.e["G5"]["routes"][m.G.ROUTES[0]]["attempts"][0]["verdict"]="UNKNOWN"
            bad=plan_for(f)
        if mode=="wrong_did": bad["expected_did"]="did:key:z6Mk"+"2"*42
        if mode=="bad_owner": bad["approval"]["signature"]="0"*128
        if mode=="duplicate": bad["packets"].append(copy.deepcopy(bad["packets"][0]))
        with pytest.raises((m.Stop,m.G.Deny)):
            m.authorizations(bad,synth.NOW)


def test_long_preservation_session_does_not_weaken_release_fence():
    f=synth.Synthetic();packet=next(p for p in f.bundle()["packets"] if p["body"]["gate"]=="G4")
    e=copy.deepcopy(packet["body"]["evidence"])
    now=synth.NOW+1000
    e.update(held_until=now-1,lease_expires_at=now+30)
    current=f.sign("independent",{"gate":"G4","context":f.context,"observed_at":now-1,"expires_at":now+60,"evidence":e})
    session={"approval":f.sign("owner",{"action":"preserve_restore","context":f.context,"binding":"a"*64,
        "approved_at":synth.NOW,"expires_at":now+120}),"binding":"a"*64}
    with pytest.raises(m.G.Deny): m.G.check_gate("G4",e,{}, {"G4":current},f.trust,now)
    m.G.check_gate("G4",e,{}, {"G4":current},f.trust,now,preservation_session=session)
    for mode in ("expired","changed_barrier","unknown_writer"):
        bad=copy.deepcopy(e);approval=copy.deepcopy(session)
        if mode=="expired": approval["approval"]["body"]["expires_at"]=now
        if mode=="changed_barrier": approval["binding"]="b"*64
        if mode=="unknown_writer": bad["writable_fds"]=1
        with pytest.raises(m.G.Deny):
            m.G.check_gate("G4",bad,{}, {"G4":current},f.trust,now,preservation_session=approval)


@LINUX
def test_source_rechecks_renewed_signed_lease_and_readonly_mounts(monkeypatch):
    f=synth.Synthetic();packet=next(p for p in f.bundle()["packets"] if p["body"]["gate"]=="G4")
    e=packet["body"]["evidence"]
    class Admission:
        parent=None
        def lstat(self):
            return type("S",(),dict(st_mode=0o100600,st_uid=0,st_nlink=1,st_size=1024))()
        def is_symlink(self):return False
        def read_bytes(self):return m.G.canonical(packet)
    class Parent:
        def lstat(self):return type("S",(),dict(st_mode=0o40700,st_uid=0))()
        def is_symlink(self):return False
    admission=Admission();admission.parent=Parent()
    class Root:
        def is_dir(self):return True
        def is_symlink(self):return False
    guard=m.SourceGuard.__new__(m.SourceGuard)
    guard.admission=admission;guard.trust=f.trust;guard.evidence={"G4":e}
    guard.barrier=e["barrier_digest"];guard.roots={"app":Root(),"state":Root()};guard.last_scan=0
    guard.plan={"synthetic":"bound"}
    guard.plan["approval"]=f.sign("owner",{"action":"preserve_restore","context":f.context,
        "binding":m.G.sha(guard.plan),"approved_at":synth.NOW-1,"expires_at":synth.NOW+120})
    checks=[];guard.scan_descriptors=lambda:checks.append(True)
    monkeypatch.setattr(m.time,"time",lambda:synth.NOW)
    monkeypatch.setattr(m.os,"statvfs",lambda _:type("V",(),{"f_flag":m.os.ST_RDONLY})())
    guard.check(full=True);assert checks==[True]
    monkeypatch.setattr(m.os,"statvfs",lambda _:type("V",(),{"f_flag":0})())
    with pytest.raises(m.Stop,match="SOURCE_FENCE_LOST"):guard.check()
    monkeypatch.setattr(m.os,"statvfs",lambda _:type("V",(),{"f_flag":m.os.ST_RDONLY})())
    monkeypatch.setattr(m.time,"time",lambda:synth.NOW+32)
    with pytest.raises(m.G.Deny,match="FENCE_NOT_CURRENT"):guard.check()


def test_source_descriptor_races_and_write_handles_never_prove_absence(monkeypatch):
    monkeypatch.setattr(m.os,"O_ACCMODE",3,raising=False)  # Linux FD flags in this synthetic /proc.
    guard=m.SourceGuard.__new__(m.SourceGuard);guard.roots={"app":Path("/synthetic-original")}
    class Fd:
        name="3"
        def stat(self):return type("S",(),{"st_mode":0o100600})()
    class Fds:
        def iterdir(self):return iter([Fd()])
    class Info:
        def __init__(self,flags):self.flags=flags
        def __truediv__(self,_):return self
        def open(self,_):return io.BytesIO(b'flags:\t'+self.flags+b'\n')
    class Proc:
        name="123"
        flags=b'0100002'
        def __truediv__(self,leaf):return Fds() if leaf=="fd" else Info(self.flags)
    proc=Proc()
    class Procs:
        def iterdir(self):return iter([proc])
    monkeypatch.setattr(m,"Path",lambda _:Procs())
    monkeypatch.setattr(m.os,"readlink",lambda _:str(guard.roots["app"])+"/database")
    with pytest.raises(m.Stop,match="SOURCE_FENCE_LOST"):guard.scan_descriptors()
    proc.flags=b'0100000';guard.scan_descriptors()
    monkeypatch.setattr(m.os,"readlink",lambda _:(_ for _ in ()).throw(PermissionError("synthetic")))
    with pytest.raises(PermissionError):guard.scan_descriptors()


@LINUX
def test_real_wire_independent_authentication_then_inert_restore_resume(data,monkeypatch):
    root,manifest,plain,key,wire,contents=data
    archive=receive_posix(data)
    landing=root/"disarmed";landing.mkdir(mode=0o700)
    monkeypatch.setattr(m.D,"ROOT",landing)
    monkeypatch.setattr(m.D,"machine_digest",lambda:"a"*64)
    monkeypatch.setattr(m.D.shutil,"disk_usage",lambda _:type("Disk",(),{"free":60*m.GIB})())
    with m.LockedArchive(archive) as held:
        with pytest.raises(m.Stop): held.stream(key,io.BytesIO())
        actual,proof=held.verify(key)
        assert actual==manifest and proof["symlinks"]==28
        stream=io.BytesIO();held.stream(key,stream)
        assert stream.getvalue()==plain
        # An actual interrupted restore, then exact-prefix continuation.
        with pytest.raises((m.D.Stop,m.T.Stop,m.D.T.Stop)):
            m.D.restore_stream(io.BytesIO(plain[:len(plain)//2]),"f"*32,"a"*64,os.geteuid(),
                quota_bytes=8*m.GIB,expected_epoch=manifest["epoch"],expected_manifest_sha256=m.G.sha(manifest),
                preserve_inert_links=True,resume=True)
        kwargs=dict(quota_bytes=8*m.GIB,expected_epoch=manifest["epoch"],
            expected_manifest_sha256=m.G.sha(manifest),preserve_inert_links=True,resume=True)
        result=m.D.restore_stream(io.BytesIO(plain),"f"*32,"a"*64,os.geteuid(),**kwargs)
        assert result["symlinks"]==28 and result["sqlite_cursors"]==[(1,7),(1,7)]
        assert (landing/("f"*32)/"app/link00").readlink()==Path("/opt/flop-shadow/DO-NOT-FOLLOW")
        assert (landing/("f"*32)/"state/nonces.json").read_bytes()==contents["state/nonces.json"]
        again=m.D.restore_stream(io.BytesIO(plain),"f"*32,"a"*64,os.geteuid(),**kwargs)
        assert result==again and result["cutover"]=="NO_GO"


@LINUX
@pytest.mark.parametrize("failure",["wrong_key","tamper","missing_commit","partial_wire"])
def test_corruption_never_emits_plaintext(data,failure):
    archive=receive_posix(data);key=data[3]
    if failure=="wrong_key":key=os.urandom(48)
    if failure=="tamper":
        p=archive/"part-0000.bin";v=bytearray(p.read_bytes());v[-3]^=1;p.write_bytes(v)
    if failure=="missing_commit":(archive/"commit.bin").unlink()
    if failure=="partial_wire":
        target=data[0]/"interrupted"
        with pytest.raises(Exception):
            m.W.receive_offhost_ciphertext(io.BytesIO(data[4][:-5]),target,quota_bytes=m.GIB)
        assert not (target/"commit.bin").exists()
        return
    output=io.BytesIO()
    with pytest.raises(Exception):
        with m.LockedArchive(archive) as held:
            held.verify(key);held.stream(key,output)
    assert output.getvalue()==b""


def test_remote_commands_and_bundle_are_fixed_and_sandboxed():
    sources=m.bundle()
    assert set(sources)==set(m.BUNDLE_FILES)
    for mode in ("source","capacity","restore"):
        command=m.remote_argv(["synthetic-ssh"],mode,sources)
        text=command[-1]
        assert "-I" in text and "-B" in text and "sudo -n" in text
        if mode!="source":
            assert "ProtectSystem=strict" in text and "MemoryMax=256M" in text
            assert "ReadWritePaths=/var/lib/flop-migration-r1066" in text
            assert "tradebot-k137" not in text
        assert "--timer" not in text and "enable" not in text
    with pytest.raises(m.Stop):m.remote_argv([],"arbitrary;command",sources)


def test_owner_public_source_pins_cover_all_remote_and_native_dependencies():
    pins=json.loads((PKG/"r1089_source_pins.json").read_bytes())
    def blob(path):
        raw=path.read_bytes().replace(b'\r\n',b'\n')
        return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    for name,digest in pins.items():assert blob(PKG/name)==digest,name
    expected={os.path.relpath(PKG.parent/name,PKG).replace('\\','/') for name in m.BUNDLE_FILES}
    assert set(pins)==expected|{'r1089_owner_control_pipe.cs','r1085_windows_offhost_sink.cs',
        'r1085_windows_offhost_sink.ps1','r1088_windows_ciphertext_custody.cs','r1088_windows_ciphertext_custody.ps1'}
    ps=(PKG/"r1066_owner_workflow.ps1").read_text()
    assert blob(PKG/"r1089_source_pins.json") in ps
    assert ps.index("$pins=Read-R1066PinnedSource")<ps.index("$recovery=Read-Host")
    assert 'PRESERVED_AND_DISARMED_RESTORED' in ps


def test_remote_stop_frames_are_fixed_codes_not_exception_or_path():
    stream=io.BytesIO();m.frame_write(stream,b'FLOPERR9',{'code':'SOURCE_ADMISSION_REQUIRED'});stream.seek(0)
    with pytest.raises(m.Stop,match='^SOURCE_ADMISSION_REQUIRED$'):m.frame_read(stream,m.META)
    stream=io.BytesIO();m.frame_write(stream,b'FLOPERR9',{'code':'PRIVATE EXCEPTION CONTENT'});stream.seek(0)
    with pytest.raises(m.Stop,match='^MIGRATION_GUARD_STOP$'):m.frame_read(stream,m.META)


def test_binary_metadata_to_native_sink_handoff_has_no_read_ahead_loss():
    # Actual pipes/children: metadata and wire arrive together. Buffered Python
    # read-ahead MUST NOT swallow wire bytes before native sink inheritance.
    producer="import sys,struct;sys.stdout.buffer.write(b'FLOPAD89'+struct.pack('>I',2)+b'{}'+bytes(range(256))*8192)"
    consumer="import sys,json,hashlib;d=sys.stdin.buffer.read();print(json.dumps({'bytes':len(d),'hash':hashlib.sha256(d).hexdigest()}))"
    with m.child([sys.executable,"-I","-B","-c",producer],stdin=subprocess.DEVNULL,timeout=30) as p:
        assert m.frame_read(p.stdout,m.META)=={}
        with m.child([sys.executable,"-I","-B","-c",consumer],stdin=p.stdout,timeout=30) as sink:
            result=m.bounded_result(sink)
        assert p.wait(timeout=5)==0
    assert result=={"bytes":2097152,"hash":hashlib.sha256(bytes(range(256))*8192).hexdigest()}


@WIN
def test_native_owner_pipe_binary_framing_redacts_errors_and_environment(tmp_path):
    probe=tmp_path/"probe.py"
    probe.write_text('''import sys,struct,json,os
def read(n):
 b=bytearray()
 while len(b)<n:
  x=sys.stdin.buffer.read(n-len(b))
  assert x;b.extend(x)
 return bytes(b)
assert read(8)==b'FLOPR189'
control=json.loads(read(struct.unpack('>I',read(4))[0]))
key=bytearray(read(struct.unpack('>I',read(4))[0]))
assert len(key)==48 and sys.stdin.buffer.read(1)==b''
assert 'R1089_ENV_CANARY' not in os.environ
assert not any(x in os.environ for x in ('SIGN_SEED','AWS_SECRET_ACCESS_KEY','OCI_CLI_KEY_CONTENT'))
assert os.path.isdir(os.environ['TEMP'])
assert len(sys.argv)==1 and control=={'synthetic':'public'}
key[:]=b'\\0'*len(key)
sys.stderr.write('SYNTHETIC_ERROR_MUST_NOT_SURFACE')
print('{"operation":"BINARY_PIPE_PASS"}')
''',encoding="utf8")
    script=tmp_path/"run.ps1"
    script.write_text(r'''
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition ([IO.File]::ReadAllText('NATIVE'))
$recovery=New-Object Security.SecureString
1..48 | ForEach-Object { $recovery.AppendChar([char]65) }
$env:R1089_ENV_CANARY='MUST_NOT_INHERIT'
try {
 $arg='-I -B "PROBE"'
 $r=[FlopR1089.OwnerPipe]::Run('PYTHON',$arg,[Text.Encoding]::UTF8.GetBytes('{"synthetic":"public"}'),$recovery,30000)
 if($r.ExitCode -ne 0){throw 'PROBE_STOP'}
 [Console]::Out.Write([Text.Encoding]::ASCII.GetString($r.Output))
} finally { $recovery.Dispose();Remove-Item Env:\R1089_ENV_CANARY }
'''.replace("NATIVE",str(PKG/"r1089_owner_control_pipe.cs")).replace("PROBE",str(probe)).replace("PYTHON",sys.executable),encoding="utf-8-sig")
    p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",str(script)],capture_output=True,timeout=50)
    assert p.returncode==0,(p.stdout,p.stderr)
    assert p.stderr==b"" and json.loads(p.stdout)=={"operation":"BINARY_PIPE_PASS"}


@LINUX
def test_restore_capacity_and_cursor_mismatch_never_certify_completion(data,monkeypatch):
    root,manifest,plain,_,_,_=data
    landing=root/"disarmed";landing.mkdir(mode=0o700)
    monkeypatch.setattr(m.D,"ROOT",landing)
    monkeypatch.setattr(m.D,"machine_digest",lambda:"a"*64)
    monkeypatch.setattr(m.D.shutil,"disk_usage",lambda _:type("Disk",(),{"free":m.D.RESERVE})())
    kwargs=dict(quota_bytes=8*m.GIB,expected_epoch=manifest["epoch"],
                expected_manifest_sha256=m.G.sha(manifest),preserve_inert_links=True,resume=True)
    name="d"*32
    with pytest.raises(m.D.Stop,match="TRADEBOT_SPACE_STOP"):
        m.D.restore_stream(io.BytesIO(plain),name,"a"*64,os.geteuid(),**kwargs)
    assert not (landing/name).exists()
    monkeypatch.setattr(m.D.shutil,"disk_usage",lambda _:type("Disk",(),{"free":60*m.GIB})())
    with pytest.raises(m.D.Stop,match="SQLITE_CURSOR_BINDING_STOP"):
        m.D.restore_stream(io.BytesIO(plain),name,"a"*64,os.geteuid(),expected_cursors=[[1,8],[1,7]],**kwargs)
    assert not (landing/name/"DISARMED-STREAM-RECEIPT.json").exists()


@WIN
def test_owner_timeout_kills_descendants_before_custody_cleanup(tmp_path):
    marker=tmp_path/"must-not-be-created"
    probe=tmp_path/"timeout.py"
    # Wait for the broker's framed input, exactly like the real owner, before
    # spawning. A parent-only kill would leave this child alive to write later.
    probe.write_text("import sys,subprocess,time\nsys.stdin.buffer.read()\nsubprocess.Popen([sys.executable,'-c',"+
        repr("import time,pathlib;time.sleep(2);pathlib.Path("+repr(str(marker))+").write_text('orphan')")+"] )\ntime.sleep(120)\n",encoding="utf8")
    script=tmp_path/"timeout.ps1"
    script.write_text(r'''
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition ([IO.File]::ReadAllText('NATIVE'))
$stopped=$false
try { $null=[FlopR1089.OwnerPipe]::Run('PYTHON','-I -B "PROBE"',[Text.Encoding]::ASCII.GetBytes('{}'),$null,1000) }
catch { $stopped=$true }
if(-not $stopped){throw 'TIMEOUT_NOT_ENFORCED'}
Start-Sleep -Milliseconds 2500
if([IO.File]::Exists('MARKER')){throw 'ORPHAN_PROCESS'}
[Console]::Out.WriteLine('TREE_CLEANUP_PASS')
'''.replace("NATIVE",str(PKG/"r1089_owner_control_pipe.cs")).replace("PYTHON",sys.executable)
        .replace("PROBE",str(probe)).replace("MARKER",str(marker)),encoding="utf-8-sig")
    p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",str(script)],capture_output=True,timeout=30)
    assert p.returncode==0 and p.stderr==b"",(p.stdout,p.stderr)
    assert p.stdout.strip()==b'TREE_CLEANUP_PASS' and not marker.exists()


@LINUX
def test_partial_restore_prefix_conflict_does_not_overwrite(data,monkeypatch):
    root,manifest,plain,_,_,_=data
    landing=root/"disarmed";landing.mkdir(mode=0o700)
    monkeypatch.setattr(m.D,"ROOT",landing)
    monkeypatch.setattr(m.D,"machine_digest",lambda:"a"*64)
    monkeypatch.setattr(m.D.shutil,"disk_usage",lambda _:type("Disk",(),{"free":60*m.GIB})())
    kwargs=dict(quota_bytes=8*m.GIB,expected_epoch=manifest["epoch"],
                expected_manifest_sha256=m.G.sha(manifest),preserve_inert_links=True,resume=True)
    with pytest.raises(Exception):
        m.D.restore_stream(io.BytesIO(plain[:len(plain)//2]),"e"*32,"a"*64,os.geteuid(),**kwargs)
    binary=landing/("e"*32)/"app/binary"
    original=binary.read_bytes();bad=b'X'+original[1:];binary.write_bytes(bad)
    with pytest.raises(m.D.Stop,match="RESUME_PREFIX_STOP"):
        m.D.restore_stream(io.BytesIO(plain),"e"*32,"a"*64,os.geteuid(),**kwargs)
    assert binary.read_bytes()==bad


@WIN
def test_windows_real_r1084_wire_r1085_sink_r1088_custody_r1001_aead(data):
    root,manifest,plain,key,wire,_=data
    parent=root/"private"
    setup=r"""
$ErrorActionPreference='Stop'
$path='REPLACE'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
foreach($who in @($sid,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($who,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
$null=[IO.Directory]::CreateDirectory($path,$acl)
[IO.Directory]::SetAccessControl($path,$acl)
"""
    p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",
        setup.replace("REPLACE",str(parent).replace("'","''"))],capture_output=True,timeout=40)
    assert p.returncode==0,p.stderr
    p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",str(PKG/"r1085_windows_offhost_sink.ps1"),
        "-ExistingPrivateNtfsParent",str(parent),"-NewArchiveFolder","candidate","-QuotaBytes",str(m.GIB),
        "-AllowCiphertextOnly"],input=wire,capture_output=True,timeout=60)
    assert p.returncode==0,(p.stdout,p.stderr)
    archive=parent/"candidate"
    output=io.BytesIO()
    with m.LockedArchive(archive,windows_validator=m.windows_custody) as held:
        actual,proof=held.verify(key)
        assert actual==manifest and proof["symlinks"]==28
        with pytest.raises(OSError):
            with (archive/"part-0000.bin").open("wb"): pass
        held.stream(key,output)
    assert output.getvalue()==plain
    with m.LockedArchive(archive,windows_validator=m.windows_custody) as held:
        with pytest.raises(Exception):held.verify(os.urandom(48))


@WIN
def test_ps_owner_mode_without_approval_never_prompts_or_connects():
    p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-File",
        str(PKG/"r1066_owner_workflow.ps1"),"-PreserveAndRestore"],capture_output=True,timeout=30)
    assert p.returncode==42 and p.stderr==b""
    r=json.loads(p.stdout)
    assert r["code"]=="OWNER_APPROVAL_REQUIRED" and r["cutover"]=="NO_GO"
