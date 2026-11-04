"""Disposable synthetic credentials only; never select local custody files."""
import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

import test_r1157_operator as prior

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/'packaging/migration/r1160_owner_continuity.py'
PS=ROOT/'packaging/windows/r1160_owner_custody.ps1'
CS=ROOT/'packaging/migration/r1160_recipient_cng.cs'
spec=importlib.util.spec_from_file_location('flop_r1160_owner_continuity',PATH)
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
M=prior.M
WINDOWS=pytest.mark.skipif(os.name!='nt',reason='native PS5.1/CNG synthetic-only')


@pytest.fixture
def case(tmp_path,monkeypatch):
    # New dummy keys per test. No Init or persistent CNG key creation.
    owner=ed25519.Ed25519PrivateKey.generate();recipient=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    old=m.sha(b'synthetic OLD SID');new=m.sha(b'synthetic NEW SID');machine=m.sha(b'synthetic NEW machine')
    public=m.canonical(M.descriptor(owner,'owner',old))
    password=b'synthetic-only-existing-owner-passphrase'
    encrypted=owner.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(password))
    assert len(public)==377 and len(encrypted)==302
    oracle=os.urandom(672);k137=ed25519.Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.OpenSSH,serialization.NoEncryption())
    files=dict(zip(m.ARTIFACTS,(public,encrypted,oracle,k137)))
    for name,value in dict(public_sha=m.sha(public),old_control=old,oracle_sha=m.sha(oracle)).items():monkeypatch.setitem(m.ROOT_PINS,name,value)
    p=recipient.public_key().public_numbers()
    blob=struct.pack('<6I',0x31415352,3072,3,384,0,0)+p.e.to_bytes(3,'big')+p.n.to_bytes(384,'big')
    body=dict(version=1,kind='R1160_LOCAL_RECIPIENT',transfer_id='a'*32,new_control=new,new_machine=machine,
        algorithm=m.ALGORITHM,public_blob=base64.b64encode(blob).decode(),created_at=1000,expires_at=87400)
    packet=dict(body=body,signature=base64.b64encode(recipient.sign(m.RECIPIENT_DOMAIN+m.canonical(body),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())).decode())
    plan=dict(version=1,transfer_id=body['transfer_id'],recipient_sha256=m.sha(m.canonical(packet)),original_public_sha256=m.sha(public),
        encrypted_approval_sha256=m.sha(encrypted),oracle_cipher_sha256=m.sha(oracle),k137_sha256=m.sha(k137),source_control=old,
        source_clearance_ref='https://github.com/hanamaru777/technocore-safe-agent/issues/948#issuecomment-1',
        source_clearance_sha256=m.sha(b'synthetic clearance NOT live evidence'),consent=m.CONSENT,expires_at=87400)
    root=tmp_path/'private';root.mkdir(mode=0o700);M.protect_file(root)
    target=tmp_path/'synthetic-approval';monkeypatch.setattr(M,'store_path',lambda:target)
    monkeypatch.setattr(m,'machine_identity',lambda:machine)
    return dict(owner=owner,recipient=recipient,files=files,password=password,plan=plan,packet=packet,old=old,new=new,machine=machine,root=root,target=target)


def seal(c):
    files={k:bytearray(v) for k,v in c['files'].items()}
    value=m.seal(files,c['plan'],c['packet'],M,now=1001,source_control=c['old'])
    assert all(not any(v) for v in files.values())
    return value


def unwrap(c,envelope):
    return bytearray(c['recipient'].decrypt(base64.b64decode(envelope['wrapped_key']),padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)))


def imported(c,envelope=None):
    envelope=envelope or seal(c);aes=unwrap(c,envelope);password=bytearray(c['password'])
    binding,retained=m.bind_import(envelope,c['plan'],c['packet'],aes,password,M,now=1001,control=c['new'],machine=c['machine'])
    assert not any(aes) and not any(password)
    return envelope,binding,retained


def test_same_original_descriptor_and_key_with_separate_host_signature(case,monkeypatch):
    c=case
    # OLD sealing must never call the encrypted private-key loader.
    load=m.load_pem_private_key
    monkeypatch.setattr(m,'load_pem_private_key',lambda *_:pytest.fail('OLD must not unseal owner'))
    envelope=seal(c);monkeypatch.setattr(m,'load_pem_private_key',load)
    envelope,binding,retained=imported(c,envelope)
    public=m.verify_binding(retained['public.json'],binding,c['plan'],c['packet'],m.sha(m.canonical(envelope)),M,control=c['new'],machine=c['machine'])
    assert public['body']['control']==c['old'] and bytes(retained['public.json'])==c['files']['public.json']
    assert bytes(retained['approval.pem.enc'])==c['files']['approval.pem.enc']
    assert 'k137.pem' not in retained and c['files']['k137.pem'] not in m.canonical(envelope)
    assert binding['body']['owner_key_id']==M.validate_descriptor(public)


@pytest.mark.parametrize('fault',['old_sid','public_hash','cipher_hash','oracle_hash','k137_hash','recipient_pin','recipient_signature','expired','same_sid','source_clearance'])
def test_wrong_source_or_original_plan_fails_before_sealing(case,fault):
    c=case;plan=copy.deepcopy(c['plan']);packet=copy.deepcopy(c['packet']);sid=c['old']
    if fault=='old_sid':sid=c['new']
    elif fault in ('public_hash','cipher_hash','oracle_hash','k137_hash'):
        field=dict(public_hash='original_public_sha256',cipher_hash='encrypted_approval_sha256',oracle_hash='oracle_cipher_sha256',k137_hash='k137_sha256')[fault];plan[field]='f'*64
    elif fault=='recipient_pin':plan['recipient_sha256']='f'*64
    elif fault=='recipient_signature':packet['signature']=base64.b64encode(b'0'*384).decode();plan['recipient_sha256']=m.sha(m.canonical(packet))
    elif fault=='expired':plan['expires_at']=1000
    elif fault=='same_sid':packet['body']['new_control']=c['old'];plan['recipient_sha256']=m.sha(m.canonical(packet))
    else:plan['source_clearance_ref']='https://example.invalid/arbitrary'
    files={k:bytearray(v) for k,v in c['files'].items()}
    with pytest.raises(Exception):m.seal(files,plan,packet,M,now=1001,source_control=sid)
    assert all(not any(v) for v in files.values())


@pytest.mark.parametrize('fault',['sid','machine','tag','header','password','wrong_owner','truncated'])
def test_new_side_rejects_bad_identity_or_envelope_and_wipes(case,fault):
    c=case
    if fault=='wrong_owner':
        other=ed25519.Ed25519PrivateKey.generate()
        c['files']['approval.pem.enc']=other.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(c['password']))
        c['plan']['encrypted_approval_sha256']=m.sha(c['files']['approval.pem.enc'])
    envelope=seal(c);aes=unwrap(c,envelope);password=bytearray(c['password']);sid=c['new'];machine=c['machine']
    if fault=='sid':sid=c['old']
    elif fault=='machine':machine='f'*64
    elif fault=='tag':
        raw=bytearray(base64.b64decode(envelope['ciphertext']));raw[-1]^=1;envelope['ciphertext']=base64.b64encode(raw).decode()
    elif fault=='header':envelope['header']['transfer_id']='b'*32
    elif fault=='password':password=bytearray(b'wrong'*9)
    elif fault=='truncated':envelope['ciphertext']=envelope['ciphertext'][:-4]
    with pytest.raises(Exception):m.bind_import(envelope,c['plan'],c['packet'],aes,password,M,now=1001,control=sid,machine=machine)
    assert not any(aes) and not any(password) and not c['target'].exists()


def test_atomic_import_keeps_original_bytes_no_plain_k137_and_replay_refused(case):
    c=case;e,b,r=imported(c)
    m.commit_import(c['root'],b,r,c['plan'],c['packet'],e,M,control=c['new'],machine=c['machine'])
    assert (c['target']/'public.json').read_bytes()==c['files']['public.json']
    assert (c['target']/'approval.pem.enc').read_bytes()==c['files']['approval.pem.enc']
    assert m.verify_local(c['target'],m.decode(c['files']['public.json']),M,control=c['new'])==c['plan']['encrypted_approval_sha256']
    assert not list(c['root'].rglob('*.pem')) and not list(c['target'].rglob('*.pem'))
    assert all(c['files']['k137.pem'] not in p.read_bytes() for root in (c['root'],c['target']) for p in root.rglob('*') if p.is_file())
    with pytest.raises(ValueError,match='DESTINATION_EXISTS'):m.commit_import(c['root'],b,{},c['plan'],c['packet'],e,M,control=c['new'],machine=c['machine'])


@pytest.mark.parametrize('fault',['write','hash','rename','cleanup'])
def test_partial_import_never_commits_or_claims_success(case,monkeypatch,fault):
    c=case;e,b,r=imported(c);write=M.local_write
    def broken(path,raw):
        if path.name=='approval.pem.enc':
            if fault=='write':raise OSError('SENSITIVE_CANARY')
            if fault=='hash':raw=raw[:-1]
        write(path,raw)
    monkeypatch.setattr(M,'local_write',broken)
    def move(*_):raise OSError('SENSITIVE_CANARY')
    if fault=='cleanup':
        def guard(path,**kw):
            if path.name=='public.json' and path.exists():raise OSError('SENSITIVE_CANARY')
            return original(path,**kw)
        original=M.secure_path;monkeypatch.setattr(M,'secure_path',guard)
    with pytest.raises(ValueError,match='R1160_(IMPORT_UNKNOWN_NO_RETRY|CLEANUP_UNVERIFIED)'):
        m.commit_import(c['root'],b,r,c['plan'],c['packet'],e,M,control=c['new'],machine=c['machine'],move=move)
    assert not c['target'].exists() and all(not any(x) for x in r.values())


def test_existing_owner_api_requires_same_key_signed_new_host_and_preserves_v1(case,monkeypatch):
    c=case;e,b,r=imported(c)
    m.commit_import(c['root'],b,r,c['plan'],c['packet'],e,M,control=c['new'],machine=c['machine'])
    with M.local_key(c['target'],bytearray(c['password']),identity=lambda:c['new']) as (key,public):
        assert key.public_key().public_bytes_raw()==c['owner'].public_key().public_bytes_raw()
        assert public==m.decode(c['files']['public.json'])
    with pytest.raises(Exception):
        with M.local_key(c['target'],bytearray(c['password']),identity=lambda:'f'*64):pass
    raw=m.decode((c['target']/'host-binding.json').read_bytes());raw['body']['new_control']='f'*64
    (c['target']/'host-binding.json').write_bytes(m.canonical(raw))
    with pytest.raises(Exception):
        with M.local_key(c['target'],bytearray(c['password']),identity=lambda:'f'*64):pass
    # Existing original-SID custody needs no continuity override, unchanged.
    native=c['root']/'native';native.mkdir(mode=0o700);M.protect_file(native)
    for name in ('public.json','approval.pem.enc'):M.local_write(native/name,c['files'][name])
    with M.local_key(native,bytearray(c['password']),identity=lambda:c['old']) as (_,public):assert public['body']['control']==c['old']


def test_r1159_public_preflight_does_not_unlock_key_for_bound_new_sid(case,monkeypatch):
    import test_r1159_m2_bootstrap as prior59
    c=case;e,b,r=imported(c);m.commit_import(c['root'],b,r,c['plan'],c['packet'],e,M,control=c['new'],machine=c['machine'])
    monkeypatch.setattr(M,'control_identity',lambda:c['new'])
    monkeypatch.setattr(M,'local_key',lambda *_:pytest.fail('public check cannot open private key'))
    assert M.require_control(c['target'],m.decode(c['files']['public.json']),identity=M.control_identity)==c['plan']['encrypted_approval_sha256']
    text=prior59.PATH.read_text(encoding='utf-8')
    assert 'M.require_control(' in text and 'M.local_key(' not in text


@pytest.mark.parametrize('raw',[b'{"x":1,"x":2}',b'{"x":NaN}',b' '*65537],ids=['duplicate','NaN','oversized'])
def test_strict_public_json_rejects_ambiguous_or_unbounded(raw):
    with pytest.raises(Exception):m.decode(raw)


@pytest.mark.parametrize('change',['partial','trailing','count','oversized'])
def test_binary_framing_rejects_partial_or_unknown_file_set(case,change):
    raw=m.pack_files(case['files'])
    if change=='partial':raw=raw[:-1]
    elif change=='trailing':raw+=b'X'
    elif change=='count':raw[:4]=struct.pack('>I',5)
    else:raw[4:8]=struct.pack('>I',1<<30)
    with pytest.raises(Exception):m.unpack_files(raw)


def test_binary_control_and_secret_are_separate_and_partial_input_rejected():
    meta=m.canonical(dict(operation='synthetic'));raw=struct.pack('>I',len(meta))+meta+b'\0\xff\x80binary'
    packet=b'FLOPR189'+struct.pack('>I',len(raw))+raw
    value,data=m.packet_input(io.BytesIO(packet));assert value['operation']=='synthetic' and data==b'\0\xff\x80binary'
    with pytest.raises(Exception):m.packet_input(io.BytesIO(packet[:-1]))


def native(code):
    return subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',code],capture_output=True,timeout=65)


@WINDOWS
def test_native_ps51_parse_default_no_execute_no_credential_access():
    path=str(PS).replace("'","''")
    code="$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseFile('"+path+"',[ref]$t,[ref]$e);if($e.Count){exit 42};& '"+path+"'"
    r=native(code);assert r.returncode==0 and not r.stderr
    assert json.loads(r.stdout)['code']=='EXPLICIT_SOURCE_ONLY_OPERATION_REQUIRED'


@WINDOWS
def test_native_ephemeral_cng_nonexportability_and_python_interop(tmp_path):
    # Ephemeral dummy CNG only: do not call Recipient.Create/Open or touch the
    # user's persisted key store. RSA public/signature/wrapped key are synthetic.
    out=tmp_path/'dummy-public.json'
    code="$ErrorActionPreference='Stop';Add-Type -TypeDefinition ([IO.File]::ReadAllText('"+str(CS).replace("'","''")+"'))\n"+r'''
$p=New-Object Security.Cryptography.CngKeyCreationParameters
$p.Provider=New-Object Security.Cryptography.CngProvider('Microsoft Software Key Storage Provider')
$p.KeyUsage=[Security.Cryptography.CngKeyUsages]::Signing -bor [Security.Cryptography.CngKeyUsages]::Decryption
$p.ExportPolicy=[Security.Cryptography.CngExportPolicies]::None
$p.Parameters.Add((New-Object Security.Cryptography.CngProperty('Length',[BitConverter]::GetBytes(3072),[Security.Cryptography.CngPropertyOptions]::None)))
Add-Type -TypeDefinition 'using System.Security.Cryptography; public static class DummyR1160 { public static CngKey Ephemeral(CngKeyCreationParameters p) {return CngKey.Create(CngAlgorithm.Rsa,null,p);} }'
$key=[DummyR1160]::Ephemeral($p)
try {
 [FlopR1160.Recipient]::Validate($key)
 $denied=$false;try{$null=$key.Export([Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)}catch{$denied=$true}
 if(-not $denied){throw 'EXPORT_ALLOWED'}
 $rsa=New-Object Security.Cryptography.RSACng($key)
 try {
  $pub=$key.Export([Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob)
  $message=[Text.Encoding]::ASCII.GetBytes('synthetic-public-interoperability')
  $sig=$rsa.SignData($message,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pss)
  $data=New-Object byte[] 32;for($i=0;$i -lt 32;$i++){$data[$i]=$i}
  $wrapped=$rsa.Encrypt($data,[Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
  $plain=$rsa.Decrypt($wrapped,[Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
  if([Convert]::ToBase64String($plain) -cne [Convert]::ToBase64String($data)){throw 'ROUNDTRIP_STOP'}
  [IO.File]::WriteAllText('OUTFILE',(@{blob=[Convert]::ToBase64String($pub);signature=[Convert]::ToBase64String($sig)}|ConvertTo-Json -Compress),[Text.Encoding]::ASCII)
  [Array]::Clear($data,0,$data.Length);[Array]::Clear($plain,0,$plain.Length)
 }finally{$rsa.Dispose()}
}finally{$key.Dispose()}
[Console]::Write('SYNTHETIC_CNG_PASS')
'''.replace('OUTFILE',str(out).replace("'","''"))
    r=native(code);assert r.returncode==0,r.stderr.decode(errors='replace')
    assert r.stdout==b'SYNTHETIC_CNG_PASS' and not r.stderr
    v=json.loads(out.read_bytes());key=m.public_rsa(base64.b64decode(v['blob']))
    key.verify(base64.b64decode(v['signature']),b'synthetic-public-interoperability',padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())


def test_no_network_init_source_unseal_or_arbitrary_credential_lane():
    text=PATH.read_text(encoding='utf-8');ps=PS.read_text(encoding='utf-8')
    for forbidden in ('Invoke-WebRequest','Invoke-RestMethod','ssh.exe','Start-Transcript','Set-Clipboard','init_key('):assert forbidden not in ps
    assert 'load_pem_private_key' not in text[text.index('def seal('):text.index('def inspect_envelope(')]
    assert "'approval.pem.enc'" in ps and 'Read-Host' in ps and '-AsSecureString' in ps
    assert 'NO_AUTOMATIC_RETRY' in ps and 'OwnerPipe]::Run' in ps


def definitions():
    path=str(PS).replace("'","''")
    return "$ErrorActionPreference='Stop';$PSScriptRoot='"+str(PS.parent).replace("'","''")+"'\n"+r'''
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('PSFILE',[ref]$tokens,[ref]$errors)
if($errors.Count -ne 0){throw 'PARSE_STOP'}
foreach($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) {
 $definition=$node.Extent.Text
 if($node.Name -ceq 'Read-R1160Code'){$definition=$definition.Replace('$PSScriptRoot',"'TESTROOT'")}
 Invoke-Expression $definition
}
'''.replace('PSFILE',path).replace('TESTROOT',str(PS.parent).replace("'","''"))


@WINDOWS
def test_native_source_pins_real_binary_pipe_and_fixed_redacted_failure():
    code=definitions()+r'''
$map=Read-R1160Code 'packaging/migration/r1155_source_pins.json' 'MAPROOT'
foreach($p in ($map|ConvertFrom-Json).PSObject.Properties){$null=Read-R1160Code $p.Name $p.Value}
$lib=Read-R1160Code 'packaging/migration/r1066_owner_workflow.ps1' '13978d6afb01fc3898018e045aded87d673ef683'
foreach($name in @('Read-R1066PinnedSource','Initialize-R1066')){Import-R1160Function $lib $name}
$script:R1066Root=Join-Path $PSScriptRoot '..\migration';Initialize-R1066
$denied=$false;try{$null=Read-R1160Code 'packaging/migration/r1160_owner_continuity.py' ('0'*40)}catch{$denied=$true}
if(-not $denied){throw 'UNPINNED_CODE_ALLOWED'}
Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:R1066Root 'r1089_owner_control_pipe.cs')))
$script:R1160Python=Join-Path $PSScriptRoot '..\..\.venv\Scripts\python.exe'
$script:R1160Program=Join-Path $script:R1066Root 'r1160_owner_continuity.py'
$stopped=$false
try {$null=Invoke-R1160Local @{operation='SYNTHETIC_SECRET_CANARY'} ([byte[]]@(0,255,128,10))}catch{
 if($_.Exception.Message -cne 'LOCAL_VALIDATION_STOP'){throw 'UNSAFE_ERROR'};$stopped=$true
}
if(-not $stopped){throw 'UNSAFE_OPERATION_ALLOWED'}
[Console]::Write('SYNTHETIC_PIN_BINARY_PIPE_PASS')
'''
    pins=ROOT/'packaging/migration/r1155_source_pins.json';raw=pins.read_bytes().replace(b'\r\n',b'\n')
    import hashlib
    code=code.replace('MAPROOT',hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
    r=native(code);assert r.returncode==0,r.stderr.decode(errors='replace')
    assert r.stdout==b'SYNTHETIC_PIN_BINARY_PIPE_PASS' and not r.stderr


@WINDOWS
def test_native_owner_only_input_acl_and_reparse_rejection(case):
    root=str(case['root']).replace("'","''")
    code=definitions()+r'''
$lib=[IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\migration\r1066_owner_workflow.ps1'))
foreach($name in @('Read-R1066PinnedSource','Initialize-R1066')){Import-R1160Function $lib $name}
$script:R1066Root=Join-Path $PSScriptRoot '..\migration';Initialize-R1066
$old=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'r1159_authenticated_m2_bootstrap.ps1'))
Import-R1160Function $old 'Assert-R1159ExistingFile'
$file=Join-Path 'PRIVATE_ROOT' 'synthetic-input'
[IO.File]::WriteAllBytes($file,([byte[]]@(0,255,128,10)))
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$a=New-Object Security.AccessControl.FileSecurity
$a.SetOwner($sid);$a.SetAccessRuleProtection($true,$false)
$a.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow')))
[IO.File]::SetAccessControl($file,$a)
$b=Read-R1160File $file 10
if([Convert]::ToBase64String($b) -cne 'AP+ACg=='){throw 'BINARY_CORRUPTED'}
$everyone=New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
$a.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($everyone,'Read','Allow')))
[IO.File]::SetAccessControl($file,$a)
$stopped=$false;try{$null=Read-R1160File $file 10}catch{$stopped=$true}
if(-not $stopped){throw 'UNSAFE_ACL_ALLOWED'}
# Never repair existing credentials: this is a disposable test file only.
[IO.File]::Delete($file)
[Console]::Write('SYNTHETIC_ACL_PASS')
'''.replace('PRIVATE_ROOT',root)
    r=native(code);assert r.returncode==0,r.stderr.decode(errors='replace')
    assert r.stdout==b'SYNTHETIC_ACL_PASS' and not r.stderr


def test_signed_binding_corruption_and_cipher_swap_rejected(case):
    c=case;e,b,r=imported(c);b['signature']='0'*128
    with pytest.raises(ValueError,match='OWNER_SIGNATURE_STOP'):
        m.verify_binding(r['public.json'],b,c['plan'],c['packet'],m.sha(m.canonical(e)),M,control=c['new'],machine=c['machine'])


def test_plan_cannot_outlive_recipient_request(case):
    c=case;c['plan']['expires_at']=87401
    with pytest.raises(ValueError,match='PLAN_EXPIRED'):
        m.validate_plan(c['plan'],c['packet'],now=1002)


def test_pipe_failure_wipes_synthetic_password_without_printing_exception(case,monkeypatch,capsys):
    from types import SimpleNamespace
    # Validate the real binary parser/finally boundary without loading any
    # machine store or querying the running account. No Init or real password.
    meta=m.canonical(dict(operation='import',unknown='SYNTHETIC_PRIVATE_CANARY'))
    control=struct.pack('>I',len(meta))+meta
    password=b'SYNTHETIC_PRIVATE_CANARY'*2
    wire=b'FLOPR189'+struct.pack('>I',len(control))+control+struct.pack('>I',len(password))+password
    monkeypatch.setattr(m.sys,'argv',['r1160','--pipe'])
    monkeypatch.setattr(m.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(wire)))
    fake=SimpleNamespace(control_identity=lambda:case['new'])
    loader=SimpleNamespace(exec_module=lambda _:None)
    util=SimpleNamespace(spec_from_file_location=lambda *args:SimpleNamespace(name='r1160_dummy_only',loader=loader),module_from_spec=lambda _:fake)
    monkeypatch.setattr(m,'importlib',SimpleNamespace(util=util))
    frames=[];read=m.private_frame
    def tracked(*args):
        value=read(*args);frames.append(value);return value
    monkeypatch.setattr(m,'private_frame',tracked)
    assert m.main()==42
    out=capsys.readouterr()
    assert json.loads(out.out)['code']=='R1160_STOP_NO_RETRY' and not out.err
    assert 'CANARY' not in out.out and len(frames)==2 and all(not any(b) for b in frames)


@WINDOWS
def test_native_old_approval_store_does_not_inherit_management_acl_allowance(case):
    root=str(case['root']).replace("'","''")
    code=definitions()+r'''
$lib=[IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\migration\r1066_owner_workflow.ps1'))
foreach($name in @('Read-R1066PinnedSource','Initialize-R1066')){Import-R1160Function $lib $name}
$script:R1066Root=Join-Path $PSScriptRoot '..\migration';Initialize-R1066
$old=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'r1159_authenticated_m2_bootstrap.ps1'))
Import-R1160Function $old 'Assert-R1159ExistingFile'
$folder=Join-Path 'PRIVATE_ROOT' 'dummy-original-store';New-R1027Custody $folder
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
foreach($name in @('public.json','approval.pem.enc')) {
 $p=Join-Path $folder $name;[IO.File]::WriteAllBytes($p,([byte[]]@(1,2,3)))
 $a=New-Object Security.AccessControl.FileSecurity;$a.SetOwner($sid);$a.SetAccessRuleProtection($true,$false)
 $a.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow')))
 [IO.File]::SetAccessControl($p,$a)
}
Assert-R1160OwnerCustody $folder
$p=Join-Path $folder 'approval.pem.enc';$a=[IO.File]::GetAccessControl($p)
$admin=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$a.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($admin,'Read','Allow')))
[IO.File]::SetAccessControl($p,$a)
$stopped=$false;try{Assert-R1160OwnerCustody $folder}catch{$stopped=$true}
if(-not $stopped){throw 'APPROVAL_ACL_WEAKENED'}
[Console]::Write('SYNTHETIC_ORIGINAL_ACL_PASS')
'''.replace('PRIVATE_ROOT',root)
    r=native(code);assert r.returncode==0,r.stderr.decode(errors='replace')
    assert r.stdout==b'SYNTHETIC_ORIGINAL_ACL_PASS' and not r.stderr
