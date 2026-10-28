"""Synthetic host metadata and mocked SSH only. Never read real credentials."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "packaging/migration"
spec = importlib.util.spec_from_file_location("r1066_probe_test", FILES / "r1066_preflight_readonly.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
WINDOWS = pytest.mark.skipif(os.name != "nt", reason="actual Windows PowerShell 5.1/ACL fixture")


@pytest.fixture
def host(monkeypatch):
    request = dict(role="k137", machine_sha256=hashlib.sha256(b"a" * 32).hexdigest(),
                   uid=1234, head=m.K137_STAGE_SHA, cgroup_sha256=hashlib.sha256(b"0::/test.scope").hexdigest(),
                   minimum_free_bytes=1024**3, challenge="c" * 64)
    reads = {"/etc/machine-id": b"a" * 32, "/proc/self/cgroup": b"0::/test.scope\n",
             "/sys/fs/cgroup/test.scope/memory.max": b"134217728\n",
             "/sys/fs/cgroup/test.scope/pids.max": b"32\n",
             "/sys/fs/cgroup/test.scope/cpu.max": b"10000 100000\n"}
    monkeypatch.setattr(m.sys, "platform", "linux")
    monkeypatch.setattr(m.os, "geteuid", lambda: request["uid"], raising=False)
    monkeypatch.setattr(m, "read_small", lambda p, limit=4096: reads[p])
    monkeypatch.setattr(m, "directory", lambda p: SimpleNamespace(
        st_uid=1234 if p == m.LANDING else 0, st_mode=stat.S_IFDIR | 0o700))
    monkeypatch.setattr(m.os, "access", lambda p, flags: p == m.LANDING)
    monkeypatch.setattr(m.os, "statvfs", lambda p: SimpleNamespace(f_bavail=2**30, f_frsize=4096), raising=False)
    monkeypatch.setattr(m.os.path, "lexists", lambda p: False)
    monkeypatch.setattr(m, "git_head", lambda p: request["head"])
    return request, reads


def test_both_host_proofs_redacted_and_never_admit_restore(host):
    request, _ = host
    for role in ("k137", "oci"):
        request["role"] = role
        if role == "oci":
            request.update(uid=0, head=m.HEAD)
        result = m.probe(request)
        assert result["host_identity"] == result["head"] == result["scope"] == "MATCH"
        assert result["read_only"] is True
        for name in ("writer_admission", "five_post_finality", "common_sqlite_epoch", "signer_portability", "restore_authority"):
            assert result[name] == "NOT_PROVEN"
        assert result["oci_retirement"] == "STRICT_NO_GO" and result["cutover"] == "NO_GO"
        text = json.dumps(result)
        assert request["machine_sha256"] not in text and "/opt/" not in text


@pytest.mark.parametrize("field,value", [("machine_sha256", "f" * 64), ("head", "bad"),
    ("cgroup_sha256", "f" * 64), ("uid", 0), ("minimum_free_bytes", True),
    ("role", "other"), ("challenge", "injection")])
def test_wrong_binding_is_rejected(host, field, value):
    request, _ = host
    request[field] = value
    with pytest.raises(m.Stop):
        m.probe(request)


@pytest.mark.parametrize("path,value", [("memory.max", b"max"), ("pids.max", b"1000"),
    ("cpu.max", b"max 100000"), ("cpu.max", b"200000 100000")])
def test_resource_scope_not_assumed_safe(host, path, value):
    request, reads = host
    reads["/sys/fs/cgroup/test.scope/" + path] = value
    with pytest.raises(m.Stop):
        m.probe(request)


def test_protected_writability_insufficient_disk_and_source_drift(host, monkeypatch):
    request, _ = host
    monkeypatch.setattr(m.os, "access", lambda *a: True)
    with pytest.raises(m.Stop):
        m.probe(request)
    monkeypatch.setattr(m.os, "access", lambda p, f: p == m.LANDING)
    monkeypatch.setattr(m.os, "statvfs", lambda p: SimpleNamespace(f_bavail=0, f_frsize=4096))
    with pytest.raises(m.Stop):
        m.probe(request)
    request.update(role="oci", uid=0, head=m.HEAD)
    monkeypatch.setattr(m, "git_head", lambda p: "f" * 40)
    with pytest.raises(m.Stop):
        m.probe(request)


def test_guest_error_never_discloses_raw_content(monkeypatch, capsys):
    def fail(_):
        raise RuntimeError("PRIVATE_CANARY /private/path")
    monkeypatch.setattr(m, "probe", fail)
    with pytest.raises(SystemExit) as e:
        m.run({})
    assert e.value.code == 42
    assert capsys.readouterr().out == '{"code":"PREFLIGHT_UNVERIFIED"}\n'


def test_probe_and_transport_pinned_and_read_only():
    text = (FILES / "r1066_owner_workflow.ps1").read_text()
    for name in ("r1066_preflight_readonly.py", "r1066_preflight_transport.cs"):
        raw = (FILES / name).read_bytes().replace(b"\r\n", b"\n")
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        assert blob in text
    tree = ast.parse((FILES / "r1066_preflight_readonly.py").read_text())
    calls = [ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)]
    assert not any(x in calls for x in ("os.system", "os.chmod", "os.unlink", "os.rename", "shutil.copy", "sqlite3.connect"))
    assert "shell=True" not in ast.unparse(tree)
    assert "'/usr/bin/git'" in ast.unparse(tree)
    assert "Get-R1027Source $" not in text and "Invoke-R1062" not in text
    for option in ("StrictHostKeyChecking=yes", "IdentityAgent=none", "ProxyCommand=none", "ProxyJump=none",
                   "KnownHostsCommand=none", "BatchMode=yes", "ClearAllForwardings=yes", "GlobalKnownHostsFile=NUL"):
        assert option in text


def ps_script(body):
    # Extract function definitions ONLY, not an operator invocation. No dot source.
    script = str(FILES / "r1066_owner_workflow.ps1").replace("'", "''")
    root = str(FILES).replace("'", "''")
    return f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('{script}',[ref]$tokens,[ref]$errors)
if ($errors.Count) {{ throw 'SYNTAX' }}
foreach ($n in $ast.FindAll({{param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]}},$true)) {{
    $p=@($n.Parameters | Where-Object {{ $null -ne $_ }} | ForEach-Object {{ $_.Extent.Text }}) -join ','
    $b=$n.Body.Extent.Text
    Set-Item ('Function:'+$n.Name) ([scriptblock]::Create(('param('+$p+")`n"+$b.Substring(1,$b.Length-2))))
}}
$script:R1066Root='{root}'
Initialize-R1066
function Need($v) {{ if (-not $v) {{ throw ('ASSERT_LINE_'+$MyInvocation.ScriptLineNumber) }} }}
{body}
"""


def run_ps(tmp_path, body):
    fixture = tmp_path / "synthetic-test.ps1"
    fixture.write_text(ps_script(body), encoding="utf-8-sig")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(fixture)],
                            capture_output=True, timeout=90)
    assert result.returncode == 0, (result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace"))
    return result.stdout.decode(errors="replace")


@WINDOWS
def test_ps51_missing_enrollment_never_prompts_or_connects(tmp_path):
    output = run_ps(tmp_path, """
function Read-R1027Backup { throw 'MUST_NOT_READ' }
function Invoke-R1066Ssh { throw 'MUST_NOT_CONNECT' }
$r=Invoke-R1066Workflow '' ''
Need ($r.code -ceq 'K137_INDEPENDENT_ENROLLMENT_REQUIRED')
Need ($r.operation -ceq 'blocked')
Write-Output 'PASS'
""")
    assert output.strip() == "PASS"


@WINDOWS
def test_ps51_binary_timeout_bound_and_environment(tmp_path):
    output = run_ps(tmp_path, """
# Test the transport itself, not cold-start latency of a second PowerShell host.
$exe=Join-Path $PSScriptRoot 'synthetic-binary-child.exe'
Add-Type -OutputAssembly $exe -OutputType ConsoleApplication -TypeDefinition @'
using System;
using System.Threading;
public class SyntheticBinaryChild {
    public static int Main(string[] args) {
        if (Environment.GetEnvironmentVariable("R1066_CANARY") != null) return 3;
        if (args.Length > 0 && args[0] == "sleep") { Thread.Sleep(30000); return 0; }
        var output = Console.OpenStandardOutput();
        if (args.Length > 0 && args[0] == "large") { output.Write(new byte[17000],0,17000); return 0; }
        Console.Error.Write("PRIVATE_STDERR_CANARY");
        var input = Console.OpenStandardInput(); byte[] b = new byte[256]; int n;
        while ((n = input.Read(b,0,b.Length)) > 0) output.Write(b,0,n);
        return 0;
    }
}
'@
$env:R1066_CANARY='PRIVATE_CANARY'
[Console]::InputEncoding=New-Object Text.UTF8Encoding($true)
$bytes=[byte[]](0..255)
$r=[FlopR1066.Transport]::Run($exe,'',$bytes,10000)
Need ([Console]::InputEncoding.GetPreamble().Length -eq 3)
if ($r.ExitCode -ne 0 -or $r.Output.Length -ne 256) { throw ('BINARY_EXIT_'+$r.ExitCode+'_LENGTH_'+$r.Output.Length) }
for ($i=0; $i -lt 256; $i++) { Need ($r.Output[$i] -eq $i) }
$blocked=$false
try { $null=[FlopR1066.Transport]::Run($exe,'sleep',([byte[]]@()),200) } catch { $blocked=$true }
Need $blocked
$blocked=$false
try { $null=[FlopR1066.Transport]::Run($exe,'large',([byte[]]@()),10000) } catch { $blocked=$true }
Need $blocked
Write-Output 'PASS'
""")
    assert output.strip() == "PASS"


@WINDOWS
def test_ps51_response_schema_forgery_and_replay(tmp_path):
    request = dict(role="k137", minimum_free_bytes=1024**3, challenge="c" * 64)
    # Response from actual synthetic probe, not an invented alternate schema.
    result = dict(schema_version=1, role="k137", challenge="c" * 64, host_identity="MATCH", head="MATCH", scope="MATCH",
                  disk_free_bytes=2**40, disk_required_bytes=1024**3, resources="BOUNDED_SCOPE_OBSERVED", memory_max_bytes=2**27,
                  pids_max=32, protected_tradebot="DIRECTORY_WRITE_DENIED_ONLY", read_only=True,
                  writer_admission="NOT_PROVEN", five_post_finality="NOT_PROVEN", common_sqlite_epoch="NOT_PROVEN",
                  signer_portability="NOT_PROVEN", restore_authority="NOT_PROVEN", cutover="NO_GO", oci_retirement="STRICT_NO_GO")
    output = run_ps(tmp_path, f"""
$q=('{json.dumps(request)}' | ConvertFrom-Json)
$raw='{json.dumps(result)}'
$r=Read-R1066Response ([Text.Encoding]::ASCII.GetBytes($raw)) $q
Need ($r.cutover -ceq 'NO_GO')
foreach ($bad in @($raw.Replace('NOT_PROVEN','PASS'),$raw.Replace(([char]123+'"schema_version"'),([char]123+'"schema_version":1,"schema_version"')),
    $raw.Replace(('c'*64),('d'*64)),($raw+'PRIVATE_CANARY'))) {{
    $blocked=$false
    try {{ $null=Read-R1066Response ([Text.Encoding]::ASCII.GetBytes($bad)) $q }} catch {{ $blocked=$true }}
    Need $blocked
}}
Write-Output 'PASS'
""")
    assert output.strip() == "PASS"


@WINDOWS
def test_ps51_enrollment_workflow_cleanup_and_failure(tmp_path):
    fixture = str(tmp_path / "custody").replace("'", "''")
    output = run_ps(tmp_path, f"""
$d='{fixture}'
New-R1027Custody $d
try {{
    $key=Write-R1027Key $d ([Text.Encoding]::ASCII.GetBytes('SYNTHETIC-K137-FIXTURE'))
    $script:fixtureK137Key=$key
    $e=[pscustomobject]@{{schema_version=1; purpose='R1066_READONLY_PREFLIGHT';
        oci=[pscustomobject]@{{host='140.238.55.171';user='ubuntu';host_key=('ecdsa-sha2-nistp256 '+[Convert]::ToBase64String([byte[]](1..32)));
            host_key_sha256=[FlopR1062.Guards]::Sha256([byte[]](1..32));credential_sha256=[FlopR1062.Guards]::Sha256([Text.Encoding]::ASCII.GetBytes('SYNTHETIC-OCI-FIXTURE'));
            identity_file='R987_V2_ESCROW'; machine_sha256=('a'*64);uid=0;head='ec4bc4892d40cdd2a03e102faa44d72c89e01b99';cgroup_sha256=('b'*64);minimum_free_bytes=1073741824}};
        k137=[pscustomobject]@{{host='192.0.2.10';user='quarantine';host_key=('ssh-ed25519 '+[Convert]::ToBase64String([byte[]](2..33)));
            host_key_sha256=[FlopR1062.Guards]::Sha256([byte[]](2..33));credential_sha256=(Get-R1066FileDigest $key);
            identity_file=$key;machine_sha256=('c'*64);uid=1234;head=('d'*40);cgroup_sha256=('e'*64);minimum_free_bytes=1073741824}}
    }}
    $profile=Join-Path $d 'enrollment.json'
    [IO.File]::WriteAllText($profile,($e | ConvertTo-Json -Depth 5 -Compress),[Text.Encoding]::ASCII)
    $acl=[IO.File]::GetAccessControl($profile)
    $acl.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User)
    [IO.File]::SetAccessControl($profile,$acl)
    $digest=Get-R1066FileDigest $profile
    $valid=Read-R1066Enrollment $profile $digest
    Need ($valid.k137.uid -eq 1234)
    foreach ($bad in @('wrong',[string]('f'*64))) {{
        $blocked=$false
        try {{ $null=Read-R1066Enrollment $profile $bad }} catch {{ $blocked=$true }}
        Need $blocked
    }}
    $valid.k137.host='host;evil'
    $blocked=$false
    try {{ Assert-R1066Endpoint $valid.k137 'k137' }} catch {{ $blocked=$true }}
    Need $blocked
    $valid.k137.host='192.0.2.10'
    $valid.oci.host='192.0.2.10'
    $blocked=$false
    try {{ Assert-R1066Endpoint $valid.oci 'oci' }} catch {{ $blocked=$true }}
    Need $blocked
    function Initialize-R1066 {{}}
    function Read-R1027Backup {{ return ,([byte[]]@(0)) }}
    function Read-Host {{ return (New-Object Security.SecureString) }}
    function Unprotect-R1027 {{ return ,([Text.Encoding]::ASCII.GetBytes('SYNTHETIC-OCI-FIXTURE')) }}
    $script:calls=0; $script:remoteFailure=$false; $script:lastTemp=$null
    function Invoke-R1066Ssh($Executable,$Arguments,$InputBytes) {{
        $script:calls++
        Need ($Arguments -ccontains 'StrictHostKeyChecking=yes')
        Need ($Arguments -ccontains 'ProxyCommand=none')
        $i=[Array]::IndexOf($Arguments,'-i')
        $used=$Arguments[$i+1]
        if ($Arguments[-2] -ceq 'ubuntu@140.238.55.171') {{
            Need ($Arguments[-1] -ceq 'sudo -n /usr/bin/python3 -I -B -')
            $script:lastTemp=[IO.Path]::GetDirectoryName($used)
            Need ($used -cne $script:fixtureK137Key)
        }} else {{
            Need ($Arguments[-2] -ceq 'quarantine@192.0.2.10')
            Need ($Arguments[-1] -ceq '/usr/bin/python3 -I -B -')
            Need ($used -ceq $script:fixtureK137Key)
        }}
        if ($script:remoteFailure) {{ throw 'PRIVATE-SSH-ERROR-CANARY' }}
        $text=[Text.Encoding]::UTF8.GetString($InputBytes)
        $hex=[regex]::Match($text,"fromhex\\('([A-F0-9]+)'\\)").Groups[1].Value
        $bytes=New-Object byte[] ($hex.Length/2)
        for ($i=0; $i -lt $bytes.Length; $i++) {{ $bytes[$i]=[Convert]::ToByte($hex.Substring(2*$i,2),16) }}
        $q=[Text.Encoding]::ASCII.GetString($bytes) | ConvertFrom-Json
        $r=[ordered]@{{schema_version=1;role=$q.role;challenge=$q.challenge;host_identity='MATCH';head='MATCH';scope='MATCH';
            disk_free_bytes=1099511627776;disk_required_bytes=$q.minimum_free_bytes;resources='NOT_ASSESSED';memory_max_bytes=0;pids_max=0;
            protected_tradebot='NOT_PRESENT';read_only=$true;writer_admission='NOT_PROVEN';five_post_finality='NOT_PROVEN';
            common_sqlite_epoch='NOT_PROVEN';signer_portability='NOT_PROVEN';restore_authority='NOT_PROVEN';cutover='NO_GO';oci_retirement='STRICT_NO_GO'}}
        if ($q.role -ceq 'k137') {{
            $r.resources='BOUNDED_SCOPE_OBSERVED';$r.memory_max_bytes=134217728;$r.pids_max=32;$r.protected_tradebot='DIRECTORY_WRITE_DENIED_ONLY'
        }}
        return [pscustomobject]@{{ExitCode=0;Output=[Text.Encoding]::ASCII.GetBytes(($r | ConvertTo-Json -Compress))}}
    }}
    $r=Invoke-R1066Workflow $profile $digest
    if ($r.operation -cne 'preflight_verified') {{ throw ('RESULT_'+$r.code+'_'+$script:calls+'_'+$Error[0].Exception.Message) }}
    Need ($r.operation -ceq 'preflight_verified' -and $script:calls -eq 2)
    Need ($r.code -ceq 'WRITER_ADMISSION_AUTHORIZATION_REQUIRED')
    Need (-not [IO.Directory]::Exists($script:lastTemp))
    Need ([IO.File]::Exists($key))
    $script:remoteFailure=$true
    $r=Invoke-R1066Workflow $profile $digest
    Need ($r.operation -ceq 'blocked' -and $script:calls -eq 3)
    Need (-not (($r | ConvertTo-Json) -match 'CANARY'))
    Need (-not [IO.Directory]::Exists($script:lastTemp))
    $script:remoteFailure=$false
    # A simulated cleanup failure must invalidate an otherwise successful proof.
    $realCleanup=${{function:Remove-R1027Custody}}
    function Remove-R1027Custody($Directory) {{ & $realCleanup $Directory; throw 'SYNTHETIC' }}
    # Prevent initialization re-importing the intentionally replaced helper.
    function Initialize-R1066 {{}}
    $r=Invoke-R1066Workflow $profile $digest
    Need ($r.operation -ceq 'blocked' -and $r.code -ceq 'CLEANUP_STOP')
    Need (-not [IO.Directory]::Exists($script:lastTemp))
    Write-Output 'PASS'
}} finally {{
    [IO.File]::Delete((Join-Path $d 'enrollment.json'))
    [IO.File]::Delete((Join-Path $d 'recovered-v2'))
    [IO.Directory]::Delete($d,$false)
}}
""")
    assert output.strip() == "PASS"


def test_k137_stage_binding_uses_owner_evidenced_release_not_container(host, monkeypatch):
    request, _ = host
    seen = []
    def git_at(path):
        seen.append(path)
        return request["head"]
    monkeypatch.setattr(m, "git_head", git_at)
    result = m.probe(request)
    assert result["head"] == "MATCH"
    assert seen == [m.K137_STAGE]
    assert m.K137_STAGE == "/opt/flop-shadow/releases/" + m.K137_STAGE_SHA
    assert m.K137_STAGE_SHA == "3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e"
    request["head"] = "b" * 40
    with pytest.raises(m.Stop):
        m.probe(request)
    assert seen == [m.K137_STAGE]  # rejection before untrusted Git lookup


def test_k137_source_guard_does_not_accept_unverified_release_head(host, monkeypatch):
    request, _ = host
    monkeypatch.setattr(m, "git_head", lambda _: "c" * 40)
    with pytest.raises(m.Stop):
        m.probe(request)


def test_stage_relay_source_is_exactly_blob_pinned_in_windows_owner_controller():
    content = (FILES / "r1066_owner_workflow.ps1").read_text()
    source = (FILES / "r1066_ciphertext_ssh_relay.py").read_bytes().replace(b"\r\n", b"\n")
    blob = hashlib.sha1(b"blob " + str(len(source)).encode() + b"\0" + source).hexdigest()
    assert blob in content
    assert "Invoke-R1066CiphertextStage" in content
    assert "Assert-R1066StageIntent $PerformStage" in content
    assert "Get-R1066FileDigest $k137Hosts" in content
    assert "--k137-free-bytes" in content
    assert "STRICT_NO_GO" in content


@WINDOWS
def test_ps51_stage_intent_fails_before_remote_or_escrow(tmp_path):
    output = run_ps(tmp_path, """
$valid = 'aa' * 16
Assert-R1066StageIntent $false '' ''
Assert-R1066StageIntent $true '/private/immutable-sealed' $valid
foreach ($case in @(
    @($false,'/private/immutable-sealed',$valid),
    @($true,'/var/lib/technocore-safe-agent',$valid),
    @($true,'/private/../live',$valid),
    @($true,'/private/immutable-sealed','abc'),
    @($true,'/private//sealed',$valid),
    @($true,'/private/immutable-sealed;whoami',$valid)
)) {
    $rejected = $false
    try { Assert-R1066StageIntent ([bool]$case[0]) ([string]$case[1]) ([string]$case[2]) }
    catch { $rejected = $true }
    Need $rejected
}
function Read-R1027Backup { throw 'MUST_NOT_READ' }
function Invoke-R1066Ssh { throw 'MUST_NOT_CONNECT' }
$r=Invoke-R1066Workflow '' '' $true '/private/../live' $valid
Need ($r.operation -ceq 'blocked')
Need ($r.code -ceq 'ARCHIVE_SCOPE_STOP')
Write-Output 'PASS'
""")
    assert output.strip() == "PASS"


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1 only")
def test_r1072_owner_ps51_parses_and_refuses_extra_arguments():
    owner = ROOT / "packaging/migration/r1072_oci_owner_capacity_readonly.ps1"
    windows_path = str(owner).replace("'", "''")
    command = (
        "$t=$null;$e=$null;"
        "[void][System.Management.Automation.Language.Parser]::ParseFile('"
        + windows_path
        + "',[ref]$t,[ref]$e);"
        "if($e.Count -ne 0){exit 42}else{exit 0}"
    )
    parsed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, timeout=30)
    assert parsed.returncode == 0, parsed.stderr.decode(errors="replace")
    stopped = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
         str(owner), "extra-argument"], capture_output=True, timeout=30)
    assert stopped.returncode == 0
    assert b"ARGS_STOP" in stopped.stdout


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1 only")
def test_r1072_owner_public_bootstrap_parses_on_windows():
    bootstrap = ROOT / "packaging/windows/r1072_owner_public_bootstrap.ps1"
    path = str(bootstrap).replace("'", "''")
    program = (
        "$t=$null;$e=$null;"
        "[void][System.Management.Automation.Language.Parser]::ParseFile('"
        + path
        + "',[ref]$t,[ref]$e);"
        "if($e.Count -ne 0){exit 42}else{exit 0}"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive",
         "-Command", program], capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr.decode(errors="replace")


@WINDOWS
def test_r1072_ps51_accepts_actual_valid_metadata_receipt_and_rejects_cutover(tmp_path):
    controller = ROOT / "packaging/migration/r1072_oci_owner_capacity_readonly.ps1"
    receipt = {
        "phase": "R1072_ORIGINAL_READONLY_CAPACITY",
        "result": "INVENTORY_ONLY", "original_git": "MATCH",
        "tree": {"entries": 3020, "regular": 2901, "directories": 99,
                 "symlinks": 19, "hardlink_repeated": 1,
                 "special_objects": 4, "regular_bytes": 20900000000,
                 "sqlite_bases": 2, "sqlite_wals": 2, "sqlite_shms": 0},
        "free_bytes": 4000000000,
        "writer_admission": "NOT_PROVEN",
        "common_sqlite_epoch": "NOT_PROVEN",
        "original_archive": "NOT_CREATED",
        "offhost_backup": "NOT_CREATED",
        "k137_restore": "NOT_PERFORMED",
        "cutover": "NO_GO",
        "oci_retirement": "STRICT_NO_GO",
    }
    good = tmp_path / "r1072_good.json"
    good.write_text(json.dumps(receipt, sort_keys=True), encoding="ascii")
    bad = tmp_path / "r1072_bad.json"
    bad.write_text(json.dumps(dict(receipt, cutover="GO"), sort_keys=True),
                   encoding="ascii")
    validator = tmp_path / "r1072_windows_validate.ps1"
    validator.write_text(
        "$ErrorActionPreference='Stop'\n"
        "$tokens=$null; $errors=$null\n"
        "$ast=[Management.Automation.Language.Parser]::ParseFile('"
        + str(controller).replace("'", "''")
        + "',[ref]$tokens,[ref]$errors)\n"
        "if($errors.Count -ne 0){exit 40}\n"
        "$func=@($ast.FindAll({param($n) "
        "$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)"
        "|Where-Object {$_.Name -eq 'Check-R1072Result'})\n"
        "if($func.Count -ne 1){exit 41}\n"
        "Invoke-Expression $func[0].Extent.Text\n"
        "$raw=[Text.Encoding]::ASCII.GetBytes([IO.File]::ReadAllText('"
        + str(good).replace("'", "''") + "'))\n"
        "$ok=Check-R1072Result $raw\n"
        "if(($ok|ConvertFrom-Json).result -ne 'INVENTORY_ONLY'){exit 42}\n"
        "$raw=[Text.Encoding]::ASCII.GetBytes([IO.File]::ReadAllText('"
        + str(bad).replace("'", "''") + "'))\n"
        "try {$null=Check-R1072Result $raw;exit 43}\n"
        "catch {Write-Output 'R1072_VALID_RECEIPT_ACCEPTED_AND_BAD_CUTOVER_DENIED';exit 0}\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive",
         "-File", str(validator)],
        capture_output=True, timeout=35)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert b"R1072_VALID_RECEIPT_ACCEPTED_AND_BAD_CUTOVER_DENIED" in result.stdout


@WINDOWS
def test_r1072_ps51_ssh_nonzero_is_classified_without_raw_output(tmp_path):
    controller=ROOT / "packaging/migration/r1072_oci_owner_capacity_readonly.ps1"
    path=str(controller).replace("'","''")
    script=tmp_path/"r1072_ssh_exit_classes.ps1"
    script.write_text(
        "$ErrorActionPreference='Stop';$ts=$null;$errs=$null\n"
        "$ast=[Management.Automation.Language.Parser]::ParseFile('"
        + path + "',[ref]$ts,[ref]$errs)\n"
        "if($errs.Count -ne 0){exit 40}\n"
        "$f=@($ast.FindAll({param($n) "
        "$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)"
        "|Where-Object {$_.Name -eq 'Get-R1072RemoteStop'})\n"
        "if($f.Count -ne 1){exit 41}\n"
        "Invoke-Expression $f[0].Extent.Text\n"
        "$unknown=[Text.Encoding]::ASCII.GetBytes('cannot-connect')\n"
        "$a=Get-R1072RemoteStop 255 $unknown\n"
        "if($a -cne 'SSH_AUTH_ROUTE_OR_PIN_STOP'){exit 42}\n"
        "$b=Get-R1072RemoteStop 127 $unknown\n"
        "if($b -cne 'REMOTE_EXEC_STOP'){exit 43}\n"
        "$c=Get-R1072RemoteStop 42 $unknown\n"
        "if($c -cne 'REMOTE_UNRECOGNIZED_STOP'){exit 44}\n"
        "$safe='{\"phase\":\"R1072_ORIGINAL_READONLY_CAPACITY\","
        "\"result\":\"STOP\",\"code\":\"ORIGINAL_HEAD_STOP\","
        "\"cutover\":\"NO_GO\",\"oci_retirement\":\"STRICT_NO_GO\"}'\n"
        "$d=Get-R1072RemoteStop 42 ([Text.Encoding]::ASCII.GetBytes($safe))\n"
        "if($d -cne 'GUEST_ORIGINAL_HEAD_STOP'){exit 45}\n"
        "$bad=$safe.Replace('NO_GO','GO')\n"
        "$e=Get-R1072RemoteStop 42 ([Text.Encoding]::ASCII.GetBytes($bad))\n"
        "if($e -cne 'REMOTE_UNRECOGNIZED_STOP'){exit 46}\n"
        "Write-Output 'R1072_REDACTED_SSH_EXIT_CLASSES=PASS'\n",
        encoding="utf-8")
    out=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive",
                        "-File",str(script)],capture_output=True,timeout=30)
    assert out.returncode==0,(out.stdout,out.stderr)
    assert b"R1072_REDACTED_SSH_EXIT_CLASSES=PASS" in out.stdout
