"""R1027 synthetic escrow/PowerShell tests. Never accesses an actual backup or Oracle."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging/windows/r1027_oci_escrow_v2_direct_readonly.ps1"
GUEST = ROOT / "packaging/oracle/r1023_unit_identity_readonly.py"
PS = shutil.which("powershell.exe") if os.name == "nt" else None
WINDOWS = pytest.mark.skipif(not PS, reason="Windows PowerShell 5.1 runtime required")
EXPECTED_SHA256 = "8dae15bf339e54ece1a23b7c78fdcb43a5adb0534b01064fe44d5713c9d96301"
BLOB = "937039a7c136b409f46573abcc1982ba5023ae66"


def literal(path):
    return "'" + str(path).replace("'", "''") + "'"


def ps_run(tmp_path, body, *, initialize=True):
    harness = tmp_path / "synthetic-test.ps1"
    prefix = r"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'POWERSHELL_PARSE_FAILED' }
foreach ($node in $ast.EndBlock.Statements) {
    if ($node -is [Management.Automation.Language.FunctionDefinitionAst]) {
        Invoke-Expression $node.Extent.Text
    }
}
function New-SyntheticCode([string]$Value) {
    $result = New-Object Security.SecureString
    foreach ($letter in $Value.ToCharArray()) { $result.AppendChar($letter) }
    $result.MakeReadOnly()
    return $result
}
"""
    prefix = prefix.replace("SCRIPT,", literal(SCRIPT) + ",")
    if initialize:
        prefix += "\nInitialize-R1027\n"
    harness.write_text(prefix + body, encoding="utf-8-sig")
    result = subprocess.run(
        [PS, "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True, timeout=100, check=False,
    )
    assert result.returncode == 0, (result.stdout + result.stderr).decode(errors="replace")[-4000:]
    return result.stdout.decode("utf-8", errors="replace")


def public_report():
    spec = importlib.util.spec_from_file_location("r1023_synthetic", GUEST)
    guest = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guest)
    installed = guest.metadata_names(guest.PREFIX + "signer.service enabled\n")
    live = guest.metadata_names(guest.PREFIX + "signer.service loaded active running\n", live=True)
    return guest.analyze_units(installed, live)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def encrypted_fixture(salt_size, password=b"synthetic-recovery-only"):
    plain = b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.b64encode(os.urandom(96)) + b"\n-----END OPENSSH PRIVATE KEY-----\n"
    salt = os.urandom(salt_size)
    material = PBKDF2HMAC(algorithm=hashes.SHA256(), length=48, salt=salt, iterations=600000).derive(password)
    pad = padding.PKCS7(128).padder()
    padded = pad.update(plain) + pad.finalize()
    encryptor = Cipher(algorithms.AES(material[:32]), modes.CBC(material[32:])).encryptor()
    return b"Salted__" + salt + encryptor.update(padded) + encryptor.finalize(), plain


def test_fixed_source_and_narrow_scope_static():
    raw = SCRIPT.read_bytes()
    raw.decode("ascii")  # No BOM/non-ASCII ambiguity in Windows PowerShell 5.1.
    text = raw.decode("ascii")
    assert EXPECTED_SHA256 in text
    assert "1983c9893f05a7b7769d04ba5c5d321428c7ea3d" in text and BLOB in text
    guest = GUEST.read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha1(b"blob " + str(len(guest)).encode() + b"\0" + guest).hexdigest() == BLOB
    for forbidden in ("openssl.exe", "ssh-keygen", "SIGN_SEED", "Start-Transcript",
                      "Get-ChildItem", "Invoke-WebRequest", "AcceptNew", "StrictHostKeyChecking=no",
                      "systemctl stop", "systemctl restart", "sqlite3", "vault",
                      "Write-Error", "$_.Exception", "ConvertFrom-SecureString"):
        assert forbidden not in text
    assert "Read-Host 'R987 V2 recovery code' -AsSecureString" in text
    assert "ZeroFreeGlobalAllocUnicode" in text and "Array.Clear(chars" in text
    assert "ALL_WRITERS_FENCED=NO" in text and "OCI_RETIREMENT=STRICT_NO_GO" in text
    assert "UseShellExecute = false" in text
    assert "ConnectionAttempts=1" in text
    assert "AllowAutoRedirect = $false" in text
    assert text.index("Sha256($encrypted)") < text.index("Read-Host 'R987 V2")
    assert text.index("Remove-R1027Custody $directory") < text.index("[Console]::WriteLine($summary)")


@WINDOWS
def test_ps51_parse_and_source_pin_rejection(tmp_path):
    guest = tmp_path / "public-source.py"
    guest.write_bytes(GUEST.read_bytes().replace(b"\r\n", b"\n"))
    output = ps_run(tmp_path, rf"""
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {{ throw 'EXPECTED_PS51' }}
[FlopR1027.Guards]::VerifySource([IO.File]::ReadAllBytes({literal(guest)}))
$failed = $false
try {{ [FlopR1027.Guards]::VerifySource([Text.Encoding]::ASCII.GetBytes('tampered')) }} catch {{ $failed = $true }}
if (-not $failed) {{ throw 'UNPINNED_SOURCE_ACCEPTED' }}
[Console]::WriteLine('PIN=PASS')
""")
    assert output.strip() == "PIN=PASS"


@WINDOWS
@pytest.mark.parametrize("salt_size", [8, 16])
def test_openssl_pbkdf2_aes_compatibility_synthetic(tmp_path, salt_size):
    encrypted, plain = encrypted_fixture(salt_size)
    fixture = tmp_path / "synthetic.enc"
    fixture.write_bytes(encrypted)
    output = ps_run(tmp_path, rf"""
$data = [IO.File]::ReadAllBytes({literal(fixture)})
$code = New-SyntheticCode 'synthetic-recovery-only'
try {{
    $plain = [FlopR1027.Guards]::Decrypt($data, '{hashlib.sha256(encrypted).hexdigest()}', $code)
    if ([FlopR1027.Guards]::Sha256($plain) -cne '{hashlib.sha256(plain).hexdigest()}') {{ throw 'DECRYPT_MISMATCH' }}
    [Console]::WriteLine('CRYPTO=PASS')
}} finally {{
    $code.Dispose()
    [FlopR1027.Guards]::Clear($plain)
    [FlopR1027.Guards]::Clear($data)
}}
""")
    assert output.strip() == "CRYPTO=PASS"
    assert "synthetic-recovery-only" not in output


@WINDOWS
def test_wrong_hash_before_password_and_wrong_recovery_code_stop(tmp_path):
    encrypted, _ = encrypted_fixture(8)
    fixture = tmp_path / "synthetic.enc"
    fixture.write_bytes(encrypted)
    output = ps_run(tmp_path, rf"""
$data = [IO.File]::ReadAllBytes({literal(fixture)})
$rejected = 0
try {{ [FlopR1027.Guards]::Decrypt($data, ('0' * 64), $null) }} catch {{ $rejected++ }}
$code = New-SyntheticCode 'wrong-synthetic-code'
try {{
    try {{ [FlopR1027.Guards]::Decrypt($data, '{hashlib.sha256(encrypted).hexdigest()}', $code) }} catch {{ $rejected++ }}
}} finally {{ $code.Dispose() }}
if ($rejected -ne 2) {{ throw 'FAIL_CLOSE_MISSING' }}
[Console]::WriteLine('REJECTED=2')
""")
    assert output.strip() == "REJECTED=2"


@WINDOWS
def test_private_temp_acl_and_cleanup(tmp_path):
    directory = tmp_path / "custody"
    output = ps_run(tmp_path, rf"""
$directory = {literal(directory)}
New-R1027Custody $directory
$key = Write-R1027Key $directory ([Text.Encoding]::ASCII.GetBytes('synthetic-not-a-key'))
Assert-R1027Acl $directory
Assert-R1027Acl $key
$acl = [IO.Directory]::GetAccessControl($directory)
if (-not $acl.AreAccessRulesProtected) {{ throw 'INHERITED_DIRECTORY_ACL' }}
Remove-R1027Custody $directory
if ([IO.Directory]::Exists($directory)) {{ throw 'CLEANUP_MISSING' }}
[Console]::WriteLine('ACL_CLEANUP=PASS')
""")
    assert output.strip() == "ACL_CLEANUP=PASS"
    assert not directory.exists()


@WINDOWS
def test_strict_ssh_argv_and_quoting(tmp_path):
    # Synthetic paths exercise spaces/backslashes without reading a user SSH file.
    key = str(tmp_path / "space directory" / "synthetic")
    hosts = str(tmp_path / "space hosts")
    output = ps_run(tmp_path, rf"""
$argsList = Get-R1027SshArguments {literal(key)} {literal(hosts)}
if ($argsList[-1] -cne 'sudo -n /usr/bin/python3 -') {{ throw 'REMOTE_COMMAND' }}
if ($argsList[-2] -cne 'ubuntu@140.238.55.171') {{ throw 'HOST' }}
$expectedHosts = 'UserKnownHostsFile="' + {literal(hosts)}.Replace('\', '/') + '"'
if ($argsList -cnotcontains $expectedHosts) {{ throw 'HOSTS_PATH_QUOTING' }}
foreach ($required in @('NUL','StrictHostKeyChecking=yes','HostKeyAlgorithms=ecdsa-sha2-nistp256',
    'PasswordAuthentication=no','KbdInteractiveAuthentication=no','BatchMode=yes',
    'PreferredAuthentications=publickey','HostbasedAuthentication=no','GSSAPIAuthentication=no','UpdateHostKeys=no',
    'IdentitiesOnly=yes','IdentityAgent=none','ClearAllForwardings=yes','ProxyCommand=none',
    'ProxyJump=none','KnownHostsCommand=none','PermitLocalCommand=no','GlobalKnownHostsFile=NUL')) {{
    if ($argsList -cnotcontains $required) {{ throw 'SSH_OPTION_MISSING' }}
}}
$argument = 'space path\"quoted\\'
$probe = Join-Path {literal(tmp_path)} 'argv-probe.ps1'
[IO.File]::WriteAllText($probe, 'param([string]$Value) if ($Value -cne ''space path\"quoted\\'') {{ exit 7 }}; exit 0')
$result = [FlopR1027.Guards]::Run((Get-Process -Id $PID).Path,
    @('-NoProfile','-NonInteractive','-File',$probe,$argument), [byte[]]@(), 10000, 1024)
if ($result.ExitCode -ne 0) {{ throw 'ARGUMENT_QUOTING' }}
[Console]::WriteLine('ARGV=PASS')
""")
    assert output.strip() == "ARGV=PASS"


@WINDOWS
def test_bounded_runner_stderr_failure_timeout_and_output_limit(tmp_path):
    output = ps_run(tmp_path, r"""
$exe = (Get-Process -Id $PID).Path
$source = [Text.Encoding]::ASCII.GetBytes('public-guest-source')
$success = [FlopR1027.Guards]::Run($exe, @('-NoProfile','-NonInteractive','-Command',
    '[Console]::In.ReadToEnd() | Out-Null; [Console]::Error.WriteLine("synthetic-private-stderr"); [Console]::Out.Write("ok"); exit 0'), $source, 10000, 1024)
if ($success.ExitCode -ne 0 -or [Text.Encoding]::ASCII.GetString($success.Output) -cne 'ok') { throw 'RUNNER' }
$failure = [FlopR1027.Guards]::Run($exe, @('-NoProfile','-NonInteractive','-Command',
    '[Console]::In.ReadToEnd() | Out-Null; exit 255'), $source, 10000, 1024)
if ($failure.ExitCode -ne 255) { throw 'EXIT_CODE' }
$rejected = 0
try { [FlopR1027.Guards]::Run($exe, @('-NoProfile','-NonInteractive','-Command',
    'Start-Sleep -Seconds 30'), $source, 100, 1024) } catch { $rejected++ }
try { [FlopR1027.Guards]::Run($exe, @('-NoProfile','-NonInteractive','-Command',
    '[Console]::In.ReadToEnd() | Out-Null; [Console]::Out.Write(("x"*8192))'), $source, 10000, 1024) } catch { $rejected++ }
if ($rejected -ne 2) { throw 'BOUNDS' }
[Console]::WriteLine('RUNNER=PASS')
""")
    assert output.strip() == "RUNNER=PASS"
    assert "synthetic-private-stderr" not in output


@WINDOWS
def test_strict_json_schema_forgery_and_no_raw_output(tmp_path):
    values = [public_report()]
    for field, bad in [("flags", {}), ("original_head", "wrong"), ("unexpected", "synthetic-secret")]:
        item = public_report()
        item[field] = bad
        values.append(item)
    for field, bad in [("identity", "unsafe@synthetic-secret.service"), ("active_states", ["bad"]),
                       ("known", False), ("signer_candidate", False)]:
        item = public_report()
        item["units"][0][field] = bad
        values.append(item)
    item = public_report()
    item["units"].append(dict(item["units"][0]))
    values.append(item)
    raws = [encoded(value) for value in values] + [b"not-json\n", b"x" * 65537,
                                                   encoded(public_report()).replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1')]
    fixtures = []
    for index, raw in enumerate(raws):
        fixture = tmp_path / f"report-{index}.json"
        fixture.write_bytes(raw)
        fixtures.append(literal(fixture))
    output = ps_run(tmp_path, """
$paths = @(""" + ",".join(fixtures) + """)
$accepted = 0; $rejected = 0
for ($i = 0; $i -lt $paths.Count; $i++) {
    try {
        $safe = [FlopR1027.Guards]::ValidateReport([IO.File]::ReadAllBytes($paths[$i]))
        if ($i -ne 0 -or -not $safe.Contains('STRICT_NO_GO')) { throw 'BAD_ACCEPT' }
        $accepted++
    } catch { $rejected++ }
}
if ($accepted -ne 1 -or $rejected -ne ($paths.Count-1)) { throw 'SCHEMA_GUARD' }
[Console]::WriteLine('JSON=PASS')
""")
    assert output.strip() == "JSON=PASS"
    assert "synthetic-secret" not in output


@WINDOWS
@pytest.mark.parametrize("scenario,expected", [
    ("success", "READONLY=PASS"), ("ssh-failure", "STOP=SSH_TRANSPORT_OR_AUTH_STOP"),
    ("timeout", "STOP=SSH_INVOKE_STOP"), ("invalid-report", "STOP=RESPONSE_STOP"),
    ("guest-stage", "STOP=GUEST_READONLY_HEAD_EXIT_STOP"),
    ("guest-identity", "STOP=GUEST_ORIGINAL_HEAD_MISMATCH_STOP"),
    ("guest-forgery", "STOP=GUEST_UNRECOGNIZED_STOP"),
    ("remote-nonstandard", "STOP=SSH_REMOTE_EXIT_STOP"),
    ("cleanup-failure", "STOP=CLEANUP_STOP"), ("decrypt-failure", "STOP=DECRYPT_STOP"),
    ("hash-failure", "STOP=BACKUP_HASH_STOP"),
])
def test_one_shot_finally_cleanup_and_safe_status(tmp_path, scenario, expected):
    fixture = tmp_path / "public-report.json"
    fixture.write_bytes(encoded(public_report()))
    output = ps_run(tmp_path, rf"""
$script:created = $null
$script:calls = 0
$script:recovery = $null
$script:plain = [Text.Encoding]::ASCII.GetBytes('synthetic-not-a-key')
function Get-R1027Prerequisites {{ return @{{ Ssh='mock-never-executed'; Hosts='mock-existing-known-hosts' }} }}
function Read-R1027Backup {{
    if ('{scenario}' -eq 'hash-failure') {{ throw 'synthetic-secret-error' }}
    return ,([byte[]]@(1,2,3))
}}
function Get-R1027Source {{ return ,([Text.Encoding]::ASCII.GetBytes('mock-public-source')) }}
function Read-Host {{
    param($Prompt, [switch]$AsSecureString)
    if (-not $AsSecureString) {{ throw 'VISIBLE_PROMPT' }}
    $script:recovery = New-SyntheticCode 'synthetic-recovery-only'
    return $script:recovery
}}
function Unprotect-R1027 {{
    param($Encrypted, $Code)
    if ('{scenario}' -eq 'decrypt-failure') {{ throw 'synthetic-secret-error' }}
    return ,$script:plain
}}
$originalNew = ${{function:New-R1027Custody}}
$originalRemove = ${{function:Remove-R1027Custody}}
function New-R1027Custody {{
    param($Directory)
    $script:created = $Directory
    & $originalNew $Directory
}}
function Invoke-R1027Ssh {{
    param($Ssh, $Arguments, $Source)
    $script:calls++
    if ($Arguments[-1] -cne 'sudo -n /usr/bin/python3 -') {{ throw 'REMOTE_COMMAND' }}
    if ('{scenario}' -eq 'timeout') {{ throw 'synthetic-private-stderr' }}
    if ('{scenario}' -eq 'invalid-report') {{ return @{{ ExitCode=0; Output=[Text.Encoding]::ASCII.GetBytes('synthetic-secret') }} }}
    if ('{scenario}' -eq 'guest-stage') {{ return @{{ ExitCode=42; Output=[Text.Encoding]::ASCII.GetBytes("FLOP_R1023_STOP=READONLY_HEAD_EXIT_STOP`n") }} }}
    if ('{scenario}' -eq 'guest-identity') {{ return @{{ ExitCode=42; Output=[Text.Encoding]::ASCII.GetBytes("FLOP_R1023_STOP=ORIGINAL_HEAD_MISMATCH_STOP`n") }} }}
    if ('{scenario}' -eq 'guest-forgery') {{ return @{{ ExitCode=42; Output=[Text.Encoding]::ASCII.GetBytes("FLOP_R1023_STOP=SYNTHETIC_PRIVATE_INFORMATION`n") }} }}
    return @{{ ExitCode=$(if ('{scenario}' -eq 'ssh-failure') {{255}} elseif ('{scenario}' -eq 'remote-nonstandard') {{17}} else {{0}});
              Output=[IO.File]::ReadAllBytes({literal(fixture)}) }}
}}
function Remove-R1027Custody {{
    param($Directory)
    if ('{scenario}' -eq 'cleanup-failure') {{ throw 'synthetic-secret-error' }}
    & $originalRemove $Directory
}}
try {{
    Invoke-R1027
    if ($script:calls -gt 1) {{ throw 'RETRY' }}
    if ($script:created -and '{scenario}' -ne 'cleanup-failure' -and [IO.Directory]::Exists($script:created)) {{ throw 'KEY_REMAINS' }}
    if ($script:recovery) {{
        $disposed = $false
        try {{ $copy = $script:recovery.Copy(); $copy.Dispose() }} catch {{ $disposed = $true }}
        if (-not $disposed) {{ throw 'CODE_RETAINED' }}
    }}
    if ($script:created -and @($script:plain | Where-Object {{ $_ -ne 0 }}).Count -ne 0) {{ throw 'PLAINTEXT_RETAINED' }}
}} finally {{
    if ($script:created -and [IO.Directory]::Exists($script:created)) {{ & $originalRemove $script:created }}
}}
""")
    assert "FLOP_R1027_" + expected in output
    assert "synthetic-" not in output
    if scenario != "success":
        assert "PASS" not in output


@WINDOWS
def test_backup_hash_and_size_stop_without_secret_prompt(tmp_path):
    wrong = tmp_path / "wrong-synthetic.enc"
    oversized = tmp_path / "oversized-synthetic.enc"
    wrong.write_bytes(b"Salted__" + b"x" * 24)
    oversized.write_bytes(b"x" * 65537)
    output = ps_run(tmp_path, rf"""
$script:fixture = {literal(wrong)}
function Find-R1027Backup {{ return $script:fixture }}
$rejected = 0
try {{ Read-R1027Backup }} catch {{ $rejected++ }}
$script:fixture = {literal(oversized)}
try {{ Read-R1027Backup }} catch {{ $rejected++ }}
if ($rejected -ne 2) {{ throw 'BACKUP_REJECTION' }}
[Console]::WriteLine('BACKUP_GUARDS=PASS')
""")
    assert output.strip() == "BACKUP_GUARDS=PASS"


def writer_route_report():
    names = (
        "technocore-safe-agent-close1-discord-activation.service",
        "technocore-safe-agent-close1-discord-activation.timer",
        "technocore-safe-agent-close1-standalone-watch.timer",
        "technocore-safe-agent-postreboot-check.service",
    )
    units = [
        dict(identity=name, active="inactive", installed="disabled",
             load="loaded", command_kind="FLOP_PYTHON", fragment_origin="ETC_SYSTEMD")
        for name in names
    ]
    return dict(
        schema_version=2, original_head="ec4bc4892d40cdd2a03e102faa44d72c89e01b99",
        units=units,
        cron=dict(cron_regular_files_read=2, cron_flop_matching_lines=1,
                  cron_unverified_entries=0, cron_scan_complete=False),
        processes=dict(matching_processes=5, cgroup_inspected_candidates=5,
                       unknown_or_raced_processes=1, process_scan_complete=False),
        flags=dict(original_source_pin="PASS", no_service_or_state_modification="YES",
                   process_and_cron_discovery_complete="NO", all_writers_fenced="NO",
                   signer_inflight_post_resolved="NO", capture_common_epoch_proven="NO",
                   oci_retirement="STRICT_NO_GO"),
    )


@WINDOWS
def test_r1036_pin_and_schema_reject_forgery(tmp_path):
    route = ROOT / "packaging/oracle/r1036_writer_routes_readonly.py"
    raw = route.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    assert blob == "759090ef4f38b11464602fabb3a79e2286a4a782"
    fixture = tmp_path / "route-public.json"
    fixture.write_bytes(encoded(writer_route_report()))
    forged = writer_route_report()
    forged["units"][0]["command_kind"] = "PRIVATE_UNTRUSTED_COMMAND"
    bad = tmp_path / "route-bad.json"
    bad.write_bytes(encoded(forged))
    output = ps_run(tmp_path, rf"""
[FlopR1027.Guards]::VerifySource([IO.File]::ReadAllBytes({literal(route)}),
    [FlopR1027.Guards]::GuestRouteBlob)
$valid = [FlopR1027.Guards]::ValidateRoutes([IO.File]::ReadAllBytes({literal(fixture)}))
if (-not $valid.Contains('STRICT_NO_GO')) {{ throw 'ROUTE_REJECT' }}
$rejected = $false
try {{
    [FlopR1027.Guards]::ValidateRoutes([IO.File]::ReadAllBytes({literal(bad)}) | Out-Null
}} catch {{ $rejected = $true }}
if (-not $rejected) {{ throw 'ROUTE_FORGERY' }}
[Console]::WriteLine('R1036_JSON=PASS')
""")
    assert output.strip() == "R1036_JSON=PASS"


@WINDOWS
@pytest.mark.parametrize(("exit_code", "expect"), [
    (0, "FLOP_R1036_READONLY=PASS"),
    (42, "FLOP_R1027_STOP=GUEST_ROUTE_GUARD_STOP"),
    (255, "FLOP_R1027_STOP=SSH_TRANSPORT_OR_AUTH_STOP"),
])
def test_r1036_one_shot_mode_and_no_raw_error(tmp_path, exit_code, expect):
    fixture = tmp_path / "route-public.json"
    fixture.write_bytes(encoded(writer_route_report()))
    output = ps_run(tmp_path, rf"""
$script:calls = 0
$script:clean = 0
function Get-R1027Prerequisites {{ return @{{ Ssh='MOCK'; Hosts='MOCK' }} }}
function Read-R1027Backup {{ return ,([byte[]]@(1,2,3)) }}
function Get-R1027Source {{ param([bool]$RouteProbe)
    if (-not $RouteProbe) {{ throw 'WRONG_ROUTE_MODE' }}
    return ,([Text.Encoding]::ASCII.GetBytes('mock-guest')) }}
function Read-Host {{ param($Prompt, [switch]$AsSecureString)
    if (-not $AsSecureString) {{ throw 'VISIBLE_PROMPT' }}
    return New-SyntheticCode 'mock-only' }}
function Unprotect-R1027 {{ param($Encrypted, $Code)
    return ,([Text.Encoding]::ASCII.GetBytes('mock-key')) }}
function New-R1027Custody {{ param($Directory) }}
function Write-R1027Key {{ param($Directory, $Bytes) return 'MOCK-KEY' }}
function Get-R1027SshArguments {{ param($Key, $Hosts)
    return @('MOCK-TRANSPORT', 'sudo -n /usr/bin/python3 -') }}
function Invoke-R1027Ssh {{ param($Ssh, $Arguments, $Source)
    $script:calls++
    if ($Arguments[-1] -cne 'sudo -n /usr/bin/python3 -') {{ throw 'ARGUMENT_FAIL' }}
    return @{{ ExitCode={exit_code}; Output=$(if ({exit_code} -eq 0) {{
        [IO.File]::ReadAllBytes({literal(fixture)})
    }} else {{ [Text.Encoding]::ASCII.GetBytes('SENSITIVE_BAD_ERROR') }}) }} }}
function Remove-R1027Custody {{ param($Directory) $script:clean++ }}
Invoke-R1027 $true
if ($script:calls -ne 1 -or $script:clean -ne 1) {{ throw 'CALL_COUNT_OR_CLEANUP' }}
""")
    assert expect in output
    assert "SENSITIVE_BAD_ERROR" not in output
    if exit_code == 0:
        assert "FLOP_R1036_ALL_WRITERS_FENCED=NO" in output
