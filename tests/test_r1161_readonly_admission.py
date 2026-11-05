"""Offline synthetic-only R1161 tests, including native Windows PS5.1.

Never run an owner entrypoint with real paths, selectors, or SSH.
"""
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
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import test_r1159_m2_bootstrap as prior

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "packaging/migration/r1161_readonly_admission.py"
PS = ROOT / "packaging/windows/r1161_k137_first_readonly.ps1"
sp = importlib.util.spec_from_file_location("r1161_test", PATH)
m = importlib.util.module_from_spec(sp)
sp.loader.exec_module(m)
WINDOWS = pytest.mark.skipif(os.name != "nt", reason="native Windows PS5.1")
fixture = prior.fixture
guest = prior.guest


@pytest.fixture
def setup(fixture):
    v = fixture.control["reports"]["k137"]
    p = dict(version=1, challenge=v["challenge"], expires_at=fixture.now + 180,
             k137_boot_sha256=v["boot_runtime_sha256"], k137_scope_sha256=v["cgroup"]["raw_sha256"],
             tradebot_cgroup_sha256=v["tradebot"]["cgroup_sha256"], consent="READ_ONLY_R1161_NO_M2_NO_HOLD")
    return SimpleNamespace(plan=p, raw=m.canonical(v), now=fixture.now, old=prior.m)


def test_frozen_commit_tree_and_local_source_integrity(monkeypatch):
    old = m.dependencies()
    assert old.K137_KEY == prior.m.K137_KEY
    read = m.source
    monkeypatch.setattr(m, "source", lambda p: read(p) + b"\n" if p.endswith("r1159_m2_bootstrap.py") else read(p))
    with pytest.raises(ValueError, match="SOURCE_PIN_STOP"):
        m.dependencies()


def test_k137_receipt_tamper_evidence_no_machine_user_plaintext(setup):
    r = m.receipt(setup.old, setup.plan, setup.raw, setup.now)
    assert r["sha256"] == m.sha(m.canonical(r["body"]))
    assert r["body"]["expires_at"] == setup.now + 180
    assert r["body"]["code"] == "K137_BOUND_READONLY_ADMISSION_PASS"
    raw = m.canonical(r)
    for forbidden in (b"machine_sha256", b"boot_raw_sha256", b"ubuntu", b"52.198", b"identity_file"):
        assert forbidden not in raw
    changed = copy.deepcopy(r); changed["body"]["m2"] = "GO"
    assert m.sha(m.canonical(changed["body"])) != r["sha256"]


@pytest.mark.parametrize("fault", ["memory", "pids", "cpu", "machine", "boot", "scope", "head", "tradebot", "clock", "ttl", "challenge", "pin", "duplicate"])
def test_no_k137_admission_on_differing_or_unbounded_evidence(setup, fault):
    v = json.loads(setup.raw); p = setup.plan
    if fault == "memory": v["cgroup"]["memory_max"] = None
    if fault == "pids": v["cgroup"]["pids_max"] = 65
    if fault == "cpu": v["cgroup"]["cpu_quota"] = v["cgroup"]["cpu_period"] + 1
    if fault == "machine": v["machine_sha256"] = m.sha(b"changed")
    if fault == "boot": v["boot_runtime_sha256"] = m.sha(b"changed")
    if fault == "scope": v["cgroup"]["raw_sha256"] = m.sha(b"changed")
    if fault == "head": v["head"] = "f" * 40
    if fault == "tradebot": v["tradebot"]["memory_max"] += 1
    if fault == "clock": v["observed_at"] -= 181
    if fault == "ttl": p = dict(p, expires_at=setup.now)
    if fault == "challenge": p = dict(p, challenge=m.sha(b"different independent challenge"))
    if fault == "pin": v["source_blobs"]["bootstrap"] = "f" * 40
    raw = m.canonical(v)
    if fault == "duplicate": raw = raw[:-1] + b',"uid":1000}'
    with pytest.raises(ValueError): m.receipt(setup.old, p, raw, setup.now)


def test_independent_trust_cannot_be_created_by_url_or_user_digest(setup):
    for value in ({}, {"reference": "https://github.com/hanamaru777/technocore-safe-agent/issues/949#issuecomment-1"},
                  {"oracle_key_sha256": m.ORIGINAL_ECDSA_SHA256}):
        with pytest.raises(ValueError, match="ORIGINAL_ED25519_INDEPENDENT_TRUST_REQUIRED"):
            m.authorize_original(setup.old, m.canonical(value))
    with pytest.raises(ValueError, match="INDEPENDENT_TRUST_REQUIRED"): m.oracle_guest("a" * 64)


@pytest.fixture
def anchor(monkeypatch, setup):
    key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    ecdsa = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    monkeypatch.setattr(m, "ORIGINAL_ED25519_SHA256", setup.old.host_key(key, "ssh-ed25519"))
    monkeypatch.setattr(m, "ORIGINAL_ECDSA_SHA256", setup.old.host_key(ecdsa, "ecdsa-sha2-nistp256"))
    value = dict(kind="PREVIOUSLY_AUTHENTICATED_ORIGINAL_GUEST_SSHD_ARCHIVE", known_hosts="140.238.55.171 " + key,
                 independent_archive_sha256=m.sha(b"separate authenticated synthetic guest archive"), reference="synthetic archive")
    raw = m.canonical(value)
    monkeypatch.setattr(m, "PINNED_ORIGINAL_EVIDENCE_SHA256", m.sha(raw))
    return SimpleNamespace(key=key, ecdsa=ecdsa, raw=raw, value=value)


@pytest.mark.parametrize("fault", ["key", "algorithm", "host", "hash", "alias", "injection", "duplicate", "october", "fake_digest", "serial_proxy"])
def test_strict_original_host_and_independent_evidence(anchor, setup, fault, monkeypatch):
    v = dict(anchor.value)
    line = v["known_hosts"]
    if fault == "key": line = line[:-4] + "AAAA"
    if fault == "algorithm": line = "140.238.55.171 " + anchor.ecdsa
    if fault == "host": line = line.replace("140.238.55.171", "oracle.example")
    if fault == "hash": line = "|1|AAAA|AAAA " + anchor.key
    if fault == "alias": line = line.replace("140.238.55.171", "140.238.55.171,alias")
    if fault == "injection": line += "\nProxyCommand=anything"
    if fault == "duplicate": line += "\n" + line
    if fault == "october": monkeypatch.setattr(m, "ORIGINAL_ED25519_SHA256", m.ORIGINAL_ECDSA_SHA256)
    if fault == "fake_digest": v["oracle_key_sha256"] = setup.old.host_key(anchor.key, "ssh-ed25519")
    if fault == "serial_proxy": v["kind"] = "OCI_SERIAL_CONSOLE_PROXY"
    v["known_hosts"] = line
    # Even a source-reviewed packet must meet fixed host and algorithm binding.
    if fault != "fake_digest": monkeypatch.setattr(m, "PINNED_ORIGINAL_EVIDENCE_SHA256", m.sha(m.canonical(v)))
    with pytest.raises(ValueError): m.authorize_original(setup.old, m.canonical(v))


def test_synthetic_original_crosscert_and_original_k137_binding(setup, anchor):
    assert m.authorize_original(setup.old, anchor.raw) == anchor.key
    report = dict(challenge=m.sha(b"R1161-original:" + setup.plan["challenge"].encode()), observed_at=setup.now,
                  public_key=anchor.ecdsa, public_path="/etc/ssh/ssh_host_ecdsa_key.pub", read_only=True)
    r = m.receipt(setup.old, setup.plan, setup.raw, setup.now, oraw=m.canonical(report), evidence=anchor.raw)
    assert r["body"]["code"] == "ORIGINAL_GUEST_ED25519_ECDSA_CROSSCERT_PASS"
    for k, value in (("challenge", "b" * 64), ("public_key", anchor.key), ("read_only", False), ("public_path", "/wrong")):
        with pytest.raises(ValueError):
            m.receipt(setup.old, setup.plan, setup.raw, setup.now, oraw=m.canonical(dict(report, **{k:value})), evidence=anchor.raw)


def test_guests_are_fixed_bounded_readonly_no_secret_or_writer_calls(setup, anchor):
    for code in (m.k137_guest(setup.old, "a" * 64), m.oracle_guest("b" * 64)):
        assert len(code) <= 16384
        tree = ast.parse(code)
        calls = {ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
        assert not calls.intersection({"os.system", "os.unlink", "os.rename", "os.mkdir", "os.chmod", "socket.socket"})
        for forbidden in (b"systemd-run", b"shell=True", b"sudo", b"approval.pem", b"ssh_host_ecdsa_key'", b"httpx", b"urlopen"):
            assert forbidden not in code
    assert b"os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK" in m.oracle_guest("a" * 64)
    with pytest.raises(ValueError): m.k137_guest(setup.old, "a" * 63 + ";")


@pytest.mark.parametrize("fault", ["none", "extra_pids", "machine_changed", "tradebot_changed", "same_scope", "late_scope_move"])
def test_added_guest_guard_runs_and_rejects_changed_identity_or_extra_processes(setup, fault):
    v = json.loads(setup.raw)
    scope = "/synthetic.scope"
    data = {"/etc/machine-id": b"synthetic-machine",
            "/proc/self/cgroup": ("0::" + scope + "\n").encode(),
            "/sys/fs/cgroup" + scope + "/cgroup.procs": b"1\n2\n"}
    v["machine_sha256"] = m.sha(data["/etc/machine-id"])
    v["cgroup"]["raw_sha256"] = m.sha(data["/proc/self/cgroup"])
    if fault == "extra_pids": data["/sys/fs/cgroup" + scope + "/cgroup.procs"] = b"1\n" * 65
    if fault == "machine_changed": data["/etc/machine-id"] = b"changed"
    if fault == "same_scope": v["tradebot"]["cgroup_sha256"] = m.sha(scope.encode())
    if fault == "late_scope_move": v["cgroup"]["raw_sha256"] = m.sha(b"previous scope")
    def trade(_):
        return dict(v["tradebot"], memory_max=1) if fault == "tradebot_changed" else v["tradebot"]
    R = SimpleNamespace(read_small=lambda path, *args: data[path])
    ns = dict(probe=lambda *_: v, need=setup.old.need, sha=m.sha, tradebot_evidence=trade)
    exec(m.K137_GUARD, ns)
    if fault == "none": assert ns["probe"]("k137", "a"*64, R, None, {}) == v
    else:
        with pytest.raises(ValueError): ns["probe"]("k137", "a"*64, R, None, {})


def test_generated_k137_guest_healthy_probe_uses_only_mocked_linux_reads(fixture, guest, monkeypatch):
    _, data = guest
    code = m.k137_guest(prior.m, "a" * 64)
    tree = ast.parse(code)
    assert isinstance(tree.body[-1], ast.Try)
    tree.body.pop()  # Definitions only; never run its real filesystem entry.
    ns = {}
    exec(compile(tree, "<synthetic-r1161-guest>", "exec"), ns)
    assert "public_file" not in ns and "did_identity" not in ns
    R = ns["R"]
    ns["K137_MACHINE"] = m.sha(b"a" * 32)
    monkeypatch.setattr(m.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(m.os, "access", lambda p, f: p == R.LANDING)
    monkeypatch.setattr(R, "read_small", lambda p, *args: data[p])
    monkeypatch.setattr(R, "directory", lambda p: SimpleNamespace(st_uid=1000 if p == R.LANDING else 0, st_mode=stat.S_IFDIR|0o700))
    monkeypatch.setattr(R, "git_head", lambda p: R.K137_STAGE_SHA)
    body = b"LoadState=loaded\nActiveState=active\nMemoryHigh=1048576000\nMemoryMax=1258291200\nControlGroup=/system.slice/k137q-public-k58.service\n"
    monkeypatch.setattr(R.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout=body, stderr=b""))
    data["/sys/fs/cgroup/system.slice/k137q-public-k58.service/memory.max"] = b"1258291200"
    v = ns["probe"]("k137", "a"*64, R, ns["_b58decode"], prior.m.sources()[2])
    assert v["read_only"] is True and v["uid"] == 1000 and v["source_did"] is None


@pytest.mark.parametrize("fault", ["none", "oversize", "writable", "symlink", "race", "wrong_key"])
def test_original_probe_opens_only_bounded_public_file(anchor, monkeypatch, fault):
    raw = (anchor.ecdsa + " synthetic-comment\n").encode()
    if fault == "wrong_key": raw = (anchor.key + "\n").encode()
    item = SimpleNamespace(parents=[SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=stat.S_IFDIR|0o755, st_uid=0))])
    monkeypatch.setattr(m, "Path", lambda path: item if path == "/etc/ssh/ssh_host_ecdsa_key.pub" else pytest.fail("wrong path"))
    monkeypatch.setattr(m.os, "O_NOFOLLOW", 0x10000, raising=False)
    monkeypatch.setattr(m.os, "O_NONBLOCK", 0x20000, raising=False)
    calls = []
    def opened(path, flags):
        assert path is item and flags == m.os.O_RDONLY | m.os.O_NOFOLLOW | m.os.O_NONBLOCK
        calls.append("open"); return 123
    def info(fd):
        calls.append("stat")
        return SimpleNamespace(st_mode=(stat.S_IFLNK if fault == "symlink" else stat.S_IFREG) | (0o666 if fault == "writable" else 0o644),
                               st_uid=0, st_nlink=1, st_dev=1, st_ino=1,
                               st_size=1025 if fault == "oversize" else len(raw),
                               st_mtime_ns=len(calls) if fault == "race" else 1)
    monkeypatch.setattr(m.os, "open", opened)
    monkeypatch.setattr(m.os, "fstat", info)
    monkeypatch.setattr(m.os, "read", lambda fd, count: raw if count == 1025 else pytest.fail("unbounded read"))
    monkeypatch.setattr(m.os, "close", lambda fd: calls.append("close"))
    if fault == "none":
        assert m.oracle_probe("a" * 64)["public_key"] == anchor.ecdsa
    else:
        with pytest.raises(ValueError): m.oracle_probe("a" * 64)
    assert calls[-1] == "close"


def native(body, local_root=None):
    # Only definitions; current native identity is never a credential input.
    code = prior.native("")
    code += "\n$a=[Management.Automation.Language.Parser]::ParseFile('" + str(PS).replace("'", "''") + "',[ref]$null,[ref]$null)\n"
    code += "foreach($n in $a.FindAll({param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){\n"
    code += "$p=@($n.Parameters|Where-Object {$null -ne $_}|ForEach-Object {$_.Extent.Text}) -join ',';$b=$n.Body.Extent.Text\n"
    code += "$b=$b.Replace('$PSScriptRoot',\"'" + str(PS.parent).replace("'", "''") + "'\")\n"
    if local_root is not None:
        code += "$b=$b.Replace(\"[Environment]::GetFolderPath('LocalApplicationData')\",\"'" + str(local_root).replace("'", "''") + "'\")\n"
        code += "$b=$b.Replace('Local\\FLOP-R1161-','Local\\FLOP-R1161-SYNTHETIC-" + os.urandom(8).hex() + "-')\n"
    code += "Set-Item ('Function:'+$n.Name) ([scriptblock]::Create(('param('+$p+\")`n\"+$b.Substring(1,$b.Length-2))))}\n"
    return code + body


def run_native(code, timeout=40):
    r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", code], capture_output=True, timeout=timeout)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert not r.stderr
    return r.stdout


@WINDOWS
def test_native_ps51_parse_and_safe_entrypoint_no_private_paths():
    code = "$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseFile('" + str(PS).replace("'", "''") + "',[ref]$t,[ref]$e);if($e.Count){throw 'PARSE_STOP'};[Console]::Write($PSVersionTable.PSVersion.ToString())"
    assert run_native(code).startswith(b"5.1.")
    for args, expected in (([], "EXPLICIT_READONLY_EXECUTION_REQUIRED"), (["-Execute"], "PUBLIC_PLAN_REQUIRED")):
        r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(PS), *args], capture_output=True, timeout=15)
        assert r.returncode == 42 and json.loads(r.stdout)["code"] == expected and not r.stderr


@WINDOWS
def test_native_real_helper_source_check_and_guest_pipe(setup):
    raw = base64.b64encode(m.canonical(setup.plan)).decode()
    code = native("Initialize-R1161\n$wire=[Convert]::FromBase64String('" + raw + "')\n" + r'''
$lib=Read-R1161Pinned 'packaging/migration/r1066_owner_workflow.ps1' '13978d6afb01fc3898018e045aded87d673ef683'
foreach($name in @('Read-R1066PinnedSource','Initialize-R1066','Get-R1066Arguments')){Import-R1159Function $lib $name}
Initialize-R1066
$check=Invoke-R1161Local '--check' $wire
if(([Text.Encoding]::UTF8.GetString($check)|ConvertFrom-Json).code -cne 'R1161_PUBLIC_PLAN_PASS'){throw 'PLAN_STOP'}
$guest=Invoke-R1161Local '--guest-k137' $wire
if($guest.Length -lt 5000 -or $guest.Length -gt 16384){throw 'GUEST_STOP'}
$caught=$false
try{$null=Invoke-R1161Local '--trust-status' ([Text.Encoding]::ASCII.GetBytes('{}'))}catch{$caught=$_.Exception.Message -ceq 'ORIGINAL_ED25519_INDEPENDENT_TRUST_REQUIRED'}
if(-not $caught){throw 'UNPROVEN_TRUST_ACCEPTED'}
[Console]::Write('SYNTHETIC_PIPE_PASS')
''')
    assert run_native(code) == b"SYNTHETIC_PIPE_PASS"


@WINDOWS
def test_native_arguments_acl_duplicate_attempt_and_cleanup(tmp_path):
    folder = str(tmp_path / "synthetic-attempt").replace("'", "''")
    pem = tmp_path / "synthetic.pem"; pem.write_bytes(os.urandom(128))
    prior.prior.M.protect_file(pem)
    code = native("Initialize-R1066\n$folder='" + folder + "'\n$pem='" + str(pem).replace("'", "''") + "'\n" + r'''
Assert-R1161Private $pem
New-R1161Attempt $folder
Assert-R1161Private (Join-Path $folder 'ATTEMPTED.json')
$known=Write-R1161Known $folder 'k137' 'ssh-ed25519 synthetic'
Assert-R1161Private $known
$blocked=$false;try{Write-R1161NewPublicFile $known ([byte[]]@(1))}catch{$blocked=$true}
if(-not $blocked){throw 'EXISTING_FILE_REPLACED'}
$blocked=$false;try{New-R1161Attempt $folder}catch{$blocked=$true}
if(-not $blocked){throw 'DUPLICATE_ACCEPTED'}
$a=Get-R1161Arguments 'original' $pem (Join-Path $folder 'known')
if($a[-1] -cne '/usr/bin/python3 -I -B -' -or $a[-2] -cne 'ubuntu@140.238.55.171' -or $a -cnotcontains 'HostKeyAlgorithms=ssh-ed25519'){throw 'ARGUMENT_STOP'}
foreach($bad in @('relative','C:\bad"arg',('C:\bad'+[char]10+'arg'))){
    $blocked=$false;try{$null=Get-R1161Arguments 'k137' $bad 'C:\known'}catch{$blocked=$true}
    if(-not $blocked){throw 'INJECTION_ACCEPTED'}
}
$blocked=$false;try{$null=Write-R1161Public $folder 'k137-admission.json' ([byte[]]@(1)) $false}catch{$blocked=$true}
if(-not $blocked -or [IO.File]::Exists((Join-Path $folder 'k137-admission.json'))){throw 'DIRTY_RECEIPT'}
$a=[IO.File]::GetAccessControl($pem)
$rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-1-0')),'Read','Allow')
$a.AddAccessRule($rule);[IO.File]::SetAccessControl($pem,$a)
$blocked=$false;try{Assert-R1161Private $pem}catch{$blocked=$true}
if(-not $blocked){throw 'OPEN_ACL_ACCEPTED'}
[Console]::Write('SYNTHETIC_LOCAL_GUARDS_PASS')
''')
    assert run_native(code) == b"SYNTHETIC_LOCAL_GUARDS_PASS"


def test_entry_source_pins_frozen_files_not_modified():
    text = PS.read_text(encoding="utf-8")
    assert m.blob(PATH.read_bytes().replace(b"\r\n", b"\n")) in text
    assert text.index("$kraw=Invoke-R1161Ssh 'k137'") < text.index("'--trust-status' ([Text.Encoding]") < text.index("$backup=Find-R1027Backup")
    for bad in ("Invoke-R1159", "Invoke-R1138", "Set-R1138SinglePemAcl", "Download", "ssh-keyscan", "StrictHostKeyChecking=no", "-Operation Init"):
        assert bad not in text
    assert "-AsSecureString" in text and "Unprotect-R1027 $encrypted $password" in text


@WINDOWS
@pytest.mark.parametrize("scenario", ["kfail", "missing_key", "trust_missing", "kpass", "dirty", "locked"])
def test_native_orchestration_no_oracle_before_k137_and_no_credentials_without_trust(tmp_path, setup, scenario):
    # All owner-dependent calls are replaced. Real filesystem accesses are
    # restricted to fresh random synthetic fixtures under pytest's temp root.
    (tmp_path / "Temp").mkdir()
    pem = tmp_path / "synthetic.pem"; pem.write_bytes(os.urandom(128)); prior.prior.M.protect_file(pem)
    plan = tmp_path / "public-plan.json"; plan.write_bytes(m.canonical(setup.plan))
    prior.prior.M.protect_file(plan)
    preamble = "Initialize-R1066\n$Execute=$true;$CrossCertOriginal=$true;$OriginalEvidenceFile=''\n"
    preamble += "$PlanFile='" + str(plan).replace("'", "''") + "';$PlanSha256='" + m.sha(plan.read_bytes()) + "'\n"
    preamble += "$script:pem='" + str(pem).replace("'", "''") + "';$script:scenario='" + scenario + "'\n"
    body = preamble + r'''
$script:trace=New-Object Collections.Generic.List[string]
function Initialize-R1161 {}
function Read-R1161Pinned {return ''}
function Import-R1159Function {}
function Initialize-R1066 {}
function Import-Module {}
function Get-AuthenticodeSignature {return [pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='O=Microsoft Corporation'}}}
function Read-Host {return 'READ_ONLY_R1161_NO_M2_NO_HOLD'}
function Get-R1138ExactPem {
    $script:trace.Add('key')
    if($script:scenario -ceq 'missing_key'){throw 'MISSING'}
    return Get-Item -LiteralPath $script:pem
}
function Find-R1027Backup {throw 'REAL_ESCROW_ACCESS_FORBIDDEN'}
function Unprotect-R1027 {throw 'REAL_RECOVERY_FORBIDDEN'}
function Invoke-R1161Local([string]$Operation,[byte[]]$InputBytes) {
    $script:trace.Add($Operation)
    if($Operation -ceq '--check'){return ,[Text.Encoding]::ASCII.GetBytes('{"code":"R1161_PUBLIC_PLAN_PASS","k137_key":"ssh-ed25519 synthetic"}')}
    if($Operation -ceq '--guest-k137'){return ,[Text.Encoding]::ASCII.GetBytes('synthetic stdin never executed')}
    if($Operation -ceq '--receipt-k137'){return ,[Text.Encoding]::ASCII.GetBytes('{"synthetic":true}')}
    if($Operation -ceq '--trust-status'){throw 'ORIGINAL_ED25519_INDEPENDENT_TRUST_REQUIRED'}
    throw 'FORBIDDEN_OPERATION'
}
function Invoke-R1161Ssh([string]$Role,[string]$Identity,[string]$Known,[byte[]]$Guest) {
    $script:trace.Add('ssh-'+$Role)
    if($Role -cne 'k137'){throw 'REAL_ORACLE_FORBIDDEN'}
    if($script:scenario -ceq 'kfail'){throw 'K137_LOGIN_CGROUP_UNBOUNDED'}
    return 'e30='
}
if($scenario -ceq 'dirty'){
    function Remove-R1161Temporary {throw 'CLEANUP_STOP'}
}
if($scenario -ceq 'locked'){
    function New-R1161Mutex {
        $x=New-Object PSObject
        $x|Add-Member ScriptMethod WaitOne {param($n) return $false}
        $x|Add-Member ScriptMethod Dispose {}
        return $x
    }
}
if($scenario -ceq 'kpass'){$CrossCertOriginal=$false}
$exit=Invoke-R1161
[Console]::WriteLine(($script:trace|ConvertTo-Json -Compress))
'''
    output = run_native(native(body, tmp_path)).splitlines()
    result = json.loads(output[0]); trace = json.loads(output[1])
    expected = dict(kfail="K137_LOGIN_CGROUP_UNBOUNDED", missing_key="K137_KEY_SELECTION_STOP",
                    trust_missing="ORIGINAL_ED25519_INDEPENDENT_TRUST_REQUIRED", kpass="K137_BOUND_READONLY_ADMISSION_PASS",
                    dirty="CLEANUP_STOP", locked="R1161_ATTEMPT_LOCKED")
    assert result["code"] == expected[scenario]
    assert "ssh-original" not in trace
    if scenario in ("kfail", "missing_key", "locked", "dirty"):
        assert "--trust-status" not in trace
        assert result["k137_receipt_sha256"] is None
    if scenario in ("kpass", "trust_missing"):
        assert (tmp_path / "FLOP-R1161/k137-admission.json").is_file()
        assert trace.index("ssh-k137") < trace.index("--receipt-k137")
    if scenario in ("missing_key", "locked"):
        assert "ssh-k137" not in trace
    assert b"recovery code" not in b"\n".join(output)
