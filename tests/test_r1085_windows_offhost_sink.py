"""R1085 real Windows NTFS private ACL and bounded fake ciphertext wire tests."""
from pathlib import Path
import hashlib
import json
import os
import struct
import subprocess
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
CS=ROOT/"packaging/migration/r1085_windows_offhost_sink.cs"
PS=CS.with_name("r1085_windows_offhost_sink.ps1")
WIN=pytest.mark.skipif(sys.platform!="win32",reason="Only real Windows PowerShell5.1 + NTFS")


def wire_file(name,data):
    def record(tag,content=b""):
        return struct.pack(">cI",tag,len(content))+content
    return (record(b"S",name.encode())+record(b"D",data)+
            record(b"E",struct.pack(">Q",len(data))+hashlib.sha256(data).digest()))


def wire():
    return (b"FLOPST01"+wire_file("header.bin",b"FLOPENV1"+bytes(44))+
            wire_file("part-0000.bin",b"synthetic-encrypted-payload")+
            wire_file("commit.bin",b"synthetic-final-envelope")+
            struct.pack(">cI",b"F",0))


def test_r1085_no_ssh_or_live_authority_and_exact_source_pin():
    code=CS.read_bytes()
    digest=hashlib.sha1(b"blob "+str(len(code)).encode()+b"\0"+code).hexdigest()
    script=PS.read_text()
    assert digest in script
    for forbidden in ("ssh.exe","oci.vault","systemctl ","oracle_signer.py",
                      "terraform destroy","InstancePrincipalsSecurityTokenSigner"):
        assert forbidden not in code.decode() and forbidden not in script
    for required in ("NTFS_ONLY","OFFHOST_SPACE","REPARSE_PARENT","OWNER_DACL",
                     "NO_OVERWRITE","FINAL_EOF","CIPHERTEXT_ONLY_NOT_AEAD_VERIFIED"):
        assert required in CS.read_text()


def run_ps(code,timeout=40,input_data=b""):
    return subprocess.run(["powershell.exe","-NoProfile","-NonInteractive",
                           "-Command",code],input=input_data,capture_output=True,timeout=timeout)


@WIN
def test_r1085_windows_private_ntfs_stream_success_and_no_overwrite(tmp_path):
    parent=tmp_path/"owner"
    # A freshly-created privately ACL-protected test folder; not a user disk.
    path=str(parent).replace("'","''")
    body=r"""
$ErrorActionPreference='Stop'
$path='PATH_REPLACE'
$me=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($me)
$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @($me,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
    $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
}
$null=[IO.Directory]::CreateDirectory($path,$acl)
"""
    setup=run_ps(body.replace("PATH_REPLACE",path))
    assert setup.returncode==0,setup.stderr.decode(errors="replace")[:500]
    cmd=["powershell.exe","-NoProfile","-NonInteractive","-File",str(PS),
         "-ExistingPrivateNtfsParent",str(parent),
         "-NewArchiveFolder","synthetic1",
         "-QuotaBytes",str(1024**3),"-AllowCiphertextOnly"]
    good=subprocess.run(cmd,input=wire(),capture_output=True,timeout=50)
    assert good.returncode==0,(good.stdout,good.stderr[:600])
    assert json.loads(good.stdout)["operation"]=="CIPHERTEXT_ONLY_NOT_AEAD_VERIFIED"
    candidate=parent/"synthetic1"
    assert (candidate/"commit.bin").is_file()
    assert not (candidate/"commit.bin.pending").exists()
    repeat=subprocess.run(cmd,input=wire(),capture_output=True,timeout=50)
    assert repeat.returncode==42
    assert (candidate/"header.bin").read_bytes()==b"FLOPENV1"+bytes(44)

    cmd[-2]="synthetic2"
    incomplete=subprocess.run(cmd,input=wire()[:-5],capture_output=True,timeout=50)
    assert incomplete.returncode==42
    assert not (parent/"synthetic2"/"commit.bin").exists()


@WIN
def test_r1085_optin_and_untrusted_directory_rejected_before_writing(tmp_path):
    cmd=["powershell.exe","-NoProfile","-NonInteractive","-File",str(PS),
         "-ExistingPrivateNtfsParent",str(tmp_path),
         "-NewArchiveFolder","synthetic",
         "-QuotaBytes",str(1024**3)]
    first=subprocess.run(cmd,input=wire(),capture_output=True,timeout=40)
    assert first.returncode==42
    second=subprocess.run([*cmd,"-AllowCiphertextOnly"],input=wire(),
                          capture_output=True,timeout=50)
    assert second.returncode==42
    assert not (tmp_path/"synthetic").exists()
