"""R1088 native read-only Windows NTFS ACL test; no source host connection."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import pytest

M=Path(__file__).resolve().parents[1]/"packaging/migration"
CS=M/"r1088_windows_ciphertext_custody.cs"
PS=M/"r1088_windows_ciphertext_custody.ps1"
REC=M/"r1085_windows_offhost_sink.ps1"
WIN=pytest.mark.skipif(sys.platform!="win32",reason="Windows PowerShell5.1 NTFS")

def part(name,b):
    def frame(t,v=b""):return struct.pack(">cI",t,len(v))+v
    return frame(b"S",name.encode())+frame(b"D",b)+frame(b"E",struct.pack(">Q",len(b))+hashlib.sha256(b).digest())

def wire():
    return b"FLOPST01"+part("header.bin",b"FLOPENV1"+bytes(44))+part("part-0000.bin",b"synthetic-secret-free-ciphertext")+part("commit.bin",b"synthetic-commit")+struct.pack(">cI",b"F",0)

def psrun(*a,payload=b""):
    return subprocess.run(["powershell.exe","-NoProfile","-NonInteractive",*a],
                          input=payload,capture_output=True,timeout=50)

def test_r1088_pin_and_readonly_scope():
    data=CS.read_bytes().replace(b"\r\n",b"\n")
    assert hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest() in PS.read_text()
    text=CS.read_text()+PS.read_text()
    for forbidden in ("Directory.Delete(","File.Delete(","ssh.exe","oci.vault",
                      "OpenWrite(","FileMode.Create","Process.Start"):
        assert forbidden not in text

@WIN
def test_r1088_real_ntfs_good_and_extra_file_rejected(tmp_path):
    parent=tmp_path/"private"
    body=r"""
$ErrorActionPreference='Stop'
$path='FIX'
$me=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($me)
$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @($me,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))){
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
  $sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
$null=[IO.Directory]::CreateDirectory($path,$acl)
"""
    setup=psrun("-Command",body.replace("FIX",str(parent).replace("'","''")))
    assert setup.returncode==0,(setup.stdout,setup.stderr[:500])
    src=psrun("-File",str(REC),"-ExistingPrivateNtfsParent",str(parent),
              "-NewArchiveFolder","candidate","-QuotaBytes",str(1024**3),
              "-AllowCiphertextOnly",payload=wire())
    assert src.returncode==0,(src.stdout,src.stderr[:500])
    path=parent/"candidate"
    valid=psrun("-File",str(PS),"-ArchiveRoot",str(path))
    assert valid.returncode==0,(valid.stdout,valid.stderr[:500])
    assert json.loads(valid.stdout)["operation"]=="NTFS_PRIVATE_CIPHERTEXT_ARCHIVE"
    (path/"extra.bin").write_bytes(b"bad")
    blocked=psrun("-File",str(PS),"-ArchiveRoot",str(path))
    assert blocked.returncode==42 and b'"operation":"BLOCKED"' in blocked.stdout
