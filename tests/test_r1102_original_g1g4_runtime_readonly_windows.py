"""R1102 one-shot pinned Windows R987 read-only OCI G1/G4 transport."""
from pathlib import Path
import hashlib
import re
ROOT=Path(__file__).resolve().parents[1]
P=ROOT/"packaging/windows/r1102_original_g1g4_runtime_readonly.ps1"

def test_immutable_source_pins():
    raw=P.read_text(encoding="utf-8")
    entries=re.findall(r"@\{path='([^']+)';blob='([0-9a-f]{40})'\}",raw)
    assert len(entries)==5
    for path,expected in entries:
        data=(ROOT/path).read_bytes().replace(b"\r\n",b"\n")
        digest=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
        assert digest==expected,path

def test_readonly_guest_and_secure_r987_transport():
    s=P.read_text(encoding="utf-8")
    assert "r1102_original_g1g4_runtime_readonly.py" in s
    assert "Read-R1102Report $reply.Output" in s
    assert "'sudo -n /usr/bin/python3 -I -B -'" in s
    assert "StrictHostKeyChecking=yes" in s
    assert "R987 V2 local recovery code" in s
    assert "r1066_owner_workflow.ps1" in s
    assert "REPORT_GUARD_STOP" in s
    assert "NOT_AUTHORIZED" in s
    for bad in ("DeleteProvenCache","apply-obsolete","-Delete","systemctl stop"):
        assert bad not in s
