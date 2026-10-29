"""R1093 Windows owner runner invariants; no privileged remote action tests."""
from pathlib import Path
import hashlib
import re
ROOT=Path(__file__).resolve().parents[1]
P=ROOT/"packaging/windows/r1093_original_hotspots_readonly.ps1"

def test_only_readonly_guest_no_deletion_path():
    s=P.read_text(encoding="utf8")
    assert "r1093_hotspots_readonly.py" in s
    assert "Read-R1093Report" in s
    assert "'sudo -n /usr/bin/python3 -I -B -'" in s
    assert "StrictHostKeyChecking=yes" in s
    assert "R987 V2 local recovery code" in s
    assert "--delete-proven-cache" not in s
    assert "DeleteProvenCache" not in s
    assert "CloudShell" not in s

def test_all_embedded_dependency_git_blobs_match():
    s=P.read_text(encoding="utf8")
    pairs=re.findall(r"@\\{path='([^']+)';blob='([0-9a-f]{40})'\\}",s)
    assert len(pairs)==5
    for p,pin in pairs:
        raw=(ROOT/p).read_bytes().replace(b"\\r\\n",b"\\n")
        digest=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\\0"+raw).hexdigest()
        assert digest==pin,p
