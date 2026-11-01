"""R1095 owner PS5.1 original OCI deletion is strictly scoped by pinned guest."""
from pathlib import Path
import hashlib
import re
ROOT=Path(__file__).resolve().parents[1]
P=ROOT/"packaging/windows/r1095_original_orphan_cleanup.ps1"

def test_fixed_delete_action_and_original_pin_only():
    s=P.read_text(encoding="utf8")
    assert "r1095_orphan_atomic_cleanup.py" in s
    assert "Read-R1095Report $reply.Output" in s
    assert "'sudo -n /usr/bin/python3 -I -B - --apply-obsolete-atomic-temp'" in s
    assert "R987 V2 local recovery code" in s
    assert "StrictHostKeyChecking=yes" in s
    assert "Read-R1027Backup" in s and "Unprotect-R1027" in s
    assert "CloudShell" not in s
    assert "delete-proven-cache" not in s

def test_fixed_all_dependency_git_blob_pins():
    s=P.read_text(encoding="utf8")
    matches=re.findall(r"@\{path='([^']+)';blob='([0-9a-f]{40})'\}",s)
    assert len(matches)==5
    for path,blob in matches:
        raw=(ROOT/path).read_bytes().replace(b"\r\n",b"\n")
        sha=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        assert sha==blob,path
