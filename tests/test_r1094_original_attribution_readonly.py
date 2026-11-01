"""R1094 Windows owner tool: only the pinned read-only probe."""
from pathlib import Path
import hashlib
import re
ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/"packaging/windows/r1094_original_attribution_readonly.ps1"

def test_exact_readonly_and_r987():
    s=SRC.read_text(encoding="utf8")
    assert "Read-R1094Report" in s
    assert "r1094_two_hotspot_attribution.py" in s
    assert "'sudo -n /usr/bin/python3 -I -B -'" in s
    assert "StrictHostKeyChecking=yes" in s
    assert "Read-R1027Backup" in s and "Unprotect-R1027" in s
    assert "R987 V2 local recovery code" in s
    assert "--delete-proven-cache" not in s
    assert "DeleteProvenCache" not in s
    assert "CloudShell" not in s

def test_git_blob_pins_all_dependencies():
    s=SRC.read_text(encoding="utf8")
    pairs=re.findall(r"@\{path='([^']+)';blob='([0-9a-f]{40})'\}",s)
    assert len(pairs)==5
    for p,pin in pairs:
        b=(ROOT/p).read_bytes().replace(b"\r\n",b"\n")
        digest=hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
        assert digest==pin,p
