"""R1092: Windows owner runner source-only invariants; no OCI contact."""
from pathlib import Path
import hashlib
import re
ROOT=Path(__file__).resolve().parents[1]
P=ROOT/"packaging/windows/r1092_original_cache_cleanup.ps1"
SOURCE=ROOT/"packaging/oracle/r1091_safe_cache_cleanup.py"

def test_fixed_ssh_r987_and_no_cloud_shell():
    t=P.read_text(encoding="utf8")
    assert "ubuntu@140.238.55.171" in t
    assert "Read-R1027Backup" in t and "Unprotect-R1027" in t
    assert "New-R1027Custody" in t and "Remove-R1027Custody" in t
    assert "FlopR1079.Transport" in t and "ProgramData" not in t
    assert "StrictHostKeyChecking=yes" in t
    assert "PasswordAuthentication=no" in t
    assert "sudo -n /usr/bin/python3 -I -B -" in t
    assert "--delete-proven-cache" in t
    assert "Invoke-WebRequest" in t and "Get-R1092GitBlob" in t
    assert "CloudShell" not in t and "ssh-keyscan" not in t

def test_every_existing_code_dependency_pin_matches_git_blob():
    text=P.read_text(encoding="utf8")
    pins=re.findall(r"@\{path='([^']+)';blob='([0-9a-f]{40})'\}",text)
    assert len(pins)==5
    for path,pin in pins:
        data=(ROOT/path).read_bytes().replace(b"\r\n",b"\n")
        actual=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
        assert actual==pin,path

def test_cleanup_never_deletes_state_or_unverified_data():
    t=SOURCE.read_text(encoding="utf8")
    assert 'CACHE_DIRS = frozenset({"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"})' in t
    assert 'if root_name == "state":' in t
    assert "state_other_PROTECTED" in t
    assert "ORIGINAL_HEAD" in t and "protected_context()" in t
    assert 'parser.add_argument("--delete-proven-cache"' in t
    assert "DELETED_PROVEN_CACHE=" not in t

def test_one_shot_delete_consumed_and_diagnostics_narrow():
    t=P.read_text(encoding="utf8")
    assert 'DELETE_ONE_SHOT_CONSUMED' in t
    assert t.index('if ($DeleteProvenCache) {') < t.index("        $stage='PUBLIC_SOURCE_PIN'")
    assert "REPORT_UNKNOWN_FIELD_STOP" in t
    assert "REPORT_UNCLASSIFIED_STOP" in t
    assert 'Read-R1092Report $reply.Output ([bool]$DeleteProvenCache)' in t

def test_real_source_label_local_state_requires_exact_normalization():
    from importlib.util import spec_from_file_location, module_from_spec
    spec=spec_from_file_location("r1091_for_r1092",SOURCE)
    module=module_from_spec(spec)
    spec.loader.exec_module(module)
    actual=module.classify("app",Path("local-state/history")).upper()+"_ALLOCATED_BYTES"
    assert actual=="APP_LOCAL-STATE_PROTECTED_ALLOCATED_BYTES"
    ps=P.read_text(encoding="utf8")
    assert "$sourceCategory='APP_LOCAL-STATE_PROTECTED_ALLOCATED_BYTES='" in ps
    assert "'APP_LOCAL_STATE_PROTECTED_ALLOCATED_BYTES='" in ps
    assert "DELETE_ONE_SHOT_CONSUMED" in ps
