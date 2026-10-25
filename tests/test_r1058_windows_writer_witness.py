"""R1058 secure R987 read-only carrier source checks, no credentials or host use."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "packaging/windows/r1058_oci_writer_admission_one_shot_readonly.ps1"
GUEST = ROOT / "packaging/oracle/r1056_writer_admission_readonly.py"


def test_exact_new_guest_and_host_pins():
    src = TARGET.read_text(encoding="utf8")
    assert "1e3487157084bcc5bb80441a988533779c22eed6" in src
    assert 'GuestBlob = "3b87a266678597c3221344b1d5334e37583adc6b"' in src
    assert 'OriginalHead = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"' in src
    assert "r1056_writer_admission_readonly.py" in src
    assert "if ($args.Count -eq 0) { Invoke-R1058 }" in src
    assert "LEGACY_MODE_FORBIDDEN_STOP" in src
    assert "Invoke-R1027 $true" not in src
    assert "Invoke-R1027 $false" not in src
    assert "namespace FlopR1058" in src


def test_pins_required_r987_without_credential_output():
    src = TARGET.read_text(encoding="utf8")
    for token in (
        "FLOP_NEW_SSH_20261018_AES256_V2.enc",
        "EXPECTED_SHA256", "StrictHostKeyChecking=yes",
        "UserKnownHostsFile=", "PasswordAuthentication=no",
        "PermitLocalCommand=no", "ProxyCommand=none",
        "IdentityAgent=none", "sudo -n /usr/bin/python3 -",
        "Read-Host 'R987 V2 recovery code' -AsSecureString",
        "FlopR1058.Guards]::ValidateR1058",
        "Remove-R1027Custody",
    ):
        assert token in src
    assert "function Get-R1027SshArguments" in src
    assert "[Console]::WriteLine($summary)" in src
    assert "FLOP_R1058_STOP=CLEANUP_STOP" in src


def test_all_critical_rejections_permanently_fail_closed():
    src = TARGET.read_text(encoding="utf8")
    for token in ("FLOP_R1058_ALL_WRITERS_FENCED=NO",
                  "FLOP_R1058_SIGNER_EXTERNAL_POST_RESOLVED=NO",
                  "FLOP_R1058_OCI_RETIREMENT=STRICT_NO_GO",
                  'doc["schema_version"]',
                  'doc["original_source_head"]',
                  'doc["no_service_file_or_network_mutation"]'):
        assert token in src
    assert "FlopR1041" not in src
    assert "function Invoke-R1027(" not in src
    assert "FLOP_R1058_STOP=ARGUMENTS_STOP" in src


def test_original_guest_is_still_readonly():
    src = GUEST.read_text(encoding="utf8")
    assert '"all_writers_fenced": "NO"' in src
    assert '"oci_retirement": "STRICT_NO_GO"' in src
    assert 'preflight()' in src


def test_only_one_powershell_invocation_at_end():
    src = TARGET.read_text(encoding="utf8")
    assert src.count("function Invoke-R1058") == 1
    assert src.count("if ($args.Count -eq 0) { Invoke-R1058 }") == 1
    assert src.rstrip().endswith("else { [Console]::WriteLine('FLOP_R1058_STOP=ARGUMENTS_STOP') }")
    assert re.search(r"(?m)^Set-StrictMode -Version 2\.0$", src)
