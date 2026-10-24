"""R1041 only synthetic Windows SSH+schema tests; never uses owner secret or OCI."""
import importlib.util
import hashlib
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging/windows/r1041_oci_signer_unit_cron_readonly.ps1"
GUEST = ROOT / "packaging/oracle/r1041_signer_unit_cron_readonly.py"
spec = importlib.util.spec_from_file_location(
    "r1041_original_synthetic_driver", ROOT/"tests/test_r1027_windows_escrow_readonly.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
WINDOWS = m.WINDOWS

def report():
    names=(
        "technocore-safe-agent-close1-discord-activation.service",
        "technocore-safe-agent-postreboot-check.service",
    )
    units=[
        dict(identity=name,active="inactive",command_kind="SHELL_WRAPPER",
             declared_write_scope="FLOP_STATE_DECLARED",
             dependency_kind="NO_FLOP_DEPENDENCY_REFERENCE",
             fragment_origin="ETC_SYSTEMD",pre_exec_configured=False,
             post_exec_configured=False,service_type="oneshot") for name in names
    ]
    return dict(
        schema_version=1,original_head="ec4bc4892d40cdd2a03e102faa44d72c89e01b99",
        units=units,
        cron=dict(regular_size_bounded=4,symlink=1,oversized=0,nonregular=0,
                  multiple_links=0,raced=0),
        signer=dict(validation="PASS",result=dict(
            prepared_total=2,quarantined_total=2,recognized_quarantined_e2e=2,
            unreconciled_prepared=0,unreconciled_quarantined=0,
            ack_ids_consistent=True,nonce_binding_consistent=True,
            active_or_ambiguous_outbox=0,autopilot_enabled=False,autopilot_paused=True)),
        flags=dict(original_source_pin="PASS",no_source_or_unit_modification="YES",
                   all_writers_fenced="NO",cron_discovery_complete="NO",
                   process_enumeration_complete="NO",signer_inflight_post_resolved="NO",
                   capture_common_epoch_proven="NO",oci_retirement="STRICT_NO_GO"),
    )

@WINDOWS
def test_exact_new_payload_blob_and_invalid_report_rejected(tmp_path,monkeypatch):
    monkeypatch.setattr(m,"SCRIPT",SOURCE)
    original=GUEST.read_bytes().replace(b"\r\n",b"\n")
    actual=hashlib.sha1(b"blob "+str(len(original)).encode()+b"\0"+original).hexdigest()
    assert actual=="0e5a28b6fbbebd9d9be785e86b839159461b2591"
    canonical=tmp_path/"guest.py"
    canonical.write_bytes(original)
    valid=tmp_path/"valid.json"
    valid.write_bytes(m.encoded(report()))
    tampered=report()
    tampered["signer"]["result"]["nonce_binding_consistent"] = "LEAK_ATTEMPT"
    invalid=tmp_path/"invalid.json"
    invalid.write_bytes(m.encoded(tampered))
    output=m.ps_run(tmp_path,rf"""
[FlopR1041.Guards]::VerifySource([IO.File]::ReadAllBytes({m.literal(canonical)}),
    [FlopR1041.Guards]::GuestCombinedBlob)
$v=[FlopR1041.Guards]::ValidateCombined([IO.File]::ReadAllBytes({m.literal(valid)}))
if (-not $v.Contains('STRICT_NO_GO')) {{ throw 'VALIDATION_FAIL' }}
$denied=$false
try {{
    [FlopR1041.Guards]::ValidateCombined([IO.File]::ReadAllBytes({m.literal(invalid)})) | Out-Null
}} catch {{ $denied=$true }}
if (-not $denied) {{ throw 'INVALID_ACCEPTED' }}
[Console]::WriteLine('R1041_SCHEMA_AND_PIN=PASS')
""")
    assert output.strip()=="R1041_SCHEMA_AND_PIN=PASS"

@WINDOWS
@pytest.mark.parametrize(("exit_code","expected"),(
    (0,"FLOP_R1041_READONLY=PASS"),
    (42,"FLOP_R1027_STOP=GUEST_COMBINED_GUARD_STOP"),
    (255,"FLOP_R1027_STOP=SSH_TRANSPORT_OR_AUTH_STOP"),
))
def test_r1041_single_mock_ssh_and_guarded_cleanup(tmp_path,monkeypatch,exit_code,expected):
    monkeypatch.setattr(m,"SCRIPT",SOURCE)
    output_file=tmp_path/"safe-report.json"
    output_file.write_bytes(m.encoded(report()))
    output=m.ps_run(tmp_path,rf"""
$script:calls=0
$script:clean=0
function Get-R1027Prerequisites {{ return @{{Ssh='MOCK';Hosts='MOCK'}} }}
function Read-R1027Backup {{ return ,([byte[]]@(1,2,3)) }}
function Get-R1027Source {{ param([bool]$RouteProbe,[bool]$CombinedProbe)
    if ($RouteProbe -or -not $CombinedProbe) {{ throw 'WRONG_SOURCE' }}
    return ,([Text.Encoding]::ASCII.GetBytes('synthetic-guest')) }}
function Read-Host {{ param($Prompt,[switch]$AsSecureString)
    if (-not $AsSecureString) {{ throw 'VISIBLE_INPUT' }}
    return New-SyntheticCode 'dummy-only' }}
function Unprotect-R1027 {{ param($Encrypted,$Code)
    return ,([Text.Encoding]::ASCII.GetBytes('dummy-key-material')) }}
function New-R1027Custody {{ param($Directory) }}
function Write-R1027Key {{ param($Directory,$Bytes) return 'MOCK-KEY' }}
function Get-R1027SshArguments {{ param($Key,$Hosts)
    return @('MOCK','sudo -n /usr/bin/python3 -') }}
function Invoke-R1027Ssh {{ param($Ssh,$Arguments,$Source)
    $script:calls++
    if ($Arguments[-1] -cne 'sudo -n /usr/bin/python3 -') {{ throw 'WRONG_COMMAND' }}
    return @{{ ExitCode={exit_code}; Output=$(if ({exit_code} -eq 0) {{
      [IO.File]::ReadAllBytes({m.literal(output_file)})
    }} else {{ [Text.Encoding]::ASCII.GetBytes('PRIVATE_RAW_ERROR') }}) }} }}
function Remove-R1027Custody {{ param($Directory) $script:clean++ }}
Invoke-R1027 $false $true
if ($script:calls -ne 1 -or $script:clean -ne 1) {{ throw 'ONE_SHOT_OR_CLEANUP' }}
""")
    assert expected in output
    assert "PRIVATE_RAW_ERROR" not in output
    assert "dummy-key-material" not in output

@WINDOWS
def test_older_clr_type_cannot_shadow_r1041(tmp_path,monkeypatch):
    monkeypatch.setattr(m,"SCRIPT",SOURCE)
    output=m.ps_run(tmp_path,r"""
Add-Type -TypeDefinition @'
namespace FlopR1036 { public static class Guards { public const string GuestBlob = "OLD"; } }
'@
if (-not ('FlopR1041.Guards' -as [type])) { throw 'NEW_GUARD_MISSING' }
if ([FlopR1036.Guards]::GuestBlob -cne 'OLD') { throw 'OLD_TYPE_MODIFIED' }
[Console]::WriteLine('R1041_ISOLATED_TYPE=PASS')
""")
    assert output.strip()=="R1041_ISOLATED_TYPE=PASS"
