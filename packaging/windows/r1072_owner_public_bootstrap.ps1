# R1072 owner Windows PowerShell 5.1 — verified public source bootstrap.
# Creates/removes ONLY owned temporary public source files on local Windows.
# Source operation reads only Oracle file metadata; does NOT open SQLite data,
# change services, create backups, transfer secrets, restore or authorize cutover.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$commit='2ccbce9103b72e28fe552e8769dd75b29cb20a7a'
$prefix='https://raw.githubusercontent.com/hanamaru777/technocore-safe-agent/'+$commit+'/'
$items=@(
    @{path='packaging/migration/r1072_oci_owner_capacity_readonly.ps1';blob='1f73b7a5afb59f8df38304b58ab744bb779a5db2'},
    @{path='packaging/migration/r1066_owner_workflow.ps1';blob='7a7d9790ccd9bb464c254188096d85fb315ee550'},
    @{path='packaging/migration/r1073_exit_preserving_transport.cs';blob='8d08e13f060488326854fac3f014470d8b1f3ec5'},
    @{path='packaging/migration/r1066_preflight_transport.cs';blob='305530a86db7e5cc8812fbac57c3e2c7c089a7be'},
    @{path='packaging/windows/r1062_writer_attribution_one_shot_readonly.ps1';blob='7ad3432b89b2aa2fe4a5e6b0142ec7578554baaa'},
    @{path='packaging/oracle/r1072_original_readonly_capacity.py';blob='0ee105633366abe9e92d72eacc86e7be789aa851'}
)
function Hash-GitBlob([byte[]]$data) {
    $label=[Text.Encoding]::ASCII.GetBytes(('blob '+$data.Length+[char]0))
    $s=[Security.Cryptography.SHA1]::Create()
    try {
        $null=$s.TransformBlock($label,0,$label.Length,$label,0)
        $null=$s.TransformFinalBlock($data,0,$data.Length)
        return [BitConverter]::ToString($s.Hash).Replace('-','').ToLowerInvariant()
    } finally { $s.Dispose() }
}
$root=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) (
    'Temp\flop-r1072-public-'+[Guid]::NewGuid().ToString('N'))
$clean=$true;$success=$false
try {
    if ($PSVersionTable.PSVersion.Major -ne 5 -or
        $PSVersionTable.PSVersion.Minor -lt 1) { throw 'PS51_STOP' }
    if ([IO.Directory]::Exists($root) -or [IO.File]::Exists($root)) {
        throw 'PUBLIC_ROOT_PREEXISTS_STOP'
    }
    $null=New-Item -ItemType Directory -Path $root -ErrorAction Stop
    $oldTls=[Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        foreach ($row in $items) {
            $target=Join-Path $root ($row.path.Replace('/','\'))
            $parent=Split-Path -Parent $target
            if (-not [IO.Directory]::Exists($parent)) {
                $null=New-Item -ItemType Directory -Path $parent -Force
            }
            Invoke-WebRequest -Uri ($prefix+$row.path) -OutFile $target -UseBasicParsing -TimeoutSec 25
            $data=[IO.File]::ReadAllBytes($target)
            if ($data.Length -lt 10 -or $data.Length -gt 65536 -or
                (Hash-GitBlob $data) -cne $row.blob) {
                throw 'GITHUB_BLOB_PIN_STOP'
            }
        }
    } finally {
        [Net.ServicePointManager]::SecurityProtocol=$oldTls
    }
    $entry=Join-Path $root 'packaging\migration\r1072_oci_owner_capacity_readonly.ps1'
    # This is the ONLY invoked script; old source files are loaded by AST
    # helper extraction and their old one-shot entrypoints are not executed.
    & $entry
    $success=$true
} catch {
    Write-Output '{"phase":"R1072_BOOTSTRAP","result":"STOP","code":"PUBLIC_PIN_OR_RUNTIME_STOP"}'
} finally {
    if ([IO.Directory]::Exists($root)) {
        try { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
        catch { $clean=$false }
    }
}
if (-not $clean) {
    Write-Output '{"phase":"R1072_BOOTSTRAP","result":"STOP","code":"PUBLIC_TEMP_CLEANUP_STOP"}'
}
