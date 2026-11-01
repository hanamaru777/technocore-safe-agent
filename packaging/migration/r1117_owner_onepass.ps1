# R1117 versioned owner admission entrypoint; ASCII, Windows PowerShell 5.1.
# No R987 recovery input, SSH, service invocation, POST, or old R1112 fallback.
param([switch]$DryRun,[string]$PublicProofFile='',[string]$PublicProofSha256='',
      [string]$EnrollmentFile='',[string]$EnrollmentSha256='')
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if($args.Count -ne 0 -or -not $DryRun -or $PSVersionTable.PSVersion.Major -ne 5) {
    [Console]::Out.WriteLine('{"phase":"R1117","mode":"DISARMED","reason":"R1117_DISARMED_ONLY","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}')
    exit 42
}
function Stop-R1117 {
    [Console]::Out.WriteLine('{"phase":"R1117","mode":"DISARMED","G3":"REAL_CUSTODY_NOT_PROVEN","G4":"G4_NOT_PROVABLE","G5":"AUTHORITATIVE_HISTORY_UNAVAILABLE","G6":"NO_SOURCE_EXPORT","G7":"NOT_PERFORMED","reason":"INDEPENDENT_BACKEND_HISTORY_AND_EXACT_OWNER_APPROVAL_REQUIRED","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}')
    exit 42
}
function Read-R1117Pinned([string]$Name,[string]$Pin) {
    $raw=[IO.File]::ReadAllText((Join-Path $PSScriptRoot $Name),[Text.Encoding]::UTF8).Replace("`r`n","`n")
    $bytes=[Text.Encoding]::UTF8.GetBytes($raw)
    if($bytes.Length -gt 524288){throw 'PIN_STOP'}
    $head=[Text.Encoding]::ASCII.GetBytes(('blob '+$bytes.Length+[char]0))
    $sha=[Security.Cryptography.SHA1]::Create()
    try {
        $actual=[BitConverter]::ToString($sha.ComputeHash([byte[]]($head+$bytes))).Replace('-','').ToLowerInvariant()
        if($actual -cne $Pin){throw 'PIN_STOP'}
    } finally {$sha.Dispose()}
    return $raw
}
if(-not $PublicProofFile -or -not $EnrollmentFile){Stop-R1117}
try {
    $map=Read-R1117Pinned 'r1117_source_pins.json' 'a8df2c5c5f77f588ceda4acfae7a71e6cfe7bb4a'
    foreach($entry in ($map|ConvertFrom-Json).PSObject.Properties){$null=Read-R1117Pinned $entry.Name $entry.Value}
    # Reuse ONLY the immutable local public-file ACL/hash reader, not the old
    # owner entrypoint or any escrow/remote operation.
    $old=Read-R1117Pinned 'r1107_owner_dryrun.ps1' 'ec7aa52aeae5e56d564b428197ab91ee8f33e2ab'
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($old,[ref]$tokens,[ref]$errors)
    if($errors.Count -ne 0){throw 'PARSE_STOP'}
    $fn=$ast.Find({param($n)
        $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Read-R1107Public'
    },$true)
    if($null -eq $fn){throw 'PARSE_STOP'}
    Invoke-Expression $fn.Extent.Text
    $proof=Read-R1107Public $PublicProofFile $PublicProofSha256
    $enrollment=Read-R1107Public $EnrollmentFile $EnrollmentSha256
    $control=[Text.Encoding]::UTF8.GetBytes(('{"enrollment":'+$enrollment+',"g3":'+$proof+'}'))
    if($control.Length -gt 4194304){throw 'INPUT_STOP'}
    if('FlopR1089.OwnerPipe' -as [type]){throw 'FRESH_PROCESS_REQUIRED'}
    $native=Read-R1117Pinned 'r1089_owner_control_pipe.cs' 'f8d4d7f586a0cde53d1ffec06816869f47df0b11'
    Add-Type -TypeDefinition $native
    $python=Join-Path $PSScriptRoot '..\..\.venv\Scripts\python.exe'
    if(-not [IO.File]::Exists($python)){throw 'PYTHON_STOP'}
    $file=Join-Path $PSScriptRoot 'r1117_migration.py'
    if($file.Contains('"')){throw 'PATH_STOP'}
    $answer=[FlopR1089.OwnerPipe]::Run($python,('-I -B "'+$file+'" --dry-run'),$control,$null,60000)
    $text=[Text.Encoding]::ASCII.GetString($answer.Output)
    $result=$text|ConvertFrom-Json
    if($answer.ExitCode -ne 42 -or $result.phase -cne 'R1117' -or $result.mode -cne 'DISARMED' -or
       $result.G6 -cne 'NO_SOURCE_EXPORT' -or $result.cutover -cne 'NO_GO' -or
       $result.oci_retirement -cne 'STRICT_NO_GO'){throw 'REPORT_STOP'}
    [Console]::Out.WriteLine($text.Trim())
    exit 42
} catch {Stop-R1117}
