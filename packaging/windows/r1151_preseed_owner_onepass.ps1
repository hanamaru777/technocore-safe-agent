# R1151 owner public READINESS only. No production runtime is enrolled.
# No R987 prompt, key lookup, SSH, decrypt, transfer, service or deletion here.
param([string]$EnrollmentFile='',[string]$EnrollmentSha256='',
      [string]$RequestFile='',[string]$RequestSha256='')
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function Stop-R1151([string]$Code) {
    [Console]::Out.WriteLine(('{"phase":"R1151","result":"READINESS_STOP","code":"'+$Code+'","ready_for_owner_call":false,"source_bytes_transferred":0,"source_complete":false,"aead_verified":false,"activated":false,"cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}'))
    exit 42
}
function Read-R1151Code([string]$Name,[string]$Pin) {
    $raw=[IO.File]::ReadAllText((Join-Path $PSScriptRoot $Name),[Text.Encoding]::UTF8).Replace("`r`n","`n")
    $bytes=[Text.Encoding]::UTF8.GetBytes($raw)
    if($bytes.Length -gt 524288){throw 'PIN_STOP'}
    $prefix=[Text.Encoding]::ASCII.GetBytes(('blob '+$bytes.Length+[char]0))
    $hash=[Security.Cryptography.SHA1]::Create()
    try {
        $value=[BitConverter]::ToString($hash.ComputeHash([byte[]]($prefix+$bytes))).Replace('-','').ToLowerInvariant()
        if($value -cne $Pin){throw 'PIN_STOP'}
    } finally {$hash.Dispose()}
    return $raw
}
if($args.Count -ne 0){Stop-R1151 'ARGS_STOP'}
# Missing identity: STOP BEFORE Python, credentials, secret prompts or SSH.
if(-not $EnrollmentFile){Stop-R1151 'SOURCE_IDENTITY_STOP'}
try {
    if($PSVersionTable.PSVersion.Major -ne 5){throw 'PS51_REQUIRED'}
    $map=Read-R1151Code '..\migration\r1151_source_pins.json' '6f2314eb53c1367f32e106f8f0988c949b96c90d'
    foreach($entry in ($map|ConvertFrom-Json).PSObject.Properties) {
        $null=Read-R1151Code ('..\..\'+$entry.Name.Replace('/','\')) $entry.Value
    }
    # Reuse only the pinned public file ACL+hash reader. Never run old owner
    # scripts, consumed operations, R987 custody or generic R1079 transport.
    $old=Read-R1151Code '..\migration\r1107_owner_dryrun.ps1' 'ec7aa52aeae5e56d564b428197ab91ee8f33e2ab'
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($old,[ref]$tokens,[ref]$errors)
    if($errors.Count -ne 0){throw 'PIN_STOP'}
    $fn=$ast.Find({param($n)
        $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Read-R1107Public'
    },$true)
    if($null -eq $fn){throw 'PIN_STOP'}
    Invoke-Expression $fn.Extent.Text
    $enrollment=Read-R1107Public $EnrollmentFile $EnrollmentSha256
    if(-not $RequestFile){Stop-R1151 'OWNER_GRANT_STOP'}
    $request=Read-R1107Public $RequestFile $RequestSha256
    $control=[Text.Encoding]::UTF8.GetBytes(('{"enrollment":'+$enrollment+',"enrollment_sha256":"'+$EnrollmentSha256+'","request":'+$request+'}'))
    if($control.Length -gt 1048576){throw 'INPUT_STOP'}
    if('FlopR1089.OwnerPipe' -as [type]){throw 'FRESH_PROCESS_REQUIRED'}
    Add-Type -TypeDefinition (Read-R1151Code '..\migration\r1089_owner_control_pipe.cs' 'f8d4d7f586a0cde53d1ffec06816869f47df0b11')
    $python=Join-Path $PSScriptRoot '..\..\.venv\Scripts\python.exe'
    if(-not [IO.File]::Exists($python)){throw 'PYTHON_STOP'}
    $program=Join-Path $PSScriptRoot '..\migration\r1151_preseed_owner_bridge.py'
    if($program.Contains('"')){throw 'PATH_STOP'}
    $answer=[FlopR1089.OwnerPipe]::Run($python,('-I -B "'+$program+'" --readiness'),$control,$null,30000)
    $value=[Text.Encoding]::ASCII.GetString($answer.Output)|ConvertFrom-Json
    if($answer.ExitCode -ne 42 -or $value.phase -cne 'R1151' -or $value.result -cne 'READINESS_STOP' -or
       $value.ready_for_owner_call -isnot [bool] -or $value.ready_for_owner_call -or
       $value.source_bytes_transferred -ne 0 -or $value.source_complete -or $value.aead_verified -or
       $value.activated -or $value.cutover -cne 'NO_GO' -or $value.oci_retirement -cne 'STRICT_NO_GO' -or
       $value.code -cnotmatch '\A[A-Z0-9_]{3,80}\z'){throw 'REPORT_STOP'}
    Stop-R1151 $value.code
} catch {Stop-R1151 'PUBLIC_ADMISSION_STOP'}
