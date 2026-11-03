# R1153 PUBLIC offline preflight only. No SSH/R987 secret prompt or cloud call.
param([string]$EnrollmentFile='', [string]$EnrollmentSha256='',
      [string]$BundleFile='', [string]$BundleSha256='')
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function Stop-R1153([string]$Code) {
    [Console]::Out.WriteLine(('{"phase":"R1153","result":"PREFLIGHT_ONLY","code":"'+$Code+'","source_archive":"NO_GO","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO","activated":false}'))
    exit 42
}
function Read-R1153Code([string]$Name,[string]$Pin) {
    $path=Join-Path $PSScriptRoot $Name
    $raw=[IO.File]::ReadAllText($path,[Text.Encoding]::UTF8).Replace("`r`n","`n")
    $bytes=[Text.Encoding]::UTF8.GetBytes($raw)
    if($bytes.Length -gt 524288){throw 'PIN_STOP'}
    $hash=[Security.Cryptography.SHA1]::Create()
    try {
        $prefix=[Text.Encoding]::ASCII.GetBytes(('blob '+$bytes.Length+[char]0))
        if([BitConverter]::ToString($hash.ComputeHash([byte[]]($prefix+$bytes))).Replace('-','').ToLowerInvariant() -cne $Pin){throw 'PIN_STOP'}
    } finally {$hash.Dispose()}
    return $raw
}
if($args.Count -ne 0){Stop-R1153 'COLD_ARGUMENT_STOP'}
if(-not $EnrollmentFile -or -not $BundleFile){Stop-R1153 'COLD_AUTHORITY_REQUIRED'}
try {
    if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion -lt [Version]'5.1'){throw 'PS51_STOP'}
    $map=Read-R1153Code '..\migration\r1153_source_pins.json' '688110f1b518d30814a6116f1112336e712b5e62'
    foreach($entry in ($map|ConvertFrom-Json).PSObject.Properties){
        $null=Read-R1153Code ('..\..\'+$entry.Name.Replace('/','\')) $entry.Value
    }
    $null=Read-R1153Code '..\migration\r1153_cold_migration.py' 'd734164eb8ab2108b7ced683133c21ae9a2cd596'
    # Public ACL/hash reader ONLY; never invoke the old owner operation.
    $old=Read-R1153Code '..\migration\r1107_owner_dryrun.ps1' 'ec7aa52aeae5e56d564b428197ab91ee8f33e2ab'
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($old,[ref]$tokens,[ref]$errors)
    if($errors.Count -ne 0){throw 'PIN_STOP'}
    $fn=$ast.Find({param($n)
        $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Read-R1107Public'
    },$true)
    if($null -eq $fn){throw 'PIN_STOP'}
    Invoke-Expression $fn.Extent.Text
    $enrollment=Read-R1107Public $EnrollmentFile $EnrollmentSha256
    $bundle=Read-R1107Public $BundleFile $BundleSha256
    $control=[Text.Encoding]::UTF8.GetBytes(('{"enrollment":'+$enrollment+',"enrollment_sha":"'+$EnrollmentSha256+'","bundle":'+$bundle+'}'))
    if($control.Length -gt 4194304){throw 'INPUT_BOUND_STOP'}
    if('FlopR1089.OwnerPipe' -as [type]){throw 'FRESH_PROCESS_STOP'}
    Add-Type -TypeDefinition (Read-R1153Code '..\migration\r1089_owner_control_pipe.cs' 'f8d4d7f586a0cde53d1ffec06816869f47df0b11')
    $python=Join-Path $PSScriptRoot '..\..\.venv\Scripts\python.exe'
    $program=Join-Path $PSScriptRoot '..\migration\r1153_cold_migration.py'
    if(-not [IO.File]::Exists($python) -or $program.Contains('"')){throw 'RUNTIME_STOP'}
    $answer=[FlopR1089.OwnerPipe]::Run($python,('-I -B "'+$program+'" --preflight'),$control,$null,30000)
    $value=[Text.Encoding]::ASCII.GetString($answer.Output)|ConvertFrom-Json
    if($answer.ExitCode -ne 42 -or $value.phase -cne 'R1153' -or $value.result -cne 'PREFLIGHT_ONLY' -or
       $value.source_archive -cne 'NO_GO' -or $value.cutover -cne 'NO_GO' -or
       $value.oci_retirement -cne 'STRICT_NO_GO' -or $value.activated -isnot [bool] -or $value.activated -or
       @('COLD_CONTRACT_CHECKED_NOT_EXECUTION_AUTHORITY','COLD_ADMISSION_STOP') -cnotcontains $value.code){throw 'REPORT_STOP'}
    Stop-R1153 $value.code
} catch {Stop-R1153 'COLD_ADMISSION_STOP'}
