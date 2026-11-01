# R1107 NEW version. Windows PowerShell 5.1, public evidence ONLY.
# No escrow prompt/decryption, SSH, signing, POST, activation or deletion.
param([string]$PlanFile='',[string]$PlanSha256='',
      [string]$EnrollmentFile='',[string]$EnrollmentSha256='')
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function Stop-R1107([string]$Code) {
    [Console]::Out.WriteLine(('{"phase":"R1107","result":"DRY_RUN_ONLY","reason":"'+$Code+'","source_archive":"NO_GO","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}'))
    exit 42
}
function Read-R1107Public([string]$Path,[string]$Digest) {
    if($Digest -cnotmatch '\A[0-9a-f]{64}\z' -or -not [IO.Path]::IsPathRooted($Path) -or
       [IO.Path]::GetFileName($Path) -match '(?i)seed|secret|credential|private[_-]?key') {throw 'INPUT_STOP'}
    $info=Get-Item -LiteralPath $Path -Force
    if($info.PSIsContainer -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
       $info.Length -lt 2 -or $info.Length -gt 4000000) {throw 'INPUT_STOP'}
    $acl=[IO.File]::GetAccessControl($Path)
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid.Value){throw 'CUSTODY_STOP'}
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
           @($sid.Value,'S-1-5-18') -cnotcontains $rule.IdentityReference.Value){throw 'CUSTODY_STOP'}
    }
    $f=[IO.File]::Open($Path,'Open','Read','Read')
    try {
        if($f.Length -gt 4000000){throw 'INPUT_STOP'}
        $hash=[Security.Cryptography.SHA256]::Create()
        try {$seen=[BitConverter]::ToString($hash.ComputeHash($f)).Replace('-','').ToLowerInvariant()}
        finally {$hash.Dispose()}
        if($seen -cne $Digest){throw 'INPUT_STOP'}
        $f.Position=0
        $reader=New-Object IO.StreamReader($f,(New-Object Text.UTF8Encoding($false,$true)),$false)
        try {return $reader.ReadToEnd()} finally {$reader.Dispose()}
    } finally {$f.Dispose()}
}
function Read-R1107Code([string]$Name,[string]$Pin) {
    $raw=[IO.File]::ReadAllText((Join-Path $PSScriptRoot $Name),[Text.Encoding]::UTF8).Replace("`r`n","`n")
    $b=[Text.Encoding]::UTF8.GetBytes($raw)
    if($b.Length -gt 524288){throw 'SOURCE_PIN_STOP'}
    $h=[Security.Cryptography.SHA1]::Create()
    try {
        $prefix=[Text.Encoding]::ASCII.GetBytes(('blob '+$b.Length+[char]0))
        $null=$h.TransformBlock($prefix,0,$prefix.Length,$prefix,0)
        $null=$h.TransformFinalBlock($b,0,$b.Length)
        if([BitConverter]::ToString($h.Hash).Replace('-','').ToLowerInvariant() -cne $Pin){throw 'SOURCE_PIN_STOP'}
    } finally {$h.Dispose()}
    return $raw
}
if($args.Count -ne 0){Stop-R1107 'DRY_RUN_ONLY'}
if(-not $PlanFile -or -not $EnrollmentFile){Stop-R1107 'INDEPENDENT_EVIDENCE_REQUIRED'}
try {
    if($PSVersionTable.PSVersion.Major -ne 5){throw 'PS51_REQUIRED'}
    $pins=Read-R1107Code 'r1107_source_pins.json' '90e1eb9ef54f4499e7b17c6aa6a5e7cd8ed5bdcb'
    $map=$pins | ConvertFrom-Json
    foreach($entry in $map.PSObject.Properties){$null=Read-R1107Code $entry.Name $entry.Value}
    $plan=Read-R1107Public $PlanFile $PlanSha256
    $trust=Read-R1107Public $EnrollmentFile $EnrollmentSha256
    $control=[Text.Encoding]::UTF8.GetBytes(('{"enrollment":'+$trust+',"plan":'+$plan+'}'))
    if($control.Length -gt 4194304){throw 'INPUT_STOP'}
    $native=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'r1089_owner_control_pipe.cs'))
    # A fresh PS process prevents stale Add-Type implementations being reused.
    if('FlopR1089.OwnerPipe' -as [type]){throw 'FRESH_PROCESS_REQUIRED'}
    Add-Type -TypeDefinition $native
    $python=Join-Path $PSScriptRoot '..\..\.venv\Scripts\python.exe'
    if(-not [IO.File]::Exists($python)){throw 'PROJECT_PYTHON_REQUIRED'}
    $program=Join-Path $PSScriptRoot 'r1107_readiness.py'
    if($program.Contains('"')){throw 'SOURCE_PIN_STOP'}
    $answer=[FlopR1089.OwnerPipe]::Run($python,('-I -B "'+$program+'" --dry-run'),$control,$null,60000)
    $text=[Text.Encoding]::ASCII.GetString($answer.Output)
    $value=$text | ConvertFrom-Json
    if($value.phase -cne 'R1107' -or $value.result -cne 'DRY_RUN_ONLY' -or $value.source_archive -cne 'NO_GO' -or
       $value.cutover -cne 'NO_GO' -or $value.oci_retirement -cne 'STRICT_NO_GO'){throw 'REPORT_STOP'}
    # Output is only the pinned program's fixed redacted schema, never raw SSH.
    [Console]::Out.WriteLine($text.Trim())
    exit $answer.ExitCode
} catch {
    $allowed=@('INPUT_STOP','CUSTODY_STOP','SOURCE_PIN_STOP','PS51_REQUIRED','PROJECT_PYTHON_REQUIRED','FRESH_PROCESS_REQUIRED','REPORT_STOP')
    $code='EVIDENCE_INVALID_OR_UNAVAILABLE'
    if($allowed -ccontains $_.Exception.Message){$code=$_.Exception.Message}
    Stop-R1107 $code
}
