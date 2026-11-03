# Native PS5.1, synthetic public request only. Never -Execute, SSH or escrow.
param([string]$RequestFile,[string]$RequestSha,[string]$EnrollmentSha)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -ne 5){throw 'PS51_REQUIRED'}
$scriptPath='packaging/windows/r1154_warm_owner.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-Location) $scriptPath),[ref]$tokens,[ref]$errors)
if($errors.Count -ne 0){throw 'R1154_SYNTAX_STOP'}
$fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Import-R1154Function'},$true)
Invoke-Expression $fn.Extent.Text
$lib=[IO.File]::ReadAllText('packaging/migration/r1066_owner_workflow.ps1')
Import-R1154Function $lib 'Read-R1066PinnedSource'
Import-R1154Function $lib 'Initialize-R1066'
$script:R1066Root=Join-Path (Get-Location) 'packaging/migration'
Initialize-R1066
# Only audited helper definitions/class compilation above; no backup discovery.
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=New-Object Security.AccessControl.FileSecurity
$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
foreach($id in @($sid,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','Allow')))
}
[IO.File]::SetAccessControl($RequestFile,$acl)
$result=& powershell.exe -NoProfile -NonInteractive -File $scriptPath -RequestFile $RequestFile -RequestSha256 $RequestSha -EnrollmentSha256 $EnrollmentSha
if($LASTEXITCODE -ne 42){throw 'R1154_PREFLIGHT_EXIT_STOP'}
$value=$result|ConvertFrom-Json
if($value.code -cne 'PUBLIC_REQUEST_CHECKED_NO_SSH' -or $value.vm_stop -cne 'NOT_IMPLEMENTED' -or
   $value.cutover -cne 'NO_GO'){throw 'R1154_PREFLIGHT_STOP'}
Write-Host 'R1154_PS51_OFFLINE=PASS'
