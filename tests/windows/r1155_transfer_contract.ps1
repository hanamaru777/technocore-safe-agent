# Synthetic PUBLIC plan. No -Execute, escrow, private key or SSH.
param([string]$PlanFile,[string]$PlanSha,[string]$AuthoritySha)
$ErrorActionPreference='Stop'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=New-Object Security.AccessControl.FileSecurity
$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
foreach($id in @($sid,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','Allow')))
}
[IO.File]::SetAccessControl($PlanFile,$acl)
$result=& powershell.exe -NoProfile -NonInteractive -File 'packaging/windows/r1155_warm_transfer.ps1' -PlanFile $PlanFile -PlanSha256 $PlanSha -AuthoritySha256 $AuthoritySha
if($LASTEXITCODE -ne 42){throw 'R1155_PREFLIGHT_EXIT_STOP'}
$value=$result|ConvertFrom-Json
if($value.code -cne 'PUBLIC_PLAN_CHECKED_NO_SSH' -or $value.cutover -cne 'NO_GO'){throw 'R1155_PREFLIGHT_STOP'}
Write-Host 'R1155_PS51_OFFLINE=PASS'
