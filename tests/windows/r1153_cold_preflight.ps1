# Synthetic public enrollment/bundle only; no cloud access or secret input.
param([string]$EnrollmentFile, [string]$EnrollmentSha256, [string]$BundleFile, [string]$BundleSha256)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -ne 5){throw 'PS51_REQUIRED'}
$path='packaging/windows/r1153_cold_owner_preflight.ps1'
$tokens=$null;$errors=$null
$null=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-Location) $path),[ref]$tokens,[ref]$errors)
if($errors.Count -ne 0){throw 'PS51_SYNTAX_STOP'}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
foreach($file in @($EnrollmentFile,$BundleFile)) {
    $acl=New-Object Security.AccessControl.FileSecurity
    $acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
    foreach($id in @($sid,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','Allow')))
    }
    [IO.File]::SetAccessControl($file,$acl)
}
$output=& powershell.exe -NoProfile -NonInteractive -File $path -EnrollmentFile $EnrollmentFile -EnrollmentSha256 $EnrollmentSha256 -BundleFile $BundleFile -BundleSha256 $BundleSha256
if($LASTEXITCODE -ne 42){throw 'PREFLIGHT_EXIT_STOP'}
$report=$output|ConvertFrom-Json
if($report.phase -cne 'R1153' -or $report.code -cne 'COLD_CONTRACT_CHECKED_NOT_EXECUTION_AUTHORITY' -or
   $report.source_archive -cne 'NO_GO' -or $report.cutover -cne 'NO_GO' -or
   $report.oci_retirement -cne 'STRICT_NO_GO' -or $report.activated){throw 'PREFLIGHT_REPORT_STOP'}
Write-Host 'R1153_PS51_PREFLIGHT=PASS'
