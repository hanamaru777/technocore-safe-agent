# Synthetic PS5.1 binary peer contracts ONLY. No SSH, real key or owner operation.
param([string]$EnrollmentFile='', [string]$EnrollmentSha256='',
      [string]$RequestFile='', [string]$RequestSha256='')
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -ne 5){throw 'R1151_PS51_REQUIRED'}
foreach($path in @('packaging/windows/r1151_preseed_owner_onepass.ps1')) {
    $tokens=$null;$errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-Location) $path),[ref]$tokens,[ref]$errors)
    if($errors.Count -ne 0){throw 'R1151_PS51_SYNTAX_STOP'}
}
Add-Type -TypeDefinition ([IO.File]::ReadAllText('packaging/windows/r1151_preseed_control.cs'))
Add-Type -TypeDefinition ([IO.File]::ReadAllText('packaging/windows/r1140_binary_ciphertext_bridge.cs'))
. 'packaging/windows/r1141_k137_recipient_receipt_gate.ps1'
$python=(Get-Command python.exe -ErrorAction Stop).Source
$base=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
$temp=Join-Path $base ('r1151-synthetic-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp)|Out-Null
$recovery=New-Object Security.SecureString
function Set-R1151Private([string]$Path,[bool]$Directory) {
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    if($Directory){$acl=New-Object Security.AccessControl.DirectorySecurity}
    else {$acl=New-Object Security.AccessControl.FileSecurity}
    $acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
    foreach($id in @($sid,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','Allow')))
    }
    if($Directory){[IO.Directory]::SetAccessControl($Path,$acl)}
    else {[IO.File]::SetAccessControl($Path,$acl)}
}
function Assert-R1151Blocked([scriptblock]$Action) {
    $blocked=$false
    try { & $Action } catch {$blocked=$true}
    if(-not $blocked){throw 'R1151_EXPECTED_STOP'}
}
try {
    Set-R1151Private $temp $true
    foreach($c in (('x'*40)+[char]0+[char]255+"`r`n").ToCharArray()) {$recovery.AppendChar($c)}
    $recovery.MakeReadOnly()
    $frame=[FlopR1151.Control]::Frame([Text.Encoding]::ASCII.GetBytes('{}'),$recovery)
    $source=Join-Path $temp 'source.py';$sink=Join-Path $temp 'recipient.py'
    [IO.File]::WriteAllText($source,@'
import sys
expected=b'R1151S01'+(2).to_bytes(4,'big')+b'{}'+(45).to_bytes(4,'big')+b'x'*40+b'\x00\xc3\xbf\r\n'
if sys.stdin.buffer.read()!=expected: sys.exit(67)
sys.stdout.buffer.write(b'FLOPST01'+bytes(range(256))*64)
'@,[Text.Encoding]::ASCII)
    [IO.File]::WriteAllText($sink,@'
import sys,json
data=sys.stdin.buffer.read()
if data!=b'FLOPST01'+bytes(range(256))*64: sys.exit(68)
print(json.dumps(dict(phase='R1129',result='PROVISIONAL_CIPHERTEXT_STORED_ONLY',files=3,bytes=len(data),aead_verified=False,source_complete=False,sqlite_epoch='NOT_PROVEN',history_finality='UNKNOWN',signer_portability='NOT_PROVEN',activated=False,cutover='NO_GO',oci_retirement='STRICT_NO_GO')))
'@,[Text.Encoding]::ASCII)
    $src='-I -B "'+$source+'"';$dst='-I -B "'+$sink+'"'
    $result=[FlopR1140.Bridge]::Pump($python,$src,$python,$dst,$frame,10000)
    $safe=Assert-R1141R1129Receipt $result.RecipientReport $result.ForwardedBytes
    if($safe.aead_verified -or $safe.source_complete -or $safe.activated -or
       $safe.oci_retirement -cne 'STRICT_NO_GO' -or @($frame|Where-Object {$_ -ne 0}).Count -ne 0) {
        throw 'R1151_FRAME_OR_RECEIPT_STOP'
    }
    # Exclusive durable attempt marker survives an interruption and forbids reuse.
    $id='0123456789abcdef0123456789abcdef';$binding=('a'*64)
    [FlopR1151.Control]::Reserve($temp,$id,$binding)
    $journal=Join-Path $temp ('r1151-'+$id+'.unknown.json')
    $before=[IO.File]::ReadAllBytes($journal)
    Assert-R1151Blocked { [FlopR1151.Control]::Reserve($temp,$id,$binding) }
    if([Convert]::ToBase64String($before) -cne [Convert]::ToBase64String([IO.File]::ReadAllBytes($journal))){throw 'R1151_REPLAY_STOP'}
    $stored=[Text.Encoding]::ASCII.GetString($before)|ConvertFrom-Json
    if($stored.state -cne 'UNKNOWN_POST' -or $stored.binding_sha256 -cne $binding){throw 'R1151_JOURNAL_STOP'}
    $acl=[IO.File]::GetAccessControl($journal)
    if(-not $acl.AreAccessRulesProtected){throw 'R1151_JOURNAL_ACL_STOP'}
    $loose=Join-Path $temp 'inherited';[IO.Directory]::CreateDirectory($loose)|Out-Null
    Assert-R1151Blocked { [FlopR1151.Control]::Reserve($loose,('f'*32),$binding) }
    Assert-R1151Blocked { [FlopR1151.Control]::Reserve($temp,'../bad',$binding) }
    # Deadline and child failure are synthetic, never a real SSH invocation.
    [IO.File]::WriteAllText($source,"import time; time.sleep(8)",[Text.Encoding]::ASCII)
    $frame=[FlopR1151.Control]::Frame([Text.Encoding]::ASCII.GetBytes('{}'),$recovery)
    Assert-R1151Blocked { $null=[FlopR1140.Bridge]::Pump($python,$src,$python,$dst,$frame,1000) }
    if(@($frame|Where-Object {$_ -ne 0}).Count -ne 0){throw 'R1151_TIMEOUT_ZEROIZE_STOP'}
    [IO.File]::WriteAllText($source,"import sys; sys.stdin.buffer.read(); sys.exit(42)",[Text.Encoding]::ASCII)
    $frame=[FlopR1151.Control]::Frame([Text.Encoding]::ASCII.GetBytes('{}'),$recovery)
    Assert-R1151Blocked { $null=[FlopR1140.Bridge]::Pump($python,$src,$python,$dst,$frame,5000) }
    if(@($frame|Where-Object {$_ -ne 0}).Count -ne 0){throw 'R1151_FAILURE_ZEROIZE_STOP'}
    if($EnrollmentFile) {
        Set-R1151Private $EnrollmentFile $false;Set-R1151Private $RequestFile $false
        $output=& powershell.exe -NoProfile -NonInteractive -File 'packaging/windows/r1151_preseed_owner_onepass.ps1' -EnrollmentFile $EnrollmentFile -EnrollmentSha256 $EnrollmentSha256 -RequestFile $RequestFile -RequestSha256 $RequestSha256
        if($LASTEXITCODE -ne 42){throw 'R1151_READINESS_EXIT_STOP'}
        $report=$output|ConvertFrom-Json
        if($report.code -cne 'INDEPENDENT_SOURCE_RUNTIME_NOT_ENROLLED' -or $report.ready_for_owner_call -or
           $report.source_bytes_transferred -ne 0){throw 'R1151_READINESS_ADMISSION_STOP'}
    }
} finally {
    if($null -ne $frame){[Array]::Clear($frame,0,$frame.Length)}
    $recovery.Dispose()
    # Only this invocation's exact synthetic temp tree; cleanup failure is FAIL.
    $resolved=[IO.Path]::GetFullPath($temp)
    if(-not $resolved.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or
       [IO.Path]::GetFileName($resolved) -cnotmatch '\Ar1151-synthetic-[0-9a-f]{32}\z'){throw 'R1151_TEST_CLEANUP_SCOPE_STOP'}
    if([IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
    if([IO.Directory]::Exists($resolved)){throw 'R1151_TEST_CLEANUP_STOP'}
}
Write-Host 'R1151_NATIVE_OFFLINE=PASS'
