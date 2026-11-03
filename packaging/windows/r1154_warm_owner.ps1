# PS5.1 explicit original-host application HOLD/VERIFY/ROLLBACK only.
# No VM operation, K137 activation, arbitrary remote command or seed input.
param([string]$RequestFile='', [string]$RequestSha256='', [string]$EnrollmentSha256='', [switch]$Execute)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function Stop-R1154([string]$Code) {
    [Console]::Out.WriteLine(('{"phase":"R1154","code":"'+$Code+'","vm_stop":"NOT_IMPLEMENTED","source_archive":"NO_GO","aws_publisher":"DISARMED","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}'))
    exit 42
}
function Read-R1154Code([string]$Name,[string]$Pin) {
    $raw=[IO.File]::ReadAllText((Join-Path $PSScriptRoot $Name),[Text.Encoding]::UTF8).Replace("`r`n","`n")
    $bytes=[Text.Encoding]::UTF8.GetBytes($raw)
    if($bytes.Length -gt 524288){throw 'PIN_STOP'}
    $hash=[Security.Cryptography.SHA1]::Create()
    try {
        $prefix=[Text.Encoding]::ASCII.GetBytes(('blob '+$bytes.Length+[char]0))
        if([BitConverter]::ToString($hash.ComputeHash([byte[]]($prefix+$bytes))).Replace('-','').ToLowerInvariant() -cne $Pin){throw 'PIN_STOP'}
    } finally {$hash.Dispose()}
    return $raw
}
function Import-R1154Function([string]$Text,[string]$Name) {
    $tok=$null;$err=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tok,[ref]$err)
    if($err.Count -ne 0){throw 'PIN_STOP'}
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $Name},$true)
    if($null -eq $node){throw 'PIN_STOP'}
    # Definition only: consumed owner entrypoints are never dot-sourced/run.
    Set-Item -Path ('Function:script:'+$Name) -Value ([scriptblock]::Create(
        ('param('+(@($node.Parameters | Where-Object {$null -ne $_} | ForEach-Object {$_.Extent.Text}) -join ',')+')'+"`n"+$node.Body.Extent.Text.Substring(1,$node.Body.Extent.Text.Length-2))))
}
if($args.Count -ne 0 -or -not $RequestFile){Stop-R1154 'WARM_SIGNED_OWNER_REQUIRED'}
$private=$null;$plain=$null;$password=$null;$reply=$null;$control=$null;$stage='WARM_OWNER_STOP_UNKNOWN_NO_AUTO_RETRY';$clean=$true
try {
    if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1){throw 'PS51_REQUIRED'}
    $map=Read-R1154Code '..\migration\r1154_source_pins.json' 'a2097cb1fa95451bb907eea91763069429baf847'
    foreach($entry in ($map|ConvertFrom-Json).PSObject.Properties) {
        $null=Read-R1154Code ('..\..\'+$entry.Name.Replace('/','\')) $entry.Value
    }
    $old=Read-R1154Code '..\migration\r1107_owner_dryrun.ps1' 'ec7aa52aeae5e56d564b428197ab91ee8f33e2ab'
    Import-R1154Function $old 'Read-R1107Public'
    $request=Read-R1107Public $RequestFile $RequestSha256
    $value=$request|ConvertFrom-Json
    if($EnrollmentSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $value.enrollment_sha -cne $EnrollmentSha256){throw 'ENROLLMENT_STOP'}
    if('FlopR1089.OwnerPipe' -as [type]){throw 'FRESH_PROCESS_REQUIRED'}
    Add-Type -TypeDefinition (Read-R1154Code '..\migration\r1089_owner_control_pipe.cs' 'f8d4d7f586a0cde53d1ffec06816869f47df0b11')
    $python=Join-Path $PSScriptRoot '..\..\.venv\Scripts\python.exe'
    $program=Join-Path $PSScriptRoot '..\migration\r1154_owner.py'
    if(-not [IO.File]::Exists($python) -or $program.Contains('"')){throw 'RUNTIME_STOP'}
    $ssh=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe'
    $known=Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\known_hosts'
    $obj=@{expected_enrollment_sha=$EnrollmentSha256;ssh=$ssh;identity='';known_hosts=$known;known_hosts_sha=$value.scope.known_hosts_sha}
    $meta=$obj|ConvertTo-Json -Depth 30 -Compress
    # Preserve raw request bytes structurally: Python's strict decoder must
    # reject duplicate keys instead of trusting ConvertFrom-Json's last value.
    $control=[Text.Encoding]::UTF8.GetBytes(('{"request":'+$request+','+$meta.Substring(1)))
    $check=[FlopR1089.OwnerPipe]::Run($python,('-I -B "'+$program+'" --check'),$control,$null,30000)
    $safe=[Text.Encoding]::ASCII.GetString($check.Output)|ConvertFrom-Json
    if($check.ExitCode -ne 42 -or $safe.code -cne 'PUBLIC_REQUEST_CHECKED_NO_SSH'){throw 'PUBLIC_ADMISSION_STOP'}
    if(-not $Execute){Stop-R1154 'PUBLIC_REQUEST_CHECKED_NO_SSH'}
    # Everything below is opt-in and never executed by tests against real hosts.
    $script:R1066Root=Join-Path $PSScriptRoot '..\migration'
    $lib=Read-R1154Code '..\migration\r1066_owner_workflow.ps1' '13978d6afb01fc3898018e045aded87d673ef683'
    Import-R1154Function $lib 'Read-R1066PinnedSource';Import-R1154Function $lib 'Initialize-R1066'
    Initialize-R1066
    Assert-R1027LocalPath $ssh;Assert-R1027LocalPath $known
    if((Get-Item -LiteralPath $known).Length -gt 1048576){throw 'HOST_PIN_STOP'}
    $knownHash=[Security.Cryptography.SHA256]::Create()
    try {$actual=[BitConverter]::ToString($knownHash.ComputeHash([IO.File]::ReadAllBytes($known))).Replace('-','').ToLowerInvariant()}
    finally {$knownHash.Dispose()}
    if($actual -cne $obj.known_hosts_sha){throw 'HOST_PIN_STOP'}
    Add-Type -TypeDefinition (Read-R1154Code 'r1151_preseed_control.cs' 'b4307d827fd5fd57e9e1ee4203d75dc21f392fd5')
    $local=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'flop-r1154-operations'
    if(-not [IO.Directory]::Exists($local)){New-R1027Custody $local}else{Assert-R1027Acl $local}
    if(@('verify','status') -cnotcontains $value.operation) {
        $hash=[Security.Cryptography.SHA256]::Create()
        try {$id=[BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::ASCII.GetBytes(($value.operation+'|'+$value.scope.run_id)))).Replace('-','').ToLowerInvariant().Substring(0,32)}
        finally {$hash.Dispose()}
        [FlopR1151.Control]::Reserve($local,$id,$RequestSha256)
    }
    $encrypted=Read-R1027Backup
    $password=Read-Host 'R987 V2 local recovery code (this PC only)' -AsSecureString
    try {$plain=Unprotect-R1027 $encrypted $password}finally{$password.Dispose();$password=$null}
    $private=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Temp\flop-r1154-key-'+[Guid]::NewGuid().ToString('N'))
    New-R1027Custody $private
    $obj.identity=Write-R1027Key $private $plain
    [FlopR1062.Guards]::Clear($plain);$plain=$null
    $meta=$obj|ConvertTo-Json -Depth 30 -Compress
    $control=[Text.Encoding]::UTF8.GetBytes(('{"request":'+$request+','+$meta.Substring(1)))
    $answer=[FlopR1089.OwnerPipe]::Run($python,('-I -B "'+$program+'" --owner'),$control,$null,660000)
    $reply=[Text.Encoding]::ASCII.GetString($answer.Output)|ConvertFrom-Json
    if($answer.ExitCode -ne 0 -or @('HELD_VM_AND_SSH_UNCHANGED','RESTORED_DISARMED_POST_DENY_RETAINED','SOURCE_HOLD_STATUS_REQUIRES_VERIFY') -cnotcontains $reply.code){throw 'REMOTE_UNKNOWN_STOP'}
} catch {$reply=$null}
finally {
    if($null -ne $plain){[FlopR1062.Guards]::Clear($plain)}
    if($null -ne $password){$password.Dispose()}
    if($null -ne $control){[Array]::Clear($control,0,$control.Length)}
    if($null -ne $private) {
        try {
            Assert-R1027Acl $private
            $publicKnown=Join-Path $private 'r1154-known-hosts'
            if([IO.File]::Exists($publicKnown)){[IO.File]::Delete($publicKnown)}
            Remove-R1027Custody $private
        } catch {$clean=$false}
    }
}
if(-not $clean){Stop-R1154 'CLEANUP_STOP_NO_SUCCESS'}
if($null -eq $reply){Stop-R1154 $stage}
# New restricted result only; never raw SSH stdout/stderr or source objects.
$digests=''
foreach($field in @('scope_sha','journal_sha')) {
    if($null -ne $reply.PSObject.Properties[$field]) {
        if($reply.$field -cnotmatch '\A[0-9a-f]{64}\z'){Stop-R1154 'RESPONSE_STOP'}
        $digests+=(',"'+$field+'":"'+$reply.$field+'"')
    }
}
[Console]::Out.WriteLine(('{"phase":"R1154","code":"'+$reply.code+'","vm_stop":"NOT_IMPLEMENTED","source_archive":"NO_GO","aws_publisher":"DISARMED","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"'+$digests+'}'))
exit 0
