# Windows PowerShell 5.1. Full ciphertext acquisition and DISARMED restore.
# Public validation by default. Never signs, starts publishers or stops a VM.
param([string]$PlanFile='',[string]$PlanSha256='',[string]$AuthoritySha256='',
      [string]$EndpointsFile='',[string]$EndpointsSha256='',[switch]$Execute)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$private=$null;$rawKey=$null;$recovery=$null;$password=$null;$result=$null;$control=$null
$clean=$true
function Stop-R1155([string]$Code) {
    [Console]::Out.WriteLine(('{"task":"R1155","operation":"BLOCKED","code":"'+$Code+'","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}'))
    exit 42
}
try {
    if($args.Count -ne 0 -or -not $PlanFile -or $AuthoritySha256 -cnotmatch '\A[0-9a-f]{64}\z'){throw 'PUBLIC_PLAN_REQUIRED'}
    if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1){throw 'PS51_REQUIRED'}
    # The only new trust root is this canonical Git blob; it pins ALL code,
    # including the old helper definitions. No legacy entrypoint is invoked.
    $mapPath=Join-Path $PSScriptRoot '..\migration\r1155_source_pins.json'
    $mapText=[IO.File]::ReadAllText($mapPath,[Text.Encoding]::UTF8).Replace("`r`n","`n")
    $hash=[Security.Cryptography.SHA1]::Create()
    try {
        $b=[Text.Encoding]::UTF8.GetBytes($mapText);$p=[Text.Encoding]::ASCII.GetBytes(('blob '+$b.Length+[char]0))
        if([BitConverter]::ToString($hash.ComputeHash([byte[]]($p+$b))).Replace('-','').ToLowerInvariant() -cne 'f629cc8f463c6f8cf5179429c9cf31694964fca4'){throw 'SOURCE_PIN_STOP'}
    } finally {$hash.Dispose()}
    $map=$mapText|ConvertFrom-Json
    foreach($entry in $map.PSObject.Properties) {
        $path=Join-Path $PSScriptRoot ('..\..\'+$entry.Name.Replace('/','\'))
        $b=[Text.Encoding]::UTF8.GetBytes([IO.File]::ReadAllText($path,[Text.Encoding]::UTF8).Replace("`r`n","`n"))
        $h=[Security.Cryptography.SHA1]::Create()
        try {
            $p=[Text.Encoding]::ASCII.GetBytes(('blob '+$b.Length+[char]0))
            if([BitConverter]::ToString($h.ComputeHash([byte[]]($p+$b))).Replace('-','').ToLowerInvariant() -cne $entry.Value){throw 'SOURCE_PIN_STOP'}
        } finally {$h.Dispose()}
    }
    # Extract audited definitions only, never dot-source consumed workflows.
    $helper=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'r1154_warm_owner.ps1'))
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($helper,[ref]$tokens,[ref]$errors)
    if($errors.Count -ne 0){throw 'PARSE_STOP'}
    $definition=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Import-R1154Function'},$true)
    if($null -eq $definition){throw 'PARSE_STOP'}
    Set-Item -Path 'Function:script:Import-R1154Function' -Value ([scriptblock]::Create(
        ('param([string]$Text,[string]$Name)'+"`n"+$definition.Body.Extent.Text.Substring(1,$definition.Body.Extent.Text.Length-2))))
    $script:R1066Root=Join-Path $PSScriptRoot '..\migration'
    $old=[IO.File]::ReadAllText((Join-Path $script:R1066Root 'r1066_owner_workflow.ps1'))
    foreach($name in @('Read-R1066PinnedSource','Initialize-R1066','Assert-R1066Keys','Test-R1066Integer','Get-R1066FileDigest','Assert-R1066Endpoint','Read-R1066Enrollment')) {
        Import-R1154Function $old $name
    }
    Initialize-R1066
    $reader=[IO.File]::ReadAllText((Join-Path $script:R1066Root 'r1107_owner_dryrun.ps1'))
    Import-R1154Function $reader 'Read-R1107Public'
    $raw=Read-R1107Public $PlanFile $PlanSha256
    $plan=$raw|ConvertFrom-Json
    if($plan.enrollment_sha -cne $AuthoritySha256){throw 'ENROLLMENT_STOP'}
    Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:R1066Root 'r1089_owner_control_pipe.cs')))
    $python=Join-Path $script:R1066Root '..\..\.venv\Scripts\python.exe'
    $program=Join-Path $script:R1066Root 'r1155_transfer.py'
    if(-not [IO.File]::Exists($python) -or $program.Contains('"')){throw 'RUNTIME_STOP'}
    $control=[Text.Encoding]::UTF8.GetBytes(('{"plan":'+$raw+'}'))
    $check=[FlopR1089.OwnerPipe]::Run($python,('-I -B "'+$program+'" --check-plan'),$control,$null,30000)
    if($check.ExitCode -ne 0 -or ([Text.Encoding]::ASCII.GetString($check.Output)|ConvertFrom-Json).operation -cne 'OWNER_SESSION_VERIFIED'){throw 'PLAN_STOP'}
    if(-not $Execute){Stop-R1155 'PUBLIC_PLAN_CHECKED_NO_SSH'}
    $e=Read-R1066Enrollment $EndpointsFile $EndpointsSha256
    Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:R1066Root 'r1085_windows_offhost_sink.cs'))) -ReferencedAssemblies @('System.dll','System.Core.dll','System.Security.dll')
    $required=[long]$plan.quota_bytes
    if([IO.Directory]::Exists((Join-Path $plan.offhost_parent $plan.run_id))){$required=0}
    [FlopR1085.Sink]::AdmitExistingParent($plan.offhost_parent,$required)
    $ssh=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe'
    Assert-R1027LocalPath $ssh
    $recovery=Read-Host 'Independent ARCHIVE recovery code (32+ UTF-8 bytes; NOT DID seed)' -AsSecureString
    $encrypted=Read-R1027Backup
    $password=Read-Host 'R987 V2 local recovery code (OCI SSH only)' -AsSecureString
    try {$rawKey=Unprotect-R1027 $encrypted $password}finally{$password.Dispose();$password=$null}
    if([FlopR1062.Guards]::Sha256($rawKey) -cne $e.oci.credential_sha256){throw 'OCI_CREDENTIAL_STOP'}
    $private=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Temp\flop-r1155-'+[Guid]::NewGuid().ToString('N'))
    New-R1027Custody $private
    $key=Write-R1027Key $private $rawKey
    [FlopR1062.Guards]::Clear($rawKey);$rawKey=$null
    $hosts=@{}
    foreach($role in @('oci','k137')) {
        $hosts[$role]=Join-Path $private ($role+'-known-hosts')
        [IO.File]::WriteAllText($hosts[$role],($e.$role.host+' '+$e.$role.host_key+"`n"),[Text.Encoding]::ASCII)
    }
    $meta=@{endpoints=$e;ssh=$ssh;oci_key=$key;oci_hosts=$hosts.oci;k137_hosts=$hosts.k137}|ConvertTo-Json -Depth 20 -Compress
    $control=[Text.Encoding]::UTF8.GetBytes(('{"plan":'+$raw+','+$meta.Substring(1)))
    $answer=[FlopR1089.OwnerPipe]::Run($python,('-I -B "'+$program+'" --owner'),$control,$recovery,14400000)
    $reply=[Text.Encoding]::ASCII.GetString($answer.Output)|ConvertFrom-Json
    if($answer.ExitCode -eq 0 -and $reply.task -ceq 'R1155' -and $reply.operation -ceq 'PRESERVED_AND_DISARMED_RESTORED' -and $reply.cutover -ceq 'NO_GO'){$result=$true}
} catch {$result=$null}
finally {
    if($null -ne $rawKey){[Array]::Clear($rawKey,0,$rawKey.Length)}
    if($null -ne $control){[Array]::Clear($control,0,$control.Length)}
    if($null -ne $password){$password.Dispose()}
    if($null -ne $recovery){$recovery.Dispose()}
    if($null -ne $private) {
        try {
            foreach($name in @('oci-known-hosts','k137-known-hosts')){ $p=Join-Path $private $name;if([IO.File]::Exists($p)){[IO.File]::Delete($p)} }
            Remove-R1027Custody $private
        } catch {$clean=$false}
    }
}
if(-not $clean){Stop-R1155 'CLEANUP_STOP'}
if($null -eq $result){Stop-R1155 'TRANSFER_UNKNOWN_NO_AUTO_RETRY'}
[Console]::Out.WriteLine('{"task":"R1155","operation":"PRESERVED_AND_DISARMED_RESTORED","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}')
exit 0
