# Windows PowerShell 5.1. V2 one-human consent; NO fabricated witness.
param([ValidateSet('Audit','Init','Enroll','Build','Assemble','Consent','Collect','Rpc','Transfer','Monitor')]
      [string]$Operation='Audit',[string]$RequestFile='',[string]$RequestSha256='',
      [string]$OutputDirectory='',[switch]$Execute,[switch]$DIDTransferApproved,
      [string]$EndpointsFile='',[string]$EndpointsSha256='')
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$password=$null;$rawKey=$null;$private=$null;$control=$null;$reply=$null;$clean=$true
function Read-R1158Code([string]$Name,[string]$Pin) {
    $path=Join-Path $PSScriptRoot ('..\..\'+$Name.Replace('/','\'))
    $text=[IO.File]::ReadAllText($path,[Text.Encoding]::UTF8).Replace("`r`n","`n")
    $bytes=[Text.Encoding]::UTF8.GetBytes($text)
    if($bytes.Length -gt 524288){throw 'SOURCE_PIN_STOP'}
    $h=[Security.Cryptography.SHA1]::Create()
    try {
        $prefix=[Text.Encoding]::ASCII.GetBytes(('blob '+$bytes.Length+[char]0))
        if([BitConverter]::ToString($h.ComputeHash([byte[]]($prefix+$bytes))).Replace('-','').ToLowerInvariant() -cne $Pin){throw 'SOURCE_PIN_STOP'}
    } finally {$h.Dispose()}
    return $text
}
try {
    if($args.Count -ne 0 -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1){throw 'PS51_STOP'}
    $pins=Read-R1158Code 'packaging/migration/r1155_source_pins.json' '845e571b11603d029ade6b27d53e3dd03ecb038b'
    foreach($p in ($pins|ConvertFrom-Json).PSObject.Properties){$null=Read-R1158Code $p.Name $p.Value}
    # Import definitions only. Never invoke a consumed R987/R1089 bootstrap.
    $helper=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'r1154_warm_owner.ps1'))
    $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($helper,[ref]$t,[ref]$e)
    if($e.Count -ne 0){throw 'SOURCE_PIN_STOP'}
    $fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Import-R1154Function'},$true)
    if($null -eq $fn){throw 'SOURCE_PIN_STOP'}
    Set-Item 'Function:script:Import-R1154Function' ([scriptblock]::Create('param([string]$Text,[string]$Name)'+"`n"+$fn.Body.Extent.Text.Substring(1,$fn.Body.Extent.Text.Length-2)))
    $script:R1066Root=Join-Path $PSScriptRoot '..\migration'
    $lib=[IO.File]::ReadAllText((Join-Path $script:R1066Root 'r1066_owner_workflow.ps1'))
    foreach($name in @('Read-R1066PinnedSource','Initialize-R1066','Assert-R1066Keys','Test-R1066Integer','Get-R1066FileDigest','Assert-R1066Endpoint','Read-R1066Enrollment')){Import-R1154Function $lib $name}
    Initialize-R1066
    Import-R1154Function ([IO.File]::ReadAllText((Join-Path $script:R1066Root 'r1107_owner_dryrun.ps1'))) 'Read-R1107Public'
    if($Operation -ceq 'Init'){$raw='{"role":"owner"}'}else{$raw=Read-R1107Public $RequestFile $RequestSha256}
    $data=$raw|ConvertFrom-Json
    if(-not $OutputDirectory){$OutputDirectory=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'FLOP-R1158-public'}
    if(-not [IO.Directory]::Exists($OutputDirectory)){New-R1027Custody $OutputDirectory}else{Assert-R1027Acl $OutputDirectory}
    $op=$Operation.ToLowerInvariant();$confirmation='READ_ONLY'
    if($op -cne 'audit') {
        if(-not $Execute){throw 'SOLO_EXPLICIT_EXECUTE_REQUIRED'}
        switch -CaseSensitive ($op) {
            'init' {$confirmation='INIT_OWNER_ONLY'}
            'enroll' {$confirmation='ONE_HUMAN_NO_INDEPENDENT_REVIEW_CLAIM'}
            'build' {$confirmation='BUILD_PUBLIC_ONLY'}
            'assemble' {$confirmation='ASSEMBLE_REVIEWED_OWNER_GRANT'}
            'consent' {
                $levels=@{
                    'r1154-hold'='FLOP_APP_HOLD_KEEP_VM_SSH';'r1154-custody'='ORIGINAL_DID_ENCRYPTED_EXPORT';
                    'r1154-preserve'='FULL_ENCRYPTED_DISARMED_RESTORE';'r1155-transfer'='FULL_ENCRYPTED_DISARMED_RESTORE';
                    'r1154-permanent-no-replay'='PERMANENT_FIVE_ROUTE_NO_REPLAY';'r1155-activate'='NEW_ONLY_ACTIVATION';
                    'r1155-new-request'='NEW_ONLY_FIXED_REPLY';'r1156-autonomy'='NEW_ONLY_ACTIVATION';
                    'r1156-stage'='NEW_ONLY_ACTIVATION';'r1156-identities'='ISOLATED_LOCAL_SETUP';
                    'r1155-recipient-init'='ORIGINAL_DID_ENCRYPTED_EXPORT';'r1154-rollback'='DISARMED_ROLLBACK_NO_OLD_POST_RELEASE';
                    'r1158-machine-init'='ISOLATED_LOCAL_SETUP';'r1158-inventory'='FULL_ENCRYPTED_DISARMED_RESTORE';
                    'r1158-capacity'='EXISTING_HOST_ZERO_NEW_BILLING';
                    'r1158-monitor-session'='BOUNDED_MACHINE_MONITOR_SESSION'}
                if(-not $levels.ContainsKey($data.kind)){throw 'SOLO_OPERATION_REJECTED'}
                $confirmation=$levels[$data.kind]
                if($data.kind -ceq 'r1154-custody' -and -not $DIDTransferApproved){throw 'SOLO_DID_TRANSFER_OPT_IN_REQUIRED'}
            }
            'collect' {$confirmation='READ_ONLY_FIXED_HOSTS'}
            'monitor' {$confirmation='BOUNDED_MACHINE_MONITOR_SESSION'}
            'rpc' {
                if($data.operation -ceq 'source-custody-once' -and -not $DIDTransferApproved){throw 'SOLO_DID_TRANSFER_OPT_IN_REQUIRED'}
                $confirmation='EXECUTE_FIXED_'+$data.operation.ToUpperInvariant()
            }
            'transfer' {
                if(-not $DIDTransferApproved){throw 'SOLO_DID_TRANSFER_OPT_IN_REQUIRED'}
                $confirmation='FULL_ENCRYPTED_DISARMED_RESTORE'
            }
        }
        if((Read-Host ('Type '+$confirmation+' after reviewing the public request')) -cne $confirmation){throw 'SOLO_CONSENT_STOP'}
    }
    $connection=''
    if(@('collect','rpc','transfer','monitor') -ccontains $op) {
        $ends=Read-R1066Enrollment $EndpointsFile $EndpointsSha256
        $ssh=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe';Assert-R1027LocalPath $ssh
        # R987 V2 only for OCI; never used for the separately pinned K137 key.
        $encrypted=Read-R1027Backup
        $password=Read-Host 'R987 V2 recovery code (OCI SSH only)' -AsSecureString
        try {$rawKey=Unprotect-R1027 $encrypted $password}finally{$password.Dispose();$password=$null}
        if([FlopR1062.Guards]::Sha256($rawKey) -cne $ends.oci.credential_sha256){throw 'SOLO_CREDENTIAL_STOP'}
        $private=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Temp\flop-r1158-'+[Guid]::NewGuid().ToString('N'))
        New-R1027Custody $private
        $key=Write-R1027Key $private $rawKey;[FlopR1062.Guards]::Clear($rawKey);$rawKey=$null
        $hosts=@{}
        foreach($role in @('oci','k137')) {
            $hosts[$role]=Join-Path $private ($role+'-known-hosts')
            [IO.File]::WriteAllText($hosts[$role],($ends.$role.host+' '+$ends.$role.host_key+"`n"),[Text.Encoding]::ASCII)
        }
        $connection=',"connection":'+(@{endpoints=$ends;ssh=$ssh;oci_key=$key;oci_hosts=$hosts.oci;k137_hosts=$hosts.k137}|ConvertTo-Json -Depth 25 -Compress)
    }
    $python=Join-Path $PSScriptRoot '..\..\.venv\Scripts\python.exe'
    $program=Join-Path $script:R1066Root 'r1158_owner.py'
    if(-not [IO.File]::Exists($python) -or $program.Contains('"')){throw 'SOLO_RUNTIME_STOP'}
    Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:R1066Root 'r1089_owner_control_pipe.cs')))
    if($op -ceq 'init') {
        $store=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'FLOP-R1157-approval'
        if(-not [IO.Directory]::Exists($store)){New-R1027Custody $store}else{Assert-R1027Acl $store}
        $password=Read-Host 'NEW owner approval-key encryption passphrase (32+ UTF-8 bytes; NOT DID seed)' -AsSecureString
    } elseif($op -ceq 'consent') {
        $password=Read-Host 'Owner approval-key encryption passphrase (NOT DID seed)' -AsSecureString
    } elseif($op -ceq 'transfer') {
        $password=Read-Host 'Encrypted archive recovery code (32+ UTF-8 bytes; NOT DID seed)' -AsSecureString
    }
    $safe=@{operation=$op;output=$OutputDirectory;confirmation=$confirmation}|ConvertTo-Json -Compress
    # Preserve raw strict JSON; do not reserialize approval/evidence objects.
    $control=[Text.Encoding]::UTF8.GetBytes(($safe.Substring(0,$safe.Length-1)+',"data":'+$raw+$connection+'}'))
    $answer=[FlopR1089.OwnerPipe]::Run($python,('-I -B "'+$program+'" --pipe'),$control,$password,3600000)
    $reply=[Text.Encoding]::ASCII.GetString($answer.Output)|ConvertFrom-Json
    if($answer.ExitCode -ne 0){
        $codes=@('SOLO_TARGET_UID_CONFLICT','SOLO_PROTECTED_RESERVE_STOP','SOLO_TARGET_RESOURCES_STOP','SOLO_ACTIVATION_NOT_PROVEN',
            'SOLO_SESSION_EXPIRED','SOLO_WATCHDOG_STOP_NO_RETRY','SOLO_G4_G5_NOT_PROVEN','SOLO_SOURCE_HOLD_NOT_PROVEN',
            'SOLO_HOST_BOOT_STOP','SOLO_MACHINE_ATTESTER_NOT_ENROLLED','SOLO_MACHINE_EVIDENCE_NOT_PROVEN','SOLO_MEMORY_BUDGET_NOT_PROVEN',
            'SOLO_RECIPIENT_NOT_PROVEN','SOLO_SOURCE_SIZE_STOP','SOLO_LEDGER_MEMORY_BOUND_STOP','SOLO_CUSTODY_ATTEMPT_EXISTS_NO_RETRY',
            'SOLO_CUSTODY_RECEIPT_NOT_PROVEN','SOLO_LATE_OR_REPLAYED_MACHINE_CHECK','WARM_PROCESS_RACE_STOP','WARM_PROCESS_STILL_ALIVE',
            'SOLO_ZERO_COST_CONSENT_REQUIRED','WARM_SCOPE_DRIFT_STOP','WARM_LAUNCHER_DRIFT_STOP')
        $code=if($codes -ccontains $reply.code){$reply.code}else{'SOLO_STOP_NO_AUTO_RETRY'}
        $reply=@{code=$code;cutover='NO_GO';oci_retirement='STRICT_NO_GO'}
    }
    elseif(@('SOLO_CONSENT_DRAFT_ONLY','SOLO_PUBLIC_ARTIFACT_CREATED') -cnotcontains $reply.code){throw 'SOLO_RESPONSE_STOP'}
} catch {$reply=@{code='SOLO_STOP_NO_AUTO_RETRY';cutover='NO_GO';oci_retirement='STRICT_NO_GO'}}
finally {
    if($null -ne $password){$password.Dispose()}
    if($null -ne $rawKey){[Array]::Clear($rawKey,0,$rawKey.Length)}
    if($null -ne $control){[Array]::Clear($control,0,$control.Length)}
    if($null -ne $private){
        try {
            foreach($name in @('oci-known-hosts','k137-known-hosts')){$p=Join-Path $private $name;if([IO.File]::Exists($p)){[IO.File]::Delete($p)}}
            Remove-R1027Custody $private
        } catch {$clean=$false}
    }
}
if(-not $clean){$reply=@{code='CLEANUP_STOP';cutover='NO_GO';oci_retirement='STRICT_NO_GO'}}
if($null -eq $reply){$reply=@{code='SOLO_STOP_NO_AUTO_RETRY';cutover='NO_GO';oci_retirement='STRICT_NO_GO'}}
[Console]::Out.WriteLine(($reply|ConvertTo-Json -Depth 4 -Compress))
if($reply.code -ceq 'SOLO_CONSENT_DRAFT_ONLY' -or $reply.code -ceq 'SOLO_PUBLIC_ARTIFACT_CREATED'){exit 0}
exit 42
