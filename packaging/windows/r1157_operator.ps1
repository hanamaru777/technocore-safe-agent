# Windows PowerShell 5.1. Local approval preparation; READ ONLY by default.
param([ValidateSet('Audit','Draft','Init','Enroll','Issue','Assemble','Collect','Hold','Transfer')]
      [string]$Operation='Audit',[string]$RequestFile='',[string]$RequestSha256='',
      [string]$OutputDirectory='',[switch]$Execute,[switch]$DIDTransferApproved,
      [ValidateSet('owner','independent','destination')][string]$InitRole='owner',
      [string]$AuthoritySha256='',[string]$EndpointsFile='',[string]$EndpointsSha256='')
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$password=$null;$rawKey=$null;$private=$null;$control=$null;$clean=$true;$reply=$null
function Stop-R1157([string]$Code) {
    [Console]::Out.WriteLine(('{"task":"R1157","code":"'+$Code+'","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}'))
    exit 42
}
function Read-R1157Code([string]$Name,[string]$Pin) {
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
    $pins=Read-R1157Code 'packaging/migration/r1155_source_pins.json' '845e571b11603d029ade6b27d53e3dd03ecb038b'
    foreach($p in ($pins|ConvertFrom-Json).PSObject.Properties){$null=Read-R1157Code $p.Name $p.Value}
    $null=Read-R1157Code 'packaging/migration/r1157_operator.py' '9f4703da3057c4517635dc7a91e2f75ddec4fb59'
    $null=Read-R1157Code 'packaging/migration/r1157_metadata.py' '98f8684efd70c9f48668f6ce08353e9de10dfc22'
    # Only import audited definitions, never run a consumed bootstrap.
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
    $reader=[IO.File]::ReadAllText((Join-Path $script:R1066Root 'r1107_owner_dryrun.ps1'))
    Import-R1154Function $reader 'Read-R1107Public'
    if($Operation -ceq 'Init'){$raw=@{role=$InitRole}|ConvertTo-Json -Compress}
    else{$raw=Read-R1107Public $RequestFile $RequestSha256}
    $data=$raw|ConvertFrom-Json
    if($Operation -ceq 'Hold' -or $Operation -ceq 'Transfer') {
        # Existing entrypoints verify exact signatures BEFORE their secret prompt.
        # R1157 never signs an instruction or invents a missing held receipt.
        if($Operation -ceq 'Hold') {
            if($Execute -and (Read-Host 'Type STOP_FLOP_ONLY_KEEP_VM_AND_SSH') -cne 'STOP_FLOP_ONLY_KEEP_VM_AND_SSH'){throw 'OPERATOR_CONSENT_STOP'}
            & (Join-Path $PSScriptRoot 'r1154_warm_owner.ps1') -RequestFile $RequestFile -RequestSha256 $RequestSha256 -EnrollmentSha256 $AuthoritySha256 -Execute:$Execute
            exit $LASTEXITCODE
        }
        if($Execute -and (-not $DIDTransferApproved -or (Read-Host 'Type ENCRYPT_ORIGINAL_DID_DISARMED_ONLY') -cne 'ENCRYPT_ORIGINAL_DID_DISARMED_ONLY')){throw 'OPERATOR_CONSENT_STOP'}
        & (Join-Path $PSScriptRoot 'r1155_warm_transfer.ps1') -PlanFile $RequestFile -PlanSha256 $RequestSha256 -AuthoritySha256 $AuthoritySha256 -EndpointsFile $EndpointsFile -EndpointsSha256 $EndpointsSha256 -Execute:$Execute
        exit $LASTEXITCODE
    }
    if(-not $OutputDirectory){$OutputDirectory=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'FLOP-R1157-public'}
    if(-not [IO.Directory]::Exists($OutputDirectory)){New-R1027Custody $OutputDirectory}else{Assert-R1027Acl $OutputDirectory}
    $op=$Operation.ToLowerInvariant();$confirmation='READ_ONLY'
    if($op -cne 'audit') {
        if(-not $Execute){throw 'OPERATOR_EXPLICIT_EXECUTE_REQUIRED'}
        $confirmation='CONFIRM_'+$Operation.ToUpperInvariant()
        if((Read-Host ('Type '+$confirmation+' after reviewing the pinned public request')) -cne $confirmation){throw 'OPERATOR_CONSENT_STOP'}
    }
    $python=Join-Path $PSScriptRoot '..\..\.venv\Scripts\python.exe'
    $program=Join-Path $script:R1066Root 'r1157_operator.py'
    if(-not [IO.File]::Exists($python) -or $program.Contains('"')){throw 'OPERATOR_RUNTIME_STOP'}
    Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $script:R1066Root 'r1089_owner_control_pipe.cs')))
    if($op -ceq 'init') {
        if(@('owner','independent','destination') -cnotcontains $data.role){throw 'OPERATOR_ROLE_STOP'}
        $store=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'FLOP-R1157-approval'
        if(-not [IO.Directory]::Exists($store)){New-R1027Custody $store}else{Assert-R1027Acl $store}
        $password=Read-Host 'NEW local approval-key encryption passphrase (32+ UTF-8 bytes; NOT DID seed or SSH recovery)' -AsSecureString
    } elseif($op -ceq 'issue') {
        $password=Read-Host 'Local approval-key encryption passphrase (NOT DID seed)' -AsSecureString
    } elseif($op -ceq 'collect') {
        $ends=Read-R1066Enrollment $EndpointsFile $EndpointsSha256
        if($data.enrollment_sha -cne $AuthoritySha256){throw 'ENROLLMENT_STOP'}
        $ssh=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe';Assert-R1027LocalPath $ssh
        # Correct V2 custody only, exclusively for the fixed OCI endpoint.
        $encrypted=Read-R1027Backup
        $password=Read-Host 'R987 V2 local recovery code (OCI SSH only)' -AsSecureString
        try {$rawKey=Unprotect-R1027 $encrypted $password}finally{$password.Dispose();$password=$null}
        if([FlopR1062.Guards]::Sha256($rawKey) -cne $ends.oci.credential_sha256){throw 'OPERATOR_CREDENTIAL_STOP'}
        $private=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Temp\flop-r1157-'+[Guid]::NewGuid().ToString('N'))
        New-R1027Custody $private
        $key=Write-R1027Key $private $rawKey;[FlopR1062.Guards]::Clear($rawKey);$rawKey=$null
        $hosts=@{}
        foreach($role in @('oci','k137')) {
            $hosts[$role]=Join-Path $private ($role+'-known-hosts')
            [IO.File]::WriteAllText($hosts[$role],($ends.$role.host+' '+$ends.$role.host_key+"`n"),[Text.Encoding]::ASCII)
        }
        # Preserve raw enrollment JSON. Strict Python decoder rejects duplicates.
        $meta=@{endpoints=$ends;ssh=$ssh;oci_key=$key;oci_hosts=$hosts.oci;k137_hosts=$hosts.k137}|ConvertTo-Json -Depth 25 -Compress
        $raw=$raw.TrimEnd().Substring(0,$raw.TrimEnd().Length-1)+','+$meta.Substring(1)
    }
    $safe=@{operation=$op;output=$OutputDirectory;confirmation=$confirmation}|ConvertTo-Json -Compress
    $control=[Text.Encoding]::UTF8.GetBytes(($safe.Substring(0,$safe.Length-1)+',"data":'+$raw+'}'))
    $answer=[FlopR1089.OwnerPipe]::Run($python,('-I -B "'+$program+'" --pipe'),$control,$password,420000)
    $reply=[Text.Encoding]::ASCII.GetString($answer.Output)|ConvertFrom-Json
    if($answer.ExitCode -ne 0){
        $allowed=@('OPERATOR_WITNESS_NOT_ENROLLED','OPERATOR_WITNESS_NOT_INDEPENDENT','G4_NOT_PROVABLE','G5_NOT_PROVABLE',
            'OPERATOR_K137_CAPACITY_STOP','OPERATOR_PASSWORD_STOP','OPERATOR_CUSTODY_HOST_STOP','OPERATOR_PERMISSIONS_STOP','OPERATOR_CONSENT_STOP')
        if($allowed -ccontains $reply.code){$code=$reply.code}else{$code='OPERATOR_PREPARATION_STOP'}
        $reply=@{code=$code;cutover='NO_GO';oci_retirement='STRICT_NO_GO'}
    } elseif(@('OPERATOR_PUBLIC_DRAFT_CHECKED','OPERATOR_PUBLIC_ARTIFACT_CREATED') -cnotcontains $reply.code){throw 'RESPONSE_STOP'}
} catch {$reply=@{code='OPERATOR_PREPARATION_STOP';cutover='NO_GO';oci_retirement='STRICT_NO_GO'}}
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
if(-not $clean){Stop-R1157 'CLEANUP_STOP'}
if($null -eq $reply){Stop-R1157 'OPERATOR_PREPARATION_STOP'}
# No raw SSH output, exception message, paths, IPs or private key data.
[Console]::Out.WriteLine(($reply|ConvertTo-Json -Depth 4 -Compress))
if($reply.code -ceq 'OPERATOR_PUBLIC_DRAFT_CHECKED' -or $reply.code -ceq 'OPERATOR_PUBLIC_ARTIFACT_CREATED'){exit 0}
exit 42
