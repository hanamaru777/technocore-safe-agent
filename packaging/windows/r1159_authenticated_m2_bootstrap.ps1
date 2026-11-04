# Source-only M2. Windows PowerShell 5.1. Existing approval-key Init is CONSUMED.
param([switch]$Execute,[string]$OracleHostKeySha256='',[string]$OracleTrustReference='')
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function Read-R1159Code([string]$Name,[string]$Pin) {
    $p=Join-Path $PSScriptRoot ('..\..\'+$Name.Replace('/','\'))
    $s=[IO.File]::ReadAllText($p,[Text.Encoding]::UTF8).Replace("`r`n","`n")
    $b=[Text.Encoding]::UTF8.GetBytes($s)
    if($b.Length -gt 524288){throw 'SOURCE_PIN_STOP'}
    $h=[Security.Cryptography.SHA1]::Create()
    try {
        $pre=[Text.Encoding]::ASCII.GetBytes(('blob '+$b.Length+[char]0))
        if([BitConverter]::ToString($h.ComputeHash([byte[]]($pre+$b))).Replace('-','').ToLowerInvariant() -cne $Pin){throw 'SOURCE_PIN_STOP'}
    } finally {$h.Dispose()}
    return $s
}
function Import-R1159Function([string]$Text,[string]$Name) {
    $t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$t,[ref]$e)
    if($e.Count -ne 0){throw 'SOURCE_PIN_STOP'}
    $nodes=@($a.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)|Where-Object {$_.Name -ceq $Name})
    if($nodes.Count -ne 1){throw 'SOURCE_PIN_STOP'}
    $p=@($nodes[0].Parameters|Where-Object {$null -ne $_}|ForEach-Object {$_.Extent.Text}) -join ','
    $b=$nodes[0].Body.Extent.Text
    Set-Item ('Function:script:'+$Name) ([scriptblock]::Create(('param('+$p+")`n"+$b.Substring(1,$b.Length-2))))
}
function Assert-R1159ExistingFile([string]$Path,[long]$Minimum,[long]$Maximum) {
    Assert-R1027LocalPath $Path
    $f=Get-Item -LiteralPath $Path -Force
    if($f.PSIsContainer -or $f.Length -lt $Minimum -or $f.Length -gt $Maximum -or
        ($f.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'LOCAL_FILE_UNVERIFIED'}
    $a=[IO.File]::GetAccessControl($Path)
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid -or -not $a.AreAccessRulesProtected -or -not $a.AreAccessRulesCanonical){throw 'LOCAL_ACL_UNVERIFIED'}
    # Same OS-management boundary as R1138, without running its ACL repair.
    $allow=@($sid,'S-1-5-18','S-1-5-32-544');$read=$false
    foreach($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($allow -cnotcontains $r.IdentityReference.Value -or $r.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow){throw 'LOCAL_ACL_UNVERIFIED'}
        if($r.IdentityReference.Value -ceq $sid -and ([int]$r.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]::ReadData)){$read=$true}
    }
    if(-not $read){throw 'LOCAL_ACL_UNVERIFIED'}
}
function Get-R1159Hash($Stream) {
    $h=[Security.Cryptography.SHA256]::Create()
    try {$Stream.Position=0;return [BitConverter]::ToString($h.ComputeHash($Stream)).Replace('-','').ToLowerInvariant()}
    finally {$h.Dispose();$Stream.Position=0}
}
function Read-R1159Bytes($Stream,[int]$Maximum) {
    if($Stream.Length -lt 1 -or $Stream.Length -gt $Maximum){throw 'LOCAL_FILE_BOUND'}
    $Stream.Position=0;$b=New-Object byte[] ([int]$Stream.Length);$offset=0
    while($offset -lt $b.Length){$n=$Stream.Read($b,$offset,$b.Length-$offset);if($n -le 0){throw 'LOCAL_FILE_BOUND'};$offset+=$n}
    return ,$b
}
function Invoke-R1159Local([string]$Operation,[byte[]]$InputBytes,[string]$Role='',[string]$Challenge='') {
    $null=Read-R1159Code 'packaging/migration/r1159_m2_bootstrap.py' '8c9f38b7ff6000900fa5f6fb8710132b41794f3e'
    if(@('--prepare','--guest','--finish') -cnotcontains $Operation){throw 'LOCAL_OPERATION_STOP'}
    $arguments='-I -B '+[FlopR1062.Guards]::Quote($script:R1159Program)+' '+$Operation
    if($Operation -ceq '--guest') {
        if(@('oci','k137') -cnotcontains $Role -or $Challenge -cnotmatch '\A[a-f0-9]{64}\z'){throw 'LOCAL_OPERATION_STOP'}
        $arguments+=' '+$Role+' '+$Challenge
    }
    $r=[FlopR1079.Transport]::Run($script:R1159Python,$arguments,$InputBytes,58000)
    if($r.ExitCode -ne 0) {
        try {$v=[Text.Encoding]::UTF8.GetString($r.Output)|ConvertFrom-Json;$script:R1159GuestCode=$v.code}catch{}
        throw 'LOCAL_HELPER_STOP'
    }
    return ,$r.Output
}
function Complete-R1159([bool]$Ready,[bool]$Clean,[byte[]]$Control) {
    if(-not $Clean){throw 'CLEANUP_STOP'}
    if(-not $Ready){throw 'M2_AUTHENTICATION_NOT_PROVEN'}
    $answer=Invoke-R1159Local '--finish' $Control
    $result=[Text.Encoding]::UTF8.GetString($answer)|ConvertFrom-Json
    if($result.code -cne 'M2_AUTHENTICATED_PUBLIC_ARTIFACTS_ONLY'){throw 'M2_PUBLIC_ARTIFACT_UNVERIFIED'}
    return $result
}
function Invoke-R1159 {
    $stage='SOURCE_PIN_STOP';$reply=$null;$password=$null;$rawKey=$null;$private=$null;$clean=$true
    $knownHandle=$null;$awsHandle=$null;$cipherHandle=$null;$control=$null;$encrypted=$null;$ready=$false;$output=$null
    $script:R1159GuestCode=''
    try {
        if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1){throw 'PS51_REQUIRED'}
        if(-not $Execute){$stage='EXPLICIT_READONLY_EXECUTION_REQUIRED';throw 'STOP'}
        $stage='OCI_INDEPENDENT_TRUST_REQUIRED'
        if($OracleHostKeySha256 -cnotmatch '\A[a-f0-9]{64}\z' -or
            $OracleTrustReference -cnotmatch '\Ahttps://github\.com/hanamaru777/technocore-safe-agent/issues/[0-9]+#issuecomment-[0-9]+\z'){throw 'STOP'}
        $stage='SOURCE_PIN_STOP'
        $null=Read-R1159Code 'packaging/migration/r1066_preflight_readonly.py' '9f5f90ed6ad22a253b18c1510ec2651a117a01bc'
        $null=Read-R1159Code 'packaging/migration/r1159_m2_bootstrap.py' '8c9f38b7ff6000900fa5f6fb8710132b41794f3e'
        $pins=Read-R1159Code 'packaging/migration/r1155_source_pins.json' 'e1ac08ced545205772808e403dbae1fba6dd8331'
        foreach($p in ($pins|ConvertFrom-Json).PSObject.Properties){$null=Read-R1159Code $p.Name $p.Value}
        $lib=Read-R1159Code 'packaging/migration/r1066_owner_workflow.ps1' '13978d6afb01fc3898018e045aded87d673ef683'
        foreach($name in @('Read-R1066PinnedSource','Initialize-R1066','Get-R1066Arguments')){Import-R1159Function $lib $name}
        $script:R1066Root=Join-Path $PSScriptRoot '..\migration';Initialize-R1066
        $awsLib=Read-R1159Code 'packaging/windows/r1138_lightsail_pem_single_acl_and_readonly_ssh.ps1' '317b245bca0161ad3827318892b12cbb24fc4cab'
        Import-R1159Function $awsLib 'Get-R1138ExactPem'
        $transport=Read-R1159Code 'packaging/migration/r1079_profile_ssh_transport.cs' 'b150af9fe7a335bc6c02e8fc1e5451599d124a97'
        if(-not ('FlopR1079.Transport' -as [type])){Add-Type -TypeDefinition $transport}
        $script:R1159Python=Join-Path $PSScriptRoot '..\..\.venv\Scripts\python.exe'
        $script:R1159Program=Join-Path $script:R1066Root 'r1159_m2_bootstrap.py'
        $stage='LOCAL_FILES_UNVERIFIED'
        $output=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'FLOP-R1159-M2'
        if([IO.Directory]::Exists($output) -or [IO.File]::Exists($output)){$stage='M2_ATTEMPT_ALREADY_EXISTS';throw 'STOP'}
        $ssh=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe';Assert-R1027LocalPath $ssh
        # Resolve the built-in PS5.1 security module from the OS, not inherited
        # PSModulePath (which may contain incompatible PowerShell 7 modules).
        Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
        $signature=Get-AuthenticodeSignature -LiteralPath $ssh
        if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation'){$stage='SSH_CLIENT_SIGNATURE_UNVERIFIED';throw 'STOP'}
        $known=Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\known_hosts'
        $stage='KNOWN_HOSTS_ACL_UNVERIFIED'
        Assert-R1159ExistingFile $known 1 16384
        $knownHandle=[IO.File]::Open($known,'Open','Read','Read')
        $knownBytes=Read-R1159Bytes $knownHandle 16384
        $planInput=@{oracle_key_sha256=$OracleHostKeySha256;oracle_trust_reference=$OracleTrustReference;
            known_hosts=(New-Object Text.UTF8Encoding($false,$true)).GetString($knownBytes)}|ConvertTo-Json -Depth 5 -Compress
        $stage='HOST_TRUST_UNVERIFIED'
        $plan=[Text.Encoding]::UTF8.GetString((Invoke-R1159Local '--prepare' ([Text.Encoding]::UTF8.GetBytes($planInput))))|ConvertFrom-Json
        $stage='AWS_KEY_SELECTION_UNVERIFIED'
        $aws=Get-R1138ExactPem;$stage='AWS_KEY_ACL_UNVERIFIED';Assert-R1159ExistingFile $aws.FullName 64 32768
        $awsHandle=[IO.File]::Open($aws.FullName,'Open','Read','Read');$awsHash=Get-R1159Hash $awsHandle
        $stage='OCI_ESCROW_SELECTION_UNVERIFIED';$backup=Find-R1027Backup
        $stage='OCI_ESCROW_ACL_UNVERIFIED';Assert-R1159ExistingFile $backup 32 65536
        $cipherHandle=[IO.File]::Open($backup,'Open','Read','Read');$encrypted=Read-R1159Bytes $cipherHandle 65536
        if([FlopR1062.Guards]::Sha256($encrypted) -cne [FlopR1062.Guards]::EXPECTED_SHA256){$stage='BACKUP_HASH_STOP';throw 'STOP'}
        if((Read-Host 'Type READ_ONLY_M2_NO_ENROLL_NO_HOLD') -cne 'READ_ONLY_M2_NO_ENROLL_NO_HOLD'){$stage='OWNER_READONLY_CONSENT_REQUIRED';throw 'STOP'}
        $stage='R987_RECOVERY_STOP'
        $password=Read-Host 'R987 V2 recovery code (OCI SSH only; NOT owner approval passphrase)' -AsSecureString
        try {$rawKey=Unprotect-R1027 $encrypted $password}finally{$password.Dispose();$password=$null}
        $ociHash=[FlopR1062.Guards]::Sha256($rawKey)
        $private=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Temp\flop-r1159-'+[Guid]::NewGuid().ToString('N'))
        New-R1027Custody $private;$key=Write-R1027Key $private $rawKey
        [FlopR1062.Guards]::Clear($rawKey);$rawKey=$null
        New-R1027Custody $output
        [IO.File]::WriteAllText((Join-Path $output 'ATTEMPTED.json'),'{"task":"R1159","authentication":"NOT_PROVEN","no_automatic_retry":true,"cutover":"NO_GO"}',[Text.Encoding]::ASCII)
        $reports=@{};$challenges=@{}
        foreach($role in @('oci','k137')) {
            $stage=$role.ToUpperInvariant()+'_SSH_READONLY_STOP'
            $knownTemp=Join-Path $private ($role+'-known-hosts')
            [IO.File]::WriteAllText($knownTemp,($plan.$role.host+' '+$plan.$role.host_key+"`n"),[Text.Encoding]::ASCII)
            Assert-R1027Acl $knownTemp
            $random=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
            try {$rng.GetBytes($random);$challenge=[BitConverter]::ToString($random).Replace('-','').ToLowerInvariant()}finally{$rng.Dispose();[Array]::Clear($random,0,$random.Length)}
            $guest=Invoke-R1159Local '--guest' ([byte[]]@()) $role $challenge
            $identity=if($role -ceq 'oci'){$key}else{$aws.FullName}
            $arguments=Get-R1066Arguments $plan.$role $role $identity $knownTemp
            $arguments=$arguments[0..($arguments.Count-3)]+@('-o','LogLevel=ERROR')+$arguments[($arguments.Count-2)..($arguments.Count-1)]
            $argText=(@($arguments|ForEach-Object {[FlopR1062.Guards]::Quote($_)}) -join ' ')
            $stage=$role.ToUpperInvariant()+'_SSH_READONLY_STOP'
            try {$r=[FlopR1079.Transport]::Run($ssh,$argText,$guest,58000)}catch {
                if($null -ne $_.Exception.InnerException -and $_.Exception.InnerException.Message -ceq 'TIMEOUT'){$stage=$role.ToUpperInvariant()+'_SSH_TIMEOUT'}
                throw 'STOP'
            }
            if($r.ExitCode -ne 0) {
                if($r.ExitCode -eq 255){$stage=$role.ToUpperInvariant()+'_'+$r.FailureKind}
                else {try {$v=[Text.Encoding]::UTF8.GetString($r.Output)|ConvertFrom-Json;$script:R1159GuestCode=$v.code}catch{}}
                throw 'STOP'
            }
            # Preserve exact remote JSON bytes. ConvertFrom-Json would erase
            # duplicate keys before the strict Python decoder could reject them.
            $reports[$role]=[Convert]::ToBase64String($r.Output);$challenges[$role]=$challenge
            if($role -ceq 'oci') {
                # No further OCI authentication in this one-shot. Do not keep
                # its plaintext SSH key while waiting on the K137 probe.
                $stage='CLEANUP_STOP'
                try {[IO.File]::Delete($key);if([IO.File]::Exists($key)){throw 'STOP'}}catch{$clean=$false;throw 'STOP'}
            }
        }
        if((Get-R1159Hash $awsHandle) -cne $awsHash){$stage='AWS_CREDENTIAL_CHANGED';throw 'STOP'}
        $finish=@{plan=$plan;report_bytes=$reports;challenges=$challenges;credential_hashes=@{oci=$ociHash;k137=$awsHash};k137_identity_file=$aws.FullName;output=$output}
        $control=[Text.Encoding]::UTF8.GetBytes(($finish|ConvertTo-Json -Depth 18 -Compress));$ready=$true
    } catch {
        $codes=@('OCI_INDEPENDENT_TRUST_REQUIRED','OCI_HOST_TRUST_MISMATCH','KNOWN_HOSTS_AMBIGUOUS','KNOWN_HOSTS_INVALID','K137_HOST_TRUST_MISMATCH',
            'K137_LOGIN_CGROUP_UNBOUNDED','M2_CGROUP_MEMBERSHIP_UNVERIFIED','M2_BOOT_CHANGED','M2_CGROUP_CHANGED','M2_UID_MISMATCH',
            'M2_MACHINE_MISMATCH','M2_HEAD_MISMATCH','M2_PUBLIC_DID_UNVERIFIED','M2_PUBLIC_DID_CHANGED','M2_DISK_INSUFFICIENT',
            'M2_TRADEBOT_CAP_CHANGED','M2_TRADEBOT_METADATA_UNVERIFIED','M2_SOURCE_PIN_MISMATCH','M2_OWNER_PUBLIC_UNVERIFIED')
        if($codes -ccontains $script:R1159GuestCode){$stage=$script:R1159GuestCode}
        # Stage is assigned only fixed literals or the pinned carrier taxonomy.
        $allowed=@('SOURCE_PIN_STOP','PS51_REQUIRED','EXPLICIT_READONLY_EXECUTION_REQUIRED','OCI_INDEPENDENT_TRUST_REQUIRED','LOCAL_FILES_UNVERIFIED','CLEANUP_STOP',
            'KNOWN_HOSTS_ACL_UNVERIFIED','AWS_KEY_SELECTION_UNVERIFIED','AWS_KEY_ACL_UNVERIFIED','OCI_ESCROW_SELECTION_UNVERIFIED','OCI_ESCROW_ACL_UNVERIFIED','OCI_SSH_TIMEOUT','K137_SSH_TIMEOUT',
            'M2_ATTEMPT_ALREADY_EXISTS','SSH_CLIENT_SIGNATURE_UNVERIFIED','HOST_TRUST_UNVERIFIED','BACKUP_HASH_STOP','OWNER_READONLY_CONSENT_REQUIRED',
            'R987_RECOVERY_STOP','OCI_SSH_READONLY_STOP','K137_SSH_READONLY_STOP','AWS_CREDENTIAL_CHANGED')+$codes
        foreach($role in @('OCI','K137')){foreach($kind in @('SSH_OPTION_REJECTED','SSH_HOSTKEY_REJECTED','SSH_IDENTITY_UNREADABLE','SSH_PUBLIC_KEY_REJECTED','SSH_CONNECTIVITY_REJECTED','SSH_REMOTE_CLOSED','SSH_UNKNOWN')){$allowed+=($role+'_'+$kind)}}
        if($allowed -cnotcontains $stage){$stage='M2_UNVERIFIED_STOP'}
        $reply=@{code=$stage;cutover='NO_GO';oci_retirement='STRICT_NO_GO'}
    } finally {
        if($null -ne $password){$password.Dispose()}
        foreach($b in @($rawKey,$encrypted)){if($null -ne $b){[Array]::Clear($b,0,$b.Length)}}
        foreach($handle in @($knownHandle,$awsHandle,$cipherHandle)){if($null -ne $handle){try{$handle.Dispose()}catch{$clean=$false}}}
        if($null -ne $private){try {
            foreach($name in @('oci-known-hosts','k137-known-hosts')){$p=Join-Path $private $name;if([IO.File]::Exists($p)){[IO.File]::Delete($p)}}
            Remove-R1027Custody $private
        }catch{$clean=$false}}
    }
    # No public endpoints/receipt until ephemeral SSH-key cleanup succeeded.
    if(-not $clean){$ready=$false;$reply=@{code='CLEANUP_STOP';cutover='NO_GO';oci_retirement='STRICT_NO_GO'}}
    try {
        if($ready){
            $reply=Complete-R1159 $ready $clean $control
        }
    } catch {$reply=@{code='M2_PUBLIC_ARTIFACT_UNVERIFIED';cutover='NO_GO';oci_retirement='STRICT_NO_GO'}}
    finally {if($null -ne $control){[Array]::Clear($control,0,$control.Length)}}
    [Console]::Out.WriteLine(($reply|ConvertTo-Json -Compress))
    if($ready -and $reply.code -ceq 'M2_AUTHENTICATED_PUBLIC_ARTIFACTS_ONLY'){return 0};return 42
}
if($args.Count -ne 0){[Console]::Out.WriteLine('{"code":"ARGS_STOP","cutover":"NO_GO"}');exit 42}
exit (Invoke-R1159)
