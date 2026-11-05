# R1161 isolated owner-local PS5.1 one-shot. Definition imports only; no old entrypoint.
param([switch]$Execute,[string]$PlanFile='',[string]$PlanSha256='',
      [switch]$CrossCertOriginal,[string]$OriginalEvidenceFile='')
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Read-R1161Pinned([string]$Name,[string]$Pin) {
    $path=Join-Path $PSScriptRoot ('..\..\'+$Name.Replace('/','\'))
    $f=Get-Item -LiteralPath $path
    if($f.Length -gt 524288 -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'SOURCE_PIN_STOP'}
    $text=[IO.File]::ReadAllText($path,[Text.Encoding]::UTF8).Replace("`r`n","`n")
    $b=[Text.Encoding]::UTF8.GetBytes($text)
    $h=[Security.Cryptography.SHA1]::Create()
    try {
        $pre=[Text.Encoding]::ASCII.GetBytes(('blob '+$b.Length+[char]0))
        if([BitConverter]::ToString($h.ComputeHash([byte[]]($pre+$b))).Replace('-','').ToLowerInvariant() -cne $Pin){throw 'SOURCE_PIN_STOP'}
    } finally {$h.Dispose()}
    return $text
}

function Import-R1161Definition([string]$Text,[string]$Name) {
    $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$t,[ref]$e)
    if($e.Count -ne 0){throw 'SOURCE_PIN_STOP'}
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)|Where-Object {$_.Name -ceq $Name})
    if($nodes.Count -ne 1){throw 'SOURCE_PIN_STOP'}
    $parameters=@($nodes[0].Parameters|Where-Object {$null -ne $_}|ForEach-Object {$_.Extent.Text}) -join ','
    $body=$nodes[0].Body.Extent.Text
    Set-Item ('Function:script:'+$Name) ([scriptblock]::Create(('param('+$parameters+")`n"+$body.Substring(1,$body.Length-2))))
}

function Initialize-R1161 {
    $base=Read-R1161Pinned 'packaging/windows/r1159_authenticated_m2_bootstrap.ps1' '48029e5c61c51a8edf3993130b7014c11f68b077'
    foreach($n in @('Import-R1159Function','Read-R1159Bytes')){Import-R1161Definition $base $n}
    $carrier=Read-R1161Pinned 'packaging/migration/r1079_profile_ssh_transport.cs' 'b150af9fe7a335bc6c02e8fc1e5451599d124a97'
    if(-not ('FlopR1079.Transport' -as [type])){Add-Type -TypeDefinition $carrier}
    $null=Read-R1161Pinned 'packaging/migration/r1161_readonly_admission.py' 'da22367446c9d740a9e116e5989638257f9717e8'
    $script:R1161Python=Join-Path $PSScriptRoot '..\..\.venv\Scripts\python.exe'
    $script:R1161Program=Join-Path $PSScriptRoot '..\migration\r1161_readonly_admission.py'
    if(-not [IO.File]::Exists($script:R1161Python)){throw 'SOURCE_PIN_STOP'}
}

function Invoke-R1161Local([string]$Operation,[byte[]]$InputBytes) {
    if(@('--check','--guest-k137','--trust-status','--authorize-original','--guest-original','--receipt-k137','--receipt-original') -cnotcontains $Operation){throw 'SOURCE_PIN_STOP'}
    $null=Read-R1161Pinned 'packaging/migration/r1161_readonly_admission.py' 'da22367446c9d740a9e116e5989638257f9717e8'
    # This also precedes Initialize-R1027, so use the strictly quoted fixed paths.
    foreach($p in @($script:R1161Program,$script:R1161Python)){
        if($p -match '["\x00-\x1f]' -or $p.EndsWith('\')){throw 'SOURCE_PIN_STOP'}
    }
    $a='-I -B "'+$script:R1161Program+'" '+$Operation
    $r=[FlopR1079.Transport]::Run($script:R1161Python,$a,$InputBytes,58000)
    if($r.ExitCode -ne 0){
        $code='R1161_SCHEMA_STOP'
        try {
            $v=[Text.Encoding]::UTF8.GetString($r.Output)|ConvertFrom-Json
            if(@('SOURCE_PIN_STOP','K137_BOOT_SCOPE_STOP','K137_GUEST_STOP','K137_LOGIN_CGROUP_UNBOUNDED',
                'ORIGINAL_ED25519_INDEPENDENT_TRUST_REQUIRED','ORIGINAL_HOST_KEY_STOP','ORIGINAL_CROSSCERT_STOP',
                'PLAN_EXPIRED_STOP','K137_ADMISSION_REQUIRED') -ccontains $v.code){$code=$v.code}
        }catch{}
        throw $code
    }
    return ,$r.Output
}

function Convert-R1161Bytes($Value) {
    return ,[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 20 -Compress))
}

function Assert-R1161Private([string]$Path,[bool]$Directory=$false) {
    Assert-R1027LocalPath $Path
    $f=Get-Item -LiteralPath $Path -Force
    if($f.PSIsContainer -ne $Directory -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'PRIVATE_ACL_STOP'}
    $a=if($Directory){[IO.Directory]::GetAccessControl($Path)}else{[IO.File]::GetAccessControl($Path)}
    if(-not $a.AreAccessRulesCanonical -or -not $a.AreAccessRulesProtected){throw 'PRIVATE_ACL_STOP'}
    Assert-R1027Acl $Path
}

function New-R1161Attempt([string]$Output) {
    # Caller holds a current-user mutex. CreateNew marker survives every failure.
    if([IO.Directory]::Exists($Output) -or [IO.File]::Exists($Output)){throw 'R1161_ATTEMPT_ALREADY_EXISTS'}
    New-R1027Custody $Output
    $marker=Join-Path $Output 'ATTEMPTED.json'
    $f=[IO.File]::Open($marker,'CreateNew','Write','None')
    try {
        $b=[Text.Encoding]::ASCII.GetBytes('{"task":"R1161","no_automatic_retry":true,"cutover":"NO_GO"}')
        $f.Write($b,0,$b.Length);$f.Flush($true)
    }finally{$f.Dispose()}
}

function New-R1161Mutex([string]$Name) {
    return New-Object Threading.Mutex($false,$Name)
}

function Get-R1161Arguments([string]$Role,[string]$Identity,[string]$Known) {
    if(@('k137','original') -cnotcontains $Role){throw 'SSH_ARGUMENT_STOP'}
    foreach($p in @($Identity,$Known)){
        if(-not [IO.Path]::IsPathRooted($p) -or $p -match '["\x00-\x1f]' -or $p.EndsWith('\')){throw 'SSH_ARGUMENT_STOP'}
    }
    $hostIp=if($Role -ceq 'k137'){'52.198.96.243'}else{'140.238.55.171'}
    $endpoint=[pscustomobject]@{user='ubuntu';host=$hostIp;host_key='ssh-ed25519 fixed'}
    # Both roles use the reviewed K137 argument builder branch: NO sudo.
    $a=Get-R1066Arguments $endpoint 'k137' $Identity $Known
    return $a[0..($a.Count-3)]+@('-o','LogLevel=ERROR')+$a[($a.Count-2)..($a.Count-1)]
}

function Invoke-R1161Ssh([string]$Role,[string]$Identity,[string]$Known,[byte[]]$Guest) {
    $a=Get-R1161Arguments $Role $Identity $Known
    $text=(@($a|ForEach-Object {[FlopR1062.Guards]::Quote($_)}) -join ' ')
    $r=[FlopR1079.Transport]::Run($script:R1161Ssh,$text,$Guest,58000)
    if($r.ExitCode -ne 0){
        if($r.ExitCode -eq 255 -and $r.FailureKind -ceq 'SSH_HOSTKEY_REJECTED'){throw 'SSH_HOST_KEY_STOP'}
        if($Role -ceq 'k137'){
            try {$v=[Text.Encoding]::UTF8.GetString($r.Output)|ConvertFrom-Json}catch{$v=$null}
            if($null -ne $v -and $v.code -ceq 'K137_LOGIN_CGROUP_UNBOUNDED'){throw 'K137_LOGIN_CGROUP_UNBOUNDED'}
        }
        throw 'SSH_READONLY_STOP'
    }
    return ,[Convert]::ToBase64String($r.Output)
}

function Write-R1161Public([string]$Folder,[string]$Name,[byte[]]$Bytes,[bool]$Clean) {
    if(-not $Clean){throw 'CLEANUP_STOP'}
    if(@('k137-admission.json','original-crosscert.json') -cnotcontains $Name -or $Bytes.Length -gt 8192){throw 'PUBLIC_RECEIPT_STOP'}
    Assert-R1161Private $Folder $true
    $p=Join-Path $Folder $Name
    $f=[IO.File]::Open($p,'CreateNew','Write','None')
    try{$f.Write($Bytes,0,$Bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
    $h=[FlopR1062.Guards]::Sha256($Bytes)
    $f=[IO.File]::Open(($p+'.sha256'),'CreateNew','Write','None')
    try{$b=[Text.Encoding]::ASCII.GetBytes($h+"`n");$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
    return $h
}

function Remove-R1161Temporary([string]$Folder) {
    foreach($n in @('k137-known-hosts','original-known-hosts')){
        $p=Join-Path $Folder $n
        if([IO.File]::Exists($p)){[IO.File]::Delete($p)}
        if([IO.File]::Exists($p)){throw 'CLEANUP_STOP'}
    }
    Remove-R1027Custody $Folder
}

function Invoke-R1161 {
    $mutex=$null;$held=$false;$temporary=$null;$awsHandle=$null;$cipherHandle=$null
    $password=$null;$plain=$null;$encrypted=$null;$clean=$true;$code='R1161_UNVERIFIED_STOP'
    $kHash=$null;$oHash=$null
    try {
        if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'PS51_REQUIRED'}
        if(-not $Execute){throw 'EXPLICIT_READONLY_EXECUTION_REQUIRED'}
        if($PlanFile -eq '' -or $PlanSha256 -cnotmatch '\A[a-f0-9]{64}\z'){throw 'PUBLIC_PLAN_REQUIRED'}
        Initialize-R1161
        # Bound public plan only. No credential selector/old workflow runs here.
        if((Get-Item -LiteralPath $PlanFile).Length -gt 4096){throw 'PUBLIC_PLAN_REQUIRED'}
        $planBytes=[IO.File]::ReadAllBytes($PlanFile)
        $h=[Security.Cryptography.SHA256]::Create()
        try{$seen=[BitConverter]::ToString($h.ComputeHash($planBytes)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
        if($seen -cne $PlanSha256){throw 'PUBLIC_PLAN_REQUIRED'}
        $checked=[Text.Encoding]::UTF8.GetString((Invoke-R1161Local '--check' $planBytes))|ConvertFrom-Json
        $plan=[Text.Encoding]::UTF8.GetString($planBytes)|ConvertFrom-Json
        $lib=Read-R1161Pinned 'packaging/migration/r1066_owner_workflow.ps1' '13978d6afb01fc3898018e045aded87d673ef683'
        foreach($n in @('Read-R1066PinnedSource','Initialize-R1066','Get-R1066Arguments')){Import-R1159Function $lib $n}
        $script:R1066Root=Join-Path $PSScriptRoot '..\migration';Initialize-R1066
        Assert-R1161Private $PlanFile
        $pemLib=Read-R1161Pinned 'packaging/windows/r1138_lightsail_pem_single_acl_and_readonly_ssh.ps1' '317b245bca0161ad3827318892b12cbb24fc4cab'
        Import-R1159Function $pemLib 'Get-R1138ExactPem'
        $script:R1161Ssh=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe'
        Assert-R1027LocalPath $script:R1161Ssh
        Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1')
        $s=Get-AuthenticodeSignature -LiteralPath $script:R1161Ssh
        if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation'){throw 'SSH_CLIENT_SIGNATURE_STOP'}
        $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $sidHash=[FlopR1062.Guards]::Sha256([Text.Encoding]::ASCII.GetBytes($sid))
        $mutex=New-R1161Mutex ('Local\FLOP-R1161-'+$sidHash)
        $held=$mutex.WaitOne(0)
        if(-not $held){throw 'R1161_ATTEMPT_LOCKED'}
        $output=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'FLOP-R1161'
        if([IO.Directory]::Exists($output) -or [IO.File]::Exists($output)){throw 'R1161_ATTEMPT_ALREADY_EXISTS'}
        if((Read-Host 'Type READ_ONLY_R1161_NO_M2_NO_HOLD') -cne 'READ_ONLY_R1161_NO_M2_NO_HOLD'){throw 'OWNER_READONLY_CONSENT_REQUIRED'}
        New-R1161Attempt $output
        # K137 FIRST. No Oracle file, recovery prompt, or connection before PASS.
        try{$aws=Get-R1138ExactPem}catch{throw 'K137_KEY_SELECTION_STOP'}
        Assert-R1161Private $aws.FullName
        $awsHandle=[IO.File]::Open($aws.FullName,'Open','Read','Read')
        $temporary=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Temp\flop-r1161-'+[Guid]::NewGuid().ToString('N'))
        New-R1027Custody $temporary
        $known=Join-Path $temporary 'k137-known-hosts'
        [IO.File]::WriteAllText($known,('52.198.96.243 '+$checked.k137_key+"`n"),[Text.Encoding]::ASCII)
        Assert-R1027Acl $known
        $guest=Invoke-R1161Local '--guest-k137' $planBytes
        $kraw=Invoke-R1161Ssh 'k137' $aws.FullName $known $guest
        $control=@{plan=$plan;k137=$kraw}
        $kReceipt=Invoke-R1161Local '--receipt-k137' (Convert-R1161Bytes $control)
        $awsHandle.Dispose();$awsHandle=$null
        Remove-R1161Temporary $temporary;$temporary=$null
        $kHash=Write-R1161Public $output 'k137-admission.json' $kReceipt $true
        $code='K137_BOUND_READONLY_ADMISSION_PASS'
        if($CrossCertOriginal){
            # Source-root authority, NOT URL syntax or a caller-chosen digest.
            $null=Invoke-R1161Local '--trust-status' ([Text.Encoding]::ASCII.GetBytes('{}'))
            Assert-R1161Private $OriginalEvidenceFile
            $f=[IO.File]::Open($OriginalEvidenceFile,'Open','Read','Read')
            try{$evidence=[Convert]::ToBase64String((Read-R1159Bytes $f 4096))}finally{$f.Dispose()}
            $authorized=[Text.Encoding]::UTF8.GetString((Invoke-R1161Local '--authorize-original' (Convert-R1161Bytes @{evidence=$evidence})))|ConvertFrom-Json
            # Check admission freshness again before touching Oracle escrow.
            $null=Invoke-R1161Local '--receipt-k137' (Convert-R1161Bytes $control)
            $backup=Find-R1027Backup
            Assert-R1161Private $backup
            $cipherHandle=[IO.File]::Open($backup,'Open','Read','Read')
            $encrypted=Read-R1159Bytes $cipherHandle 65536
            if([FlopR1062.Guards]::Sha256($encrypted) -cne [FlopR1062.Guards]::EXPECTED_SHA256){throw 'ORIGINAL_ESCROW_HASH_STOP'}
            $password=Read-Host 'R987 V2 recovery code (local OCI SSH only)' -AsSecureString
            try{$plain=Unprotect-R1027 $encrypted $password}finally{$password.Dispose();$password=$null}
            $temporary=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Temp\flop-r1161-'+[Guid]::NewGuid().ToString('N'))
            New-R1027Custody $temporary
            $key=Write-R1027Key $temporary $plain
            [FlopR1062.Guards]::Clear($plain);$plain=$null
            $known=Join-Path $temporary 'original-known-hosts'
            [IO.File]::WriteAllText($known,('140.238.55.171 '+$authorized.key+"`n"),[Text.Encoding]::ASCII)
            Assert-R1027Acl $known
            $guest=Invoke-R1161Local '--guest-original' $planBytes
            # Recovery input may take time: do not connect on stale K137 proof.
            $null=Invoke-R1161Local '--receipt-k137' (Convert-R1161Bytes $control)
            $control.original=Invoke-R1161Ssh 'original' $key $known $guest
            $control.evidence=$evidence
            $cipherHandle.Dispose();$cipherHandle=$null
            [FlopR1062.Guards]::Clear($encrypted);$encrypted=$null
            Remove-R1161Temporary $temporary;$temporary=$null
            $oReceipt=Invoke-R1161Local '--receipt-original' (Convert-R1161Bytes $control)
            $oHash=Write-R1161Public $output 'original-crosscert.json' $oReceipt $true
            $code='ORIGINAL_GUEST_ED25519_ECDSA_CROSSCERT_PASS'
        }
    }catch {
        $allowed=@('PS51_REQUIRED','EXPLICIT_READONLY_EXECUTION_REQUIRED','PUBLIC_PLAN_REQUIRED','SOURCE_PIN_STOP',
            'R1161_SCHEMA_STOP','PRIVATE_ACL_STOP','ACL_STOP','SSH_CLIENT_SIGNATURE_STOP','R1161_ATTEMPT_LOCKED',
            'R1161_ATTEMPT_ALREADY_EXISTS','OWNER_READONLY_CONSENT_REQUIRED','K137_KEY_SELECTION_STOP','SSH_ARGUMENT_STOP',
            'SSH_HOST_KEY_STOP','SSH_READONLY_STOP','K137_LOGIN_CGROUP_UNBOUNDED','K137_GUEST_STOP','K137_BOOT_SCOPE_STOP',
            'ORIGINAL_ED25519_INDEPENDENT_TRUST_REQUIRED','ORIGINAL_HOST_KEY_STOP','ORIGINAL_CROSSCERT_STOP',
            'PLAN_EXPIRED_STOP','K137_ADMISSION_REQUIRED','ORIGINAL_ESCROW_HASH_STOP','PUBLIC_RECEIPT_STOP','CLEANUP_STOP')
        if($allowed -ccontains $_.Exception.Message){$code=$_.Exception.Message}else{$code='R1161_UNVERIFIED_STOP'}
    }finally {
        if($null -ne $password){$password.Dispose()}
        foreach($b in @($plain,$encrypted)){if($null -ne $b){[Array]::Clear($b,0,$b.Length)}}
        foreach($f in @($awsHandle,$cipherHandle)){if($null -ne $f){try{$f.Dispose()}catch{$clean=$false}}}
        if($null -ne $temporary){try{Remove-R1161Temporary $temporary}catch{$clean=$false}}
        if($held){try{$mutex.ReleaseMutex()}catch{$clean=$false}}
        if($null -ne $mutex){$mutex.Dispose()}
    }
    if(-not $clean){$code='CLEANUP_STOP';$oHash=$null}
    $answer=@{task='R1161';code=$code;k137_receipt_sha256=$kHash;original_receipt_sha256=$oHash;cutover='NO_GO';oci_retirement='STRICT_NO_GO';m2='NOT_AUTHORIZED'}
    [Console]::Out.WriteLine(($answer|ConvertTo-Json -Compress))
    if($clean -and @('K137_BOUND_READONLY_ADMISSION_PASS','ORIGINAL_GUEST_ED25519_ECDSA_CROSSCERT_PASS') -ccontains $code){return 0}
    return 42
}

if($args.Count -ne 0){[Console]::Out.WriteLine('{"code":"ARGS_STOP","cutover":"NO_GO"}');exit 42}
exit (Invoke-R1161)
