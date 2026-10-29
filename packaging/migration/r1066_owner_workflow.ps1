# Windows PowerShell 5.1: default READ-ONLY preflight; explicit R1089 preservation
# mode requires independently authenticated owner/fence evidence. Never cutover.
# Independent enrollment must exist BEFORE any escrow prompt or SSH operation.
param([string]$EnrollmentFile = '', [string]$EnrollmentSha256 = '',
    [switch]$StageCiphertext,
    [string]$SealedArchiveRoot = '',
    [string]$ArchiveId = '',
    [switch]$PreserveAndRestore,
    [string]$PlanFile = '', [string]$PlanSha256 = '')
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:R1066Root = $PSScriptRoot

function Read-R1066PinnedSource([string]$Path, [string]$Blob) {
    if ((Get-Item -LiteralPath $Path).Length -gt 65536) { throw 'SOURCE_PIN_STOP' }
    $raw = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8).Replace("`r`n", "`n")
    $bytes = [Text.Encoding]::UTF8.GetBytes($raw)
    $prefix = [Text.Encoding]::ASCII.GetBytes(('blob ' + $bytes.Length + [char]0))
    $sha = [Security.Cryptography.SHA1]::Create()
    try {
        $null = $sha.TransformBlock($prefix, 0, $prefix.Length, $prefix, 0)
        $null = $sha.TransformFinalBlock($bytes, 0, $bytes.Length)
        $seen = [BitConverter]::ToString($sha.Hash).Replace('-', '').ToLowerInvariant()
        if ($seen -cne $Blob) { throw 'SOURCE_PIN_STOP' }
    } finally { $sha.Dispose() }
    return $raw
}

function Initialize-R1066 {
    # Import ONLY pinned R987 custody/ACL helpers. Never execute the consumed
    # R1062 entrypoint or its Get-R1027Source/SSH/witness functions.
    $path = Join-Path $script:R1066Root '..\windows\r1062_writer_attribution_one_shot_readonly.ps1'
    $text = Read-R1066PinnedSource $path '7ad3432b89b2aa2fe4a5e6b0142ec7578554baaa'
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'SOURCE_PIN_STOP' }
    foreach ($name in @('Initialize-R1027', 'Assert-R1027LocalPath', 'New-R1027Custody',
        'Assert-R1027Acl', 'Write-R1027Key', 'Remove-R1027Custody',
        'Find-R1027Backup', 'Read-R1027Backup', 'Unprotect-R1027')) {
        $nodes = @($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]}, $true) |
            Where-Object { $_.Name -ceq $name })
        if ($nodes.Count -ne 1) { throw 'SOURCE_PIN_STOP' }
        $parameters = @($nodes[0].Parameters | Where-Object { $null -ne $_ } | ForEach-Object { $_.Extent.Text }) -join ','
        $body = $nodes[0].Body.Extent.Text
        $block = [scriptblock]::Create(('param(' + $parameters + ")`n" + $body.Substring(1, $body.Length - 2)))
        Set-Item -Path ('Function:script:' + $name) -Value $block
    }
    Initialize-R1027
    $carrier = Read-R1066PinnedSource (Join-Path $script:R1066Root 'r1066_preflight_transport.cs') '305530a86db7e5cc8812fbac57c3e2c7c089a7be'
    if (-not ('FlopR1066.Transport' -as [type])) { Add-Type -TypeDefinition $carrier }
}

function Assert-R1066Keys($Object, [string[]]$Expected) {
    if ($null -eq $Object -or $Object -isnot [Management.Automation.PSCustomObject]) { throw 'SCHEMA_STOP' }
    $keys = @($Object.PSObject.Properties.Name)
    if ($keys.Count -ne $Expected.Count) { throw 'SCHEMA_STOP' }
    foreach ($key in $keys) { if ($Expected -cnotcontains $key) { throw 'SCHEMA_STOP' } }
}

function Test-R1066Integer($Value, [long]$Min, [long]$Max) {
    return (($Value -is [int] -or $Value -is [long]) -and $Value -ge $Min -and $Value -le $Max)
}

function Get-R1066FileDigest([string]$Path) {
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 65536) { throw 'FILE_BOUND_STOP' }
        return [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
    } finally { $hash.Dispose(); $stream.Dispose() }
}

function Assert-R1066Endpoint($Endpoint, [string]$Role) {
    Assert-R1066Keys $Endpoint @('host', 'user', 'host_key', 'host_key_sha256',
        'credential_sha256', 'identity_file', 'machine_sha256', 'uid', 'head',
        'cgroup_sha256', 'minimum_free_bytes')
    $ip = $null
    if ($Endpoint.host -isnot [string] -or -not [Net.IPAddress]::TryParse($Endpoint.host, [ref]$ip) -or
        $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.ToString() -cne $Endpoint.host -or
        $Endpoint.host -match '^(0|127|169\.254|224|255)\.') { throw 'HOST_ENROLLMENT_STOP' }
    if ($Endpoint.user -isnot [string] -or $Endpoint.user -cnotmatch '\A[a-z][a-z0-9_-]{0,31}\z') { throw 'HOST_ENROLLMENT_STOP' }
    foreach ($key in @('host_key_sha256', 'credential_sha256', 'machine_sha256', 'cgroup_sha256')) {
        if ($Endpoint.$key -isnot [string] -or $Endpoint.$key -cnotmatch '\A[0-9a-f]{64}\z') { throw 'HOST_ENROLLMENT_STOP' }
    }
    if ($Endpoint.head -isnot [string] -or $Endpoint.head -cnotmatch '\A[0-9a-f]{40}\z' -or
        -not (Test-R1066Integer $Endpoint.uid 0 2147483647) -or
        -not (Test-R1066Integer $Endpoint.minimum_free_bytes 1073741824 1125899906842624)) { throw 'HOST_ENROLLMENT_STOP' }
    if ($Endpoint.host_key -isnot [string] -or $Endpoint.host_key.Length -gt 1024 -or
        $Endpoint.host_key -cnotmatch '\A(ssh-ed25519|ecdsa-sha2-nistp256) ([A-Za-z0-9+/]+={0,2})\z') { throw 'HOST_KEY_STOP' }
    $keyBytes = [Convert]::FromBase64String($Endpoint.host_key.Split(' ')[1])
    if ($keyBytes.Length -lt 32 -or [FlopR1062.Guards]::Sha256($keyBytes) -cne $Endpoint.host_key_sha256) { throw 'HOST_KEY_STOP' }
    if ($Role -ceq 'oci') {
        if ($Endpoint.host -cne '140.238.55.171' -or $Endpoint.user -cne 'ubuntu' -or
            $Endpoint.uid -ne 0 -or $Endpoint.identity_file -cne 'R987_V2_ESCROW' -or
            -not $Endpoint.host_key.StartsWith('ecdsa-sha2-nistp256 ') -or
            $Endpoint.head -cne 'ec4bc4892d40cdd2a03e102faa44d72c89e01b99') { throw 'OCI_BINDING_STOP' }
    } else {
        if ($Role -cne 'k137' -or $Endpoint.host -ceq '140.238.55.171' -or $Endpoint.user -ceq 'root' -or $Endpoint.uid -eq 0 -or
            $Endpoint.identity_file -isnot [string] -or $Endpoint.identity_file -match '["\r\n]' -or
            -not [IO.File]::Exists($Endpoint.identity_file)) { throw 'K137_CREDENTIAL_STOP' }
        Assert-R1027LocalPath $Endpoint.identity_file
        Assert-R1027Acl $Endpoint.identity_file
        if ((Get-R1066FileDigest $Endpoint.identity_file) -cne $Endpoint.credential_sha256) {
            throw 'K137_CREDENTIAL_STOP'
        }
    }
}

function Read-R1066Enrollment([string]$Path, [string]$Digest) {
    if (-not $Path -or $Digest -cnotmatch '\A[0-9a-f]{64}\z') { throw 'K137_INDEPENDENT_ENROLLMENT_REQUIRED' }
    Assert-R1027LocalPath $Path
    Assert-R1027Acl $Path
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try {
        if ($stream.Length -lt 50 -or $stream.Length -gt 16384) { throw 'ENROLLMENT_STOP' }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $n = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($n -le 0) { throw 'ENROLLMENT_STOP' }; $offset += $n
        }
    } finally { $stream.Dispose() }
    if ([FlopR1062.Guards]::Sha256($bytes) -cne $Digest) { throw 'ENROLLMENT_PIN_STOP' }
    $text = (New-Object Text.UTF8Encoding($false, $true)).GetString($bytes)
    $e = $text | ConvertFrom-Json
    Assert-R1066Keys $e @('schema_version', 'purpose', 'oci', 'k137')
    # Exact property-token count additionally rejects duplicate JSON keys.
    if ([regex]::Matches($text, '"[a-z0-9_]+"\s*:').Count -ne 26 -or
        -not (Test-R1066Integer $e.schema_version 1 1) -or $e.purpose -cne 'R1066_READONLY_PREFLIGHT') { throw 'ENROLLMENT_STOP' }
    Assert-R1066Endpoint $e.oci 'oci'
    Assert-R1066Endpoint $e.k137 'k137'
    if ($e.oci.credential_sha256 -ceq $e.k137.credential_sha256 -or
        $e.oci.machine_sha256 -ceq $e.k137.machine_sha256 -or
        $e.oci.host_key_sha256 -ceq $e.k137.host_key_sha256) { throw 'HOST_DOMAIN_STOP' }
    return $e
}

function Get-R1066Arguments($Endpoint, [string]$Role, [string]$Key, [string]$KnownHosts) {
    # No command/path/env override from enrollment. The roles are not interchangeable.
    $command = '/usr/bin/python3 -I -B -'
    if ($Role -ceq 'oci') { $command = 'sudo -n /usr/bin/python3 -I -B -' }
    elseif ($Role -cne 'k137') { throw 'ROLE_STOP' }
    return @('-F', 'NUL', '-T', '-i', $Key, '-o', ('UserKnownHostsFile="' + $KnownHosts.Replace('\', '/') + '"'),
        '-o', 'GlobalKnownHostsFile=NUL', '-o', 'StrictHostKeyChecking=yes',
        '-o', ('HostKeyAlgorithms=' + $Endpoint.host_key.Split(' ')[0]),
        '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'PreferredAuthentications=publickey', '-o', 'HostbasedAuthentication=no',
        '-o', 'GSSAPIAuthentication=no', '-o', 'UpdateHostKeys=no',
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
        '-o', 'ClearAllForwardings=yes', '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no',
        '-o', 'PermitLocalCommand=no', '-o', 'KnownHostsCommand=none',
        '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none', '-o', 'CanonicalizeHostname=no',
        '-o', 'ConnectionAttempts=1', '-o', 'ConnectTimeout=7',
        '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2',
        ($Endpoint.user + '@' + $Endpoint.host), $command)
}

function New-R1066Request($Endpoint, [string]$Role) {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [ordered]@{role=$Role; machine_sha256=$Endpoint.machine_sha256; uid=$Endpoint.uid;
        head=$Endpoint.head; cgroup_sha256=$Endpoint.cgroup_sha256; minimum_free_bytes=$Endpoint.minimum_free_bytes;
        challenge=([BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant())}
}

function Read-R1066Response([byte[]]$Bytes, $Request) {
    if ($Bytes.Length -lt 100 -or $Bytes.Length -gt 4096) { throw 'RESPONSE_STOP' }
    foreach ($b in $Bytes) { if ($b -ne 10 -and ($b -lt 32 -or $b -gt 126)) { throw 'RESPONSE_STOP' } }
    $text = [Text.Encoding]::ASCII.GetString($Bytes)
    $r = $text | ConvertFrom-Json
    $keys = @('schema_version', 'role', 'challenge', 'host_identity', 'head', 'scope', 'disk_free_bytes',
        'disk_required_bytes', 'resources', 'memory_max_bytes', 'pids_max', 'protected_tradebot', 'read_only',
        'writer_admission', 'five_post_finality', 'common_sqlite_epoch', 'signer_portability',
        'restore_authority', 'cutover', 'oci_retirement')
    Assert-R1066Keys $r $keys
    if ([regex]::Matches($text, '"[a-z0-9_]+"\s*:').Count -ne $keys.Count -or
        -not (Test-R1066Integer $r.schema_version 1 1) -or $r.role -cne $Request.role -or $r.challenge -cne $Request.challenge -or
        $r.read_only -isnot [bool] -or -not $r.read_only) { throw 'RESPONSE_STOP' }
    foreach ($key in @('host_identity', 'head', 'scope')) { if ($r.$key -cne 'MATCH') { throw 'RESPONSE_STOP' } }
    foreach ($key in @('writer_admission', 'five_post_finality', 'common_sqlite_epoch', 'signer_portability', 'restore_authority')) {
        if ($r.$key -cne 'NOT_PROVEN') { throw 'RESPONSE_STOP' }
    }
    if ($r.cutover -cne 'NO_GO' -or $r.oci_retirement -cne 'STRICT_NO_GO' -or
        -not (Test-R1066Integer $r.disk_free_bytes $Request.minimum_free_bytes 1152921504606846976) -or
        -not (Test-R1066Integer $r.disk_required_bytes $Request.minimum_free_bytes $Request.minimum_free_bytes)) { throw 'RESPONSE_STOP' }
    if ($Request.role -ceq 'k137') {
        if ($r.resources -cne 'BOUNDED_SCOPE_OBSERVED' -or $r.protected_tradebot -cne 'DIRECTORY_WRITE_DENIED_ONLY' -or
            -not (Test-R1066Integer $r.memory_max_bytes 1 268435456) -or
            -not (Test-R1066Integer $r.pids_max 1 64)) { throw 'RESPONSE_STOP' }
    } elseif ($r.resources -cne 'NOT_ASSESSED' -or $r.protected_tradebot -cne 'NOT_PRESENT' -or
              $r.memory_max_bytes -ne 0 -or $r.pids_max -ne 0) { throw 'RESPONSE_STOP' }
    $r.PSObject.Properties.Remove('challenge')
    return $r
}

function Invoke-R1066Ssh([string]$Executable, [string[]]$Arguments, [byte[]]$InputBytes) {
    $quoted = @($Arguments | ForEach-Object { [FlopR1062.Guards]::Quote($_) })
    return [FlopR1066.Transport]::Run($Executable, ($quoted -join ' '), $InputBytes, 58000)
}

function Invoke-R1089Migration([string]$Enrollment, [string]$EnrollmentDigest,
                              [string]$PlanPath, [string]$PlanDigest) {
    $directory=$null; $plain=$null; $code=$null; $recovery=$null; $result=$null
    $failure='MIGRATION_GUARD_STOP'
    try {
        if (-not $PlanPath -or $PlanDigest -cnotmatch '\A[0-9a-f]{64}\z') { throw 'OWNER_APPROVAL_REQUIRED' }
        Initialize-R1066
        $e=Read-R1066Enrollment $Enrollment $EnrollmentDigest
        Assert-R1027LocalPath $PlanPath
        Assert-R1027Acl $PlanPath
        $file=[IO.File]::Open($PlanPath,'Open','Read','Read')
        try {
            if ($file.Length -lt 100 -or $file.Length -gt 4194304) { throw 'PLAN_STOP' }
            $bytes=New-Object byte[] ([int]$file.Length)
            $at=0
            while ($at -lt $bytes.Length) {
                $n=$file.Read($bytes,$at,$bytes.Length-$at)
                if ($n -le 0) { throw 'PLAN_STOP' }; $at+=$n
            }
        } finally { $file.Dispose() }
        if ([FlopR1062.Guards]::Sha256($bytes) -cne $PlanDigest) { throw 'PLAN_STOP' }
        $rawPlan=(New-Object Text.UTF8Encoding($false,$true)).GetString($bytes)
        # Python's strict decoder validates the ORIGINAL bytes, including
        # duplicate JSON keys, before ConvertFrom-Json is used for presentation.
        $pins=Read-R1066PinnedSource (Join-Path $script:R1066Root 'r1089_source_pins.json') '82a4e7972f3eb0a05d1000330c8a38623307fe9f'
        $map=$pins | ConvertFrom-Json
        foreach ($entry in $map.PSObject.Properties) {
            $null=Read-R1066PinnedSource (Join-Path $script:R1066Root $entry.Name) $entry.Value
        }
        $native=[IO.File]::ReadAllText((Join-Path $script:R1066Root 'r1089_owner_control_pipe.cs'))
        if (-not ('FlopR1089.OwnerPipe' -as [type])) { Add-Type -TypeDefinition $native }
        $sink=[IO.File]::ReadAllText((Join-Path $script:R1066Root 'r1085_windows_offhost_sink.cs'))
        if (-not ('FlopR1085.Sink' -as [type])) {
            Add-Type -TypeDefinition $sink -ReferencedAssemblies @('System.dll','System.Core.dll','System.Security.dll')
        }
        $python=Join-Path $script:R1066Root '..\..\.venv\Scripts\python.exe'
        if (-not [IO.File]::Exists($python)) { throw 'OWNER_PYTHON_REQUIRED' }
        $program=Join-Path $script:R1066Root 'r1089_migration.py'
        $validation='{"plan":'+$rawPlan+'}'
        $checkArgs=@('-I','-B',$program,'--check-plan') | ForEach-Object { [FlopR1062.Guards]::Quote($_) }
        $checked=[FlopR1089.OwnerPipe]::Run($python,($checkArgs -join ' '),[Text.Encoding]::UTF8.GetBytes($validation),$null,60000)
        if ($checked.ExitCode -ne 0) { throw 'SOURCE_ADMISSION_REQUIRED' }
        if ([Text.Encoding]::ASCII.GetString($checked.Output).Trim() -cne '{"operation":"OWNER_SESSION_VERIFIED","cutover":"NO_GO"}') {
            throw 'PLAN_STOP'
        }
        $plan=$rawPlan | ConvertFrom-Json
        $archive=Join-Path $plan.offhost_parent $plan.run_id
        $required=[long]$plan.quota_bytes
        if ([IO.Directory]::Exists($archive)) { $required=0 }
        [FlopR1085.Sink]::AdmitExistingParent($plan.offhost_parent,$required)
        $ssh=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe'
        if (-not [IO.File]::Exists($ssh)) { throw 'SSH_UNAVAILABLE' }
        # No archive, recovery input or source SSH until BOTH public approval
        # domains and real local private capacity have passed.
        $recovery=Read-Host 'Independent ARCHIVE recovery code (at least 32 UTF-8 bytes; NOT DID seed)' -AsSecureString
        $encrypted=Read-R1027Backup
        $code=Read-Host 'R987 V2 recovery code (OCI SSH only)' -AsSecureString
        try { $plain=Unprotect-R1027 $encrypted $code } finally { $code.Dispose(); $code=$null }
        if ([FlopR1062.Guards]::Sha256($plain) -cne $e.oci.credential_sha256) { throw 'OCI_CREDENTIAL_STOP' }
        $directory=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Temp\flop-r1089-'+[Guid]::NewGuid().ToString('N'))
        New-R1027Custody $directory
        $ociKey=Write-R1027Key $directory $plain
        [FlopR1062.Guards]::Clear($plain); $plain=$null
        $hosts=@{}
        foreach ($role in @('oci','k137')) {
            $hosts[$role]=Join-Path $directory ($role+'-known-hosts')
            [IO.File]::WriteAllText($hosts[$role],($e.$role.host+' '+$e.$role.host_key+"`n"),[Text.Encoding]::ASCII)
        }
        $rest=[ordered]@{endpoints=$e;ssh=$ssh;oci_key=$ociKey;oci_hosts=$hosts['oci'];k137_hosts=$hosts['k137']} | ConvertTo-Json -Depth 10 -Compress
        $control='{"plan":'+$rawPlan+','+$rest.Substring(1)
        $argsForOwner=@('-I','-B',$program,'--owner') | ForEach-Object { [FlopR1062.Guards]::Quote($_) }
        $answer=[FlopR1089.OwnerPipe]::Run($python,($argsForOwner -join ' '),[Text.Encoding]::UTF8.GetBytes($control),$recovery,14400000)
        $public=[Text.Encoding]::ASCII.GetString($answer.Output) | ConvertFrom-Json
        if ($public.task -cne 'R1089' -or $public.cutover -cne 'NO_GO' -or
            $public.oci_retirement -cne 'STRICT_NO_GO') { throw 'REPORT_STOP' }
        if ($answer.ExitCode -eq 0 -and $public.operation -ceq 'PRESERVED_AND_DISARMED_RESTORED') { $result=$public }
        elseif ($public.operation -ceq 'BLOCKED' -and $public.code -cmatch '\A[A-Z_]{3,60}\z') { $failure=$public.code }
    } catch {
        if (@('OWNER_APPROVAL_REQUIRED','SOURCE_ADMISSION_REQUIRED','PLAN_STOP','OWNER_PYTHON_REQUIRED',
              'OCI_CREDENTIAL_STOP','SSH_UNAVAILABLE') -ccontains $_.Exception.Message) { $failure=$_.Exception.Message }
    } finally {
        if ($null -ne $plain) { [Array]::Clear($plain,0,$plain.Length) }
        if ($null -ne $code) { $code.Dispose() }
        if ($null -ne $recovery) { $recovery.Dispose() }
        if ($null -ne $directory) {
            try {
                foreach ($name in @('oci-known-hosts','k137-known-hosts')) {
                    $p=Join-Path $directory $name
                    if ([IO.File]::Exists($p)) { [IO.File]::Delete($p) }
                }
                Remove-R1027Custody $directory
            } catch { $result=$null; $failure='CLEANUP_STOP' }
        }
    }
    if ($null -ne $result) { return $result }
    return [ordered]@{task='R1089';operation='BLOCKED';code=$failure;cutover='NO_GO';oci_retirement='STRICT_NO_GO'}
}


function Assert-R1066StageIntent([bool]$Enabled, [string]$Source, [string]$Id) {
    if (-not $Enabled) {
        if ($Source -or $Id) { throw 'STAGE_OPT_IN_REQUIRED' }
        return
    }
    if ($Id -cnotmatch '\A[0-9a-f]{32}\z' -or
        $Source.Length -gt 256 -or $Source -cnotmatch '\A/[A-Za-z0-9_.@/-]+\z' -or
        $Source.Contains('//') -or $Source.EndsWith('/') -or
        @($Source.Substring(1).Split('/') | Where-Object { $_ -ceq '.' -or $_ -ceq '..' -or $_ -ceq '' }).Count -gt 0 -or
        $Source -ceq '/var/lib/technocore-safe-agent' -or
        $Source -ceq '/opt/technocore-safe-agent') { throw 'ARCHIVE_SCOPE_STOP' }
}

function Invoke-R1066CiphertextStage([string]$Ssh, [string]$OciKey, $Enrollment,
                                  [string]$Custody, $Reports,
                                  [string]$SourceRoot, [string]$Id) {
    Assert-R1066StageIntent $true $SourceRoot $Id
    if ($Reports.Count -ne 2 -or $Reports[0].role -cne 'oci' -or
        $Reports[1].role -cne 'k137' -or
        $Reports[0].read_only -ne $true -or $Reports[1].read_only -ne $true) {
        throw 'PREFLIGHT_BINDING_STOP'
    }
    # A staging attempt is NOT approved live-state collection or cutover.
    # This consumes only a previously sealed immutable R1001 archive.
    $program = Read-R1066PinnedSource (Join-Path $script:R1066Root 'r1066_ciphertext_ssh_relay.py') '0514e5d65c4236dfda83dfc2997e1bba14c6f8bd'
    $pythonCommand = Get-Command 'python.exe' -ErrorAction SilentlyContinue
    if ($null -eq $pythonCommand -or $pythonCommand.CommandType -ne 'Application' -or
        -not [IO.File]::Exists($pythonCommand.Source)) { throw 'OWNER_PYTHON_REQUIRED' }
    $python = $pythonCommand.Source
    $version = @(& $python -I -B -c 'import sys; print(int(sys.version_info >= (3, 9)))' 2>$null)
    if ($LASTEXITCODE -ne 0 -or $version.Count -ne 1 -or $version[0] -cne '1') {
        throw 'OWNER_PYTHON_REQUIRED'
    }
    $relay = Join-Path $Custody 'r1066_ciphertext_ssh_relay.py'
    [IO.File]::WriteAllText($relay, $program, (New-Object Text.UTF8Encoding($false)))
    Assert-R1027Acl $relay
    $ociHosts = Join-Path $Custody 'oci-known-hosts'
    $k137Hosts = Join-Path $Custody 'k137-known-hosts'
    $argsForRelay = @('-I', '-B', $relay,
        '--ssh', $Ssh, '--source-root', $SourceRoot, '--archive-id', $Id,
        '--oci-identity', $OciKey, '--oci-known-hosts', $ociHosts,
        '--oci-known-hosts-sha256', (Get-R1066FileDigest $ociHosts),
        '--k137-host', $Enrollment.k137.host, '--k137-user', $Enrollment.k137.user,
        '--k137-identity', $Enrollment.k137.identity_file,
        '--k137-known-hosts', $k137Hosts,
        '--k137-known-hosts-sha256', (Get-R1066FileDigest $k137Hosts),
        '--k137-free-bytes', ([string]$Reports[1].disk_free_bytes),
        '--allow-disarmed-ciphertext-transfer')
    $quoted = @($argsForRelay | ForEach-Object { [FlopR1062.Guards]::Quote($_) })
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $python
    $start.Arguments = ($quoted -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.EnvironmentVariables.Clear()
    $start.EnvironmentVariables.Add('SystemRoot', $env:SystemRoot)
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'CIPHERTEXT_STAGE_STOP' }
        $outputTask = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(10800000)) { throw 'CIPHERTEXT_STAGE_TIMEOUT' }
        $output = $outputTask.Result
        if ($process.ExitCode -ne 0 -or $output.Length -gt 4096) {
            throw 'CIPHERTEXT_STAGE_STOP'
        }
        $receipt = $output | ConvertFrom-Json
        Assert-R1066Keys $receipt @('result', 'files', 'source_epoch',
            'plaintext_restore', 'did_signer', 'cutover', 'oci_retirement')
        if ($receipt.result -cne 'CIPHERTEXT_MIRROR_BYTES_EQUAL_ONLY' -or
            $receipt.source_epoch -cne 'NOT_PROVEN' -or
            $receipt.plaintext_restore -cne 'NOT_PERFORMED' -or
            $receipt.did_signer -cne 'NOT_PROVEN' -or
            $receipt.cutover -cne 'NO_GO' -or
            $receipt.oci_retirement -cne 'STRICT_NO_GO' -or
            -not (Test-R1066Integer $receipt.files 3 258)) {
            throw 'CIPHERTEXT_STAGE_RECEIPT_STOP'
        }
        return $receipt
    } finally {
        if ($null -ne $process) {
            if (-not $process.HasExited) {
                # Terminate this process tree on Windows; do not leave an
                # unbounded network writer after an interrupted operation.
                $taskkill = Join-Path ([Environment]::GetFolderPath('System')) 'taskkill.exe'
                try { & $taskkill '/PID' ([string]$process.Id) '/T' '/F' *> $null } catch {}
                if (-not $process.HasExited) { $process.Kill() }
                $null = $process.WaitForExit(10000)
            }
            $process.Dispose()
        }
    }
}

function Invoke-R1066Workflow([string]$Path, [string]$Digest,
                              [bool]$PerformStage = $false,
                              [string]$StageRoot = '', [string]$StageId = '') {
    $directory = $null; $plain = $null; $code = $null; $result = $null; $failure = 'PREFLIGHT_UNVERIFIED'
    try {
        Assert-R1066StageIntent $PerformStage $StageRoot $StageId
        if (-not $Path -or -not $Digest) { throw 'K137_INDEPENDENT_ENROLLMENT_REQUIRED' }
        Initialize-R1066
        $e = Read-R1066Enrollment $Path $Digest
        $guest = Read-R1066PinnedSource (Join-Path $script:R1066Root 'r1066_preflight_readonly.py') '9f5f90ed6ad22a253b18c1510ec2651a117a01bc'
        $ssh = Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe'
        if (-not [IO.File]::Exists($ssh)) { throw 'SSH_UNAVAILABLE' }
        Assert-R1027LocalPath $ssh
        $encrypted = Read-R1027Backup
        $code = Read-Host 'R987 V2 recovery code (OCI only)' -AsSecureString
        try { $plain = Unprotect-R1027 $encrypted $code } finally { $code.Dispose(); $code = $null }
        if ([FlopR1062.Guards]::Sha256($plain) -cne $e.oci.credential_sha256) { throw 'OCI_CREDENTIAL_STOP' }
        $directory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Temp\flop-r1066-' + [Guid]::NewGuid().ToString('N'))
        New-R1027Custody $directory
        $ociKey = Write-R1027Key $directory $plain
        [FlopR1062.Guards]::Clear($plain); $plain = $null
        $reports = @()
        foreach ($role in @('oci', 'k137')) {
            $endpoint = $e.$role
            $known = Join-Path $directory ($role + '-known-hosts')
            [IO.File]::WriteAllText($known, ($endpoint.host + ' ' + $endpoint.host_key + "`n"), [Text.Encoding]::ASCII)
            $request = New-R1066Request $endpoint $role
            $hex = [BitConverter]::ToString([Text.Encoding]::ASCII.GetBytes(($request | ConvertTo-Json -Compress))).Replace('-', '')
            $payload = [Text.Encoding]::UTF8.GetBytes(($guest + "`nrun(json.loads(bytes.fromhex('" + $hex + "')))`n"))
            $key = $ociKey
            if ($role -ceq 'k137') { $key = $endpoint.identity_file }
            $arguments = Get-R1066Arguments $endpoint $role $key $known
            $response = Invoke-R1066Ssh $ssh $arguments $payload
            if ($response.ExitCode -ne 0) { throw 'SSH_OR_REMOTE_PREFLIGHT_STOP' }
            $reports += Read-R1066Response $response.Output $request
        }
        if ($PerformStage) {
            $stageReceipt = Invoke-R1066CiphertextStage $ssh $ociKey $e $directory $reports $StageRoot $StageId
            $result = [ordered]@{task='R1066'; phase='B'; operation='ciphertext_staged_only';
                receipt=$stageReceipt; source_epoch='NOT_PROVEN'; restore='NOT_PERFORMED';
                cutover='NO_GO'; oci_retirement='STRICT_NO_GO'}
        } else {
        $result = [ordered]@{task='R1066'; phase='A'; operation='preflight_verified';
            code='WRITER_ADMISSION_AUTHORIZATION_REQUIRED'; hosts=$reports;
            encrypted_transfer='NOT_PERFORMED'; restore='NOT_PERFORMED'; cutover='NO_GO'; oci_retirement='STRICT_NO_GO'}
        }
    } catch {
        $fixed = @('K137_INDEPENDENT_ENROLLMENT_REQUIRED', 'ENROLLMENT_PIN_STOP', 'HOST_DOMAIN_STOP',
            'K137_CREDENTIAL_STOP', 'OCI_CREDENTIAL_STOP', 'SOURCE_PIN_STOP', 'SSH_UNAVAILABLE',
            'STAGE_OPT_IN_REQUIRED', 'ARCHIVE_SCOPE_STOP', 'PREFLIGHT_BINDING_STOP',
            'OWNER_PYTHON_REQUIRED', 'CIPHERTEXT_STAGE_STOP', 'CIPHERTEXT_STAGE_TIMEOUT',
            'CIPHERTEXT_STAGE_RECEIPT_STOP',
            'SSH_OR_REMOTE_PREFLIGHT_STOP', 'RESPONSE_STOP')
        if ($fixed -ccontains $_.Exception.Message) { $failure = $_.Exception.Message }
    } finally {
        if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) }
        if ($null -ne $code) { $code.Dispose() }
        if ($null -ne $directory) {
            try {
                foreach ($name in @('r1066_ciphertext_ssh_relay.py', 'oci-known-hosts', 'k137-known-hosts')) {
                    $file = Join-Path $directory $name
                    if ([IO.File]::Exists($file)) { [IO.File]::Delete($file) }
                }
                Remove-R1027Custody $directory
            } catch { $result = $null; $failure = 'CLEANUP_STOP' }
        }
    }
    if ($null -eq $result) {
        return [ordered]@{task='R1066'; phase='A'; operation='blocked'; code=$failure; cutover='NO_GO'; oci_retirement='STRICT_NO_GO'}
    }
    return $result
}

if ($args.Count -ne 0) {
    Write-Output '{"operation":"blocked","code":"ARGUMENTS_STOP","oci_retirement":"STRICT_NO_GO"}'
    exit 42
}
if ($PreserveAndRestore) {
    if ($StageCiphertext -or $SealedArchiveRoot -or $ArchiveId) {
        Write-Output '{"operation":"BLOCKED","code":"MUTUALLY_EXCLUSIVE_MODES"}'
        exit 42
    }
    $report=Invoke-R1089Migration $EnrollmentFile $EnrollmentSha256 $PlanFile $PlanSha256
    Write-Output ($report | ConvertTo-Json -Depth 5 -Compress)
    if ($report.operation -ceq 'PRESERVED_AND_DISARMED_RESTORED') { exit 0 }
    exit 42
}
$report = Invoke-R1066Workflow $EnrollmentFile $EnrollmentSha256 ([bool]$StageCiphertext) $SealedArchiveRoot $ArchiveId
Write-Output ($report | ConvertTo-Json -Depth 5 -Compress)
if ($report.operation -eq 'preflight_verified' -or $report.operation -eq 'ciphertext_staged_only') { exit 0 }
exit 42
