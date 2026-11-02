# R1144: Windows PS5.1 R987 V2 -> one-shot original G1 effective identity read-only witness.
# No OCI Cloud Shell. Never an interactive shell or general remote command facility.
param()
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$script:R1066Root=$null
$script:SourcesCommit='b46d766bb165477a16d5a77ee204fc7bb5982725'
$script:SourceItems=@(
    @{path='packaging/migration/r1066_owner_workflow.ps1';blob='13978d6afb01fc3898018e045aded87d673ef683'},
    @{path='packaging/migration/r1066_preflight_transport.cs';blob='305530a86db7e5cc8812fbac57c3e2c7c089a7be'},
    @{path='packaging/migration/r1079_profile_ssh_transport.cs';blob='b150af9fe7a335bc6c02e8fc1e5451599d124a97'},
    @{path='packaging/windows/r1062_writer_attribution_one_shot_readonly.ps1';blob='7ad3432b89b2aa2fe4a5e6b0142ec7578554baaa'},
    @{path='packaging/oracle/r1139_source_preseed_metadata_readonly.py';blob='ec8317b58777c4060c1aad3215ebc50b29a02f54';commit='28013c899d05b9887eec245a4bc4a8e9bc7b0ec5'}
)

function Get-R1144GitBlob([byte[]]$bytes) {
    $prefix=[Text.Encoding]::ASCII.GetBytes(('blob '+$bytes.Length+[char]0))
    $hash=[Security.Cryptography.SHA1]::Create()
    try {
        $null=$hash.TransformBlock($prefix,0,$prefix.Length,$prefix,0)
        $null=$hash.TransformFinalBlock($bytes,0,$bytes.Length)
        return [BitConverter]::ToString($hash.Hash).Replace('-','').ToLowerInvariant()
    } finally { $hash.Dispose() }
}

function Import-R1144TrustedFunctions([string]$path) {
    $raw=[IO.File]::ReadAllBytes($path)
    if ((Get-R1144GitBlob $raw) -cne '13978d6afb01fc3898018e045aded87d673ef683') {
        throw 'LIB_PIN_STOP'
    }
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput(
        [Text.Encoding]::UTF8.GetString($raw),[ref]$tokens,[ref]$errors)
    if ($errors.Count -ne 0) { throw 'LIB_PARSE_STOP' }
    foreach ($name in @('Read-R1066PinnedSource','Initialize-R1066')) {
        $found=@($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst]
        },$true) | Where-Object { $_.Name -ceq $name })
        if ($found.Count -ne 1) { throw 'LIB_DEF_STOP' }
        $parameters=(@($found[0].Parameters |
            Where-Object { $null -ne $_ } | ForEach-Object { $_.Extent.Text }) -join ',')
        $body=$found[0].Body.Extent.Text
        $block=[scriptblock]::Create(('param('+$parameters+')'+[char]10+
            $body.Substring(1,$body.Length-2)))
        Set-Item -Path ('Function:script:'+$name) -Value $block
    }
    [Array]::Clear($raw,0,$raw.Length)
}


function Read-R1144Report([byte[]]$bytes) {
    if ($null -eq $bytes -or $bytes.Length -lt 400 -or $bytes.Length -gt 3500) {
        throw 'REPORT_BOUND_STOP'
    }
    foreach ($b in $bytes) {
        if ($b -ne 10 -and ($b -lt 32 -or $b -gt 126)) {
            throw 'REPORT_ASCII_STOP'
        }
    }
    $text=[Text.Encoding]::ASCII.GetString($bytes)
    if ($text.Contains('\') -or
        [regex]::Matches($text,'"[a-z_-]+"\s*:').Count -ne 29) {
        throw 'REPORT_SCHEMA_STOP'
    }
    $value=$text | ConvertFrom-Json -ErrorAction Stop
    $names=@('phase','result','action','source_head','machine_sha256','files',
        'data_bytes_exported','common_sqlite_epoch','source_archive',
        'cutover','oci_retirement')
    if ($value -isnot [Management.Automation.PSCustomObject] -or
        @($value.PSObject.Properties.Name).Count -ne $names.Count) {
        throw 'REPORT_SCHEMA_STOP'
    }
    foreach ($name in $value.PSObject.Properties.Name) {
        if ($names -cnotcontains $name) { throw 'REPORT_SCHEMA_STOP' }
    }
    if ($value.phase -cne 'R1139' -or
        $value.result -cnotin @('SOURCE_PRESEED_METADATA_READY','SOURCE_PRESEED_METADATA_GAPS') -or
        $value.action -cne 'READ_ONLY' -or
        $value.source_head -cne 'ec4bc4892d40cdd2a03e102faa44d72c89e01b99' -or
        $value.machine_sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        ($value.data_bytes_exported -isnot [int] -and $value.data_bytes_exported -isnot [long]) -or
        $value.data_bytes_exported -ne 0 -or
        $value.common_sqlite_epoch -cne 'NOT_PROVEN' -or
        $value.source_archive -cne 'NO_GO' -or
        $value.cutover -cne 'NO_GO' -or
        $value.oci_retirement -cne 'STRICT_NO_GO') {
        throw 'REPORT_GUARD_STOP'
    }
    $cats=@('verified-did','nonces','signer-receipts')
    $caps=@{'verified-did'=16384;'nonces'=1048576;'signer-receipts'=8388608}
    if ($value.files -isnot [Management.Automation.PSCustomObject] -or
        @($value.files.PSObject.Properties.Name).Count -ne 3) {
        throw 'REPORT_SCHEMA_STOP'
    }
    $selected=[ordered]@{}
    $ready=$true
    foreach ($name in $cats) {
        $prop=$value.files.PSObject.Properties[$name]
        if ($null -eq $prop) { throw 'REPORT_SCHEMA_STOP' }
        $row=$prop.Value
        $attrs=@('exists','regular','single_link','within_limit','size_bytes')
        if ($row -isnot [Management.Automation.PSCustomObject] -or
            @($row.PSObject.Properties.Name).Count -ne 5) {
            throw 'REPORT_SCHEMA_STOP'
        }
        foreach ($attr in $row.PSObject.Properties.Name) {
            if ($attrs -cnotcontains $attr) { throw 'REPORT_SCHEMA_STOP' }
        }
        foreach ($attr in @('exists','regular','single_link','within_limit')) {
            if ($row.$attr -isnot [bool]) { throw 'REPORT_GUARD_STOP' }
        }
        if (($row.size_bytes -isnot [int] -and $row.size_bytes -isnot [long]) -or
            $row.size_bytes -lt 0 -or $row.size_bytes -gt $caps[$name]) {
            throw 'REPORT_GUARD_STOP'
        }
        if ($row.within_limit -ne ($row.exists -and $row.regular -and
             $row.single_link -and $row.size_bytes -gt 0)) {
            throw 'REPORT_GUARD_STOP'
        }
        if (-not $row.within_limit) { $ready=$false }
        $selected[$name]=[ordered]@{
            exists=[bool]$row.exists;regular=[bool]$row.regular
            single_link=[bool]$row.single_link
            within_limit=[bool]$row.within_limit
            size_bytes=[long]$row.size_bytes
        }
    }
    if (($value.result -ceq 'SOURCE_PRESEED_METADATA_READY') -ne $ready) {
        throw 'REPORT_GUARD_STOP'
    }
    return [ordered]@{
        phase='R1144';result=$value.result;action='READ_ONLY'
        source_head=$value.source_head;machine_sha256=$value.machine_sha256
        files=$selected;data_bytes_exported=0
        common_sqlite_epoch='NOT_PROVEN'
        source_archive='NO_GO';cutover='NO_GO'
        oci_retirement='STRICT_NO_GO'
    }
}
function Read-R1144FixedStop([byte[]]$bytes) {
    if ($null -eq $bytes -or $bytes.Length -lt 90 -or $bytes.Length -gt 500) { return $null }
    foreach ($b in $bytes) {
        if ($b -ne 10 -and ($b -lt 32 -or $b -gt 126)) { return $null }
    }
    $raw=[Text.Encoding]::ASCII.GetString($bytes)
    if ($raw.Contains('\') -or
        [regex]::Matches($raw,'"[a-z_-]+"\s*:').Count -ne 6) { return $null }
    try { $v=$raw | ConvertFrom-Json -ErrorAction Stop }
    catch { return $null }
    $keys=@('phase','result','code','source_archive','cutover','oci_retirement')
    if (@($v.PSObject.Properties.Name).Count -ne 6) { return $null }
    foreach ($key in $v.PSObject.Properties.Name) {
        if ($keys -cnotcontains $key) { return $null }
    }
    $reasons=@('MOUNT_STOP','ROOT_FS_STOP','SOURCE_MOUNT_STOP',
        'ORIGINAL_SCOPE_STOP','ORIGINAL_ROOT_LINK_STOP','ORIGINAL_HEAD_STOP',
        'SOURCE_DEVICE_STOP','SOURCE_FILE_LINK_STOP','MOUNT_RACE_STOP',
        'DEVICE_RACE_STOP','MACHINE_ID_STOP','SOURCE_METADATA_STOP')
    if ($v.phase -cne 'R1139' -or $v.result -cne 'STOP' -or
        $reasons -cnotcontains $v.code -or
        $v.source_archive -cne 'NO_GO' -or
        $v.cutover -cne 'NO_GO' -or
        $v.oci_retirement -cne 'STRICT_NO_GO') { return $null }
    return [string]$v.code
}

function Invoke-R1144 {
    # Single read-only report, no delete path or source writer mutation.
    $public=$null; $private=$null; $plain=$null; $encrypted=$null
    $password=$null; $reply=$null; $success=$null
    $stage='PREPARE';$clean=$true
    try {
        if ($PSVersionTable.PSVersion.Major -ne 5 -or
            $PSVersionTable.PSVersion.Minor -lt 1) { throw 'PS51_REQUIRED' }
        $stage='PUBLIC_SOURCE_PIN'
        $public=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) (
            'Temp\flop-r1144-public-'+[Guid]::NewGuid().ToString('N'))
        $null=New-Item -ItemType Directory -Path $public -ErrorAction Stop
        $script:R1066Root=Join-Path $public 'packaging\migration'
        $oldTls=[Net.ServicePointManager]::SecurityProtocol
        try {
            [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
            foreach ($item in $script:SourceItems) {
                $target=Join-Path $public $item.path.Replace('/','\')
                $parent=Split-Path -Parent $target
                if (-not [IO.Directory]::Exists($parent)) {
                    $null=New-Item -ItemType Directory -Path $parent -Force
                }
                $rev=$script:SourcesCommit
                if ($item.ContainsKey('commit')) { $rev=$item.commit }
                $uri=('https://raw.githubusercontent.com/hanamaru777/technocore-safe-agent/' +
                    $rev + '/' + $item.path)
                Invoke-WebRequest -Uri $uri -OutFile $target -UseBasicParsing -TimeoutSec 25
                $data=[IO.File]::ReadAllBytes($target)
                if ($data.Length -lt 20 -or $data.Length -gt 65536 -or
                    (Get-R1144GitBlob $data) -cne $item.blob) {
                    throw 'PUBLIC_BLOB_PIN_STOP'
                }
                [Array]::Clear($data,0,$data.Length)
            }
        } finally { [Net.ServicePointManager]::SecurityProtocol=$oldTls }
        $stage='TRUSTED_HELPERS'
        Import-R1144TrustedFunctions (Join-Path $script:R1066Root 'r1066_owner_workflow.ps1')
        Initialize-R1066
        $transport=Read-R1066PinnedSource (
            Join-Path $script:R1066Root 'r1079_profile_ssh_transport.cs'
        ) 'b150af9fe7a335bc6c02e8fc1e5451599d124a97'
        if (-not ('FlopR1079.Transport' -as [type])) {
            Add-Type -TypeDefinition $transport
        }
        $stage='SSH_REQUIREMENTS'
        $ssh=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe'
        $known=Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\known_hosts'
        if (-not [IO.File]::Exists($ssh) -or -not [IO.File]::Exists($known)) {
            throw 'SSH_FILES_STOP'
        }
        Assert-R1027LocalPath $ssh
        Assert-R1027LocalPath $known
        $stage='LOCAL_ESCROW'
        $encrypted=Read-R1027Backup
        $stage='R987_CODE_PROMPT'
        # This is an interactive *local* SecureString prompt. Never inspect,
        # serialize, echo or log the entered value. Distinguish a host that
        # cannot prompt from empty/cancelled input before trying SSH.
        try {
            $password=Read-Host 'R987 V2 local recovery code (only on this PC)' -AsSecureString -ErrorAction Stop
        } catch {
            $stage='R987_INPUT_HOST_STOP'
            throw 'R987_INPUT_HOST_STOP'
        }
        if ($null -eq $password) {
            $stage='R987_INPUT_EMPTY_STOP'
            throw 'R987_INPUT_EMPTY_STOP'
        }
        if ($password -isnot [Security.SecureString]) {
            $stage='R987_INPUT_HOST_STOP'
            throw 'R987_INPUT_HOST_STOP'
        }
        if ($password.Length -eq 0) {
            $stage='R987_INPUT_EMPTY_STOP'
            throw 'R987_INPUT_EMPTY_STOP'
        }
        $stage='LOCAL_ESCROW_DECRYPT'
        try { $plain=Unprotect-R1027 $encrypted $password }
        finally { $password.Dispose();$password=$null }
        if ($null -eq $plain -or $plain.Length -lt 81 -or $plain.Length -gt 32768) {
            throw 'KEY_FORMAT_STOP'
        }
        $stage='TEMPORARY_KEY_CUSTODY'
        $private=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) (
            'Temp\flop-r1144-key-'+[Guid]::NewGuid().ToString('N'))
        New-R1027Custody $private
        $key=Write-R1027Key $private $plain
        [FlopR1062.Guards]::Clear($plain);$plain=$null
        $options=@('-F','NUL','-T','-i',$key,'-o',
            ('UserKnownHostsFile="'+$known.Replace('\','/')+'"'),
            '-o','GlobalKnownHostsFile=NUL','-o','StrictHostKeyChecking=yes',
            '-o','HostKeyAlgorithms=ecdsa-sha2-nistp256',
            '-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no',
            '-o','PreferredAuthentications=publickey','-o','HostbasedAuthentication=no',
            '-o','GSSAPIAuthentication=no','-o','UpdateHostKeys=no',
            '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
            '-o','ClearAllForwardings=yes','-o','ForwardAgent=no',
            '-o','ForwardX11=no','-o','PermitLocalCommand=no',
            '-o','KnownHostsCommand=none','-o','ProxyCommand=none',
            '-o','ProxyJump=none','-o','CanonicalizeHostname=no',
            '-o','ConnectionAttempts=1','-o','ConnectTimeout=7',
            '-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2',
            'ubuntu@140.238.55.171',
            'sudo -n /usr/bin/python3 -I -B -')
        $quoted=@($options | ForEach-Object { [FlopR1062.Guards]::Quote($_) })
        $guest=[IO.File]::ReadAllBytes((Join-Path $public 'packaging\oracle\r1139_source_preseed_metadata_readonly.py'))
        $stage='SSH_AND_ORACLE'
        $reply=[FlopR1079.Transport]::Run($ssh,($quoted -join ' '),$guest,58000)
        if ($reply.ExitCode -ne 0) {
            if ($reply.ExitCode -eq 255) {
                $stage='SSH_CONNECT_OR_AUTH_STOP'
            } elseif ($reply.ExitCode -eq 42) {
                $publicStop=Read-R1144FixedStop $reply.Output
                if ($null -ne $publicStop) { $stage=$publicStop }
                else { $stage='ORACLE_GUARD_STOP' }
            } else {
                $stage='ORACLE_GUARD_STOP'
            }
            throw 'NO_SUCCESS_RECEIPT'
        }
        $stage='RESPONSE_VALIDATION'
        $success=Read-R1144Report $reply.Output
    } catch {
        if ($null -eq $success -and $stage -ceq 'SSH_AND_ORACLE') {
            $stage='SSH_CARRIER_STOP'
        } elseif ($null -eq $success -and $stage -ceq 'RESPONSE_VALIDATION') {
            # Never print raw stdout, stderr, paths, credentials or exception text.
            $safe=@('REPORT_BOUND_STOP','REPORT_ASCII_STOP','REPORT_SCHEMA_STOP',
                'REPORT_DUPLICATE_STOP','REPORT_UNKNOWN_FIELD_STOP',
                'REPORT_UNKNOWN_CATEGORY_STOP','REPORT_VALUE_STOP',
                'REPORT_REQUIRED_STOP','REPORT_GUARD_STOP','REPORT_MODE_STOP',
                'REPORT_COUNT_STOP')
            $message=$_.Exception.Message
            if ($safe -ccontains $message) { $stage=$message }
            else { $stage='REPORT_UNCLASSIFIED_STOP' }
        }
    } finally {
        if ($null -ne $password) { $password.Dispose() }
        if ('FlopR1062.Guards' -as [type]) {
            [FlopR1062.Guards]::Clear($plain)
            [FlopR1062.Guards]::Clear($encrypted)
            if ($null -ne $reply) { [FlopR1062.Guards]::Clear($reply.Output) }
        }
        if ($null -ne $private) {
            try { Remove-R1027Custody $private } catch { $clean=$false }
        }
        if ($null -ne $public -and [IO.Directory]::Exists($public)) {
            try { Remove-Item -LiteralPath $public -Recurse -Force -ErrorAction Stop }
            catch { $clean=$false }
        }
    }
    if (-not $clean) {
        Write-Output '{"phase":"R1144","result":"STOP","code":"TEMP_CUSTODY_CLEANUP_STOP"}'
        return
    }
    if ($null -eq $success) {
        $allow=@('PREPARE','PUBLIC_SOURCE_PIN','TRUSTED_HELPERS','SSH_REQUIREMENTS',
            'LOCAL_ESCROW','R987_CODE_PROMPT','R987_INPUT_HOST_STOP',
            'R987_INPUT_EMPTY_STOP','LOCAL_ESCROW_DECRYPT',
            'TEMPORARY_KEY_CUSTODY','SSH_CONNECT_OR_AUTH_STOP','ORACLE_GUARD_STOP',
            'SSH_CARRIER_STOP','RESPONSE_VALIDATION','REPORT_BOUND_STOP',
            'REPORT_ASCII_STOP','REPORT_SCHEMA_STOP','REPORT_DUPLICATE_STOP',
            'REPORT_UNKNOWN_FIELD_STOP','REPORT_UNKNOWN_CATEGORY_STOP',
            'REPORT_VALUE_STOP','REPORT_REQUIRED_STOP','REPORT_GUARD_STOP',
            'ORIGINAL_ROOT_STOP','ROOT_PATH_STOP','ORIGINAL_HEAD_STOP',
            'MOUNT_UNAVAILABLE','MOUNT_BOUND_STOP','MOUNT_FORMAT_STOP',
            'ROOT_MOUNT_ALIAS_STOP','ROOT_FILESYSTEM_STOP','NONROOT_MOUNT_STOP',
            'NESTED_MOUNT_STOP','DEVICE_SCOPE_STOP','MOUNT_RACE_STOP',
            'DEVICE_RACE_STOP','READ_ONLY_UNAVAILABLE','MACHINE_ID_STOP',
            'SOURCE_FILE_LINK_STOP','SOURCE_METADATA_STOP','MOUNT_STOP',
            'ROOT_FS_STOP','SOURCE_MOUNT_STOP',
            'REPORT_MODE_STOP','REPORT_COUNT_STOP','REPORT_UNCLASSIFIED_STOP')
        if ($allow -cnotcontains $stage) { $stage='GUARD_STOP' }
        Write-Output ('{"phase":"R1144","result":"STOP","code":"'+$stage+'"}')
    } else {
        Write-Output ($success | ConvertTo-Json -Compress -Depth 7)
    }
}

if ($args.Count -ne 0) {
    Write-Output '{"phase":"R1144","result":"STOP","code":"ARGS_STOP"}'
} else {
    Invoke-R1144
}
