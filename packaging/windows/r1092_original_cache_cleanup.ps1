# R1092: Windows PS5.1 existing R987 V2 -> pinned Oracle single-purpose cache cleanup.
# No OCI Cloud Shell. Never an interactive shell or general remote command facility.
param([switch]$DeleteProvenCache)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$script:R1066Root=$null
$script:SourcesCommit='5698921f661921e9ac0669c54f3bf40d48da5c12'
$script:SourceItems=@(
    @{path='packaging/migration/r1066_owner_workflow.ps1';blob='13978d6afb01fc3898018e045aded87d673ef683'},
    @{path='packaging/migration/r1066_preflight_transport.cs';blob='305530a86db7e5cc8812fbac57c3e2c7c089a7be'},
    @{path='packaging/migration/r1079_profile_ssh_transport.cs';blob='b150af9fe7a335bc6c02e8fc1e5451599d124a97'},
    @{path='packaging/windows/r1062_writer_attribution_one_shot_readonly.ps1';blob='7ad3432b89b2aa2fe4a5e6b0142ec7578554baaa'},
    @{path='packaging/oracle/r1091_safe_cache_cleanup.py';blob='aa7e959d00cee3c12453e7c0bcccde2b3dd8a12f'}
)

function Get-R1092GitBlob([byte[]]$bytes) {
    $prefix=[Text.Encoding]::ASCII.GetBytes(('blob '+$bytes.Length+[char]0))
    $hash=[Security.Cryptography.SHA1]::Create()
    try {
        $null=$hash.TransformBlock($prefix,0,$prefix.Length,$prefix,0)
        $null=$hash.TransformFinalBlock($bytes,0,$bytes.Length)
        return [BitConverter]::ToString($hash.Hash).Replace('-','').ToLowerInvariant()
    } finally { $hash.Dispose() }
}

function Import-R1092TrustedFunctions([string]$path) {
    $raw=[IO.File]::ReadAllBytes($path)
    if ((Get-R1092GitBlob $raw) -cne '13978d6afb01fc3898018e045aded87d673ef683') {
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

function Read-R1092Report([byte[]]$bytes,[bool]$delete) {
    if ($null -eq $bytes -or $bytes.Length -lt 120 -or $bytes.Length -gt 8192) {
        throw 'REPORT_BOUND_STOP'
    }
    foreach ($b in $bytes) {
        if ($b -ne 10 -and ($b -lt 32 -or $b -gt 126)) {
            throw 'REPORT_ASCII_STOP'
        }
    }
    $map=@{}; $sizes=@{}
    $rows=([Text.Encoding]::ASCII.GetString($bytes)).Split([char]10)
    foreach ($row in $rows) {
        if (-not $row) { continue }
        # The immutable OCI R1091 source prints the real Git-ignored
        # 'local-state' directory verbatim in its category label. Map ONLY
        # that one known hyphen to the public underscore receipt schema.
        $sourceCategory='APP_LOCAL-STATE_PROTECTED_ALLOCATED_BYTES='
        if ($row.StartsWith($sourceCategory,[StringComparison]::Ordinal)) {
            $row='APP_LOCAL_STATE_PROTECTED_ALLOCATED_BYTES=' +
                $row.Substring($sourceCategory.Length)
        }
        $match=[regex]::Match($row,'\A([A-Z0-9_]{2,75})=([A-Z_]{2,60}|[0-9]{1,16})\z')
        if (-not $match.Success) { throw 'REPORT_SCHEMA_STOP' }
        $key=$match.Groups[1].Value
        $value=$match.Groups[2].Value
        if ($map.ContainsKey($key)) { throw 'REPORT_DUPLICATE_STOP' }
        $fixed=@('R1091_ORIGINAL_SCOPE','OBJECTS_INSPECTED','PROVEN_CACHE_DIR_COUNT',
            'PROVEN_CACHE_ESTIMATED_BYTES','DELETED_CACHE_DIR_COUNT',
            'DISK_FREE_BEFORE','DISK_FREE_AFTER','STATE_GIT_VENV_LOG_SIGNER_DB_DELETE',
            'RESULT','DELETE')
        if (-not $key.EndsWith('_ALLOCATED_BYTES') -and $fixed -cnotcontains $key) {
            throw 'REPORT_UNKNOWN_FIELD_STOP'
        }
        $map[$key]=$value
        if ($key.EndsWith('_ALLOCATED_BYTES')) {
            if ($key -cnotmatch '\A(APP|STATE)_[A-Z0-9_]{2,65}_ALLOCATED_BYTES\z') {
                throw 'REPORT_UNKNOWN_CATEGORY_STOP'
            }
            if ($value -notmatch '\A[0-9]{1,16}\z') { throw 'REPORT_VALUE_STOP' }
            $sizes[$key]=[long]::Parse($value)
        }
    }
    $needed=@('R1091_ORIGINAL_SCOPE','OBJECTS_INSPECTED','PROVEN_CACHE_DIR_COUNT',
        'PROVEN_CACHE_ESTIMATED_BYTES','DISK_FREE_BEFORE','DISK_FREE_AFTER',
        'STATE_GIT_VENV_LOG_SIGNER_DB_DELETE','RESULT')
    if ($delete) { $needed+= 'DELETED_CACHE_DIR_COUNT' }
    else { $needed+='DELETE' }
    foreach ($key in $needed) { if (-not $map.ContainsKey($key)) { throw 'REPORT_REQUIRED_STOP' } }
    if ($map.R1091_ORIGINAL_SCOPE -cne 'PINNED' -or
        $map.STATE_GIT_VENV_LOG_SIGNER_DB_DELETE -cne 'NONE' -or
        $map.RESULT -cne 'COMPLETE') { throw 'REPORT_GUARD_STOP' }
    if (-not $delete -and $map.DELETE -cne 'NOT_REQUESTED') {
        throw 'REPORT_MODE_STOP'
    }
    $nums=@('OBJECTS_INSPECTED','PROVEN_CACHE_DIR_COUNT','PROVEN_CACHE_ESTIMATED_BYTES',
        'DISK_FREE_BEFORE','DISK_FREE_AFTER')
    if ($delete) { $nums+='DELETED_CACHE_DIR_COUNT' }
    foreach ($key in $nums) {
        if ($map[$key] -notmatch '\A[0-9]{1,16}\z') { throw 'REPORT_VALUE_STOP' }
        $null=[long]::Parse($map[$key])
    }
    if ([long]$map.OBJECTS_INSPECTED -gt 100000 -or
        [long]$map.PROVEN_CACHE_DIR_COUNT -gt [long]$map.OBJECTS_INSPECTED) {
        throw 'REPORT_COUNT_STOP'
    }
    if ($delete -and [long]$map.DELETED_CACHE_DIR_COUNT -gt [long]$map.PROVEN_CACHE_DIR_COUNT) {
        throw 'REPORT_COUNT_STOP'
    }
    if ($delete) { $status='CACHE_CLEANUP_COMPLETED' }
    else { $status='CATEGORY_INVENTORY_ONLY' }
    return [ordered]@{
        phase='R1092'
        result=$status
        objects=[long]$map.OBJECTS_INSPECTED
        possible_cache_dirs=[long]$map.PROVEN_CACHE_DIR_COUNT
        deleted_cache_dirs= $(if ($delete) { [long]$map.DELETED_CACHE_DIR_COUNT } else { 0 })
        capacity_before_bytes=[long]$map.DISK_FREE_BEFORE
        capacity_after_bytes=[long]$map.DISK_FREE_AFTER
        allocated_by_category=$sizes
        state_sqlite_did_nonce_log_delete='NONE'
        cutover='NO_GO'
        oci_retirement='STRICT_NO_GO'
    }
}

function Invoke-R1092 {
    # This live one-shot delete path was attempted on 2026-10-29. Its response
    # was lost AFTER remote zero exit; do not risk deleting the same caches
    # again. Only allow a fresh READ-ONLY current-state receipt.
    if ($DeleteProvenCache) {
        Write-Output '{"phase":"R1092","result":"STOP","code":"DELETE_ONE_SHOT_CONSUMED"}'
        return
    }
    $public=$null; $private=$null; $plain=$null; $encrypted=$null
    $password=$null; $reply=$null; $success=$null
    $stage='PREPARE';$clean=$true
    try {
        if ($PSVersionTable.PSVersion.Major -ne 5 -or
            $PSVersionTable.PSVersion.Minor -lt 1) { throw 'PS51_REQUIRED' }
        $stage='PUBLIC_SOURCE_PIN'
        $public=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) (
            'Temp\flop-r1092-public-'+[Guid]::NewGuid().ToString('N'))
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
                $uri=('https://raw.githubusercontent.com/hanamaru777/technocore-safe-agent/' +
                    $script:SourcesCommit + '/' + $item.path)
                Invoke-WebRequest -Uri $uri -OutFile $target -UseBasicParsing -TimeoutSec 25
                $data=[IO.File]::ReadAllBytes($target)
                if ($data.Length -lt 20 -or $data.Length -gt 65536 -or
                    (Get-R1092GitBlob $data) -cne $item.blob) {
                    throw 'PUBLIC_BLOB_PIN_STOP'
                }
                [Array]::Clear($data,0,$data.Length)
            }
        } finally { [Net.ServicePointManager]::SecurityProtocol=$oldTls }
        $stage='TRUSTED_HELPERS'
        Import-R1092TrustedFunctions (Join-Path $script:R1066Root 'r1066_owner_workflow.ps1')
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
        $password=Read-Host 'R987 V2 local recovery code (only on this PC)' -AsSecureString
        if ($null -eq $password -or $password.Length -eq 0) { throw 'EMPTY_CODE_STOP' }
        $stage='LOCAL_ESCROW_DECRYPT'
        try { $plain=Unprotect-R1027 $encrypted $password }
        finally { $password.Dispose();$password=$null }
        if ($null -eq $plain -or $plain.Length -lt 81 -or $plain.Length -gt 32768) {
            throw 'KEY_FORMAT_STOP'
        }
        $stage='TEMPORARY_KEY_CUSTODY'
        $private=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) (
            'Temp\flop-r1092-key-'+[Guid]::NewGuid().ToString('N'))
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
            ('sudo -n /usr/bin/python3 -I -B -'+
             $(if ($DeleteProvenCache) {' --delete-proven-cache'} else {''})))
        $quoted=@($options | ForEach-Object { [FlopR1062.Guards]::Quote($_) })
        $guest=[IO.File]::ReadAllBytes((Join-Path $public 'packaging\oracle\r1091_safe_cache_cleanup.py'))
        $stage='SSH_AND_ORACLE'
        $reply=[FlopR1079.Transport]::Run($ssh,($quoted -join ' '),$guest,58000)
        if ($reply.ExitCode -ne 0) {
            if ($reply.ExitCode -eq 255) { $stage='SSH_CONNECT_OR_AUTH_STOP' }
            else { $stage='ORACLE_GUARD_STOP' }
            throw 'NO_SUCCESS_RECEIPT'
        }
        $stage='RESPONSE_VALIDATION'
        $success=Read-R1092Report $reply.Output ([bool]$DeleteProvenCache)
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
        Write-Output '{"phase":"R1092","result":"STOP","code":"TEMP_CUSTODY_CLEANUP_STOP"}'
        return
    }
    if ($null -eq $success) {
        $allow=@('PREPARE','PUBLIC_SOURCE_PIN','TRUSTED_HELPERS','SSH_REQUIREMENTS',
            'LOCAL_ESCROW','R987_CODE_PROMPT','LOCAL_ESCROW_DECRYPT',
            'TEMPORARY_KEY_CUSTODY','SSH_CONNECT_OR_AUTH_STOP','ORACLE_GUARD_STOP',
            'SSH_CARRIER_STOP','RESPONSE_VALIDATION','REPORT_BOUND_STOP',
            'REPORT_ASCII_STOP','REPORT_SCHEMA_STOP','REPORT_DUPLICATE_STOP',
            'REPORT_UNKNOWN_FIELD_STOP','REPORT_UNKNOWN_CATEGORY_STOP',
            'REPORT_VALUE_STOP','REPORT_REQUIRED_STOP','REPORT_GUARD_STOP',
            'REPORT_MODE_STOP','REPORT_COUNT_STOP','REPORT_UNCLASSIFIED_STOP')
        if ($allow -cnotcontains $stage) { $stage='GUARD_STOP' }
        Write-Output ('{"phase":"R1092","result":"STOP","code":"'+$stage+'"}')
    } else {
        Write-Output ($success | ConvertTo-Json -Compress -Depth 7)
    }
}

if ($args.Count -ne 0) {
    Write-Output '{"phase":"R1092","result":"STOP","code":"ARGS_STOP"}'
} else {
    Invoke-R1092
}
