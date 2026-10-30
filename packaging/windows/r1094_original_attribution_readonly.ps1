# R1094: Windows PS5.1 existing R987 V2 -> pinned Oracle single-purpose cache cleanup.
# No OCI Cloud Shell. Never an interactive shell or general remote command facility.
param()
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$script:R1066Root=$null
$script:SourcesCommit='961b283695f9b8d05d68ea1e661aff95dd22ed03'
$script:SourceItems=@(
    @{path='packaging/migration/r1066_owner_workflow.ps1';blob='13978d6afb01fc3898018e045aded87d673ef683'},
    @{path='packaging/migration/r1066_preflight_transport.cs';blob='305530a86db7e5cc8812fbac57c3e2c7c089a7be'},
    @{path='packaging/migration/r1079_profile_ssh_transport.cs';blob='b150af9fe7a335bc6c02e8fc1e5451599d124a97'},
    @{path='packaging/windows/r1062_writer_attribution_one_shot_readonly.ps1';blob='7ad3432b89b2aa2fe4a5e6b0142ec7578554baaa'},
    @{path='packaging/oracle/r1094_two_hotspot_attribution.py';blob='eb18784fe9fef8028760d85e08f3c6f7ae21cdb5'}
)

function Get-R1094GitBlob([byte[]]$bytes) {
    $prefix=[Text.Encoding]::ASCII.GetBytes(('blob '+$bytes.Length+[char]0))
    $hash=[Security.Cryptography.SHA1]::Create()
    try {
        $null=$hash.TransformBlock($prefix,0,$prefix.Length,$prefix,0)
        $null=$hash.TransformFinalBlock($bytes,0,$bytes.Length)
        return [BitConverter]::ToString($hash.Hash).Replace('-','').ToLowerInvariant()
    } finally { $hash.Dispose() }
}

function Import-R1094TrustedFunctions([string]$path) {
    $raw=[IO.File]::ReadAllBytes($path)
    if ((Get-R1094GitBlob $raw) -cne '13978d6afb01fc3898018e045aded87d673ef683') {
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

function Read-R1094Report([byte[]]$bytes) {
    if ($null -eq $bytes -or $bytes.Length -lt 200 -or $bytes.Length -gt 16384) {
        throw 'REPORT_BOUND_STOP'
    }
    foreach ($b in $bytes) {
        if ($b -ne 10 -and ($b -lt 32 -or $b -gt 126)) {
            throw 'REPORT_ASCII_STOP'
        }
    }
    $data=([Text.Encoding]::ASCII.GetString($bytes)) | ConvertFrom-Json
    $keys=@('schema','phase','result','roots','action','cutover','oci_retirement')
    if (@($data.PSObject.Properties.Name).Count -ne $keys.Count) {
        throw 'REPORT_SCHEMA_STOP'
    }
    foreach ($key in @($data.PSObject.Properties.Name)) {
        if ($keys -cnotcontains $key) { throw 'REPORT_SCHEMA_STOP' }
    }
    if ($data.schema -ne 1 -or $data.phase -cne 'R1094' -or
        $data.result -cne 'ATTRIBUTION_READONLY' -or
        $data.action -cne 'READ_ONLY' -or $data.cutover -cne 'NO_GO' -or
        $data.oci_retirement -cne 'STRICT_NO_GO') {
        throw 'REPORT_GUARD_STOP'
    }
    if (@($data.roots.PSObject.Properties.Name).Count -ne 2) {
        throw 'REPORT_SCHEMA_STOP'
    }
    $types=@('LIVE_SQLITE','SQLITE_SIDECAR','OBSERVER_ATOMIC_TMP',
        'UNCLASSIFIED_TEMP','OBSERVER_STATE','AUTOPILOT_OUTBOX',
        'AUTOPILOT_AUDIT_FAMILY','OTHER_JSONL','OTHER_JSON',
        'BACKUP_OR_ARCHIVE_UNVERIFIED','LOG','OTHER')
    $roots=[ordered]@{}
    foreach ($root in @('observer','autopilot')) {
        $v=$data.roots.$root
        $fields=@('objects','regular_files','allocated_bytes','categories','top')
        if ($null -eq $v -or @($v.PSObject.Properties.Name).Count -ne $fields.Count) {
            throw 'REPORT_SCHEMA_STOP'
        }
        foreach ($k in @($v.PSObject.Properties.Name)) {
            if ($fields -cnotcontains $k) { throw 'REPORT_SCHEMA_STOP' }
        }
        foreach ($f in @('objects','regular_files','allocated_bytes')) {
            $n=$v.$f
            if (($n -isnot [int] -and $n -isnot [long]) -or
                $n -lt 0 -or $n -gt 68719476736) { throw 'REPORT_VALUE_STOP' }
        }
        if ($v.objects -gt 100000 -or $v.regular_files -gt $v.objects) {
            throw 'REPORT_VALUE_STOP'
        }
        if (@($v.categories.PSObject.Properties.Name).Count -gt $types.Count -or
            @($v.top).Count -gt 8) { throw 'REPORT_SCHEMA_STOP' }
        $groups=[ordered]@{}
        $bytesCount=[long]0;$filesCount=[long]0
        foreach ($cat in @($v.categories.PSObject.Properties.Name)) {
            if ($types -cnotcontains $cat) { throw 'REPORT_CATEGORY_STOP' }
            $c=$v.categories.$cat
            $cols=@('files','allocated_bytes','over_7d_files',
                'over_7d_bytes','over_30d_files','over_30d_bytes')
            if (@($c.PSObject.Properties.Name).Count -ne $cols.Count) {
                throw 'REPORT_SCHEMA_STOP'
            }
            foreach ($k in @($c.PSObject.Properties.Name)) {
                if ($cols -cnotcontains $k) { throw 'REPORT_SCHEMA_STOP' }
                $n=$c.$k
                if (($n -isnot [int] -and $n -isnot [long]) -or
                    $n -lt 0 -or $n -gt 68719476736) { throw 'REPORT_VALUE_STOP' }
            }
            if ($c.over_30d_files -gt $c.over_7d_files -or
                $c.over_7d_files -gt $c.files -or
                $c.over_30d_bytes -gt $c.over_7d_bytes -or
                $c.over_7d_bytes -gt $c.allocated_bytes) {
                throw 'REPORT_VALUE_STOP'
            }
            $bytesCount+=[long]$c.allocated_bytes
            $filesCount+=[long]$c.files
            $groups[$cat]=$c
        }
        if ($bytesCount -ne [long]$v.allocated_bytes -or
            $filesCount -ne [long]$v.regular_files) {
            throw 'REPORT_TOTAL_STOP'
        }
        $items=@();$last=[long]68719476736
        foreach ($item in @($v.top)) {
            $cols=@('token','basename','class','allocated_bytes',
                'logical_bytes','age_days','hardlinks')
            if (@($item.PSObject.Properties.Name).Count -ne $cols.Count) {
                throw 'REPORT_SCHEMA_STOP'
            }
            foreach ($k in @($item.PSObject.Properties.Name)) {
                if ($cols -cnotcontains $k) { throw 'REPORT_SCHEMA_STOP' }
            }
            if ($item.token -cnotmatch '\A[0-9a-f]{12}\z' -or
                $item.basename -cnotmatch '\A[A-Za-z0-9._-]{1,100}\z' -or
                $types -cnotcontains $item.class) { throw 'REPORT_GUARD_STOP' }
            foreach ($f in @('allocated_bytes','logical_bytes','age_days','hardlinks')) {
                $n=$item.$f
                if (($n -isnot [int] -and $n -isnot [long]) -or
                    $n -lt 0 -or $n -gt 68719476736) { throw 'REPORT_VALUE_STOP' }
            }
            if ($item.age_days -gt 36500 -or $item.hardlinks -lt 1 -or
                $item.allocated_bytes -gt $last) { throw 'REPORT_VALUE_STOP' }
            $last=[long]$item.allocated_bytes
            $items+=$item
        }
        $roots[$root]=[ordered]@{
            objects=[long]$v.objects
            regular_files=[long]$v.regular_files
            allocated_bytes=[long]$v.allocated_bytes
            categories=$groups
            top=$items
        }
    }
    return [ordered]@{
        phase='R1094';result='ATTRIBUTION_READONLY';roots=$roots
        action='READ_ONLY';cutover='NO_GO';oci_retirement='STRICT_NO_GO'
    }
}

function Invoke-R1094 {
    # Single read-only report, no delete path or source writer mutation.
    $public=$null; $private=$null; $plain=$null; $encrypted=$null
    $password=$null; $reply=$null; $success=$null
    $stage='PREPARE';$clean=$true
    try {
        if ($PSVersionTable.PSVersion.Major -ne 5 -or
            $PSVersionTable.PSVersion.Minor -lt 1) { throw 'PS51_REQUIRED' }
        $stage='PUBLIC_SOURCE_PIN'
        $public=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) (
            'Temp\flop-r1094-public-'+[Guid]::NewGuid().ToString('N'))
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
                    (Get-R1094GitBlob $data) -cne $item.blob) {
                    throw 'PUBLIC_BLOB_PIN_STOP'
                }
                [Array]::Clear($data,0,$data.Length)
            }
        } finally { [Net.ServicePointManager]::SecurityProtocol=$oldTls }
        $stage='TRUSTED_HELPERS'
        Import-R1094TrustedFunctions (Join-Path $script:R1066Root 'r1066_owner_workflow.ps1')
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
            'Temp\flop-r1094-key-'+[Guid]::NewGuid().ToString('N'))
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
        $guest=[IO.File]::ReadAllBytes((Join-Path $public 'packaging\oracle\r1094_two_hotspot_attribution.py'))
        $stage='SSH_AND_ORACLE'
        $reply=[FlopR1079.Transport]::Run($ssh,($quoted -join ' '),$guest,58000)
        if ($reply.ExitCode -ne 0) {
            if ($reply.ExitCode -eq 255) { $stage='SSH_CONNECT_OR_AUTH_STOP' }
            else { $stage='ORACLE_GUARD_STOP' }
            throw 'NO_SUCCESS_RECEIPT'
        }
        $stage='RESPONSE_VALIDATION'
        $success=Read-R1094Report $reply.Output
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
        Write-Output '{"phase":"R1094","result":"STOP","code":"TEMP_CUSTODY_CLEANUP_STOP"}'
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
        Write-Output ('{"phase":"R1094","result":"STOP","code":"'+$stage+'"}')
    } else {
        Write-Output ($success | ConvertTo-Json -Compress -Depth 7)
    }
}

if ($args.Count -ne 0) {
    Write-Output '{"phase":"R1094","result":"STOP","code":"ARGS_STOP"}'
} else {
    Invoke-R1094
}
