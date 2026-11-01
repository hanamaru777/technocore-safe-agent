# R1112: Windows PS5.1 R987 V2 -> one-shot original G1 effective identity read-only witness.
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
    @{path='packaging/oracle/r1112_original_identity_readonly.py';blob='85fca46b956843b74a87cf488a4995d76ddcf982';commit='5cb573dab60359cd7c1fa6800648fa2a0957ff9d'}
)

function Get-R1112GitBlob([byte[]]$bytes) {
    $prefix=[Text.Encoding]::ASCII.GetBytes(('blob '+$bytes.Length+[char]0))
    $hash=[Security.Cryptography.SHA1]::Create()
    try {
        $null=$hash.TransformBlock($prefix,0,$prefix.Length,$prefix,0)
        $null=$hash.TransformFinalBlock($bytes,0,$bytes.Length)
        return [BitConverter]::ToString($hash.Hash).Replace('-','').ToLowerInvariant()
    } finally { $hash.Dispose() }
}

function Import-R1112TrustedFunctions([string]$path) {
    $raw=[IO.File]::ReadAllBytes($path)
    if ((Get-R1112GitBlob $raw) -cne '13978d6afb01fc3898018e045aded87d673ef683') {
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

function Read-R1112Report([byte[]]$bytes) {
    if ($null -eq $bytes -or $bytes.Length -lt 250 -or $bytes.Length -gt 3000) { throw 'REPORT_BOUND_STOP' }
    foreach ($v in $bytes) {
        if ($v -ne 10 -and ($v -lt 32 -or $v -gt 126)) { throw 'REPORT_ASCII_STOP' }
    }
    $text=[Text.Encoding]::ASCII.GetString($bytes)
    $data=$text | ConvertFrom-Json
    $fields=@('phase','result','action','source_head','expected','recognized','missing','extras',
      'loaded','unit_observation_sha256','unit_identity_sha256',
      'template_source_scope','live_template_equivalence_proven','all_launchers_proven',
      'all_writers_fenced','g5_finality','source_archive','cutover','oci_retirement')
    if (@($data.PSObject.Properties.Name).Count -ne $fields.Count) { throw 'REPORT_SCHEMA_STOP' }
    foreach ($key in $data.PSObject.Properties.Name) {
      if ($fields -cnotcontains $key) { throw 'REPORT_SCHEMA_STOP' }
    }
    if ($data.phase -cne 'R1112' -or $data.result -cne 'PRIVATE_G1_IDENTITY_WITNESS_ONLY' -or
        $data.action -cne 'READ_ONLY' -or
        $data.source_head -cne 'ec4bc4892d40cdd2a03e102faa44d72c89e01b99' -or
        $data.template_source_scope -cne 'DISK_ONLY_NOT_LIVE_EQUIVALENCE' -or
        $data.live_template_equivalence_proven -isnot [bool] -or
        $data.live_template_equivalence_proven -or
        $data.all_launchers_proven -isnot [bool] -or $data.all_launchers_proven -or
        $data.all_writers_fenced -isnot [bool] -or $data.all_writers_fenced -or
        $data.g5_finality -cne 'NOT_PROVEN' -or $data.source_archive -cne 'NO_GO' -or
        $data.cutover -cne 'NO_GO' -or $data.oci_retirement -cne 'STRICT_NO_GO') {
        throw 'REPORT_GUARD_STOP'
    }
    foreach ($key in @('expected','recognized','missing','extras','loaded')) {
      $v=$data.$key
      if (($v -isnot [int] -and $v -isnot [long]) -or $v -lt 0 -or $v -gt 4096) {
        throw 'REPORT_VALUE_STOP'
      }
    }
    if ($data.expected -ne 27 -or $data.expected -ne ($data.recognized + $data.missing)) {
      throw 'REPORT_TOTAL_STOP'
    }
    foreach ($key in @('unit_observation_sha256','unit_identity_sha256')) {
      if ($data.$key -isnot [string] -or
          $data.$key -cnotmatch '\A[0-9a-f]{64}\z') { throw 'REPORT_DIGEST_STOP' }
    }
    return [ordered]@{
      phase='R1112';result='PRIVATE_G1_IDENTITY_WITNESS_ONLY';action='READ_ONLY'
      source_head=$data.source_head
      expected=[long]$data.expected;recognized=[long]$data.recognized
      missing=[long]$data.missing;extras=[long]$data.extras;loaded=[long]$data.loaded
      unit_observation_sha256=$data.unit_observation_sha256
      unit_identity_sha256=$data.unit_identity_sha256
      template_source_scope='DISK_ONLY_NOT_LIVE_EQUIVALENCE'
      live_template_equivalence_proven=$false
      all_launchers_proven=$false;all_writers_fenced=$false
      g5_finality='NOT_PROVEN';source_archive='NO_GO'
      cutover='NO_GO';oci_retirement='STRICT_NO_GO'
    }
}


function Read-R1112FixedStop([byte[]]$bytes) {
    # A nonzero SSH exit can be an explicit, fixed original-host
    # read-only STOP. Never echo stderr or arbitrary stdout.
    if ($null -eq $bytes -or $bytes.Length -lt 100 -or $bytes.Length -gt 500) {
        return $null
    }
    foreach ($v in $bytes) {
        if ($v -ne 10 -and ($v -lt 32 -or $v -gt 126)) { return $null }
    }
    try { $value=[Text.Encoding]::ASCII.GetString($bytes) | ConvertFrom-Json }
    catch { return $null }
    $keys=@('phase','result','reason','source_archive','cutover','oci_retirement')
    if (@($value.PSObject.Properties.Name).Count -ne $keys.Count) { return $null }
    foreach ($key in $value.PSObject.Properties.Name) {
        if ($keys -cnotcontains $key) { return $null }
    }
    $reasons=@('UNIT_NAME_STOP','UNIT_SHOW_STOP','UNIT_SCHEMA_STOP',
      'UNIT_IDENTITY_STOP','TEMPLATE_CAT_STOP','UNIT_RACE_STOP',
      'UNIT_BOUND_STOP','TIME_BUDGET_STOP','READ_ONLY_WITNESS_UNAVAILABLE')
    if ($value.phase -cne 'R1112' -or $value.result -cne 'STOP' -or
        $reasons -cnotcontains $value.reason -or
        $value.source_archive -cne 'NO_GO' -or
        $value.cutover -cne 'NO_GO' -or
        $value.oci_retirement -cne 'STRICT_NO_GO') { return $null }
    return [string]$value.reason
}

function Invoke-R1112 {
    # Single read-only report, no delete path or source writer mutation.
    $public=$null; $private=$null; $plain=$null; $encrypted=$null
    $password=$null; $reply=$null; $success=$null
    $stage='PREPARE';$clean=$true
    try {
        if ($PSVersionTable.PSVersion.Major -ne 5 -or
            $PSVersionTable.PSVersion.Minor -lt 1) { throw 'PS51_REQUIRED' }
        $stage='PUBLIC_SOURCE_PIN'
        $public=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) (
            'Temp\flop-r1112-public-'+[Guid]::NewGuid().ToString('N'))
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
                    (Get-R1112GitBlob $data) -cne $item.blob) {
                    throw 'PUBLIC_BLOB_PIN_STOP'
                }
                [Array]::Clear($data,0,$data.Length)
            }
        } finally { [Net.ServicePointManager]::SecurityProtocol=$oldTls }
        $stage='TRUSTED_HELPERS'
        Import-R1112TrustedFunctions (Join-Path $script:R1066Root 'r1066_owner_workflow.ps1')
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
            'Temp\flop-r1112-key-'+[Guid]::NewGuid().ToString('N'))
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
        $guest=[IO.File]::ReadAllBytes((Join-Path $public 'packaging\oracle\r1112_original_identity_readonly.py'))
        $stage='SSH_AND_ORACLE'
        $reply=[FlopR1079.Transport]::Run($ssh,($quoted -join ' '),$guest,58000)
        if ($reply.ExitCode -ne 0) {
            if ($reply.ExitCode -eq 255) {
                $stage='SSH_CONNECT_OR_AUTH_STOP'
            } elseif ($reply.ExitCode -eq 42) {
                $publicStop=Read-R1112FixedStop $reply.Output
                if ($null -ne $publicStop) { $stage=$publicStop }
                else { $stage='ORACLE_GUARD_STOP' }
            } else {
                $stage='ORACLE_GUARD_STOP'
            }
            throw 'NO_SUCCESS_RECEIPT'
        }
        $stage='RESPONSE_VALIDATION'
        $success=Read-R1112Report $reply.Output
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
        Write-Output '{"phase":"R1112","result":"STOP","code":"TEMP_CUSTODY_CLEANUP_STOP"}'
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
            'UNIT_NAME_STOP','UNIT_SHOW_STOP','UNIT_SCHEMA_STOP','UNIT_IDENTITY_STOP',
            'TEMPLATE_CAT_STOP','UNIT_RACE_STOP','UNIT_BOUND_STOP',
            'TIME_BUDGET_STOP','READ_ONLY_WITNESS_UNAVAILABLE',
            'REPORT_MODE_STOP','REPORT_COUNT_STOP','REPORT_UNCLASSIFIED_STOP')
        if ($allow -cnotcontains $stage) { $stage='GUARD_STOP' }
        Write-Output ('{"phase":"R1112","result":"STOP","code":"'+$stage+'"}')
    } else {
        Write-Output ($success | ConvertTo-Json -Compress -Depth 7)
    }
}

if ($args.Count -ne 0) {
    Write-Output '{"phase":"R1112","result":"STOP","code":"ARGS_STOP"}'
} else {
    Invoke-R1112
}
