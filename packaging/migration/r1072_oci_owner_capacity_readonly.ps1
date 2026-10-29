# R1072 — authenticated ORIGINAL OCI metadata-only volume census.
# Uses ONLY pinned AST function definitions from R1066; never executes old consumed one-shot.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$script:R1066Root=$PSScriptRoot

function Import-R1072Library {
    $lib=Join-Path $PSScriptRoot 'r1066_owner_workflow.ps1'
    $bytes=[IO.File]::ReadAllBytes($lib)
    if ($bytes.Length -gt 32768) { throw 'LIB_SIZE_STOP' }
    $prefix=[Text.Encoding]::ASCII.GetBytes(('blob '+$bytes.Length+[char]0))
    $hash=[Security.Cryptography.SHA1]::Create()
    try {
        $null=$hash.TransformBlock($prefix,0,$prefix.Length,$prefix,0)
        $null=$hash.TransformFinalBlock($bytes,0,$bytes.Length)
        if ([BitConverter]::ToString($hash.Hash).Replace('-','').ToLowerInvariant() -cne '7a7d9790ccd9bb464c254188096d85fb315ee550') {
            throw 'LIB_PIN_STOP'
        }
    } finally { $hash.Dispose() }
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput(
        [Text.Encoding]::UTF8.GetString($bytes),[ref]$tokens,[ref]$errors)
    if ($errors.Count -ne 0) { throw 'LIB_PARSE_STOP' }
    foreach ($name in @('Read-R1066PinnedSource','Initialize-R1066')) {
        $nodes=@($ast.FindAll({
            param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]
        },$true) | Where-Object { $_.Name -ceq $name })
        if ($nodes.Count -ne 1) { throw 'LIB_DEF_STOP' }
        $parameters=(@($nodes[0].Parameters |
            Where-Object { $null -ne $_ } | ForEach-Object {$_.Extent.Text}) -join ',')
        $body=$nodes[0].Body.Extent.Text
        $fun=[scriptblock]::Create(('param('+$parameters+')'+[char]10+
            $body.Substring(1,$body.Length-2)))
        Set-Item -Path ('Function:script:'+$name) -Value $fun
    }
    [Array]::Clear($bytes,0,$bytes.Length)
}

function Check-R1072Result([byte[]]$Bytes) {
    if ($null -eq $Bytes -or $Bytes.Length -lt 150 -or $Bytes.Length -gt 3500) {
        throw 'OUTPUT_STOP'
    }
    foreach ($b in $Bytes) {
        if ($b -ne 10 -and ($b -lt 32 -or $b -gt 126)) { throw 'OUTPUT_STOP' }
    }
    $raw=[Text.Encoding]::ASCII.GetString($Bytes)
    $data=$raw | ConvertFrom-Json
    if ($data.phase -cne 'R1072_ORIGINAL_READONLY_CAPACITY' -or
        $data.result -cne 'INVENTORY_ONLY' -or
        $data.original_git -cne 'MATCH' -or
        $data.writer_admission -cne 'NOT_PROVEN' -or
        $data.common_sqlite_epoch -cne 'NOT_PROVEN' -or
        $data.original_archive -cne 'NOT_CREATED' -or
        $data.offhost_backup -cne 'NOT_CREATED' -or
        $data.k137_restore -cne 'NOT_PERFORMED' -or
        $data.cutover -cne 'NO_GO' -or
        $data.oci_retirement -cne 'STRICT_NO_GO') { throw 'RESPONSE_STOP' }
    $outer=@('phase','result','original_git','tree','free_bytes',
        'writer_admission','common_sqlite_epoch','original_archive',
        'offhost_backup','k137_restore','cutover','oci_retirement')
    $inner=@('entries','regular','directories','symlinks',
        'hardlink_repeated','special_objects','regular_bytes',
        'sqlite_bases','sqlite_wals','sqlite_shms')
    if (@($data.PSObject.Properties.Name).Count -ne $outer.Count -or
        @($data.tree.PSObject.Properties.Name).Count -ne $inner.Count -or
        [regex]::Matches($raw,'"[a-z0-9_]+"[ ]*:').Count -ne 22) {
        throw 'RESPONSE_STOP'
    }
    foreach ($key in @($data.PSObject.Properties.Name)) {
        if ($outer -cnotcontains $key) { throw 'RESPONSE_STOP' }
    }
    foreach ($key in @($data.tree.PSObject.Properties.Name)) {
        if ($inner -cnotcontains $key) { throw 'RESPONSE_STOP' }
        $v=$data.tree.$key
        if (($v -isnot [int] -and $v -isnot [long]) -or $v -lt 0) {
            throw 'RESPONSE_STOP'
        }
    }
    if (($data.free_bytes -isnot [int] -and $data.free_bytes -isnot [long]) -or
        $data.free_bytes -lt 0 -or $data.tree.entries -gt 25000 -or
        $data.tree.sqlite_bases -lt 2 -or
        $data.tree.regular_bytes -gt 68719476736) { throw 'RESPONSE_STOP' }
    # Return freshly serialized, narrow validated counts — never raw host output.
    return ([ordered]@{
        phase='R1072';result='INVENTORY_ONLY'
        entries=$data.tree.entries
        regular_bytes=$data.tree.regular_bytes
        sqlite_bases=$data.tree.sqlite_bases
        sqlite_wals=$data.tree.sqlite_wals
        symlinks=$data.tree.symlinks
        special_objects=$data.tree.special_objects
        original_disk_free_bytes=$data.free_bytes
        backup='NOT_CREATED';writer_admission='NOT_PROVEN'
        cutover='NO_GO';oci_retirement='STRICT_NO_GO'
    } | ConvertTo-Json -Compress)
}

function Get-R1072RemoteStop([int]$ExitCode,[byte[]]$Raw,[string]$Kind='SSH_UNKNOWN') {
    # Never reveal native SSH stderr, stdout, dynamic filenames, or credentials.
    # The exit status alone separates OpenSSH failures from guest guard refusal.
    if ($ExitCode -eq 255) {
        $allowed=@('SSH_OPTION_REJECTED','SSH_HOSTKEY_REJECTED',
            'SSH_IDENTITY_UNREADABLE','SSH_PUBLIC_KEY_REJECTED',
            'SSH_CONNECTIVITY_REJECTED','SSH_REMOTE_CLOSED')
        if ($allowed -ccontains $Kind) { return $Kind }
        return 'SSH_AUTH_ROUTE_OR_PIN_STOP'
    }
    if ($ExitCode -ne 42) { return 'REMOTE_EXEC_STOP' }
    if ($null -eq $Raw -or $Raw.Length -lt 100 -or $Raw.Length -gt 512) {
        return 'REMOTE_UNRECOGNIZED_STOP'
    }
    foreach ($byte in $Raw) {
        if ($byte -ne 10 -and ($byte -lt 32 -or $byte -gt 126)) {
            return 'REMOTE_UNRECOGNIZED_STOP'
        }
    }
    try {
        $text=[Text.Encoding]::ASCII.GetString($Raw)
        $obj=$text | ConvertFrom-Json
        $keys=@('phase','result','code','cutover','oci_retirement')
        if (@($obj.PSObject.Properties.Name).Count -ne $keys.Count -or
            [regex]::Matches($text,'"[a-z0-9_]+"[ ]*:').Count -ne $keys.Count) {
            return 'REMOTE_UNRECOGNIZED_STOP'
        }
        foreach ($key in @($obj.PSObject.Properties.Name)) {
            if ($keys -cnotcontains $key) { return 'REMOTE_UNRECOGNIZED_STOP' }
        }
        if ($obj.phase -cne 'R1072_ORIGINAL_READONLY_CAPACITY' -or
            $obj.result -cne 'STOP' -or $obj.cutover -cne 'NO_GO' -or
            $obj.oci_retirement -cne 'STRICT_NO_GO') {
            return 'REMOTE_UNRECOGNIZED_STOP'
        }
        $allowed=@('SOURCE_UNVERIFIED','ORIGINAL_PRIVILEGE_STOP',
            'WRONG_HOST_STOP','ORIGINAL_ROOT_STOP','ORIGINAL_HEAD_STOP',
            'INVENTORY_TIME_STOP','INVENTORY_PATH_STOP','INVENTORY_ENTRY_STOP',
            'INVENTORY_CHILD_STOP','INVENTORY_BYTES_STOP','TWO_SQLITE_STOP',
            'DISK_STATUS_STOP')
        if ($allowed -cnotcontains $obj.code) { return 'REMOTE_UNRECOGNIZED_STOP' }
        return ('GUEST_'+$obj.code)
    } catch {
        return 'REMOTE_UNRECOGNIZED_STOP'
    }
}

function Invoke-R1072 {
    $directory=$null;$plain=$null;$encrypted=$null;$code=$null;$reply=$null
    $result=$null;$clean=$true;$stage='PREPARE'
    try {
        if ($PSVersionTable.PSVersion.Major -ne 5 -or
            $PSVersionTable.PSVersion.Minor -lt 1) { throw 'PS_VERSION_STOP' }
        $stage='LOCAL_LIB_PIN'
        Import-R1072Library
        Initialize-R1066
        $freshCarrier=Read-R1066PinnedSource (
            Join-Path $PSScriptRoot 'r1079_profile_ssh_transport.cs'
        ) 'b150af9fe7a335bc6c02e8fc1e5451599d124a97'
        if (-not ('FlopR1079.Transport' -as [type])) {
            Add-Type -TypeDefinition $freshCarrier
        }
        $ssh=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe'
        $known=Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\known_hosts'
        if (-not [IO.File]::Exists($ssh) -or
            -not [IO.File]::Exists($known)) { throw 'SSH_ABSENT_STOP' }
        Assert-R1027LocalPath $ssh
        Assert-R1027LocalPath $known
        $stage='GUEST_SOURCE_PIN'
        $guest=Read-R1066PinnedSource (
            Join-Path $PSScriptRoot '..\oracle\r1072_original_readonly_capacity.py'
        ) '0ee105633366abe9e92d72eacc86e7be789aa851'
        $stage='LOCAL_ESCROW_INTEGRITY'
        $encrypted=Read-R1027Backup
        $stage='LOCAL_CODE_ENTRY'
        $code=Read-Host 'R987 V2 local recovery code' -AsSecureString
        if ($null -eq $code -or $code.Length -eq 0) {
            $stage='LOCAL_CODE_EMPTY'
            throw 'EMPTY_LOCAL_INPUT_STOP'
        }
        $stage='LOCAL_DECRYPT'
        try { $plain=Unprotect-R1027 $encrypted $code }
        finally { $code.Dispose();$code=$null }
        if ($null -eq $plain -or $plain.Length -lt 81 -or
            $plain.Length -gt 32768) { throw 'DECRYPT_OUTPUT_STOP' }
        $stage='LOCAL_CUSTODY'
        $directory=Join-Path (
            [Environment]::GetFolderPath('LocalApplicationData')
        ) ('Temp\flop-r1072-'+[Guid]::NewGuid().ToString('N'))
        New-R1027Custody $directory
        $key=Write-R1027Key $directory $plain
        [FlopR1062.Guards]::Clear($plain);$plain=$null
        $argv=@('-F','NUL','-T','-i',$key,'-o',
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
            'ubuntu@140.238.55.171','sudo -n /usr/bin/python3 -I -B -')
        $quoted=@($argv | ForEach-Object {
            [FlopR1062.Guards]::Quote($_)
        })
        $payload=[Text.Encoding]::UTF8.GetBytes($guest)
        $stage='SSH_CARRIER'
        $reply=[FlopR1079.Transport]::Run($ssh,($quoted -join ' '),$payload,58000)
        if ($reply.ExitCode -ne 0) {
            $stage=Get-R1072RemoteStop $reply.ExitCode $reply.Output $reply.FailureKind
            throw 'ORIGINAL_PROBE_STOP'
        }
        $stage='RESPONSE_SCHEMA'
        $result=Check-R1072Result $reply.Output
    } catch {
        $result=$null
        if ($stage -ceq 'SSH_CARRIER') {
            $kind=$null
            if ($null -ne $_.Exception.InnerException) {
                $kind=$_.Exception.InnerException.Message
            } elseif ($null -ne $_.Exception) {
                $kind=$_.Exception.Message
            }
            if (@('BOUND','PROFILE','START','TIMEOUT','IO','CLEANUP') -ccontains $kind) {
                $stage='SSH_CARRIER_'+$kind
            } else {
                $stage='SSH_CARRIER_UNCLASSIFIED'
            }
        }
    } finally {
        if ($null -ne $code) { $code.Dispose() }
        if ('FlopR1062.Guards' -as [type]) {
            [FlopR1062.Guards]::Clear($plain)
            [FlopR1062.Guards]::Clear($encrypted)
            if ($null -ne $reply) { [FlopR1062.Guards]::Clear($reply.Output) }
        }
        if ($null -ne $directory) {
            try { Remove-R1027Custody $directory }
            catch { $clean=$false }
        }
    }
    if (-not $clean) {
        Write-Output '{"phase":"R1072","result":"STOP","code":"CLEANUP_STOP"}'
    } elseif ($null -eq $result) {
        $valid=@('PREPARE','LOCAL_LIB_PIN','GUEST_SOURCE_PIN','LOCAL_ESCROW',
            'LOCAL_ESCROW_INTEGRITY','LOCAL_CODE_ENTRY','LOCAL_CODE_EMPTY',
            'LOCAL_DECRYPT','LOCAL_CUSTODY',
            'SSH_CARRIER','SSH_CARRIER_BOUND','SSH_CARRIER_PROFILE','SSH_CARRIER_START',
            'SSH_CARRIER_TIMEOUT','SSH_CARRIER_IO','SSH_CARRIER_CLEANUP',
            'SSH_CARRIER_UNCLASSIFIED','RESPONSE_SCHEMA',
            'SSH_AUTH_ROUTE_OR_PIN_STOP','SSH_OPTION_REJECTED',
            'SSH_HOSTKEY_REJECTED','SSH_IDENTITY_UNREADABLE',
            'SSH_PUBLIC_KEY_REJECTED','SSH_CONNECTIVITY_REJECTED',
            'SSH_REMOTE_CLOSED','REMOTE_EXEC_STOP',
            'REMOTE_UNRECOGNIZED_STOP','GUEST_SOURCE_UNVERIFIED',
            'GUEST_ORIGINAL_PRIVILEGE_STOP','GUEST_WRONG_HOST_STOP',
            'GUEST_ORIGINAL_ROOT_STOP','GUEST_ORIGINAL_HEAD_STOP',
            'GUEST_INVENTORY_TIME_STOP','GUEST_INVENTORY_PATH_STOP',
            'GUEST_INVENTORY_ENTRY_STOP','GUEST_INVENTORY_CHILD_STOP',
            'GUEST_INVENTORY_BYTES_STOP','GUEST_TWO_SQLITE_STOP',
            'GUEST_DISK_STATUS_STOP')
        if ($valid -cnotcontains $stage) { $stage='PREPARE' }
        $code=$stage
        if (-not $code.EndsWith('_STOP')) { $code+='_STOP' }
        Write-Output ('{"phase":"R1072","result":"STOP","code":"'+$code+'"}')
    } else {
        Write-Output $result
    }
}
if ($args.Count -eq 0) { Invoke-R1072 }
else { Write-Output '{"phase":"R1072","result":"STOP","code":"ARGS_STOP"}' }
