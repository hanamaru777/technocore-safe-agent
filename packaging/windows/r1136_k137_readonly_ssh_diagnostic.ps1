# R1136: PS5.1 exact host-pinned K137 read-only SSH via pinned R1079 helper.
# No Oracle operations, SSH key upload, source export, AWS mutation or retries.
param()
$script:R1136SourceCommit='8ac3a3d067461553512915a89e91dffa015de246'
$script:R1136TransportBlob='b150af9fe7a335bc6c02e8fc1e5451599d124a97'
$script:R1136HostKey='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIyiNgOHH+g+6CnwWoVfeJIWcWpQxTsPVH7eAtsGtHTE'
$script:R1136HostDigest=('74f7cca65d477fd7b7af0e5a17'+'a74e40457481457ae70190e653d29e9f6d195a')

function Get-R1136GitBlob([byte[]]$data) {
    $pre=[Text.Encoding]::ASCII.GetBytes(('blob '+$data.Length+[char]0))
    $full=New-Object byte[] ($pre.Length+$data.Length)
    [Array]::Copy($pre,0,$full,0,$pre.Length)
    [Array]::Copy($data,0,$full,$pre.Length,$data.Length)
    $sha=[Security.Cryptography.SHA1]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($full)).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose();[Array]::Clear($full,0,$full.Length) }
}
function Get-R1136HostDigest([string]$pub) {
    $p=$pub.Split(' ')
    if ($p.Count -ne 2 -or $p[0] -cne 'ssh-ed25519') { throw 'HOST_KEY_FORMAT' }
    $raw=[Convert]::FromBase64String($p[1])
    if ($raw.Length -ne 51) { throw 'HOST_KEY_FORMAT' }
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($raw)).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose();[Array]::Clear($raw,0,$raw.Length) }
}
function Get-R1136Status([int]$exit,[string]$kind) {
    if ($exit -ne 255) { return 'SSH_REMOTE_EXIT_STOP' }
    switch -CaseSensitive ($kind) {
        'SSH_IDENTITY_UNREADABLE' { return 'KEY_ACL_OR_FORMAT_STOP' }
        'SSH_HOSTKEY_REJECTED' { return 'HOST_KEY_REJECTED_STOP' }
        'SSH_PUBLIC_KEY_REJECTED' { return 'SSH_AUTH_STOP' }
        'SSH_CONNECTIVITY_REJECTED' { return 'SSH_CONNECTIVITY_STOP' }
        'SSH_OPTION_REJECTED' { return 'SSH_OPTION_STOP' }
        'SSH_REMOTE_CLOSED' { return 'SSH_REMOTE_CLOSED_STOP' }
        default { return 'SSH_UNKNOWN_STOP' }
    }
}
function Quote-R1136Arg([string]$v) {
    if ($v.Length -lt 1 -or $v.Length -gt 4096 -or $v.Contains('"') -or
        $v -match '[\x00-\x1f]' -or $v.EndsWith('\')) { throw 'SSH_ARG_STOP' }
    return ('"'+$v+'"')
}
function Get-R1136Options([string]$identity,[string]$known) {
    return @('-F','NUL','-T','-i',$identity,
      '-o',('UserKnownHostsFile='+$known.Replace('\','/')),
      '-o','GlobalKnownHostsFile=NUL','-o','StrictHostKeyChecking=yes',
      '-o','HostKeyAlgorithms=ssh-ed25519','-o','PasswordAuthentication=no',
      '-o','KbdInteractiveAuthentication=no','-o','PreferredAuthentications=publickey',
      '-o','HostbasedAuthentication=no','-o','GSSAPIAuthentication=no',
      '-o','UpdateHostKeys=no','-o','BatchMode=yes','-o','IdentitiesOnly=yes',
      '-o','IdentityAgent=none','-o','ClearAllForwardings=yes',
      '-o','ForwardAgent=no','-o','ForwardX11=no','-o','PermitLocalCommand=no',
      '-o','ProxyCommand=none','-o','ProxyJump=none','-o','CanonicalizeHostname=no',
      '-o','ConnectionAttempts=1','-o','ConnectTimeout=7',
      '-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2',
      '-o','LogLevel=ERROR','ubuntu@52.198.96.243','/usr/bin/id -u')
}
function Invoke-R1136 {
    $stage='PREPARE_STOP';$known=$null;$answer=$null;$clean=$true;$helper=$null
    try {
        if ($PSVersionTable.PSVersion.Major -ne 5 -or
            $PSVersionTable.PSVersion.Minor -lt 1) { throw 'PS51_REQUIRED' }
        $stage='SSH_CLIENT_STOP'
        $ssh=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe'
        if (-not [IO.File]::Exists($ssh)) { throw 'STOP' }
        $stage='KEY_SEARCH_STOP'
        $downloads=Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads'
        if (-not [IO.Directory]::Exists($downloads)) { throw 'STOP' }
        $keys=@(Get-ChildItem -LiteralPath $downloads -File -ErrorAction Stop |
          Where-Object { $_.Name -match '\ALightsailDefault(?:Private)?Key-ap-northeast-1(?:\s*\([0-9]+\))?\.pem\z' })
        if ($keys.Count -ne 1) { throw 'STOP' }
        $stage='KEY_FILE_STOP'
        $key=$keys[0]
        if ($key.Length -lt 64 -or $key.Length -gt 32768 -or
            ($key.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'STOP' }
        $stage='HOST_PIN_STOP'
        if ((Get-R1136HostDigest $script:R1136HostKey) -cne $script:R1136HostDigest) {
            throw 'STOP'
        }
        $stage='TRANSPORT_PIN_STOP'
        $url='https://raw.githubusercontent.com/hanamaru777/technocore-safe-agent/'+
             $script:R1136SourceCommit+'/packaging/migration/r1079_profile_ssh_transport.cs'
        $oldTls=[Net.ServicePointManager]::SecurityProtocol
        try {
            [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
            $web=New-Object Net.WebClient
            try { $helper=$web.DownloadData($url) } finally { $web.Dispose() }
        } finally { [Net.ServicePointManager]::SecurityProtocol=$oldTls }
        if ($helper.Length -lt 4000 -or $helper.Length -gt 32768 -or
            (Get-R1136GitBlob $helper) -cne $script:R1136TransportBlob) {
            throw 'STOP'
        }
        $stage='TRANSPORT_COMPILE_STOP'
        if (-not ('FlopR1079.Transport' -as [type])) {
            $code=(New-Object Text.UTF8Encoding($false,$true)).GetString($helper)
            Add-Type -TypeDefinition $code -ErrorAction Stop
        }
        $stage='KNOWN_HOST_STOP'
        $known=Join-Path ([IO.Path]::GetTempPath()) ('flop-r1136-known-'+[Guid]::NewGuid().ToString('N'))
        $fs=[IO.File]::Open($known,[IO.FileMode]::CreateNew,
                            [IO.FileAccess]::Write,[IO.FileShare]::None)
        try {
            $buf=[Text.Encoding]::ASCII.GetBytes(('52.198.96.243 '+$script:R1136HostKey+[char]10))
            $fs.Write($buf,0,$buf.Length);$fs.Flush($true)
        } finally { $fs.Dispose() }
        $stage='SSH_CONNECT_OR_AUTH_STOP'
        $opts=Get-R1136Options $key.FullName $known
        $argText=(@($opts | ForEach-Object { Quote-R1136Arg $_ }) -join ' ')
        $receipt=[FlopR1079.Transport]::Run($ssh,$argText,[byte[]]@(),30000)
        if ($receipt.ExitCode -ne 0) {
            $stage=Get-R1136Status $receipt.ExitCode $receipt.FailureKind
            throw 'STOP'
        }
        $stage='SSH_RESPONSE_STOP'
        if ($receipt.Output.Length -lt 4 -or $receipt.Output.Length -gt 8 -or
            ([Text.Encoding]::ASCII.GetString($receipt.Output) -cnotmatch '\A1000\r?\n?\z')) {
            throw 'STOP'
        }
        $answer='{"phase":"R1136","result":"WINDOWS_K137_SSH_READONLY_PASS","host_pinned":true,"uid_1000":true,"source_bytes_transferred":0,"cutover":"NO_GO"}'
    } catch {
        if ($null -eq $answer) {
            $allowed=@('PREPARE_STOP','PS51_REQUIRED','SSH_CLIENT_STOP','KEY_SEARCH_STOP',
                'KEY_FILE_STOP','HOST_PIN_STOP','TRANSPORT_PIN_STOP',
                'TRANSPORT_COMPILE_STOP','KNOWN_HOST_STOP','SSH_CONNECT_OR_AUTH_STOP',
                'KEY_ACL_OR_FORMAT_STOP','HOST_KEY_REJECTED_STOP','SSH_AUTH_STOP',
                'SSH_CONNECTIVITY_STOP','SSH_OPTION_STOP','SSH_REMOTE_CLOSED_STOP',
                'SSH_UNKNOWN_STOP','SSH_REMOTE_EXIT_STOP','SSH_RESPONSE_STOP')
            if ($allowed -cnotcontains $stage) { $stage='RUNNER_STOP' }
            $answer=(@{phase='R1136';result='STOP';code=$stage} | ConvertTo-Json -Compress)
        }
    } finally {
        if ($null -ne $helper) { [Array]::Clear($helper,0,$helper.Length) }
        if ($null -ne $known -and [IO.File]::Exists($known)) {
            try { [IO.File]::Delete($known) } catch { $clean=$false }
        }
    }
    if (-not $clean) {
        Write-Output '{"phase":"R1136","result":"STOP","code":"KNOWN_HOST_CLEANUP_STOP"}'
    } else { Write-Output $answer }
}
if ($args.Count -ne 0) {
    Write-Output '{"phase":"R1136","result":"STOP","code":"ARGS_STOP"}'
} else { Invoke-R1136 }
