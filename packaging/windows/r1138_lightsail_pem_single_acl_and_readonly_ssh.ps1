# R1138: Harden exactly one existing Tokyo Lightsail PEM ACL, then one pinned
# R1136 read-only K137 authentication attempt. No global ACL, key copy, or server write.
param()
function Get-R1138Blob([byte[]]$bytes) {
    $pre=[Text.Encoding]::ASCII.GetBytes(('blob '+$bytes.Length+[char]0))
    $tmp=New-Object byte[] ($pre.Length+$bytes.Length)
    [Array]::Copy($pre,0,$tmp,0,$pre.Length)
    [Array]::Copy($bytes,0,$tmp,$pre.Length,$bytes.Length)
    $sha=[Security.Cryptography.SHA1]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($tmp)).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose();[Array]::Clear($tmp,0,$tmp.Length) }
}
function Get-R1138ExactPem {
    $dir=Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads'
    if (-not [IO.Directory]::Exists($dir)) { throw 'KEY_SELECTION_STOP' }
    $list=@(Get-ChildItem -LiteralPath $dir -File -ErrorAction Stop |
        Where-Object { $_.Name -match '\ALightsailDefault(?:Private)?Key-ap-northeast-1(?:\s*\([0-9]+\))?\.pem\z' })
    if ($list.Count -ne 1) { throw 'KEY_SELECTION_STOP' }
    $key=$list[0]
    if ($key.Length -lt 64 -or $key.Length -gt 32768 -or
        ($key.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        [IO.Path]::GetFullPath($key.DirectoryName) -cne [IO.Path]::GetFullPath($dir)) {
        throw 'KEY_SCOPE_STOP'
    }
    return $key
}
function Set-R1138SinglePemAcl([string]$path) {
    $file=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $file.PSIsContainer) { throw 'KEY_SCOPE_STOP' }
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $ownerSid=$owner.Value
    $systemSid='S-1-5-18'; $adminsSid='S-1-5-32-544'
    $allow=@($ownerSid,$systemSid,$adminsSid)
    $original=Get-Acl -LiteralPath $path -ErrorAction Stop
    if ($original.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $ownerSid -or
        -not $original.AreAccessRulesCanonical) { throw 'KEY_OWNER_OR_CANONICAL_STOP' }
    $rules=@($original.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if (@($rules | Where-Object {
        -not $_.IsInherited -and $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny
    }).Count -gt 0) { throw 'EXPLICIT_DENY_STOP' }
    $before=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    $size=$file.Length
    $updated=Get-Acl -LiteralPath $path -ErrorAction Stop
    $updated.SetAccessRuleProtection($true,$false)
    foreach ($rule in @($updated.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))) {
        if ($allow -cnotcontains $rule.IdentityReference.Value) {
            $updated.RemoveAccessRuleSpecific($rule)
        }
    }
    $userRule=[Security.AccessControl.FileSystemAccessRule]::new(
        $owner,[Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow)
    $updated.SetAccessRule($userRule)
    # Preserve OS management access but eliminate all other principals.
    foreach ($sid in @($systemSid,$adminsSid)) {
        $id=[Security.Principal.SecurityIdentifier]::new($sid)
        $rule=[Security.AccessControl.FileSystemAccessRule]::new(
            $id,[Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow)
        $updated.SetAccessRule($rule)
    }
    $expected=@($updated.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if (-not $updated.AreAccessRulesProtected -or
        @($expected | Where-Object {
            $_.IsInherited -or $allow -cnotcontains $_.IdentityReference.Value -or
            $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow
        }).Count -ne 0) { throw 'KEY_ACL_PLAN_STOP' }
    Set-Acl -LiteralPath $path -AclObject $updated -ErrorAction Stop
    $check=Get-Acl -LiteralPath $path -ErrorAction Stop
    $actual=@($check.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    $after=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    if (-not $check.AreAccessRulesProtected -or
        $check.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $ownerSid -or
        $after -cne $before -or (Get-Item -LiteralPath $path).Length -ne $size -or
        @($actual | Where-Object {
            $_.IsInherited -or $allow -cnotcontains $_.IdentityReference.Value -or
            $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow
        }).Count -gt 0 -or
        @($actual | Where-Object { $_.IdentityReference.Value -ceq $ownerSid }).Count -lt 1) {
        throw 'KEY_ACL_POSTCHECK_STOP'
    }
    return $true
}
function Invoke-R1138 {
    $stage='PREPARE_STOP';$aclDone=$false;$bytes=$null
    try {
        if ($PSVersionTable.PSVersion.Major -ne 5 -or
            $PSVersionTable.PSVersion.Minor -lt 1) { throw 'PS51_REQUIRED' }
        $stage='KEY_SELECTION_STOP'
        $key=Get-R1138ExactPem
        $stage='KEY_ACL_REPAIR_STOP'
        $aclDone=Set-R1138SinglePemAcl $key.FullName
        $stage='PINNED_R1136_BOOTSTRAP_STOP'
        $url='https://raw.githubusercontent.com/hanamaru777/technocore-safe-agent/'+
            '8bb664d2cb044ccefb2da1dbf05526a5fe2f8457/'+
            'packaging/windows/r1136_k137_readonly_ssh_diagnostic.ps1'
        $oldTls=[Net.ServicePointManager]::SecurityProtocol
        try {
            [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
            $web=New-Object Net.WebClient
            try { $bytes=$web.DownloadData($url) } finally { $web.Dispose() }
        } finally { [Net.ServicePointManager]::SecurityProtocol=$oldTls }
        if ($bytes.Length -ne 7977 -or
            (Get-R1138Blob $bytes) -cne '8826137ea0fd1bf67ca4d95a5f4b747a69da9ad0') {
            throw 'PIN_STOP'
        }
        $stage='R1136_REMOTE_READONLY_STOP'
        $script=(New-Object Text.UTF8Encoding($false,$true)).GetString($bytes)
        $responses=@(& ([ScriptBlock]::Create($script)))
        if ($responses.Count -ne 1 -or $responses[0].Length -gt 300) { throw 'RESPONSE_STOP' }
        $r=$responses[0] | ConvertFrom-Json -ErrorAction Stop
        if ($r.phase -cne 'R1136' -or
            $r.result -cne 'WINDOWS_K137_SSH_READONLY_PASS' -or
            $r.host_pinned -ne $true -or $r.uid_1000 -ne $true -or
            $r.source_bytes_transferred -ne 0 -or $r.cutover -cne 'NO_GO') {
            if ($r.result -ceq 'STOP' -and $r.code -match '\A[A-Z0-9_]{3,64}\z') {
                return (@{phase='R1138';result='KEY_ACL_HARDENED_SSH_STOP';
                    ssh_code=$r.code;key_acl_hardened=$true;cutover='NO_GO'} |
                    ConvertTo-Json -Compress)
            }
            throw 'RESPONSE_STOP'
        }
        return '{"phase":"R1138","result":"KEY_ACL_HARDENED_K137_SSH_READONLY_PASS","key_acl_hardened":true,"host_pinned":true,"uid_1000":true,"source_bytes_transferred":0,"cutover":"NO_GO"}'
    } catch {
        $allowed=@('PREPARE_STOP','PS51_REQUIRED','KEY_SELECTION_STOP',
            'KEY_ACL_REPAIR_STOP','PINNED_R1136_BOOTSTRAP_STOP',
            'R1136_REMOTE_READONLY_STOP')
        if ($allowed -cnotcontains $stage) { $stage='RUNNER_STOP' }
        return (@{phase='R1138';result='STOP';code=$stage;
            key_acl_hardened=[bool]$aclDone;cutover='NO_GO'} | ConvertTo-Json -Compress)
    } finally {
        if ($null -ne $bytes) { [Array]::Clear($bytes,0,$bytes.Length) }
    }
}
if ($args.Count -gt 0) {
    Write-Output '{"phase":"R1138","result":"STOP","code":"ARGS_STOP"}'
} else { Write-Output (Invoke-R1138) }
