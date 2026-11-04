# Source-only, Windows PowerShell 5.1. No network or approval-key Init.
param([ValidateSet('Recipient','Seal','Import')][string]$Operation='Recipient',
    [switch]$Execute,[string]$PlanFile='',[string]$PlanSha256='',
    [string]$RecipientFile='',[string]$RecipientSha256='',
    [string]$EnvelopeFile='',[string]$EnvelopeSha256='')
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Read-R1160Code([string]$Name,[string]$Pin) {
    $path=Join-Path $PSScriptRoot ('..\..\'+$Name.Replace('/','\'))
    $text=[IO.File]::ReadAllText($path,[Text.Encoding]::UTF8).Replace("`r`n","`n")
    $raw=[Text.Encoding]::UTF8.GetBytes($text)
    if($raw.Length -gt 524288){throw 'SOURCE_PIN_STOP'}
    $h=[Security.Cryptography.SHA1]::Create()
    try {
        $pre=[Text.Encoding]::ASCII.GetBytes(('blob '+$raw.Length+[char]0))
        if([BitConverter]::ToString($h.ComputeHash([byte[]]($pre+$raw))).Replace('-','').ToLowerInvariant() -cne $Pin){throw 'SOURCE_PIN_STOP'}
    } finally {$h.Dispose()}
    return $text
}
function Import-R1160Function([string]$Text,[string]$Name) {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors)
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)|Where-Object {$_.Name -ceq $Name})
    if($errors.Count -ne 0 -or $nodes.Count -ne 1){throw 'SOURCE_PIN_STOP'}
    $parameters=@($nodes[0].Parameters|Where-Object {$null -ne $_}|ForEach-Object {$_.Extent.Text}) -join ','
    $body=$nodes[0].Body.Extent.Text
    Set-Item ('Function:script:'+$Name) ([scriptblock]::Create(('param('+$parameters+")`n"+$body.Substring(1,$body.Length-2))))
}
function Read-R1160File([string]$Path,[int]$Maximum,[string]$Expected='') {
    Assert-R1159ExistingFile $Path 1 $Maximum
    $stream=[IO.File]::Open($Path,'Open','Read','Read')
    try {
        $raw=Read-R1160Bytes $stream $Maximum
        if($Expected -cne '' -and ([FlopR1062.Guards]::Sha256($raw) -cne $Expected)){
            [Array]::Clear($raw,0,$raw.Length);throw 'INPUT_HASH_STOP'
        }
        return ,$raw
    } finally {$stream.Dispose()}
}
function Read-R1160Bytes($Stream,[int]$Maximum) {
    if($Stream.Length -lt 1 -or $Stream.Length -gt $Maximum){throw 'INPUT_BOUND_STOP'}
    $raw=New-Object byte[] ([int]$Stream.Length);$offset=0
    try {
        while($offset -lt $raw.Length){$n=$Stream.Read($raw,$offset,$raw.Length-$offset);if($n -le 0){throw 'PARTIAL_INPUT_STOP'};$offset+=$n}
        return ,$raw
    } catch {[Array]::Clear($raw,0,$raw.Length);throw 'BINARY_READ_STOP'}
}
function Invoke-R1160Local($Meta,[byte[]]$Binary,[Security.SecureString]$Password=$null) {
    $json=[Text.Encoding]::UTF8.GetBytes(($Meta|ConvertTo-Json -Compress -Depth 16))
    $control=New-Object byte[] (4+$json.Length+$Binary.Length)
    $length=[BitConverter]::GetBytes([int]$json.Length);[Array]::Reverse($length)
    [Array]::Copy($length,0,$control,0,4);[Array]::Copy($json,0,$control,4,$json.Length)
    [Array]::Copy($Binary,0,$control,4+$json.Length,$Binary.Length)
    try {
        $r=[FlopR1089.OwnerPipe]::Run($script:R1160Python,('-I -B "'+$script:R1160Program+'" --pipe'),$control,$Password,180000)
        if($r.ExitCode -ne 0){throw 'LOCAL_VALIDATION_STOP'}
        return ,$r.Output
    } finally {[Array]::Clear($control,0,$control.Length)}
}
function Invoke-R1160 {
    $stage='SOURCE_PIN_STOP';$password=$null;$aes=$null;$packed=$null;$parts=@();$handles=@();$clean=$true;$result=$null
    try {
        if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1){throw 'PS51_REQUIRED'}
        if($args.Count -ne 0){throw 'UNEXPECTED_ARGUMENT_STOP'}
        if(-not $Execute){$stage='EXPLICIT_SOURCE_ONLY_OPERATION_REQUIRED';throw 'STOP'}
        # Use a reviewed local -NoProfile console, never transcript/debug/remote
        # sessions. Input bytes never enter command arguments or environment.
        if($null -ne (Get-Variable PSSenderInfo -ErrorAction SilentlyContinue)){throw 'LOCAL_CONSOLE_REQUIRED'}
        $map=Read-R1160Code 'packaging/migration/r1155_source_pins.json' 'e1ac08ced545205772808e403dbae1fba6dd8331'
        foreach($p in ($map|ConvertFrom-Json).PSObject.Properties){$null=Read-R1160Code $p.Name $p.Value}
        $lib=Read-R1160Code 'packaging/migration/r1066_owner_workflow.ps1' '13978d6afb01fc3898018e045aded87d673ef683'
        foreach($name in @('Read-R1066PinnedSource','Initialize-R1066')){Import-R1160Function $lib $name}
        $script:R1066Root=Join-Path $PSScriptRoot '..\migration';Initialize-R1066
        $existing=Read-R1160Code 'packaging/windows/r1159_authenticated_m2_bootstrap.ps1' '48029e5c61c51a8edf3993130b7014c11f68b077'
        Import-R1160Function $existing 'Assert-R1159ExistingFile'
        $aws=Read-R1160Code 'packaging/windows/r1138_lightsail_pem_single_acl_and_readonly_ssh.ps1' '317b245bca0161ad3827318892b12cbb24fc4cab'
        Import-R1160Function $aws 'Get-R1138ExactPem'
        $pipe=Read-R1160Code 'packaging/migration/r1089_owner_control_pipe.cs' 'f8d4d7f586a0cde53d1ffec06816869f47df0b11'
        $cng=Read-R1160Code 'packaging/migration/r1160_recipient_cng.cs' 'd4aee94a10cf165b92ce35166e8daaa8ab583e2b'
        if(-not ('FlopR1089.OwnerPipe' -as [type])){Add-Type -TypeDefinition $pipe}
        if(-not ('FlopR1160.Recipient' -as [type])){Add-Type -TypeDefinition $cng}
        $script:R1160Python=Join-Path $PSScriptRoot '..\..\.venv\Scripts\python.exe'
        $script:R1160Program=Join-Path $script:R1066Root 'r1160_owner_continuity.py'
        $local=[Environment]::GetFolderPath('LocalApplicationData')
        $old=Join-Path $local 'FLOP-R1157-approval'
        $stage='EXPLICIT_CUSTODY_CONSENT_REQUIRED'
        if((Read-Host 'Type PRESERVE_SAME_OWNER_NO_INIT_NO_ROTATION') -cne 'PRESERVE_SAME_OWNER_NO_INIT_NO_ROTATION'){throw 'STOP'}
        if($Operation -ceq 'Recipient') {
            # Guard NEW SID and absence of existing owner store BEFORE key setup.
            if([IO.Directory]::Exists($old) -or [IO.File]::Exists($old)){throw 'DESTINATION_EXISTS'}
            $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $hash=[FlopR1062.Guards]::Sha256([Text.Encoding]::UTF8.GetBytes($sid))
            if($hash -ceq ('1c9bd366b0bd87e01a542b8da3eb873d'+'daa08791c162d67069bbf5f6b55c19c1')){throw 'WRONG_SOURCE_ACCOUNT'}
            $out=Join-Path $local 'FLOP-R1160-recipient';New-R1027Custody $out
            [IO.File]::WriteAllText((Join-Path $out 'ATTEMPTED'),'NO_AUTOMATIC_RETRY',[Text.Encoding]::ASCII)
            Assert-R1027Acl (Join-Path $out 'ATTEMPTED')
            $id=[Guid]::NewGuid().ToString('N')
            $stage='RECIPIENT_SETUP_UNKNOWN_NO_RETRY'
            $pub=[FlopR1160.Recipient]::Create($id)
            $body=Invoke-R1160Local @{operation='recipient-body';transfer_id=$id;public_blob=[Convert]::ToBase64String($pub)} ([byte[]]@())
            $domain=[Text.Encoding]::ASCII.GetBytes(('FLOP-R1160-RECIPIENT-POSSESSION-v1'+[char]0))
            $signature=[FlopR1160.Recipient]::SignRecipient($id,([byte[]]($domain+$body)))
            $packet=[Text.Encoding]::UTF8.GetBytes(('{"body":'+[Text.Encoding]::UTF8.GetString($body)+',"signature":"'+[Convert]::ToBase64String($signature)+'"}'))
            $result=Invoke-R1160Local @{operation='save-recipient';recipient_b64=[Convert]::ToBase64String($packet);output=$out} ([byte[]]@())
        } else {
            $stage='REVIEWED_PUBLIC_INPUT_REQUIRED'
            foreach($pin in @($PlanSha256,$RecipientSha256)){if($pin -cnotmatch '\A[a-f0-9]{64}\z'){throw 'STOP'}}
            $plan=Read-R1160File $PlanFile 65536 $PlanSha256
            $recipient=Read-R1160File $RecipientFile 8192 $RecipientSha256
            $meta=@{operation='check-source';plan_b64=[Convert]::ToBase64String($plan);recipient_b64=[Convert]::ToBase64String($recipient)}
            if($Operation -ceq 'Seal') {
                # No owner passphrase/decryption on OLD. Frozen public root is
                # checked first. Source execution clearance is a separate review.
                $sourcePublic=Read-R1160File (Join-Path $old 'public.json') 377
                $meta.source_public_b64=[Convert]::ToBase64String($sourcePublic)
                $null=Invoke-R1160Local $meta ([byte[]]@());$meta.Remove('source_public_b64')
                $stage='SOURCE_CREDENTIAL_CUSTODY_STOP'
                $escrow=Find-R1027Backup;$pem=Get-R1138ExactPem
                $paths=@((Join-Path $old 'public.json'),(Join-Path $old 'approval.pem.enc'),$escrow,$pem.FullName)
                $caps=@(377,302,672,32768)
                for($i=0;$i -lt 4;$i++) {
                    Assert-R1159ExistingFile $paths[$i] 1 $caps[$i]
                    $handle=[IO.File]::Open($paths[$i],'Open','Read','Read');$handles+=,$handle
                    $parts+=,(Read-R1160Bytes $handle $caps[$i])
                }
                $size=20;foreach($b in $parts){$size+=$b.Length};$packed=New-Object byte[] $size
                $packed[3]=4;$offset=4
                foreach($b in $parts){$n=[BitConverter]::GetBytes([int]$b.Length);[Array]::Reverse($n);[Array]::Copy($n,0,$packed,$offset,4);$offset+=4;[Array]::Copy($b,0,$packed,$offset,$b.Length);$offset+=$b.Length}
                $meta.operation='seal';$opaque=Invoke-R1160Local $meta $packed
                # Do not publish the opaque result until input handles and
                # mutable secret buffers have been cleaned successfully.
                foreach($h in $handles){$h.Dispose()};$handles=@()
                foreach($b in $parts){[Array]::Clear($b,0,$b.Length)};$parts=@()
                [Array]::Clear($packed,0,$packed.Length);$packed=$null
                $out=Join-Path $local 'FLOP-R1160-export';New-R1027Custody $out
                $meta.operation='publish-envelope';$meta.envelope_b64=[Convert]::ToBase64String($opaque)
                $meta.envelope_sha256=[FlopR1062.Guards]::Sha256($opaque);$meta.output=$out
                $result=Invoke-R1160Local $meta ([byte[]]@())
            } else {
                $stage='ENVELOPE_OR_RECIPIENT_UNVERIFIED'
                if($EnvelopeSha256 -cnotmatch '\A[a-f0-9]{64}\z'){throw 'STOP'}
                $opaque=Read-R1160File $EnvelopeFile 65536 $EnvelopeSha256
                $meta.operation='inspect';$meta.envelope_b64=[Convert]::ToBase64String($opaque);$meta.envelope_sha256=$EnvelopeSha256
                $checked=Invoke-R1160Local $meta ([byte[]]@())
                $v=[Text.Encoding]::UTF8.GetString($checked)|ConvertFrom-Json
                if($v.code -cne 'R1160_RECIPIENT_REQUIRED'){throw 'STOP'}
                $out=Join-Path $local 'FLOP-R1160-import';New-R1027Custody $out
                [IO.File]::WriteAllText((Join-Path $out 'ATTEMPTED'),'NO_AUTOMATIC_RETRY',[Text.Encoding]::ASCII)
                Assert-R1027Acl (Join-Path $out 'ATTEMPTED')
                $stage='IMPORT_UNKNOWN_NO_RETRY'
                $aes=[FlopR1160.Recipient]::Unwrap($v.transfer_id,$v.recipient_fingerprint,[Convert]::FromBase64String($v.wrapped_key))
                # Original approval password only on NEW, via SecureString pipe.
                $password=Read-Host 'Existing owner approval passphrase (NEW only; NOT R987 recovery code)' -AsSecureString
                $meta.operation='import';$meta.output=$out
                $result=Invoke-R1160Local $meta $aes $password
            }
        }
    } catch {
        # Fixed stage only; no exception, path, key, password or raw helper output.
        $result=$null
    } finally {
        if($null -ne $password){try{$password.Dispose()}catch{$clean=$false}}
        foreach($b in @($aes,$packed)+$parts){if($null -ne $b){try{[Array]::Clear($b,0,$b.Length)}catch{$clean=$false}}}
        foreach($h in $handles){try{$h.Dispose()}catch{$clean=$false}}
    }
    if(-not $clean){return '{"code":"CLEANUP_UNVERIFIED","cutover":"NO_GO"}'}
    if($null -eq $result){return ('{"code":"'+$stage+'","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}')}
    # Only the pinned helper's fixed public result fields; never encrypted bytes.
    return [Text.Encoding]::UTF8.GetString($result)
}
Invoke-R1160
