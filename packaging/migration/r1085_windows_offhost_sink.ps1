# R1085 Windows PowerShell 5.1 ciphertext-only receiver. NEVER pipe
# ciphertext through PowerShell object/text pipelines: pass RAW process stdin.
# A separate owner-enrolled private NTFS directory and authorizing transport
# must exist. This script does NOT connect to Oracle, K137 or any network.
param([string]$ExistingPrivateNtfsParent='', [string]$NewArchiveFolder='',
      [long]$QuotaBytes=0, [switch]$AllowCiphertextOnly)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
try {
    if (-not $AllowCiphertextOnly) { throw 'OPT_IN_REQUIRED' }
    $source=Join-Path $PSScriptRoot 'r1085_windows_offhost_sink.cs'
    $bytes=[IO.File]::ReadAllBytes($source)
    if ($bytes.Length -gt 20000 -or $bytes.Length -lt 500) { throw 'SOURCE_BOUND' }
    $prefix=[Text.Encoding]::ASCII.GetBytes(('blob ' + $bytes.Length + [char]0))
    $sha=[Security.Cryptography.SHA1]::Create()
    try {
        $null=$sha.TransformBlock($prefix,0,$prefix.Length,$prefix,0)
        $null=$sha.TransformFinalBlock($bytes,0,$bytes.Length)
        $pin=[BitConverter]::ToString($sha.Hash).Replace('-','').ToLowerInvariant()
        if ($pin -cne '661f8ce097aa50986d4f6847d0693edcd1531149') { throw 'SOURCE_PIN' }
    } finally { $sha.Dispose() }
    $raw=[Text.Encoding]::UTF8.GetString($bytes)
    Add-Type -TypeDefinition $raw -ReferencedAssemblies @('System.dll','System.Core.dll','System.Security.dll') -ErrorAction Stop
    $inputStream=[Console]::OpenStandardInput()
    try { $status=[FlopR1085.Sink]::Receive($inputStream,$ExistingPrivateNtfsParent,
                                             $NewArchiveFolder,$QuotaBytes) }
    finally { $inputStream.Dispose() }
    if ($status -cne 'CIPHERTEXT_ONLY_NOT_AEAD_VERIFIED') { throw 'RECEIPT' }
    [Console]::Out.WriteLine('{"operation":"CIPHERTEXT_ONLY_NOT_AEAD_VERIFIED","full_backup":"NOT_PROVEN","aead_verified":false,"common_sqlite_epoch":"NOT_PROVEN","restore":"NOT_PERFORMED","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}')
    exit 0
} catch {
    # No private path, credentials, or raw exception is disclosed.
    [Console]::Out.WriteLine('{"operation":"BLOCKED","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}')
    exit 42
}
