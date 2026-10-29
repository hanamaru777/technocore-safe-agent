# R1088 Windows PowerShell 5.1 read-only NTFS archive custody.
param([Parameter(Mandatory=$true)][string]$ArchiveRoot)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
try {
 $path=Join-Path $PSScriptRoot 'r1088_windows_ciphertext_custody.cs'
 $raw=[IO.File]::ReadAllText($path,[Text.Encoding]::UTF8).Replace(([string][char]13+[char]10),([string][char]10))
 $bytes=[Text.Encoding]::UTF8.GetBytes($raw)
 if($bytes.Length -lt 500 -or $bytes.Length -gt 16000){throw 'SOURCE_BOUND_STOP'}
 $prefix=[Text.Encoding]::ASCII.GetBytes(('blob '+$bytes.Length+[char]0))
 $sha=[Security.Cryptography.SHA1]::Create()
 try {
  $null=$sha.TransformBlock($prefix,0,$prefix.Length,$prefix,0)
  $null=$sha.TransformFinalBlock($bytes,0,$bytes.Length)
  $pin=[BitConverter]::ToString($sha.Hash).Replace('-','').ToLowerInvariant()
  if($pin -cne '16b9feffddb2339570593b588956bfaea3d496ba'){throw 'SOURCE_PIN_STOP'}
 } finally {$sha.Dispose()}
 Add-Type -TypeDefinition $raw -ReferencedAssemblies @('System.dll','System.Core.dll','System.Security.dll') -ErrorAction Stop
 $checked=[FlopR1088.Custody]::Validate($ArchiveRoot)
 if($checked -cne 'NTFS_PRIVATE_CIPHERTEXT_ARCHIVE'){throw 'CUSTODY_STOP'}
 [Console]::Out.WriteLine('{"operation":"NTFS_PRIVATE_CIPHERTEXT_ARCHIVE","aead_verified":false,"source_epoch":"NOT_PROVEN","cutover":"NO_GO"}')
 exit 0
} catch {
 [Console]::Out.WriteLine('{"operation":"BLOCKED","cutover":"NO_GO"}')
 exit 42
}
