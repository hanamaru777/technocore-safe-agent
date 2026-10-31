# R1116: Native PS5.1 offline-only R1112 positive report schema.
# No owner script, SSH, R987 escrow, Oracle or AWS calls.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$source=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\packaging\windows\r1112_original_identity_readonly.ps1')).Path
$tokens=$null;$issues=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$issues)
if (@($issues).Count -ne 0) {throw 'R1116_PARSE_STOP'}
$functions=@($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -ceq 'Read-R1112Report'
},$true))
if ($functions.Count -ne 1) {throw 'R1116_FUNCTION_STOP'}
$body=$functions[0].Extent.Text
foreach ($bad in @('Read-Host','Invoke-WebRequest','Unprotect-R1027',
  'FlopR1079.Transport','Add-Type','ssh.exe','Remove-Item')) {
    if ($body.Contains($bad)) {throw 'R1116_SIDE_EFFECT_STOP'}
}
. ([scriptblock]::Create($body))
$report=[ordered]@{
  phase='R1112';result='PRIVATE_G1_IDENTITY_WITNESS_ONLY';action='READ_ONLY'
  source_head='ec4bc4892d40cdd2a03e102faa44d72c89e01b99'
  expected=27;recognized=19;missing=8;extras=11;loaded=22
  unit_observation_sha256=('a'*64);unit_identity_sha256=('b'*64)
  template_source_scope='DISK_ONLY_NOT_LIVE_EQUIVALENCE'
  live_template_equivalence_proven=$false
  all_launchers_proven=$false;all_writers_fenced=$false
  g5_finality='NOT_PROVEN';source_archive='NO_GO'
  cutover='NO_GO';oci_retirement='STRICT_NO_GO'
}
function Check-R1116($value,[bool]$shouldPass) {
    $raw=$value | ConvertTo-Json -Compress -Depth 4
    $bytes=[Text.Encoding]::ASCII.GetBytes($raw+"\n")
    $accepted=$false
    try {
        $out=Read-R1112Report $bytes
        if ($out.template_source_scope -cne 'DISK_ONLY_NOT_LIVE_EQUIVALENCE' -or
            $out.live_template_equivalence_proven -ne $false -or
            $out.all_launchers_proven -ne $false -or
            $out.all_writers_fenced -ne $false -or
            $out.oci_retirement -cne 'STRICT_NO_GO') {
            throw 'R1116_BAD_ACCEPTANCE'
        }
        $accepted=$true
    } catch {
        if ($_.Exception.Message -ceq 'R1116_BAD_ACCEPTANCE') {throw}
    }
    if ($accepted -ne $shouldPass) {throw 'R1116_CONTRACT_STOP'}
}
Check-R1116 $report $true
$bad=$report.Clone();$bad.template_source_scope='LIVE_PROVEN';Check-R1116 $bad $false
$bad=$report.Clone();$bad.live_template_equivalence_proven=$true;Check-R1116 $bad $false
$bad=$report.Clone();$bad.all_launchers_proven=$true;Check-R1116 $bad $false
$bad=$report.Clone();$bad.all_writers_fenced=$true;Check-R1116 $bad $false
$bad=$report.Clone();$bad.unit_observation_sha256='c';Check-R1116 $bad $false
$bad=$report.Clone();$bad.Remove('template_source_scope');Check-R1116 $bad $false
$bad=$report.Clone();$bad.source_archive='GO';Check-R1116 $bad $false
Write-Output 'R1116_DISK_ONLY_WITNESS_SCHEMA_PASS'
