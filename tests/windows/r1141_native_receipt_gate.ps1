# R1141 Windows PowerShell 5.1 strict R1129 receipt tests, all synthetic.
$ErrorActionPreference='Stop'
if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'PS51_REQUIRED' }
. 'packaging/windows/r1141_k137_recipient_receipt_gate.ps1'
$good=[ordered]@{
  phase='R1129'
  result='PROVISIONAL_CIPHERTEXT_STORED_ONLY'
  files=3
  bytes=123456
  aead_verified=$false
  source_complete=$false
  sqlite_epoch='NOT_PROVEN'
  history_finality='UNKNOWN'
  signer_portability='NOT_PROVEN'
  activated=$false
  cutover='NO_GO'
  oci_retirement='STRICT_NO_GO'
}
function Invoke-R1141Test([string]$text,[long]$forward,[bool]$expectPass) {
  $raw=[Text.Encoding]::ASCII.GetBytes($text)
  $accepted=$false
  try {
    $r=Assert-R1141R1129Receipt $raw $forward
    if ($r.phase -cne 'R1141' -or $r.aead_verified -ne $false -or
        $r.activated -ne $false -or $r.source_complete -ne $false -or
        $r.cutover -cne 'NO_GO' -or $r.oci_retirement -cne 'STRICT_NO_GO' -or
        $r.recipient_ciphertext_bytes -gt $r.forwarded_wire_bytes) {
      throw 'FORGED_ACCEPTANCE_STOP'
    }
    $accepted=$true
  } catch {
    if ($_.Exception.Message -ceq 'FORGED_ACCEPTANCE_STOP') { throw }
  }
  if ($accepted -ne $expectPass) { throw 'R1141_EXPECTATION_STOP' }
}
$ok=$good | ConvertTo-Json -Compress
Invoke-R1141Test $ok 123900 $true
$dupe=$ok.Replace('"phase":"R1129"','"phase":"R1129","phase":"R1129"')
Invoke-R1141Test $dupe 123900 $false
$unknown=$ok.Replace('"phase":"R1129"','"phase":"R1129","unknown":"evil"')
Invoke-R1141Test $unknown 123900 $false
$spoof=$ok.Replace('"aead_verified":false','"aead_verified":true')
Invoke-R1141Test $spoof 123900 $false
$spoof=$ok.Replace('"source_complete":false','"source_complete":true')
Invoke-R1141Test $spoof 123900 $false
$spoof=$ok.Replace('"activated":false','"activated":true')
Invoke-R1141Test $spoof 123900 $false
$spoof=$ok.Replace('"cutover":"NO_GO"','"cutover":"GO"')
Invoke-R1141Test $spoof 123900 $false
$spoof=$ok.Replace('"bytes":123456','"bytes":123901')
Invoke-R1141Test $spoof 123900 $false
$spoof=$ok.Replace('"bytes":123456','"bytes":"123456"')
Invoke-R1141Test $spoof 123900 $false
$spoof=$ok.Replace('"files":3','"files":true')
Invoke-R1141Test $spoof 123900 $false
$spoof=$ok.Replace('"files":3','"files":259')
Invoke-R1141Test $spoof 123900 $false
$spoof=$ok.Replace('"sqlite_epoch":"NOT_PROVEN"','"sqlite_epoch":"PROVEN"')
Invoke-R1141Test $spoof 123900 $false
$spoof=$ok.Replace('"phase":"R1129"','"phase":"R1129\u0022"')
Invoke-R1141Test $spoof 123900 $false
Invoke-R1141Test ($ok+'garbage') 123900 $false
Invoke-R1141Test $ok 123450 $false
Write-Host 'R1141_NATIVE_RECIPIENT_RECEIPT=PASS'
