# R1144 native Windows PS5.1 parser tests; no source host, no SSH.
$ErrorActionPreference='Stop'
if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'R1144_PS51_REQUIRED' }
$path='packaging/windows/r1144_oracle_preseed_metadata_one_shot.ps1'
$src=[IO.File]::ReadAllText($path)
$t=$null;$issues=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($src,[ref]$t,[ref]$issues)
if (@($issues).Count -ne 0) { throw 'R1144_SYNTAX_STOP' }
foreach ($name in @('Read-R1144Report','Read-R1144FixedStop')) {
    $functions=@($ast.FindAll({
        param($n)
        $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name
    },$true))
    if ($functions.Count -ne 1) { throw 'R1144_FUNCTION_STOP' }
    Invoke-Expression $functions[0].Extent.Text
}
if (-not $src.Contains('ec8317b58777c4060c1aad3215ebc50b29a02f54') -or
    -not $src.Contains('r1139_source_preseed_metadata_readonly.py') -or
    -not $src.Contains('StrictHostKeyChecking=yes') -or
    -not $src.Contains('Unprotect-R1027') -or
    -not $src.Contains('Remove-R1027Custody') -or
    $src.Contains('SOURCE_PRESEED_METADATA_GO')) { throw 'R1144_SCOPE_STOP' }
$files=[ordered]@{
    'verified-did'=[ordered]@{exists=$true;regular=$true;single_link=$true;within_limit=$true;size_bytes=99}
    'nonces'=[ordered]@{exists=$true;regular=$true;single_link=$true;within_limit=$true;size_bytes=99}
    'signer-receipts'=[ordered]@{exists=$true;regular=$true;single_link=$true;within_limit=$true;size_bytes=99}
}
$report=[ordered]@{
    phase='R1139';result='SOURCE_PRESEED_METADATA_READY';action='READ_ONLY'
    source_head='ec4bc4892d40cdd2a03e102faa44d72c89e01b99'
    machine_sha256=('a'*64);files=$files;data_bytes_exported=0
    common_sqlite_epoch='NOT_PROVEN';source_archive='NO_GO'
    cutover='NO_GO';oci_retirement='STRICT_NO_GO'
}
function Assert-R1144Report([string]$value,[bool]$expected) {
    $accepted=$false
    try {
        $r=Read-R1144Report ([Text.Encoding]::ASCII.GetBytes($value+[char]10))
        if ($r.phase -cne 'R1144' -or $r.data_bytes_exported -ne 0 -or
            $r.source_archive -cne 'NO_GO' -or $r.cutover -cne 'NO_GO' -or
            $r.oci_retirement -cne 'STRICT_NO_GO') { throw 'FORGED_GO_STOP' }
        $accepted=$true
    } catch {
        if ($_.Exception.Message -ceq 'FORGED_GO_STOP') { throw }
    }
    if ($accepted -ne $expected) { throw 'R1144_RESULT_EXPECTATION_STOP' }
}
$json=$report | ConvertTo-Json -Compress -Depth 8
Assert-R1144Report $json $true
Assert-R1144Report ($json.Replace('"cutover":"NO_GO"','"cutover":"GO"')) $false
Assert-R1144Report ($json.Replace('"data_bytes_exported":0','"data_bytes_exported":1')) $false
Assert-R1144Report ($json.Replace('"phase":"R1139"','"phase":"R1139","phase":"R1139"')) $false
Assert-R1144Report ($json.Replace('"machine_sha256":"'+('a'*64)+'"','"machine_sha256":"hi"')) $false
Assert-R1144Report ($json.Replace('"size_bytes":99','"size_bytes":9999999999')) $false
$report.files.nonces.within_limit=$false
$report.files.nonces.size_bytes=0
$report.result='SOURCE_PRESEED_METADATA_GAPS'
Assert-R1144Report ($report | ConvertTo-Json -Compress -Depth 8) $true
$report.result='SOURCE_PRESEED_METADATA_READY'
Assert-R1144Report ($report | ConvertTo-Json -Compress -Depth 8) $false
$stop='{"phase":"R1139","result":"STOP","code":"SOURCE_FILE_LINK_STOP","source_archive":"NO_GO","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}'
if ((Read-R1144FixedStop ([Text.Encoding]::ASCII.GetBytes($stop+[char]10))) -cne 'SOURCE_FILE_LINK_STOP') {
    throw 'R1144_STOP_STOP'
}
if ($null -ne (Read-R1144FixedStop ([Text.Encoding]::ASCII.GetBytes(
    $stop.Replace('STRICT_NO_GO','GO')+[char]10)))) { throw 'R1144_FORGED_STOP' }
Write-Host 'R1144_NATIVE_METADATA_PARSER=PASS'
