# R1115: native Windows PowerShell 5.1 unit test for the ONLY fixed
# read-only remote STOP response parser. Never executes the owner wrapper.
# No SSH, credentials, escrow, network, instance or live source is contacted.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$source = Join-Path $PSScriptRoot '..\..\packaging\windows\r1112_original_identity_readonly.ps1'
$source = (Resolve-Path -LiteralPath $source).Path
$tokens = $null
$issues = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $source,[ref]$tokens,[ref]$issues
)
if (@($issues).Count -ne 0) { throw 'R1115_AST_PARSE_STOP' }
$all = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -ceq 'Read-R1112FixedStop'
},$true))
if ($all.Count -ne 1) { throw 'R1115_EXACT_FUNCTION_STOP' }
$functionText = $all[0].Extent.Text
# Keep the extraction narrow. Only this fixed, reviewed parser may be
# executed, and the extracted definition must not contain transport calls.
foreach ($disallowed in @('Read-Host','Invoke-WebRequest','Unprotect-R1027',
    'FlopR1079.Transport','Add-Type','ssh.exe','Remove-Item')) {
    if ($functionText.Contains($disallowed)) { throw 'R1115_SIDE_EFFECT_STOP' }
}
. ([scriptblock]::Create($functionText))

function Expect-R1115([string]$Raw,[string]$Want) {
    $bytes = [Text.Encoding]::ASCII.GetBytes($Raw)
    $actual = Read-R1112FixedStop $bytes
    if ($Want -ceq 'NULL') {
        if ($null -ne $actual) { throw 'R1115_BAD_RESPONSE_ACCEPTED' }
    } elseif ($actual -cne $Want) {
        throw 'R1115_VALID_RESPONSE_REJECTED'
    }
}

$good = '{"phase":"R1112","result":"STOP","reason":"UNIT_SHOW_STOP","source_archive":"NO_GO","cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}'
Expect-R1115 $good 'UNIT_SHOW_STOP'
foreach ($reason in @('UNIT_NAME_STOP','UNIT_SCHEMA_STOP','UNIT_IDENTITY_STOP',
  'TEMPLATE_CAT_STOP','UNIT_RACE_STOP','UNIT_BOUND_STOP','TIME_BUDGET_STOP',
  'READ_ONLY_WITNESS_UNAVAILABLE')) {
    Expect-R1115 ($good.Replace('UNIT_SHOW_STOP',$reason)) $reason
}
Expect-R1115 ($good.Replace('UNIT_SHOW_STOP','UNKNOWN_ORIGINAL_ERROR')) 'NULL'
Expect-R1115 ($good.Replace('STRICT_NO_GO','GO')) 'NULL'
Expect-R1115 ($good.Replace('"cutover":"NO_GO"','"cutover":"GO"')) 'NULL'
Expect-R1115 ($good.Replace('"phase":"R1112"','"phase":"R1102"')) 'NULL'
Expect-R1115 ($good.Replace('"result":"STOP"','"result":"PASS"')) 'NULL'
Expect-R1115 ($good.Replace('"reason":"UNIT_SHOW_STOP"','"reason":"UNIT_SHOW_STOP","extra":"raw"')) 'NULL'
Expect-R1115 ('garbage-prefix' + $good) 'NULL'
Expect-R1115 ($good + 'garbage-suffix') 'NULL'
Expect-R1115 '' 'NULL'
Expect-R1115 ($good + ("x" * 600)) 'NULL'
$nonAscii = [Text.Encoding]::ASCII.GetBytes($good)
$nonAscii[3] = 9
if ($null -ne (Read-R1112FixedStop $nonAscii)) { throw 'R1115_CONTROL_CHAR_ACCEPTED' }
Write-Output 'R1115_FIXED_STOP_PARSER_PASS'
