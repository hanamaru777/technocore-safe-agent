# R1140 native PS5.1 synthetic binary bridge tests. No SSH or credentials.
$ErrorActionPreference='Stop'
if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'R1140_PS51_REQUIRED' }
Add-Type -TypeDefinition ([IO.File]::ReadAllText('packaging/windows/r1140_binary_ciphertext_bridge.cs')) -ErrorAction Stop
$python=(Get-Command python.exe -ErrorAction Stop).Source
$temp=Join-Path $env:TEMP ('flop-r1140-synthetic-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp) | Out-Null
function Set-R1140Source([string]$payload) {
    $path=Join-Path $temp 'synthetic_source.py'
    [IO.File]::WriteAllText($path,$payload,[Text.Encoding]::ASCII)
    return ('-I -B "'+$path+'"')
}
function Assert-R1140Stop([string]$source,[string]$expected,[string]$dest) {
    $src=Set-R1140Source $source
    $control=[Text.Encoding]::ASCII.GetBytes('SYNTHETIC-CONTROL-ONLY')
    $stopped=$false
    try { $null=[FlopR1140.Bridge]::Pump($python,$src,$python,$dest,$control,30000) }
    catch {
        if ($_.Exception.Message -notmatch $expected) { throw }
        $stopped=$true
    }
    if (-not $stopped -or @($control | Where-Object {$_ -ne 0}).Count -ne 0) {
        throw 'R1140_REJECT_OR_ZEROIZE_STOP'
    }
}
try {
    $sink=Join-Path $temp 'synthetic_sink.py'
    $consumer=@'
import sys
import time
data=sys.stdin.buffer.read()
time.sleep(4)
sys.stdout.buffer.write(b'RECIPIENT-CIPHERTEXT-ONLY')
'@
    [IO.File]::WriteAllText($sink,$consumer,[Text.Encoding]::ASCII)
    $dst='-I -B "'+$sink+'"'
    $good=@'
import sys
request=sys.stdin.buffer.read()
expected=bytes.fromhex('00524646312d5241572d494e5055542dff0d0a')
if request!=expected:
    sys.exit(67)
sys.stdout.buffer.write(b'FLOPST01'+b'A'*100000)
sys.stdout.buffer.flush()
'@
    $src=Set-R1140Source $good
    $request=[byte[]]@(0,82,70,70,49,45,82,65,87,45,73,78,80,85,84,45,255,13,10)
    $r=[FlopR1140.Bridge]::Pump($python,$src,$python,$dst,$request,30000)
    if ($r.ForwardedBytes -ne 100008 -or $r.SourceExit -ne 0 -or
        $r.RecipientExit -ne 0 -or
        [Text.Encoding]::ASCII.GetString($r.RecipientReport) -cne
           'RECIPIENT-CIPHERTEXT-ONLY' -or
        @($request | Where-Object {$_ -ne 0}).Count -ne 0) {
        throw 'R1140_BINARY_SUCCESS_STOP'
    }
    $bad=@'
import sys
sys.stdin.buffer.read()
sys.stdout.buffer.write(b'BADMAGIC'+b'B'*4096)
'@
    Assert-R1140Stop $bad 'SOURCE_MAGIC_STOP' $dst
    $exiting=@'
import sys
sys.stdin.buffer.read()
sys.stdout.buffer.write(b'FLOPST01'+b'C'*4096)
sys.stdout.buffer.flush()
sys.exit(42)
'@
    Assert-R1140Stop $exiting 'CHILD_EXIT_STOP' $dst
    $large=@'
import sys
sys.stdin.buffer.read()
sys.stdout.buffer.write(b'FLOPST01'+b'X'*(33*1024*1024))
sys.stdout.buffer.flush()
'@
    Assert-R1140Stop $large 'WIRE_LIMIT_STOP' $dst
    $oversized=New-Object byte[] (4*1024*1024+1)
    $oversized[0]=65
    $oversized[$oversized.Length-1]=65
    $stopped=$false
    try { $null=[FlopR1140.Bridge]::Pump($python,$src,$python,$dst,$oversized,30000) }
    catch {
        if ($_.Exception.Message -notmatch 'BOUND_STOP') { throw }
        $stopped=$true
    }
    if (-not $stopped -or $oversized[0] -ne 0 -or
        $oversized[$oversized.Length-1] -ne 0) {
        throw 'R1140_CONTROL_BOUND_STOP'
    }
    Write-Host 'R1140_NATIVE_BINARY_BRIDGE=PASS'
} finally {
    if ([IO.Directory]::Exists($temp)) {
        [IO.Directory]::Delete($temp,$true)
    }
}
