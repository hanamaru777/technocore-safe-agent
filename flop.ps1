[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)] [string]$Command,
    [Parameter(Position = 1)] [string]$Room
)

$ErrorActionPreference = 'Stop'
$rootPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$needsSeed = $Command -in @('show-did', 'verify-did', 'post-signed', 'contribution-proof', 'resume-proof')
$bstr = [IntPtr]::Zero
$exitCode = 0
$expectedDid = $null
$previousPythonPath = $env:PYTHONPATH
$previousUvLinkMode = $env:UV_LINK_MODE
$env:PYTHONPATH = Join-Path $rootPath 'src'
$env:UV_LINK_MODE = 'copy'

function Resolve-Uv {
    $fromPath = Get-Command uv -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }
    $fallback = Join-Path $HOME '.local\bin\uv.exe'
    if (Test-Path -LiteralPath $fallback -PathType Leaf) { return $fallback }
    throw 'uv was not found on PATH or in $HOME\.local\bin\uv.exe'
}

try {
    $uv = Resolve-Uv
    if ($Command -eq 'verify-did') {
        $expectedDid = Read-Host 'Expected DID (public)'
    }
    if ($needsSeed) {
        $secure = Read-Host 'Existing DID seed (hidden)' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        $env:SIGN_SEED = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    if ($Command -eq 'verify-did') {
        & $uv run --project $rootPath python -m flop_agent.cli verify-did --expected-did $expectedDid
        if ($LASTEXITCODE -ne 0) { $exitCode = 1 }
    } elseif ($Command -eq 'post-signed') {
        if (-not $Room) { throw 'Room is required: .\flop.ps1 post-signed lobby' }
        $text = Read-Host 'Post text'
        Write-Host "Room: $Room"
        & $uv run --project $rootPath python -m flop_agent.cli show-did
        Write-Host "Text: $text"
        if ((Read-Host 'Send to Technocore? (yes/no)') -cne 'yes') { throw 'Send cancelled' }
        & $uv run --project $rootPath python -m flop_agent.cli post-signed $Room --text $text --confirm
    } elseif ($Command -eq 'contribution-proof') {
        $contributionUrl = Read-Host 'Public Contribution URL (https://...)'
        $proofRoom = if ($Room) { $Room } else { 'lobby' }
        $planJson = & $uv run --project $rootPath python -m flop_agent.cli proof-plan --contribution-url $contributionUrl --room $proofRoom
        if ($LASTEXITCODE -ne 0) { throw 'Proof plan creation failed. Run verify-did successfully first.' }
        $plan = $planJson | ConvertFrom-Json
        Write-Host 'The following Proof will be created once. Technocore Notes are public and world-writable.'
        $plan | ConvertTo-Json -Depth 5
        if ((Read-Host 'Write this Proof to Technocore? (yes/no)') -cne 'yes') { throw 'Write cancelled' }
        & $uv run --project $rootPath python -m flop_agent.cli create-proof --plan-id $plan.plan_id --confirm
    } elseif ($Command -eq 'resume-proof') {
        if (-not $Room) { throw 'Plan ID is required: .\flop.ps1 resume-proof c1dea36b444b7fb7' }
        $planJson = & $uv run --project $rootPath python -m flop_agent.cli show-proof-plan --plan-id $Room
        if ($LASTEXITCODE -ne 0) { throw 'Proof plan could not be read' }
        $plan = $planJson | ConvertFrom-Json
        Write-Host 'The existing plan and checkpoints follow. No Technocore write has occurred.'
        $plan | ConvertTo-Json -Depth 8
        if ((Read-Host 'Resume this existing Proof? (yes/no)') -cne 'yes') { throw 'Resume cancelled' }
        & $uv run --project $rootPath python -m flop_agent.cli resume-proof --plan-id $Room --confirm
    } elseif ($Command -in @('read-room', 'read-new', 'agent')) {
        if (-not $Room) { throw 'Room is required' }
        & $uv run --project $rootPath python -m flop_agent.cli $Command $Room
    } else {
        & $uv run --project $rootPath python -m flop_agent.cli $Command
    }
} finally {
    Remove-Item Env:SIGN_SEED -ErrorAction SilentlyContinue
    if ($null -eq $previousPythonPath) { Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue } else { $env:PYTHONPATH = $previousPythonPath }
    if ($null -eq $previousUvLinkMode) { Remove-Item Env:UV_LINK_MODE -ErrorAction SilentlyContinue } else { $env:UV_LINK_MODE = $previousUvLinkMode }
    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

if ($exitCode -ne 0) { exit $exitCode }
