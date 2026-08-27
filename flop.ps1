[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)] [string]$Command,
    [Parameter(Position = 1)] [string]$Room,
    [Parameter(Position = 2)] [string]$Value,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$rootPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$needsSeed = $Command -in @('show-did', 'verify-did', 'post-signed', 'contribution-proof', 'resume-proof', 'autopilot-publish')
$bstr = [IntPtr]::Zero
$exitCode = 0
$expectedDid = $null
$previousPythonPath = $env:PYTHONPATH
$previousUvLinkMode = $env:UV_LINK_MODE
$env:PYTHONPATH = Join-Path $rootPath 'src'
$env:UV_LINK_MODE = 'copy'

function Invoke-FlopCli {
    param([Parameter(ValueFromRemainingArguments = $true)] [string[]]$Arguments)
    & $uv run --project $rootPath python -m flop_agent.cli @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'flop command failed' }
}

function Invoke-AutopilotSession {
    param([bool]$SessionDryRun)
    $sessionSecure = $null
    if (-not $SessionDryRun) {
        $sessionSecure = Read-Host 'Existing DID seed (hidden)' -AsSecureString
    }
    try {
        while ($true) {
            $sleepSeconds = 10
            try {
                $arguments = @('autopilot-session-once')
                if ($SessionDryRun) { $arguments += '--dry-run' }
                $sessionJson = Invoke-FlopCli @arguments | Out-String
                $session = $sessionJson | ConvertFrom-Json
                $sleepSeconds = [int]$session.poll_interval_seconds
                foreach ($item in $session.results) {
                    if (-not $SessionDryRun -and $item.action -eq 'ready_to_publish') {
                        $sessionBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sessionSecure)
                        try {
                            # The plaintext exists only for this DID signer child process.
                            $env:SIGN_SEED = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($sessionBstr)
                            $didJson = Invoke-FlopCli 'autopilot-session-verify' | Out-String
                        } finally {
                            Remove-Item Env:SIGN_SEED -ErrorAction SilentlyContinue
                            if ($sessionBstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($sessionBstr) }
                        }
                        $sessionDid = ($didJson | ConvertFrom-Json).did
                        $sessionBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sessionSecure)
                        try {
                            # A separate, one-child environment is used for the actual signature.
                            $env:SIGN_SEED = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($sessionBstr)
                            Invoke-FlopCli 'autopilot-session-publish' $item.intent_id '--did' $sessionDid | Out-Null
                        } finally {
                            Remove-Item Env:SIGN_SEED -ErrorAction SilentlyContinue
                            if ($sessionBstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($sessionBstr) }
                        }
                    }
                }
            } catch {
                # Transport or validation failure is fail-closed; leave Oracle intent pending.
                Write-Warning 'Autopilot session cycle failed closed; retrying later.'
            }
            Start-Sleep -Seconds $sleepSeconds
        }
    } finally {
        Remove-Item Env:SIGN_SEED -ErrorAction SilentlyContinue
        if ($null -ne $sessionSecure) { $sessionSecure.Dispose() }
    }
}

function Resolve-Uv {
    $fromPath = Get-Command uv -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }
    $fallback = Join-Path $HOME '.local\bin\uv.exe'
    if (Test-Path -LiteralPath $fallback -PathType Leaf) { return $fallback }
    throw 'uv was not found on PATH or in $HOME\.local\bin\uv.exe'
}

try {
    $uv = Resolve-Uv
    if ($Command -eq 'autopilot-session') {
        if ($Room -or $Value) { throw 'autopilot-session accepts only --dry-run' }
        Invoke-AutopilotSession $DryRun.IsPresent
        return
    }
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
    } elseif ($Command -eq 'publish-approved') {
        if (-not $Room) { throw 'Candidate ID is required' }
        & $uv run --project $rootPath python -m flop_agent.cli candidate $Room
        if ($LASTEXITCODE -ne 0) { throw 'Candidate could not be read' }
        if ((Read-Host 'Publish this approved candidate? (yes/no)') -cne 'yes') { throw 'Publish cancelled' }
        $secure = Read-Host 'Existing DID seed (hidden)' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        $env:SIGN_SEED = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        & $uv run --project $rootPath python -m flop_agent.cli publish-approved $Room --confirm
    } elseif ($Command -eq 'autopilot-publish') {
        if (-not $Room) { throw 'Intent ID is required' }
        & $uv run --project $rootPath python -m flop_agent.cli autopilot-publish $Room --confirm
    } elseif ($Command -eq 'reject') {
        if (-not $Room -or -not $Value) { throw 'Candidate ID and rejection reason are required' }
        & $uv run --project $rootPath python -m flop_agent.cli reject $Room $Value
    } elseif ($Command -in @('read-room', 'read-new', 'agent', 'candidate', 'approve')) {
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
