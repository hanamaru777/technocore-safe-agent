[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SshKeygenExe,

    [Parameter(Mandatory = $true)]
    [string]$KeyPath,

    [ValidateRange(1000, 60000)]
    [int]$TimeoutMilliseconds = 15000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Keygen([string]$Reason) {
    throw "STOP_$Reason"
}

$SshKeygenExe = [IO.Path]::GetFullPath($SshKeygenExe)
$KeyPath = [IO.Path]::GetFullPath($KeyPath)
$PublicKeyPath = "$KeyPath.pub"

if (-not (Test-Path -LiteralPath $SshKeygenExe -PathType Leaf)) {
    Stop-Keygen 'CI_KEYGEN_EXE_MISSING'
}
if (
    $KeyPath.IndexOf('"') -ge 0 -or
    $KeyPath.IndexOf("`r") -ge 0 -or
    $KeyPath.IndexOf("`n") -ge 0
) {
    Stop-Keygen 'CI_KEY_PATH_INVALID'
}
if ((Test-Path -LiteralPath $KeyPath) -or (Test-Path -LiteralPath $PublicKeyPath)) {
    Stop-Keygen 'CI_KEYGEN_OUTPUT_ALREADY_EXISTS'
}

$parent = Split-Path -Parent $KeyPath
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}

# Windows PowerShell 5.1 can drop an empty native argv element when a native
# executable is called via an argument array. Build the CreateProcess command
# line explicitly so ssh-keygen receives the required empty passphrase as
# -N "" and never needs human input.
$startInfo = New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName = $SshKeygenExe
$startInfo.Arguments = '-q -t ed25519 -N "" -C technocore-ci-actions -f "' + $KeyPath + '"'
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardInput = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true

$process = New-Object System.Diagnostics.Process
$process.StartInfo = $startInfo
try {
    try {
        if (-not $process.Start()) {
            Stop-Keygen 'CI_KEYGEN_START_FAILED'
        }
    } catch {
        Stop-Keygen 'CI_KEYGEN_START_FAILED'
    }

    # Never allow a prompt to consume operator input. If ssh-keygen ever asks
    # for a passphrase despite the explicit empty -N value, stdin is already
    # closed and the bounded timeout below fails the operation closed.
    $process.StandardInput.Close()
    if (-not $process.WaitForExit($TimeoutMilliseconds)) {
        try {
            $process.Kill()
        } catch {
            # Timeout already determines the fail-closed result.
        }
        Stop-Keygen 'CI_KEYGEN_TIMEOUT'
    }

    $exitCode = $process.ExitCode
    $null = $process.StandardOutput.ReadToEnd()
    $null = $process.StandardError.ReadToEnd()
    if ($exitCode -ne 0) {
        Stop-Keygen 'CI_KEYGEN_FAILED'
    }
} finally {
    $process.Dispose()
}

if (-not (Test-Path -LiteralPath $KeyPath -PathType Leaf)) {
    Stop-Keygen 'CI_KEYGEN_PRIVATE_MISSING'
}
if (-not (Test-Path -LiteralPath $PublicKeyPath -PathType Leaf)) {
    Stop-Keygen 'CI_KEYGEN_PUBLIC_MISSING'
}

$publicLine = (Get-Content -LiteralPath $PublicKeyPath -Raw).Trim()
$parts = $publicLine -split '\s+'
if ($parts.Count -lt 2 -or $parts[0] -ne 'ssh-ed25519') {
    Stop-Keygen 'CI_KEYGEN_PUBLIC_INVALID'
}

Write-Output 'CI_KEYGEN_NONINTERACTIVE=PASS'
