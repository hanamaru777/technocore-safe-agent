[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)] [string]$Command,
    [Parameter(Position = 1)] [string]$Room
)

$ErrorActionPreference = 'Stop'
$rootPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$needsSeed = $Command -in @('show-did', 'post-signed')
$bstr = [IntPtr]::Zero
$previousPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = Join-Path $rootPath 'src'

try {
    if ($needsSeed) {
        $secure = Read-Host '既存DIDのseed（画面表示されません）' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        $env:SIGN_SEED = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    if ($Command -eq 'post-signed') {
        if (-not $Room) { throw 'room を指定してください: .\flop.ps1 post-signed lobby' }
        $text = Read-Host '投稿本文'
        Write-Host "Room: $Room"
        & uv run --project $rootPath python -m flop_agent.cli show-did
        Write-Host "本文: $text"
        if ((Read-Host 'Technocoreへ送信しますか? (yes/no)') -cne 'yes') { throw '送信を中止しました' }
        & uv run --project $rootPath python -m flop_agent.cli post-signed $Room --text $text --confirm
    } elseif ($Command -in @('read-room', 'read-new')) {
        if (-not $Room) { throw 'room を指定してください' }
        & uv run --project $rootPath python -m flop_agent.cli $Command $Room
    } else {
        & uv run --project $rootPath python -m flop_agent.cli $Command
    }
} finally {
    Remove-Item Env:SIGN_SEED -ErrorAction SilentlyContinue
    if ($null -eq $previousPythonPath) { Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue } else { $env:PYTHONPATH = $previousPythonPath }
    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
