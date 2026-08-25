[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)] [string]$Command,
    [Parameter(Position = 1)] [string]$Room
)

$ErrorActionPreference = 'Stop'
$rootPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$needsSeed = $Command -in @('show-did', 'post-signed', 'contribution-proof')
$bstr = [IntPtr]::Zero
$previousPythonPath = $env:PYTHONPATH
$previousUvLinkMode = $env:UV_LINK_MODE
$env:PYTHONPATH = Join-Path $rootPath 'src'
$env:UV_LINK_MODE = 'copy'

function Resolve-Uv {
    $fromPath = Get-Command uv -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }
    $fallback = Join-Path $HOME '.local\bin\uv.exe'
    if (Test-Path -LiteralPath $fallback -PathType Leaf) { return $fallback }
    throw 'uv が PATH または $HOME\.local\bin\uv.exe に見つかりません'
}

$uv = Resolve-Uv

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
        & $uv run --project $rootPath python -m flop_agent.cli show-did
        Write-Host "本文: $text"
        if ((Read-Host 'Technocoreへ送信しますか? (yes/no)') -cne 'yes') { throw '送信を中止しました' }
        & $uv run --project $rootPath python -m flop_agent.cli post-signed $Room --text $text --confirm
    } elseif ($Command -eq 'contribution-proof') {
        $contributionUrl = Read-Host '公開 Contribution URL（https://...）'
        $proofRoom = if ($Room) { $Room } else { 'lobby' }
        $planJson = & $uv run --project $rootPath python -m flop_agent.cli proof-plan --contribution-url $contributionUrl --room $proofRoom
        if ($LASTEXITCODE -ne 0) { throw 'proof plan の作成に失敗しました' }
        $plan = $planJson | ConvertFrom-Json
        Write-Host '以下の Proof を1回だけ作成します。TechnocoreのNoteは公開・world-writableです。'
        $plan | ConvertTo-Json -Depth 5
        if ((Read-Host 'この内容で Technocore へ書き込みますか? (yes/no)') -cne 'yes') { throw '書き込みを中止しました' }
        & $uv run --project $rootPath python -m flop_agent.cli create-proof --plan-id $plan.plan_id --confirm
    } elseif ($Command -in @('read-room', 'read-new')) {
        if (-not $Room) { throw 'room を指定してください' }
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
