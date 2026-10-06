[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedMainSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9.-]+$')]
    [string]$ProductionHost,

    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string]$Repository = 'hanamaru777/technocore-safe-agent',

    [ValidatePattern('^[a-z_][a-z0-9_-]*$')]
    [string]$OperatorUser = 'ubuntu',

    [string]$OperatorKey = (Join-Path $HOME '.ssh\technocore-resident.key'),
    [string]$KnownHostsPath = (Join-Path $HOME '.ssh\known_hosts'),
    [string]$CiKeyPath = (Join-Path $HOME '.ssh\technocore-ci-actions')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Stage([string]$Reason) {
    throw "STOP_$Reason"
}

function Require-Command([string]$Name) {
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        Stop-Stage "COMMAND_MISSING_$($Name.Replace('.', '_'))"
    }
    return $cmd.Source
}

function Invoke-CheckedQuiet([string]$Exe, [string[]]$Args, [string]$Reason) {
    & $Exe @Args *> $null
    if ($LASTEXITCODE -ne 0) {
        Stop-Stage $Reason
    }
}

function Set-RepoSecret([string]$Name, [string]$Value) {
    $Value | & $script:GhExe secret set $Name --repo $Repository
    if ($LASTEXITCODE -ne 0) {
        Stop-Stage "GH_SECRET_SET_$Name"
    }
}

function New-Nonce() {
    $bytes = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

function Get-ExpectedGitHubMain() {
    $shaRaw = & $script:GhExe api "repos/$Repository/commits/main" --jq '.sha' 2>$null
    if ($LASTEXITCODE -ne 0 -or $null -eq $shaRaw) {
        Stop-Stage 'GH_MAIN_READ_FAILED'
    }
    $sha = ([string]($shaRaw -join '')).Trim()
    if ($sha -notmatch '^[0-9a-f]{40}$') {
        Stop-Stage 'GH_MAIN_READ_FAILED'
    }
    return $sha
}

Write-Host '=== CI CONTROL PATH BOOTSTRAP PRECHECK ==='

$script:SshExe = Require-Command 'ssh.exe'
$ScpExe = Require-Command 'scp.exe'
$SshKeygenExe = Require-Command 'ssh-keygen.exe'
$script:GhExe = Require-Command 'gh.exe'

$OperatorKey = [IO.Path]::GetFullPath($OperatorKey)
$KnownHostsPath = [IO.Path]::GetFullPath($KnownHostsPath)
$CiKeyPath = [IO.Path]::GetFullPath($CiKeyPath)
$CiPublicKeyPath = "$CiKeyPath.pub"
$SshHome = [IO.Path]::GetFullPath((Join-Path $HOME '.ssh'))
$Separator = [string][IO.Path]::DirectorySeparatorChar
if (-not $SshHome.EndsWith($Separator)) {
    $SshHome += $Separator
}
if (-not $CiKeyPath.StartsWith($SshHome, [StringComparison]::OrdinalIgnoreCase)) {
    Stop-Stage 'CI_KEY_OUTSIDE_USER_SSH'
}

if (-not (Test-Path -LiteralPath $OperatorKey -PathType Leaf)) {
    Stop-Stage 'OPERATOR_KEY_MISSING'
}
if (-not (Test-Path -LiteralPath $KnownHostsPath -PathType Leaf)) {
    Stop-Stage 'KNOWN_HOSTS_MISSING'
}

Invoke-CheckedQuiet $script:GhExe @('auth', 'status', '--hostname', 'github.com') 'GH_AUTH_REQUIRED'
$repoRaw = & $script:GhExe repo view $Repository --json nameWithOwner --jq '.nameWithOwner' 2>$null
if ($LASTEXITCODE -ne 0 -or $null -eq $repoRaw) {
    Stop-Stage 'GH_REPOSITORY_ACCESS'
}
$repoName = ([string]($repoRaw -join '')).Trim()
if ($repoName -ne $Repository) {
    Stop-Stage 'GH_REPOSITORY_ACCESS'
}
$githubMain = Get-ExpectedGitHubMain
if ($githubMain -ne $ExpectedMainSha) {
    Stop-Stage 'GH_MAIN_SHA_MISMATCH'
}

$knownHostRaw = & $SshKeygenExe -F $ProductionHost -f $KnownHostsPath 2>$null
if ($LASTEXITCODE -ne 0) {
    Stop-Stage 'PINNED_HOST_KEY_MISSING'
}
$knownHostLines = @(
    $knownHostRaw |
        Where-Object { $_ -and -not $_.StartsWith('#') } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
)
if ($knownHostLines.Count -lt 1) {
    Stop-Stage 'PINNED_HOST_KEY_MISSING'
}
$knownHostsValue = $knownHostLines -join "`n"

$sshBase = @(
    '-T',
    '-i', $OperatorKey,
    '-o', 'BatchMode=yes',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', "UserKnownHostsFile=$KnownHostsPath",
    '-o', 'ConnectTimeout=10',
    '-o', 'LogLevel=ERROR'
)

$remotePreflight = @'
set -euo pipefail
REPO="/opt/technocore-safe-agent"
sudo -n true
BRANCH="$(sudo -n git -c safe.directory="$REPO" -C "$REPO" rev-parse --abbrev-ref HEAD)"
HEAD="$(sudo -n git -c safe.directory="$REPO" -C "$REPO" rev-parse HEAD)"
DIRTY="$(sudo -n git -c safe.directory="$REPO" -C "$REPO" status --porcelain)"
[ "$BRANCH" = "main" ] || exit 20
[ -z "$DIRTY" ] || exit 21
if [ -e /var/lib/technocore-ci/.ssh/authorized_keys ]; then
  CI_SETUP=present
else
  CI_SETUP=absent
fi
printf 'REMOTE_PRECHECK=PASS head=%s ci_setup=%s\n' "$HEAD" "$CI_SETUP"
'@

$preflightOutput = & $script:SshExe @sshBase "$OperatorUser@$ProductionHost" $remotePreflight 2>$null
if ($LASTEXITCODE -ne 0) {
    Stop-Stage 'REMOTE_PRECHECK_FAILED'
}
$preflightLine = @($preflightOutput | Where-Object { $_ -like 'REMOTE_PRECHECK=PASS*' })
if ($preflightLine.Count -ne 1) {
    Stop-Stage 'REMOTE_PRECHECK_RESPONSE_INVALID'
}
$remoteSetupPresent = $preflightLine[0] -like '*ci_setup=present*'

$privateExists = Test-Path -LiteralPath $CiKeyPath -PathType Leaf
$publicExists = Test-Path -LiteralPath $CiPublicKeyPath -PathType Leaf
if ($privateExists -xor $publicExists) {
    Stop-Stage 'CI_KEYPAIR_PARTIAL'
}
if ($remoteSetupPresent -and -not $privateExists) {
    Stop-Stage 'REMOTE_SETUP_PRESENT_LOCAL_KEY_MISSING'
}

Write-Host 'preflight=PASS'
Write-Host '=== DEDICATED CI KEYPAIR ==='

if (-not $privateExists) {
    $ciParent = Split-Path -Parent $CiKeyPath
    if (-not (Test-Path -LiteralPath $ciParent -PathType Container)) {
        New-Item -ItemType Directory -Path $ciParent -Force | Out-Null
    }
    Invoke-CheckedQuiet $SshKeygenExe @(
        '-q', '-t', 'ed25519', '-N', '', '-C', 'technocore-ci-actions', '-f', $CiKeyPath
    ) 'CI_KEYGEN_FAILED'
    $privateExists = $true
    $publicExists = $true
}

$publicLine = (Get-Content -LiteralPath $CiPublicKeyPath -Raw).Trim()
$publicParts = $publicLine -split '\s+'
if ($publicParts.Count -lt 2 -or $publicParts[0] -ne 'ssh-ed25519') {
    Stop-Stage 'CI_PUBLIC_KEY_INVALID'
}
$derivedPublic = (& $SshKeygenExe -y -f $CiKeyPath 2>$null).Trim()
if ($LASTEXITCODE -ne 0) {
    Stop-Stage 'CI_PRIVATE_KEY_INVALID'
}
$derivedParts = $derivedPublic -split '\s+'
if ($derivedParts.Count -lt 2 -or $derivedParts[0] -ne 'ssh-ed25519') {
    Stop-Stage 'CI_PRIVATE_KEY_INVALID'
}
if ($derivedParts[1] -ne $publicParts[1]) {
    Stop-Stage 'CI_KEYPAIR_MISMATCH'
}
Write-Host 'ci_keypair=READY'

Write-Host '=== EXACT-SHA PRODUCTION UPDATE + PUBLIC-KEY INSTALL ==='

$nonce = New-Nonce
$remotePublic = "/tmp/technocore-ci-$nonce.pub"
$scpArgs = @(
    '-q',
    '-i', $OperatorKey,
    '-o', 'BatchMode=yes',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', "UserKnownHostsFile=$KnownHostsPath",
    '-o', 'ConnectTimeout=10',
    $CiPublicKeyPath,
    "$OperatorUser@$ProductionHost`:$remotePublic"
)
Invoke-CheckedQuiet $ScpExe $scpArgs 'PUBLIC_KEY_COPY_FAILED'

$remoteApplyTemplate = @'
set -euo pipefail
REPO="/opt/technocore-safe-agent"
TARGET="__TARGET__"
PUB="__PUB__"
cleanup() { rm -f "$PUB"; }
trap cleanup EXIT
sudo -n true
[ -f "$PUB" ] && [ ! -L "$PUB" ] || exit 30
BRANCH="$(sudo -n git -c safe.directory="$REPO" -C "$REPO" rev-parse --abbrev-ref HEAD)"
HEAD="$(sudo -n git -c safe.directory="$REPO" -C "$REPO" rev-parse HEAD)"
DIRTY="$(sudo -n git -c safe.directory="$REPO" -C "$REPO" status --porcelain)"
[ "$BRANCH" = "main" ] || exit 31
[ -z "$DIRTY" ] || exit 32
sudo -n git -c safe.directory="$REPO" -C "$REPO" fetch --no-tags origin main
REMOTE="$(sudo -n git -c safe.directory="$REPO" -C "$REPO" rev-parse origin/main)"
[ "$REMOTE" = "$TARGET" ] || exit 33
if [ "$HEAD" != "$TARGET" ]; then
  sudo -n git -c safe.directory="$REPO" -C "$REPO" merge-base --is-ancestor "$HEAD" "$TARGET" || exit 34
  sudo -n git -c safe.directory="$REPO" -C "$REPO" merge --ff-only "$TARGET"
fi
[ "$(sudo -n git -c safe.directory="$REPO" -C "$REPO" rev-parse HEAD)" = "$TARGET" ] || exit 35
[ -z "$(sudo -n git -c safe.directory="$REPO" -C "$REPO" status --porcelain)" ] || exit 36
sudo -n "$REPO/packaging/oracle/install-technocore-ci-control-proof.sh" "$PUB"
printf 'REMOTE_SETUP=READY\n'
'@
$remoteApply = $remoteApplyTemplate.Replace('__TARGET__', $ExpectedMainSha).Replace('__PUB__', $remotePublic)
$applyOutput = & $script:SshExe @sshBase "$OperatorUser@$ProductionHost" $remoteApply 2>$null
if ($LASTEXITCODE -ne 0 -or -not (@($applyOutput) -contains 'REMOTE_SETUP=READY')) {
    Stop-Stage 'REMOTE_SETUP_FAILED'
}
Write-Host 'production_setup=READY'

Write-Host '=== LOCAL FORCED-COMMAND BOOTSTRAP PROOF ==='

$bootstrapNonce = New-Nonce
$ciSshArgs = @(
    '-T',
    '-i', $CiKeyPath,
    '-o', 'BatchMode=yes',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', "UserKnownHostsFile=$KnownHostsPath",
    '-o', 'ConnectTimeout=10',
    '-o', 'LogLevel=ERROR',
    "technocore-ci@$ProductionHost",
    "bootstrap $bootstrapNonce"
)
$bootstrapJson = (& $script:SshExe @ciSshArgs 2>$null) -join "`n"
if ($LASTEXITCODE -ne 0) {
    Stop-Stage 'LOCAL_BOOTSTRAP_PROOF_FAILED'
}
try {
    $bootstrap = $bootstrapJson | ConvertFrom-Json
} catch {
    Stop-Stage 'LOCAL_BOOTSTRAP_RESPONSE_INVALID'
}
if (
    $bootstrap.status -ne 'BOOTSTRAP_PROOF' -or
    $bootstrap.authenticated -ne $true -or
    $bootstrap.ready -ne $true -or
    $bootstrap.binding_capable -ne $false -or
    $bootstrap.quota_independent -ne $true
) {
    Stop-Stage 'LOCAL_BOOTSTRAP_PROOF_INVALID'
}
Write-Host 'local_bootstrap_proof=PASS'

Write-Host '=== GITHUB ACTIONS SECRETS ==='

$privateKeyText = [IO.File]::ReadAllText($CiKeyPath).Replace("`r`n", "`n").Replace("`r", "`n").TrimEnd("`n") + "`n"
Set-RepoSecret 'TECHNOCORE_CI_HOST' $ProductionHost
Set-RepoSecret 'TECHNOCORE_CI_SSH_KEY' $privateKeyText
Set-RepoSecret 'TECHNOCORE_CI_KNOWN_HOSTS' $knownHostsValue
$privateKeyText = $null
Write-Host 'github_secrets=READY'

Write-Host '=== GITHUB ACTIONS BOOTSTRAP PROOF ==='

if ((Get-ExpectedGitHubMain) -ne $ExpectedMainSha) {
    Stop-Stage 'GH_MAIN_MOVED_BEFORE_DISPATCH'
}

$workflow = 'production-control-path-bootstrap-proof.yml'
$beforeJson = & $script:GhExe run list --repo $Repository --workflow $workflow --limit 20 --json databaseId 2>$null
if ($LASTEXITCODE -ne 0) {
    Stop-Stage 'GH_RUN_LIST_FAILED'
}
$beforeIds = @{}
if ($beforeJson) {
    foreach ($row in ($beforeJson | ConvertFrom-Json)) {
        $beforeIds[[string]$row.databaseId] = $true
    }
}

Invoke-CheckedQuiet $script:GhExe @('workflow', 'run', $workflow, '--repo', $Repository, '--ref', 'main') 'GH_WORKFLOW_DISPATCH_FAILED'

$runId = $null
for ($attempt = 0; $attempt -lt 20 -and $null -eq $runId; $attempt++) {
    Start-Sleep -Seconds 2
    $runsJson = & $script:GhExe run list --repo $Repository --workflow $workflow --limit 20 --json databaseId,headSha,event 2>$null
    if ($LASTEXITCODE -ne 0) {
        continue
    }
    foreach ($row in ($runsJson | ConvertFrom-Json)) {
        $id = [string]$row.databaseId
        if (
            -not $beforeIds.ContainsKey($id) -and
            $row.event -eq 'workflow_dispatch' -and
            $row.headSha -eq $ExpectedMainSha
        ) {
            $runId = $id
            break
        }
    }
}
if ($null -eq $runId) {
    Stop-Stage 'GH_BOOTSTRAP_RUN_NOT_FOUND'
}

Invoke-CheckedQuiet $script:GhExe @('run', 'watch', $runId, '--repo', $Repository, '--exit-status') 'GH_BOOTSTRAP_RUN_FAILED'
$runLog = (& $script:GhExe run view $runId --repo $Repository --log 2>$null) -join "`n"
if ($LASTEXITCODE -ne 0) {
    Stop-Stage 'GH_BOOTSTRAP_LOG_READ_FAILED'
}
if ($runLog -notmatch 'CI_BOOTSTRAP_CONTROL_PATH_PROOF=PASS') {
    Stop-Stage 'GH_BOOTSTRAP_PASS_MARKER_MISSING'
}
if ($runLog -notmatch 'CONTROL_PATH_REDUNDANCY_GATE_CHANGED=NO') {
    Stop-Stage 'GH_BOOTSTRAP_GATE_MARKER_MISSING'
}

Write-Host '=== SAFE POST-DEPLOY ACTIVATION ==='

$remoteActivationTemplate = @'
set -euo pipefail
REPO="/opt/technocore-safe-agent"
TARGET="__TARGET__"
SUPERVISOR="technocore-safe-agent-precontest-supervisor.service"
DISCORD="technocore-safe-agent-discord.service"
PROTECTED=(
  technocore-safe-agent-resident.service
  technocore-safe-agent-lobby-capture.service
  technocore-safe-agent-signer.service
)
sudo -n true
[ "$(sudo -n git -c safe.directory="$REPO" -C "$REPO" rev-parse HEAD)" = "$TARGET" ] || exit 60
[ -z "$(sudo -n git -c safe.directory="$REPO" -C "$REPO" status --porcelain)" ] || exit 61
[ "$(systemctl is-active "$DISCORD")" = "active" ] || exit 62

declare -A PID_PRE
declare -A RESTART_PRE
for unit in "${PROTECTED[@]}"; do
  [ "$(systemctl is-active "$unit")" = "active" ] || exit 63
  PID_PRE["$unit"]="$(systemctl show "$unit" -p MainPID --value)"
  RESTART_PRE["$unit"]="$(systemctl show "$unit" -p NRestarts --value)"
  [[ "${PID_PRE[$unit]}" =~ ^[1-9][0-9]*$ ]] || exit 64
  [[ "${RESTART_PRE[$unit]}" =~ ^[0-9]+$ ]] || exit 65
done

sudo -n systemctl start "$SUPERVISOR"
SUP_RESULT="$(systemctl show "$SUPERVISOR" -p Result --value)"
SUP_EXIT="$(systemctl show "$SUPERVISOR" -p ExecMainStatus --value)"
[ "$SUP_RESULT" = "success" ] || exit 66
[ "$SUP_EXIT" = "0" ] || exit 67
printf 'PRECONTEST_SUPERVISOR_REFRESH=PASS\n'

sudo -n systemctl restart "$DISCORD"
sleep 2
[ "$(systemctl is-active "$DISCORD")" = "active" ] || exit 68
printf 'DISCORD_PRESENTATION_REFRESH=PASS\n'

for unit in "${PROTECTED[@]}"; do
  PID_POST="$(systemctl show "$unit" -p MainPID --value)"
  RESTART_POST="$(systemctl show "$unit" -p NRestarts --value)"
  [ "$PID_POST" = "${PID_PRE[$unit]}" ] || exit 69
  [ "$RESTART_POST" = "${RESTART_PRE[$unit]}" ] || exit 70
done
printf 'PROTECTED_SERVICES_UNCHANGED=YES\n'
printf 'POST_DEPLOY_ACTIVATION=PASS\n'
'@
$remoteActivation = $remoteActivationTemplate.Replace('__TARGET__', $ExpectedMainSha)
$activationOutput = & $script:SshExe @sshBase "$OperatorUser@$ProductionHost" $remoteActivation 2>$null
if ($LASTEXITCODE -ne 0) {
    Stop-Stage 'POST_DEPLOY_ACTIVATION_FAILED'
}
$activationLines = @($activationOutput)
foreach ($requiredMarker in @(
    'PRECONTEST_SUPERVISOR_REFRESH=PASS',
    'DISCORD_PRESENTATION_REFRESH=PASS',
    'PROTECTED_SERVICES_UNCHANGED=YES',
    'POST_DEPLOY_ACTIVATION=PASS'
)) {
    if (-not ($activationLines -contains $requiredMarker)) {
        Stop-Stage 'POST_DEPLOY_ACTIVATION_MARKER_MISSING'
    }
}

Write-Host '=== COMPLETE ==='
Write-Host 'CI_BOOTSTRAP_PHASE_B=READY'
Write-Host "main=$ExpectedMainSha"
Write-Host "github_run_id=$runId"
Write-Host 'CONTROL_PATH_REDUNDANCY_GATE_CHANGED=NO'
Write-Host 'PRECONTEST_SUPERVISOR_REFRESH=PASS'
Write-Host 'DISCORD_PRESENTATION_REFRESH=PASS'
Write-Host 'PROTECTED_SERVICES_UNCHANGED=YES'
Write-Host 'ONE_SHOT_POST_DEPLOY_ACTIVATION=PASS'
