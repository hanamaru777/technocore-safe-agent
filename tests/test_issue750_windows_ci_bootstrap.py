from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging/windows/bootstrap-technocore-ci-readonly-path.ps1"


def _text() -> str:
    return SCRIPT.read_text("utf-8")


def test_bootstrap_requires_exact_main_and_pinned_host_key():
    text = _text()

    assert "[ValidatePattern('^[0-9a-f]{40}$')]" in text
    assert "Get-ExpectedGitHubMain" in text
    assert "GH_MAIN_SHA_MISMATCH" in text
    assert "GH_MAIN_MOVED_BEFORE_DISPATCH" in text
    assert "ssh-keygen.exe" in text
    assert " -F $ProductionHost -f $KnownHostsPath" in text
    assert "StrictHostKeyChecking=yes" in text
    assert "UserKnownHostsFile=$KnownHostsPath" in text
    assert "ssh-keyscan" not in text
    assert "StrictHostKeyChecking=no" not in text


def test_bootstrap_private_key_never_leaves_local_except_gh_stdin():
    text = _text()

    assert "$CiPublicKeyPath" in text
    assert "$CiPublicKeyPath," in text
    assert "TECHNOCORE_CI_SSH_KEY' $privateKeyText" in text
    assert "$Value | & $script:GhExe secret set $Name --repo $Repository" in text
    assert "--body" not in text
    assert "gh secret set TECHNOCORE_CI_SSH_KEY" not in text
    assert "scp.exe" in text
    assert "$CiKeyPath,\n    \"$OperatorUser@$ProductionHost`:$remotePublic\"" not in text
    assert "Write-Host $privateKeyText" not in text
    assert "Write-Output $privateKeyText" not in text
    assert "Write-Host $publicLine" not in text
    assert "upload-artifact" not in text


def test_bootstrap_remote_deploy_is_clean_exact_sha_and_ff_only():
    text = _text()

    assert 'BRANCH="$(sudo -n git -c safe.directory="$REPO" -C "$REPO" rev-parse --abbrev-ref HEAD)"' in text
    assert '[ "$BRANCH" = "main" ]' in text
    assert 'status --porcelain' in text
    assert 'fetch --no-tags origin main' in text
    assert 'rev-parse origin/main' in text
    assert '[ "$REMOTE" = "$TARGET" ]' in text
    assert 'merge-base --is-ancestor "$HEAD" "$TARGET"' in text
    assert 'merge --ff-only "$TARGET"' in text
    assert 'install-technocore-ci-control-proof.sh" "$PUB"' in text
    assert "chown -R" not in text
    assert "safe.directory --global" not in text


def test_bootstrap_does_not_mutate_runtime_services_or_binding_state():
    text = _text()

    forbidden = (
        "systemctl start",
        "systemctl stop",
        "systemctl restart",
        "systemctl enable",
        "close1-approved-trade.service",
        "close1-approved-batch",
        "signer/close1-approved",
        "mark_pending",
        "POST ",
    )
    for token in forbidden:
        assert token not in text

    assert '"bootstrap $bootstrapNonce"' in text
    assert "$bootstrap.binding_capable -ne $false" in text
    assert "CONTROL_PATH_REDUNDANCY_GATE_CHANGED=NO" in text


def test_bootstrap_preflights_before_key_generation_and_remote_mutation():
    text = _text()

    gh_auth = text.index("GH_AUTH_REQUIRED")
    pinned_host = text.index("PINNED_HOST_KEY_MISSING")
    remote_preflight = text.index("REMOTE_PRECHECK=PASS")
    keygen = text.index("'-q', '-t', 'ed25519'")
    scp = text.index("$scpArgs = @(")
    remote_fetch = text.index("fetch --no-tags origin main")

    assert gh_auth < keygen
    assert pinned_host < keygen
    assert remote_preflight < keygen
    assert keygen < scp < remote_fetch


def test_bootstrap_handles_existing_setup_fail_closed_and_idempotently():
    text = _text()

    assert "ci_setup=present" in text
    assert "REMOTE_SETUP_PRESENT_LOCAL_KEY_MISSING" in text
    assert "CI_KEYPAIR_PARTIAL" in text
    assert "CI_KEYPAIR_MISMATCH" in text
    assert "install-technocore-ci-control-proof.sh" in text
    assert "production_setup=READY" in text


def test_bootstrap_dispatches_exact_manual_workflow_and_requires_pass_markers():
    text = _text()

    assert "$workflow = 'production-control-path-bootstrap-proof.yml'" in text
    assert "workflow', 'run', $workflow, '--repo', $Repository, '--ref', 'main'" in text
    assert "headSha -eq $ExpectedMainSha" in text
    assert "run', 'watch', $runId" in text
    assert "CI_BOOTSTRAP_CONTROL_PATH_PROOF=PASS" in text
    assert "CONTROL_PATH_REDUNDANCY_GATE_CHANGED=NO" in text
    assert "CI_BOOTSTRAP_PHASE_B=READY" in text


def test_powershell_syntax_when_pwsh_is_available():
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh not installed in this environment")

    path = str(SCRIPT).replace("'", "''")
    command = f"$null=[scriptblock]::Create([IO.File]::ReadAllText('{path}'))"
    subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
    )
