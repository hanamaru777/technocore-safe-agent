from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ATTRIBUTES = ROOT / ".gitattributes"
WORKFLOW = ROOT / ".github/workflows/security-gate.yml"
BOOTSTRAP = ROOT / "packaging/windows/bootstrap-technocore-ci-readonly-path.ps1"


def test_windows_bootstrap_is_forced_to_lf_checkout():
    attributes = ATTRIBUTES.read_text("utf-8")
    assert (
        "packaging/windows/bootstrap-technocore-ci-readonly-path.ps1 text eol=lf"
        in attributes.splitlines()
    )


def test_windows_ci_proves_lf_only_bootstrap_source_before_keygen_regression():
    workflow = WORKFLOW.read_text("utf-8")

    lf_check = workflow.index("Prove bootstrap remote shell source is LF-only")
    keygen_check = workflow.index(
        "Prove Windows PowerShell 5.1 non-interactive key generation"
    )

    assert lf_check < keygen_check
    assert "[IO.File]::ReadAllBytes($bootstrapPath)" in workflow
    assert "$bootstrapBytes -contains [byte]13" in workflow
    assert "WINDOWS_PS51_REMOTE_SHELL_LF_REGRESSION=PASS" in workflow


def test_remote_preflight_still_uses_bash_pipefail_marker():
    bootstrap = BOOTSTRAP.read_text("utf-8")
    assert "set -euo pipefail" in bootstrap
    assert "$preflightOutput = & $script:SshExe @sshBase" in bootstrap
