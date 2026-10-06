from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "packaging/windows/bootstrap-technocore-ci-readonly-path.ps1"
WORKFLOW = ROOT / ".github/workflows/security-gate.yml"


def test_capture_helper_temporarily_relaxes_eap_but_fails_on_exit_code():
    text = BOOTSTRAP.read_text("utf-8")

    assert "function Invoke-CapturedNative" in text
    assert "$savedErrorActionPreference = $ErrorActionPreference" in text
    assert "$ErrorActionPreference = 'Continue'" in text
    assert "$exitCode = $LASTEXITCODE" in text
    assert "$ErrorActionPreference = $savedErrorActionPreference" in text
    assert "if ($exitCode -ne 0)" in text
    assert "Stop-Stage $Reason" in text


def test_all_parsed_ssh_calls_use_capture_helper():
    text = BOOTSTRAP.read_text("utf-8")

    assert "Invoke-CapturedNative $script:SshExe $preflightArgs 'REMOTE_PRECHECK_FAILED'" in text
    assert "Invoke-CapturedNative $script:SshExe $applyArgs 'REMOTE_SETUP_FAILED'" in text
    assert "Invoke-CapturedNative $script:SshExe $ciSshArgs 'LOCAL_BOOTSTRAP_PROOF_FAILED'" in text
    assert "Invoke-CapturedNative $script:SshExe $activationArgs 'POST_DEPLOY_ACTIVATION_FAILED'" in text

    assert '$preflightOutput = & $script:SshExe' not in text
    assert '$applyOutput = & $script:SshExe' not in text
    assert '$bootstrapJson = (& $script:SshExe' not in text
    assert '$activationOutput = & $script:SshExe' not in text


def test_quiet_wrapper_also_ignores_benign_native_stderr_and_checks_exit_code():
    text = BOOTSTRAP.read_text("utf-8")
    start = text.index("function Invoke-CheckedQuiet")
    end = text.index("function Invoke-CapturedNative")
    wrapper = text[start:end]

    assert "$ErrorActionPreference = 'Continue'" in wrapper
    assert "$exitCode = $LASTEXITCODE" in wrapper
    assert "if ($exitCode -ne 0)" in wrapper


def test_windows_ps51_ci_proves_success_stderr_and_nonzero_fail_closed():
    workflow = WORKFLOW.read_text("utf-8")

    assert "Prove Windows PowerShell 5.1 benign native stderr handling" in workflow
    assert "$node.Name -eq 'Invoke-CapturedNative'" in workflow
    assert "[Console]::Error.WriteLine('benign-stderr')" in workflow
    assert "exit 0" in workflow
    assert "[Console]::Error.WriteLine('expected-failure-stderr')" in workflow
    assert "exit 23" in workflow
    assert "STOP_NONZERO_EXIT" in workflow
    assert "$global:LASTEXITCODE = 0" in workflow
    assert "WINDOWS_PS51_NATIVE_STDERR_HANDLING=PASS" in workflow
    assert "windows-native-stderr-diagnostic" not in workflow
    assert "upload-artifact" not in workflow
