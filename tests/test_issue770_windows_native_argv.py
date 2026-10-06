from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "packaging/windows/bootstrap-technocore-ci-readonly-path.ps1"
WORKFLOW = ROOT / ".github/workflows/security-gate.yml"


def test_native_wrapper_avoids_powershell_automatic_args_variable():
    text = BOOTSTRAP.read_text("utf-8")

    assert "function Invoke-CheckedQuiet" in text
    assert "[string[]]$ArgumentList" in text
    assert "& $Exe @ArgumentList" in text
    assert "[string[]]$Args" not in text
    assert "& $Exe @Args" not in text


def test_windows_ps51_ci_executes_exact_committed_wrapper_function():
    workflow = WORKFLOW.read_text("utf-8")

    argv_check = workflow.index(
        "Prove Windows PowerShell 5.1 native argv forwarding"
    )
    keygen_check = workflow.index(
        "Prove Windows PowerShell 5.1 non-interactive key generation"
    )

    assert argv_check < keygen_check
    assert "FunctionDefinitionAst" in workflow
    assert "$node.Name -eq 'Invoke-CheckedQuiet'" in workflow
    assert "Invoke-Expression $wrapper.Extent.Text" in workflow
    assert "'beta gamma'" in workflow
    assert "WINDOWS_PS51_NATIVE_ARGV_FORWARDING=PASS" in workflow


def test_scp_still_uses_checked_wrapper_and_existing_destination_shape():
    text = BOOTSTRAP.read_text("utf-8")

    assert "$scpArgs = @(" in text
    assert "Invoke-CheckedQuiet $ScpExe $scpArgs 'PUBLIC_KEY_COPY_FAILED'" in text
    assert '"$OperatorUser@$ProductionHost`:$remotePublic"' in text
