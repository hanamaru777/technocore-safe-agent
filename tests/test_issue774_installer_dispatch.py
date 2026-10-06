from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "packaging/windows/bootstrap-technocore-ci-readonly-path.ps1"
INSTALLER = ROOT / "packaging/oracle/install-technocore-ci-control-proof.sh"


def test_ci_installer_is_dispatched_through_fixed_bash_path():
    text = BOOTSTRAP.read_text("utf-8")

    safe_dispatch = (
        'sudo -n /bin/bash '
        '"$REPO/packaging/oracle/install-technocore-ci-control-proof.sh" "$PUB"'
    )
    unsafe_direct = (
        'sudo -n '
        '"$REPO/packaging/oracle/install-technocore-ci-control-proof.sh" "$PUB"'
    )

    assert '[ -x /bin/bash ] || exit 37' in text
    assert safe_dispatch in text
    assert unsafe_direct not in text
    assert 'chmod +x' not in text
    assert 'chmod 755 "$REPO/packaging/oracle/install-technocore-ci-control-proof.sh"' not in text


def test_ci_installer_is_valid_bash_even_without_execute_bit():
    result = subprocess.run(
        ["bash", "-n", str(INSTALLER)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0, result.stderr
