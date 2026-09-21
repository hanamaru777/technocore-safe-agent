from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = (
    core.ROOT
    / "packaging"
    / "oracle"
    / "issue381-cloudshell-available-plugin-readonly.sh"
)


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue381_cloudshell_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue381_cloudshell_uses_authoritative_readonly_api() -> None:
    text = _text()

    assert "oci instance-agent available-plugins get" in text
    assert "--os-name "$OS_NAME"" in text
    assert "--os-version "$OS_VERSION"" in text
    assert "--name "$TARGET_PLUGIN"" in text
    assert "--no-retry" in text
    assert "Compute Instance Run Command" in text
    assert "Canonical Ubuntu" in text
    assert "24.04" in text


def test_issue381_cloudshell_hides_sensitive_ids_and_raw_errors() -> None:
    text = _text()

    assert "TENANCY_OUTPUT=NO" in text
    assert "OCID_OUTPUT=NO" in text
    assert "RAW_OCI_ERROR_OUTPUT=NO" in text
    assert 'echo "$TENANCY"' not in text
    assert 'cat "$STDERR"' not in text
    assert 'cat "$STDOUT"' not in text


def test_issue381_cloudshell_is_read_only() -> None:
    text = _text().lower()

    for forbidden in (
        "oci iam policy create",
        "oci iam policy update",
        "oci compute instance update",
        "oci instance-agent command create",
        "oci instance-agent command cancel",
        "systemctl restart",
        "snap install",
        "apt install",
        "pip install",
        "iptables ",
    ):
        assert forbidden not in text


def test_issue381_cloudshell_safe_output() -> None:
    text = _text()

    for token in (
        "CONTROL_PLANE_CALL=",
        "AVAILABLE_PLUGIN_MATCHES=",
        "AVAILABLE_PLUGIN_NAME=",
        "AVAILABLE_PLUGIN_SUPPORTED=",
        "AVAILABLE_PLUGIN_ENABLED_BY_DEFAULT=",
        "RUN_COMMAND_AVAILABLE_RESULT=",
        "MUTATION_COMMANDS=NONE",
        "IAM_CHANGE=NO",
        "PLUGIN_ENABLE=NO",
        "RUN_COMMAND_CREATED=NO",
    ):
        assert token in text


def test_issue381_cloudshell_no_malformed_expansion() -> None:
    text = _text()

    assert (chr(36) * 2 + "{") not in text
