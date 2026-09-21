from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = (
    core.ROOT
    / "packaging"
    / "oracle"
    / "issue381-cloudshell-available-plugin-readonly-v2.sh"
)


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue381_cloudshell_v2_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue381_cloudshell_v2_requires_cloudshell_identity() -> None:
    text = _text()

    assert 'OCI_CLI_AUTH:-' in text
    assert '"instance_obo_user"' in text
    assert 'OCI_CLI_CONFIG_FILE:-' in text
    assert '"/etc/oci/config"' in text
    assert 'OCI_CLI_PROFILE:-' in text
    assert "CLOUDSHELL_ENV=PASS" in text
    assert "CLOUDSHELL_ENV=STOP:" in text


def test_issue381_cloudshell_v2_uses_authoritative_api() -> None:
    text = _text()

    assert "oci instance-agent available-plugins get" in text
    assert "oci iam compartment list" in text
    assert "--access-level ACCESSIBLE" in text
    assert "Compute Instance Run Command" in text
    assert "Canonical Ubuntu" in text
    assert "24.04" in text
    assert "--no-retry" in text


def test_issue381_cloudshell_v2_hides_ids_and_raw_errors() -> None:
    text = _text()

    assert "TENANCY_OUTPUT=NO" in text
    assert "OCID_OUTPUT=NO" in text
    assert "RAW_OCI_ERROR_OUTPUT=NO" in text
    assert 'echo "$TENANCY"' not in text
    assert 'echo "$COMPARTMENT_ID"' not in text
    assert 'cat "$STDERR"' not in text
    assert 'cat "$STDOUT"' not in text


def test_issue381_cloudshell_v2_is_read_only() -> None:
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


def test_issue381_cloudshell_v2_no_malformed_expansion() -> None:
    text = _text()

    assert (chr(36) * 2 + "{") not in text
