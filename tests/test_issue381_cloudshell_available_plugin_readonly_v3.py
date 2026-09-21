from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = (
    core.ROOT
    / "packaging"
    / "oracle"
    / "issue381-cloudshell-available-plugin-readonly-v3.sh"
)


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue381_cloudshell_v3_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue381_cloudshell_v3_requires_real_cloudshell() -> None:
    text = _text()

    assert 'OCI_CLI_AUTH:-' in text
    assert '"instance_obo_user"' in text
    assert 'OCI_CLI_CONFIG_FILE:-' in text
    assert '"/etc/oci/config"' in text
    assert 'OCI_CLI_PROFILE:-' in text
    assert "CLOUDSHELL_ENV=PASS" in text


def test_issue381_cloudshell_v3_queries_tenancy_first_then_fallback() -> None:
    text = _text()

    direct = text.index("--- DIRECT TENANCY-SCOPE PROBE ---")
    fallback = text.index("--- ACCESSIBLE COMPARTMENT FALLBACK ---")
    assert direct < fallback
    assert 'call_available "$TENANCY"' in text
    assert "TENANCY_SCOPE_FALLBACK=ACCESSIBLE_COMPARTMENTS" in text
    assert "oci iam compartment list" in text
    assert "--access-level ACCESSIBLE" in text


def test_issue381_cloudshell_v3_handles_empty_or_invalid_json() -> None:
    text = _text()

    for token in (
        "PARSE_RESULT=EMPTY",
        "PARSE_RESULT=INVALID_JSON",
        "PARSE_RESULT=UNEXPECTED_SHAPE",
        "ACCESSIBLE_COMPARTMENT_DISCOVERY_PARSE=",
        "CONTROL_PLANE_ERROR_CLASS=COMPARTMENT_DISCOVERY_PARSE",
        "CONTROL_PLANE_ERROR_CLASS=AVAILABLE_PLUGIN_PARSE",
    ):
        assert token in text

    assert "json.decoder.JSONDecodeError" not in text


def test_issue381_cloudshell_v3_does_not_toggle_errexit() -> None:
    text = _text()

    assert "set -e" not in text
    assert "set +e" not in text
    assert "|| rc=$?" in text
    assert "|| COMP_RC=$?" in text


def test_issue381_cloudshell_v3_uses_authoritative_readonly_api() -> None:
    text = _text()

    assert "oci instance-agent available-plugins get" in text
    assert "Compute Instance Run Command" in text
    assert "Canonical Ubuntu" in text
    assert "24.04" in text
    assert "--no-retry" in text


def test_issue381_cloudshell_v3_hides_ids_and_raw_errors() -> None:
    text = _text()

    assert "TENANCY_OUTPUT=NO" in text
    assert "OCID_OUTPUT=NO" in text
    assert "RAW_OCI_ERROR_OUTPUT=NO" in text
    assert 'echo "$TENANCY"' not in text
    assert 'echo "$CID"' not in text
    assert 'cat "$ROOT_ERR"' not in text
    assert 'cat "$COMP_ERR"' not in text
    assert 'cat "$ERR"' not in text


def test_issue381_cloudshell_v3_is_read_only() -> None:
    text = _text().lower()

    for forbidden in (
        "oci iam policy create",
        "oci iam policy update",
        "oci compute instance update",
        "oci instance-agent command create",
        "oci instance-agent command cancel",
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "snap install",
        "snap refresh",
        "apt install",
        "pip install",
        "iptables ",
    ):
        assert forbidden not in text


def test_issue381_cloudshell_v3_no_malformed_expansion() -> None:
    text = _text()

    assert (chr(36) * 2 + "{") not in text
