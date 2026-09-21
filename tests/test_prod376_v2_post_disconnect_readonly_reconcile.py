from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = (
    core.ROOT
    / "packaging"
    / "oracle"
    / "prod376-v2-post-disconnect-readonly-reconcile.sh"
)


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_prod376_v2_post_disconnect_reconcile_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod376_v2_post_disconnect_reconcile_is_read_only() -> None:
    text = _text().lower()

    for forbidden in (
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "snap refresh",
        "snap revert",
        "snap install",
        "snap remove",
        "iptables -a ",
        "iptables -i ",
        "iptables -d ",
        "iptables -f ",
        "iptables-restore",
        "install -o root",
        "cp -a --",
        "mv ",
        "run command create",
        "instance-agent command create",
        "client.post(",
        "client.put(",
        "client.patch(",
        "client.delete(",
        "sqlite3.connect",
        "pragma ",
    ):
        assert forbidden not in text


def test_prod376_v2_post_disconnect_reconcile_checks_new_state() -> None:
    text = _text()

    for token in (
        "EXPECTED_INSTALLED_BLOB=a21ac47654bc3c49598954e5915af6936628f6d7",
        "EXPECTED_OCA_VERSION=1.61.0-6",
        "EXPECTED_OCA_REVISION=126",
        "SNAP_DAEMON_IMDS_RETURN_RULE=",
        "ROOT_IMDS_RETURN_RULE=",
        "SIGNER_IMDS_RETURN_RULE=",
        "METADATA_FINAL_REJECT=",
        "RUN_COMMAND_ADVERTISED=",
        "RUN_COMMAND_LOCAL_ARTIFACT=",
        "RUN_COMMAND_CONFIG_PRESENT=",
        "RUN_COMMAND_LOG_PRESENT=",
        "RUN_COMMAND_PROCESS_COUNT=",
        "POST_REPAIR_LOG_CLASS_",
    ):
        assert token in text


def test_prod376_v2_post_disconnect_reconcile_has_identity_probes() -> None:
    text = _text()

    assert "probe ROOT" in text
    assert "probe SNAP_DAEMON sudo -n -u snap_daemon --" in text
    assert "probe TECHNOCORE sudo -n -u technocore --" in text
    assert "-o /dev/null" in text


def test_prod376_v2_post_disconnect_reconcile_no_malformed_expansion() -> None:
    text = _text()

    assert (chr(36) * 2 + "{") not in text
    assert 'if [[ -z "$code" ]]; then code=000; fi' in text
    assert 'if [[ -z "$root_code" ]]; then root_code=000; fi' in text


def test_prod376_v2_post_disconnect_reconcile_preserves_privacy() -> None:
    text = _text()

    assert "RAW_LOG_OUTPUT=NO" in text
    assert 'cat "$TMPDIR/oca.log"' not in text
    assert "OCID" not in text
    assert "169.254.169.254/32" in text


def test_prod376_v2_post_disconnect_reconcile_safety_tail() -> None:
    text = _text()

    for token in (
        "MUTATION_COMMANDS=NONE",
        "HELPER_INSTALL=NO",
        "FIREWALL_CHANGE=NO",
        "SERVICE_RESTART=NO",
        "SNAP_MUTATION=NO",
        "AGENT_CONFIG_CHANGE=NO",
        "RUN_COMMAND_CREATED=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "RAW_LOG_OUTPUT=NO",
        "TECHNOCORE_WRITE=NO",
    ):
        assert token in text
