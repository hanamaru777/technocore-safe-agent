from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = (
    core.ROOT
    / "packaging"
    / "oracle"
    / "prod376-post-stop-readonly-reconcile.sh"
)


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_prod376_post_stop_reconcile_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod376_post_stop_reconcile_is_read_only() -> None:
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
        "rm -f /usr/local",
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


def test_prod376_post_stop_reconcile_has_no_pid_style_parameter_bug() -> None:
    text = _text()

    assert ("$" + "{") not in text
    assert 'if [[ -z "$code" ]]; then code=000; fi' in text
    assert '${label}_IMDS_CURL_RC=' in text
    assert '${label}_IMDS_HTTP=' in text


def test_prod376_post_stop_reconcile_checks_exact_old_state() -> None:
    text = _text()

    for token in (
        "EXPECTED_APP_HEAD=b7bf27dbaa605971d340aa926fdffc17489c3afe",
        "EXPECTED_LOCAL_ORIGIN=43db3595a52bb2e19777a1c1c91842c06408f48b",
        "EXPECTED_INSTALLED_BLOB=28a53036454abf86b63a3d6571625c1440d67b71",
        "APP_HEAD_MATCH=",
        "LOCAL_ORIGIN_MATCH=",
        "INSTALLED_HELPER_MATCH=",
        "CORE_MATCH=",
        "SNAP_DAEMON_IMDS_RETURN_RULE=",
        "ROOT_IMDS_RETURN_RULE=",
        "SIGNER_IMDS_RETURN_RULE=",
        "METADATA_FINAL_REJECT=",
        '${label}_IMDS_HTTP=',
        "probe ROOT",
        "probe SNAP_DAEMON sudo -n -u snap_daemon --",
        "probe TECHNOCORE sudo -n -u technocore --",
        "OCA_MAIN_USER=",
    ):
        assert token in text


def test_prod376_post_stop_reconcile_checks_service_baselines() -> None:
    text = _text()

    for token in (
        "EXPECTED_RES_PID=1868797",
        "EXPECTED_RES_RESTARTS=0",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_CAP_RESTARTS=0",
        "EXPECTED_SIG_PID=1539554",
        "EXPECTED_SIG_RESTARTS=1",
        "EXPECTED_DIS_PID=1957840",
        "EXPECTED_DIS_RESTARTS=0",
        "EXPECTED_OCA_PID=2038593",
        "EXPECTED_OCA_RESTARTS=0",
        "EXPECTED_UPD_PID=2038595",
        "EXPECTED_UPD_RESTARTS=0",
        "SERVICE_BASELINE_",
    ):
        assert token in text


def test_prod376_post_stop_reconcile_safety_tail() -> None:
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
        "TECHNOCORE_WRITE=NO",
    ):
        assert token in text
