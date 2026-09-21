from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "prod376-v2-oca-imds-repair.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_prod376_v2_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod376_v2_has_no_malformed_double_dollar_expansion() -> None:
    text = _text()

    assert (chr(36) * 2 + "{") not in text
    assert 'if [[ -z "$code" ]]; then' in text
    assert "printf " in text and "$rc" in text and "$code" in text
    assert "AGENT_CONFIG_%s_HTTP=%s" in text


def test_prod376_v2_pins_exact_source_and_baseline() -> None:
    text = _text()

    for token in (
        "SOURCE_COMMIT=f627b0b8fbc329d845cade8efc47d9bc08bedf73",
        "SOURCE_BLOB=a21ac47654bc3c49598954e5915af6936628f6d7",
        "EXPECTED_OLD_BLOB=28a53036454abf86b63a3d6571625c1440d67b71",
        "EXPECTED_REPO=b7bf27dbaa605971d340aa926fdffc17489c3afe",
        "EXPECTED_ORIGIN_MAIN=43db3595a52bb2e19777a1c1c91842c06408f48b",
        "EXPECTED_CORE_EVENTS=117",
        "EXPECTED_CORE_MESSAGES=5083155",
        "EXPECTED_OCA_VERSION=1.61.0-6",
        "EXPECTED_OCA_REVISION=126",
    ):
        assert token in text


def test_prod376_v2_bounds_snap_daemon_trust_surface() -> None:
    text = _text()

    assert "assert_snap_daemon_scope() {" in text
    assert '[[ "$count" == 2 ]]' in text
    assert '[[ "$names" == "agent,updater" ]]' in text
    assert "SNAP_DAEMON_PROCESS_SCOPE=PASS count=2 comms=agent,updater" in text

    pre = text.index("echo '--- PRE / FIREWALL + IMDS ---'")
    first_scope = text.index("assert_snap_daemon_scope")
    assert first_scope < pre


def test_prod376_v2_has_rollback_before_mutation() -> None:
    text = _text()

    backup_file = 'cp -a -- "$INSTALLED" "$OLD_HELPER"'
    backup_fw = 'iptables-save >"$IPTABLES_BEFORE"'
    mutate = "MUTATED=1"
    install = 'install -o root -g root -m 0755 "$NEW_HELPER" "$INSTALLED"'

    for token in (
        backup_file,
        backup_fw,
        'cp -a -- "$OLD_HELPER" "$INSTALLED"',
        'iptables-restore <"$IPTABLES_BEFORE"',
        install,
    ):
        assert token in text

    assert text.index(backup_file) < text.index(mutate)
    assert text.index(backup_fw) < text.index(mutate)
    assert text.index(mutate) < text.index(install)


def test_prod376_v2_hard_gates_preserve_security_and_services() -> None:
    text = _text()

    for token in (
        "PRE_FIREWALL=PASS snap_daemon_return=NO",
        "POST_FIREWALL=PASS snap_daemon_return=YES",
        "PRE_TECHNOCORE_IMDS_BLOCKED=YES",
        "POST_TECHNOCORE_IMDS_BLOCKED=YES",
        "POST_SNAP_DAEMON_IMDS_HTTP=",
        "post_snap_daemon_return_missing",
        "post_metadata_final_reject_missing",
        "protected_core_changed",
        "OCA_RUNTIME_USER=snap_daemon",
        "OCA_VERSION=",
        "OCA_REVISION=",
        "PROD376V2_HARD_GATES=PASS",
    ):
        assert token in text

    hard = text.index("PROD376V2_HARD_GATES=PASS")
    done = text.index("DONE=1")
    assert hard < done


def test_prod376_v2_observation_is_non_binding() -> None:
    text = _text()
    done = text.index("DONE=1")
    tail = text[done:]

    assert "WAIT_SECONDS=90" in tail
    assert "OBS_T90_ROOT_IMDS_RC=" in tail
    assert "OBS_T90_SNAP_DAEMON_IMDS_RC=" in tail
    assert "OBS_T90_TECHNOCORE_IMDS_BLOCKED=" in tail
    assert "agent_config_snapshot POST_T90" in tail
    assert "stop " not in tail


def test_prod376_v2_does_not_expand_scope() -> None:
    text = _text().lower()

    for forbidden in (
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "snap refresh",
        "snap revert",
        "snap install",
        "snap remove",
        "ip route add",
        "ip route del",
        "route add",
        "route del",
        "client.post(",
        "client.put(",
        "client.patch(",
        "client.delete(",
        "post_signed(",
        "write_note(",
        "run command create",
        "instance-agent command create",
        "sqlite3.connect",
        "pragma ",
    ):
        assert forbidden not in text

    for token in (
        "SERVICE_RESTART=NO",
        "SNAP_MUTATION=NO",
        "NETWORK_ROUTE_PROXY_CHANGE=NO",
        "AGENT_CONFIG_CHANGE=NO",
        "RUN_COMMAND_CREATED=NO",
        "APPLICATION_GIT_CUTOVER=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert token.lower() in text
