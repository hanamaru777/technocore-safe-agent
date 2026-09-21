from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "prod376-oca-imds-repair.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_prod376_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod376_pins_exact_source_and_production_baseline() -> None:
    text = _text()

    for token in (
        "SOURCE_COMMIT=f627b0b8fbc329d845cade8efc47d9bc08bedf73",
        "SOURCE_BLOB=a21ac47654bc3c49598954e5915af6936628f6d7",
        "EXPECTED_OLD_BLOB=28a53036454abf86b63a3d6571625c1440d67b71",
        "EXPECTED_REPO=b7bf27dbaa605971d340aa926fdffc17489c3afe",
        "EXPECTED_ORIGIN_MAIN=43db3595a52bb2e19777a1c1c91842c06408f48b",
        "EXPECTED_CORE_EVENTS=117",
        "EXPECTED_CORE_MESSAGES=5083155",
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
    ):
        assert token in text


def test_prod376_only_installs_exact_reviewed_metadata_helper() -> None:
    text = _text()

    assert (
        'https://raw.githubusercontent.com/hanamaru777/technocore-safe-agent/'
        '$SOURCE_COMMIT/packaging/oracle/block-technocore-metadata.sh'
    ) in text
    assert '[[ "$NEW_BLOB" == "$SOURCE_BLOB" ]]' in text
    assert 'sh -n "$NEW_HELPER"' in text
    assert 'install -o root -g root -m 0755 "$NEW_HELPER" "$INSTALLED"' in text
    assert '"$INSTALLED" || stop "metadata_helper_apply_failed"' in text


def test_prod376_has_exact_rollback_material_before_mutation() -> None:
    text = _text()

    backup_file = 'cp -a -- "$INSTALLED" "$OLD_HELPER"'
    backup_fw = 'iptables-save >"$IPTABLES_BEFORE"'
    mutate = "MUTATED=1"
    install = 'install -o root -g root -m 0755 "$NEW_HELPER" "$INSTALLED"'

    assert backup_file in text
    assert backup_fw in text
    assert 'cp -a -- "$OLD_HELPER" "$INSTALLED"' in text
    assert 'iptables-restore <"$IPTABLES_BEFORE"' in text

    assert text.index(backup_file) < text.index(mutate)
    assert text.index(backup_fw) < text.index(mutate)
    assert text.index(mutate) < text.index(install)


def test_prod376_hard_gates_preserve_isolation_and_services() -> None:
    text = _text()

    for token in (
        "PRE_FIREWALL=PASS snap_daemon_return=NO",
        "POST_FIREWALL=PASS snap_daemon_return=YES",
        "PRE_TECHNOCORE_IMDS_BLOCKED=YES",
        "POST_TECHNOCORE_IMDS_BLOCKED=YES",
        "POST_SNAP_DAEMON_IMDS_HTTP=",
        "metadata_output_jump_missing",
        "metadata_root_return_missing",
        "metadata_signer_return_missing",
        "post_snap_daemon_return_missing",
        "post_metadata_final_reject_missing",
        "protected_core_changed",
        "oca_runtime_user:",
        "PROD376_HARD_GATES=PASS",
    ):
        assert token in text

    hard = text.index("PROD376_HARD_GATES=PASS")
    done = text.index("DONE=1")
    assert hard < done


def test_prod376_observation_after_acceptance_is_non_binding() -> None:
    text = _text()
    done = text.index("DONE=1")
    tail = text[done:]

    assert "WAIT_SECONDS=90" in tail
    assert "OBS_T90_ROOT_IMDS_RC=" in tail
    assert "OBS_T90_SNAP_DAEMON_IMDS_RC=" in tail
    assert "OBS_T90_TECHNOCORE_IMDS_BLOCKED=" in tail
    assert "RUN_COMMAND_POST_T90_ADVERTISED=" in tail
    assert "stop " not in tail


def test_prod376_does_not_restart_or_expand_scope() -> None:
    text = _text().lower()

    for forbidden in (
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "snap refresh",
        "snap revert",
        "snap install",
        "snap remove",
        "git -c "$app" fetch",
        "git -c "$app" pull",
        "git -c "$app" reset",
        "git -c "$app" checkout",
        "git -c "$app" switch",
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
