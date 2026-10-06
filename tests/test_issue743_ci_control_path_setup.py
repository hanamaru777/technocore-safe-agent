import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging/oracle/install-technocore-ci-control-proof.sh"


def _text() -> str:
    return SCRIPT.read_text("utf-8")


def test_installer_has_valid_bash_syntax():
    result = subprocess.run(
        ["bash", "-n", str(SCRIPT)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_installer_is_root_only_and_accepts_public_key_file_only():
    text = _text()

    assert "ROOT_REQUIRED" in text
    assert '[[ "$#" -eq 1 ]]' in text
    assert 'KEY_TYPE" == "ssh-ed25519"' in text
    assert "/usr/bin/ssh-keygen -l -f" in text
    assert "ssh-keygen -t" not in text
    assert "BEGIN OPENSSH PRIVATE KEY" not in text
    assert "PRIVATE_KEY" not in text
    assert "PROD_SSH_KEY" not in text


def test_authorized_keys_is_exact_forced_command_with_all_forwarding_disabled():
    text = _text()

    assert 'WRAPPER_DIR="/usr/local/libexec"' in text
    assert 'INSTALLED_WRAPPER="$WRAPPER_DIR/technocore-safe-agent-ci-control-proof"' in text
    assert 'command=\\"$INSTALLED_WRAPPER\\"' in text
    for option in (
        "no-agent-forwarding",
        "no-port-forwarding",
        "no-pty",
        "no-user-rc",
        "no-X11-forwarding",
    ):
        assert option in text
    assert "permitopen=" not in text
    assert "environment=" not in text
    assert "cert-authority" not in text


def test_sudoers_allows_only_exact_executor_start_and_no_wildcard():
    text = _text()

    expected = "$ACCOUNT ALL=(root) NOPASSWD: $SYSTEMCTL start $EXECUTOR_UNIT"
    assert expected in text
    assert 'EXECUTOR_UNIT="technocore-safe-agent-close1-approved-trade.service"' in text
    assert 'SYSTEMCTL="/usr/bin/systemctl"' in text
    assert "NOPASSWD: ALL" not in text
    assert "ALL=(ALL" not in text
    assert "systemctl *" not in text
    assert "sudo -i" not in text
    assert "sudo su" not in text


def test_installer_never_mutates_service_runtime_or_signer_trade_state():
    text = _text()

    for forbidden in (
        "systemctl restart",
        "systemctl stop",
        "systemctl enable",
        "systemctl disable",
        "systemctl daemon-reload",
        "close1-approved-trade.json",
        "close1-approved-batch.json",
        "mark_pending",
        "_post_one",
        "Vault",
    ):
        assert forbidden not in text


def test_existing_exact_state_is_idempotent_and_conflicts_fail_before_mutation():
    text = _text()

    useradd_at = text.index('/usr/sbin/useradd --system')

    # Exact existing files are compared and accepted; different bytes/metadata
    # stop before the first account/file mutation.
    for marker in (
        '/usr/bin/cmp -s "$SOURCE_WRAPPER" "$INSTALLED_WRAPPER" || fail "WRAPPER_CONTENT_CONFLICT"',
        '/usr/bin/cmp -s "$EXPECTED_AUTH" "$AUTHORIZED_KEYS" || fail "AUTHORIZED_KEYS_CONTENT_CONFLICT"',
        '/usr/bin/cmp -s "$EXPECTED_SUDOERS" "$SUDOERS_FILE" || fail "SUDOERS_CONTENT_CONFLICT"',
        'fail "ACCOUNT_HOME_WRITABLE_BY_OTHERS"',
        'fail "ACCOUNT_PASSWORD_SENTINEL_CONFLICT"',
        'fail "WRAPPER_METADATA_CONFLICT"',
        'fail "SSH_DIR_METADATA_CONFLICT"',
        'fail "AUTHORIZED_KEYS_METADATA_CONFLICT"',
        'fail "SUDOERS_METADATA_CONFLICT"',
    ):
        assert marker in text
        assert text.index(marker) < useradd_at

    assert 'if [[ "$ACCOUNT_EXISTS" -eq 0 ]]; then' in text
    assert 'if [[ ! -e "$INSTALLED_WRAPPER" ]]; then' in text
    assert 'if [[ ! -e "$AUTHORIZED_KEYS" ]]; then' in text
    assert 'if [[ ! -e "$SUDOERS_FILE" ]]; then' in text


def test_symlink_and_account_conflicts_are_fail_closed():
    text = _text()

    for marker in (
        "SOURCE_WRAPPER_INVALID",
        "ACCOUNT_HOME_CONFLICT",
        "ACCOUNT_SHELL_CONFLICT",
        "ACCOUNT_HOME_PATH_CONFLICT",
        "ACCOUNT_HOME_WRITABLE_BY_OTHERS",
        "HOME_EXISTS_WITHOUT_ACCOUNT",
        "WRAPPER_DIR_CONFLICT",
        "WRAPPER_PATH_CONFLICT",
        "SSH_DIR_PATH_CONFLICT",
        "AUTHORIZED_KEYS_PATH_CONFLICT",
        "SUDOERS_PATH_CONFLICT",
        "ACCOUNT_PASSWORD_SENTINEL_CONFLICT",
    ):
        assert marker in text

    assert "home_is_safe" in text
    assert "(8#$mode & 0022) == 0" in text
    assert re.search(r'\[\[ -f "\$AUTHORIZED_KEYS" && ! -L "\$AUTHORIZED_KEYS" \]\]', text)
    assert re.search(r'\[\[ -f "\$SUDOERS_FILE" && ! -L "\$SUDOERS_FILE" \]\]', text)


def test_installer_uses_invalid_noncrypt_password_sentinel_and_emits_no_key_material():
    text = _text()

    assert 'PASSWORD_SENTINEL="NP"' in text
    assert '--password "$PASSWORD_SENTINEL" "$ACCOUNT"' in text
    assert '/usr/sbin/usermod --lock "$ACCOUNT"' not in text
    assert '/usr/sbin/usermod' not in text
    assert '[[ "$PASSWORD_FIELD" == "$PASSWORD_SENTINEL" ]]' in text
    assert "ACCOUNT_PASSWORD_SENTINEL_CONFLICT" in text
    assert "ACCOUNT_POSTCHECK_PASSWORD_SENTINEL" in text
    assert "ACCOUNT_POSTCHECK_HOME_WRITABLE" in text
    assert "printf '%s\\n' 'CI_CONTROL_PATH_SETUP=READY'" in text

    # The safe summary contains only fixed paths/account name, never the key blob.
    summary = text[text.index("printf '%s\\n' 'CI_CONTROL_PATH_SETUP=READY'") :]
    assert "KEY_BLOB" not in summary
    assert "PUBLIC_KEY" not in summary
