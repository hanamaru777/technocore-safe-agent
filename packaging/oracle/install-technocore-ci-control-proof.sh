#!/usr/bin/env bash
set -euo pipefail

ACCOUNT="technocore-ci"
HOME_DIR="/var/lib/technocore-ci"
SSH_DIR="$HOME_DIR/.ssh"
AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"
REPO="/opt/technocore-safe-agent"
SOURCE_WRAPPER="$REPO/packaging/oracle/technocore-safe-agent-ci-control-proof"
WRAPPER_DIR="/usr/local/libexec"
INSTALLED_WRAPPER="$WRAPPER_DIR/technocore-safe-agent-ci-control-proof"
SUDOERS_FILE="/etc/sudoers.d/technocore-ci-control-proof"
SYSTEMCTL="/usr/bin/systemctl"
EXECUTOR_UNIT="technocore-safe-agent-close1-approved-trade.service"
SHELL_PATH="/bin/bash"

fail() {
  printf 'STOP_%s\n' "$1" >&2
  exit "${2:-1}"
}

[[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "ROOT_REQUIRED" 10
[[ "$#" -eq 1 ]] || fail "USAGE_PUBLIC_KEY_FILE" 11
PUBLIC_KEY_FILE="$1"

[[ -f "$PUBLIC_KEY_FILE" && ! -L "$PUBLIC_KEY_FILE" ]] || fail "PUBLIC_KEY_FILE_INVALID" 12
[[ -s "$PUBLIC_KEY_FILE" ]] || fail "PUBLIC_KEY_FILE_EMPTY" 13
[[ "$(wc -c < "$PUBLIC_KEY_FILE")" -le 1024 ]] || fail "PUBLIC_KEY_FILE_TOO_LARGE" 14

mapfile -t KEY_LINES < "$PUBLIC_KEY_FILE"
[[ "${#KEY_LINES[@]}" -eq 1 ]] || fail "PUBLIC_KEY_NOT_SINGLE_LINE" 15
KEY_LINE="${KEY_LINES[0]}"
read -r KEY_TYPE KEY_BLOB KEY_COMMENT <<< "$KEY_LINE"
[[ "$KEY_TYPE" == "ssh-ed25519" ]] || fail "PUBLIC_KEY_TYPE_INVALID" 16
[[ -n "${KEY_BLOB:-}" ]] || fail "PUBLIC_KEY_BLOB_MISSING" 17
[[ "$KEY_BLOB" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || fail "PUBLIC_KEY_BLOB_INVALID" 18

for required in /usr/bin/getent /usr/sbin/useradd /usr/sbin/usermod /usr/bin/install /usr/bin/cmp /usr/bin/ssh-keygen /usr/sbin/visudo "$SYSTEMCTL"; do
  [[ -x "$required" ]] || fail "REQUIRED_BINARY_MISSING" 19
done

[[ -f "$SOURCE_WRAPPER" && ! -L "$SOURCE_WRAPPER" ]] || fail "SOURCE_WRAPPER_INVALID" 20
[[ "$(stat -c '%U:%G' "$SOURCE_WRAPPER")" == "root:root" ]] || fail "SOURCE_WRAPPER_OWNER_INVALID" 21

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
CANONICAL_KEY="$TMP_DIR/key.pub"
EXPECTED_AUTH="$TMP_DIR/authorized_keys"
EXPECTED_SUDOERS="$TMP_DIR/sudoers"

printf 'ssh-ed25519 %s\n' "$KEY_BLOB" > "$CANONICAL_KEY"
/usr/bin/ssh-keygen -l -f "$CANONICAL_KEY" >/dev/null 2>&1 || fail "PUBLIC_KEY_CRYPTO_INVALID" 22

printf '%s\n' \
  "command=\"$INSTALLED_WRAPPER\",no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding ssh-ed25519 $KEY_BLOB" \
  > "$EXPECTED_AUTH"
printf '%s\n' \
  "$ACCOUNT ALL=(root) NOPASSWD: $SYSTEMCTL start $EXECUTOR_UNIT" \
  > "$EXPECTED_SUDOERS"
/usr/sbin/visudo -cf "$EXPECTED_SUDOERS" >/dev/null || fail "SUDOERS_TEMPLATE_INVALID" 23

# Preflight every existing object before the first mutation. Exact matches are
# accepted for idempotence; any conflicting state fails closed.
ACCOUNT_EXISTS=0
if /usr/bin/getent passwd "$ACCOUNT" >/dev/null; then
  ACCOUNT_EXISTS=1
  PASSWD_ROW="$(/usr/bin/getent passwd "$ACCOUNT")"
  IFS=: read -r _ _ _ _ _ EXISTING_HOME EXISTING_SHELL <<< "$PASSWD_ROW"
  [[ "$EXISTING_HOME" == "$HOME_DIR" ]] || fail "ACCOUNT_HOME_CONFLICT" 30
  [[ "$EXISTING_SHELL" == "$SHELL_PATH" ]] || fail "ACCOUNT_SHELL_CONFLICT" 31
else
  [[ ! -e "$HOME_DIR" && ! -L "$HOME_DIR" ]] || fail "HOME_EXISTS_WITHOUT_ACCOUNT" 32
fi

if [[ -e "$INSTALLED_WRAPPER" || -L "$INSTALLED_WRAPPER" ]]; then
  [[ -f "$INSTALLED_WRAPPER" && ! -L "$INSTALLED_WRAPPER" ]] || fail "WRAPPER_PATH_CONFLICT" 33
  /usr/bin/cmp -s "$SOURCE_WRAPPER" "$INSTALLED_WRAPPER" || fail "WRAPPER_CONTENT_CONFLICT" 34
  [[ "$(stat -c '%u:%g:%a' "$INSTALLED_WRAPPER")" == "0:0:755" ]] || fail "WRAPPER_METADATA_CONFLICT" 35
fi

if [[ -e "$AUTHORIZED_KEYS" || -L "$AUTHORIZED_KEYS" ]]; then
  [[ "$ACCOUNT_EXISTS" -eq 1 ]] || fail "AUTHORIZED_KEYS_WITHOUT_ACCOUNT" 36
  [[ -f "$AUTHORIZED_KEYS" && ! -L "$AUTHORIZED_KEYS" ]] || fail "AUTHORIZED_KEYS_PATH_CONFLICT" 37
  /usr/bin/cmp -s "$EXPECTED_AUTH" "$AUTHORIZED_KEYS" || fail "AUTHORIZED_KEYS_CONTENT_CONFLICT" 38
fi

if [[ -e "$SUDOERS_FILE" || -L "$SUDOERS_FILE" ]]; then
  [[ -f "$SUDOERS_FILE" && ! -L "$SUDOERS_FILE" ]] || fail "SUDOERS_PATH_CONFLICT" 39
  /usr/bin/cmp -s "$EXPECTED_SUDOERS" "$SUDOERS_FILE" || fail "SUDOERS_CONTENT_CONFLICT" 40
  [[ "$(stat -c '%u:%g:%a' "$SUDOERS_FILE")" == "0:0:440" ]] || fail "SUDOERS_METADATA_CONFLICT" 41
  /usr/sbin/visudo -cf "$SUDOERS_FILE" >/dev/null || fail "SUDOERS_EXISTING_INVALID" 42
fi

# Create the dedicated locked account only when absent. A real shell is needed
# for sshd forced-command execution; generic SSH use is prevented by the sole
# restricted authorized_keys entry below and the locked password.
if [[ "$ACCOUNT_EXISTS" -eq 0 ]]; then
  /usr/sbin/useradd --system --create-home --home-dir "$HOME_DIR" --shell "$SHELL_PATH" "$ACCOUNT"
  /usr/sbin/usermod --lock "$ACCOUNT"
fi

PASSWD_ROW="$(/usr/bin/getent passwd "$ACCOUNT")"
IFS=: read -r _ _ _ _ _ EXISTING_HOME EXISTING_SHELL <<< "$PASSWD_ROW"
[[ "$EXISTING_HOME" == "$HOME_DIR" && "$EXISTING_SHELL" == "$SHELL_PATH" ]] || fail "ACCOUNT_POSTCHECK_INVALID" 50
ACCOUNT_GROUP="$(id -gn "$ACCOUNT")"
ACCOUNT_UID="$(id -u "$ACCOUNT")"
ACCOUNT_GID="$(id -g "$ACCOUNT")"

/usr/bin/install -d -o root -g root -m 0755 "$WRAPPER_DIR"
if [[ ! -e "$INSTALLED_WRAPPER" ]]; then
  /usr/bin/install -o root -g root -m 0755 "$SOURCE_WRAPPER" "$INSTALLED_WRAPPER"
fi
/usr/bin/install -d -o "$ACCOUNT" -g "$ACCOUNT_GROUP" -m 0700 "$SSH_DIR"
if [[ ! -e "$AUTHORIZED_KEYS" ]]; then
  /usr/bin/install -o "$ACCOUNT" -g "$ACCOUNT_GROUP" -m 0600 "$EXPECTED_AUTH" "$AUTHORIZED_KEYS"
fi
if [[ ! -e "$SUDOERS_FILE" ]]; then
  /usr/bin/install -o root -g root -m 0440 "$EXPECTED_SUDOERS" "$SUDOERS_FILE"
fi

# Exact postconditions. Do not start/restart/enable any service here.
[[ -f "$INSTALLED_WRAPPER" && ! -L "$INSTALLED_WRAPPER" ]] || fail "WRAPPER_POSTCHECK_INVALID" 51
/usr/bin/cmp -s "$SOURCE_WRAPPER" "$INSTALLED_WRAPPER" || fail "WRAPPER_POSTCHECK_MISMATCH" 52
[[ "$(stat -c '%u:%g:%a' "$INSTALLED_WRAPPER")" == "0:0:755" ]] || fail "WRAPPER_POSTCHECK_METADATA" 53

[[ -d "$SSH_DIR" && ! -L "$SSH_DIR" ]] || fail "SSH_DIR_POSTCHECK_INVALID" 54
[[ "$(stat -c '%u:%g:%a' "$SSH_DIR")" == "$ACCOUNT_UID:$ACCOUNT_GID:700" ]] || fail "SSH_DIR_POSTCHECK_METADATA" 55
[[ -f "$AUTHORIZED_KEYS" && ! -L "$AUTHORIZED_KEYS" ]] || fail "AUTHORIZED_KEYS_POSTCHECK_INVALID" 56
/usr/bin/cmp -s "$EXPECTED_AUTH" "$AUTHORIZED_KEYS" || fail "AUTHORIZED_KEYS_POSTCHECK_MISMATCH" 57
[[ "$(stat -c '%u:%g:%a' "$AUTHORIZED_KEYS")" == "$ACCOUNT_UID:$ACCOUNT_GID:600" ]] || fail "AUTHORIZED_KEYS_POSTCHECK_METADATA" 58

[[ -f "$SUDOERS_FILE" && ! -L "$SUDOERS_FILE" ]] || fail "SUDOERS_POSTCHECK_INVALID" 59
/usr/bin/cmp -s "$EXPECTED_SUDOERS" "$SUDOERS_FILE" || fail "SUDOERS_POSTCHECK_MISMATCH" 60
[[ "$(stat -c '%u:%g:%a' "$SUDOERS_FILE")" == "0:0:440" ]] || fail "SUDOERS_POSTCHECK_METADATA" 61
/usr/sbin/visudo -cf "$SUDOERS_FILE" >/dev/null || fail "SUDOERS_POSTCHECK_PARSE" 62

printf '%s\n' 'CI_CONTROL_PATH_SETUP=READY'
printf 'account=%s\n' "$ACCOUNT"
printf 'wrapper=%s\n' "$INSTALLED_WRAPPER"
printf 'authorized_keys=%s\n' "$AUTHORIZED_KEYS"
printf 'sudoers=%s\n' "$SUDOERS_FILE"
