#!/usr/bin/env bash
# Review first. This prepares files but never enables or starts a service.
set -euo pipefail
app=/opt/technocore-safe-agent
state=/var/lib/technocore-safe-agent
envdir=/etc/technocore-safe-agent
discord=false
signer=false
source_repo=${1:-}
for option in "$@"; do
  [[ $option == --discord ]] && discord=true
  [[ $option == --signer ]] && signer=true
done
[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ -r /etc/os-release ]] && . /etc/os-release
[[ ${ID:-} == ubuntu || ${ID:-} == ol || ${ID_LIKE:-} == *rhel* ]] || { echo "Supported targets: Ubuntu or Oracle Linux." >&2; exit 1; }
command -v git >/dev/null || { echo "Install git first." >&2; exit 1; }
command -v uv >/dev/null || { echo "Install uv first, then rerun: https://docs.astral.sh/uv/" >&2; exit 1; }
[[ -n $source_repo && $source_repo != --discord && $source_repo != --signer ]] || { echo "Usage: install.sh REPOSITORY_URL [--discord] [--signer]" >&2; exit 1; }
id -u technocore >/dev/null 2>&1 || useradd --system --home "$state" --create-home --shell /usr/sbin/nologin technocore
if $signer; then
  getent group technocore-autopilot >/dev/null || groupadd --system technocore-autopilot
  id -u technocore-signer >/dev/null 2>&1 || useradd --system --home /nonexistent --shell /usr/sbin/nologin technocore-signer
  usermod -a -G technocore,technocore-autopilot technocore-signer
fi
install -d -o technocore -g technocore -m 0750 "$state/observer" "$envdir"
install -o root -g technocore -m 0640 /dev/null "$envdir/env"
if [[ -e $app ]]; then echo "$app already exists; review/update it rather than overwriting." >&2; exit 1; fi
git clone --origin origin "$source_repo" "$app"
chown -R root:technocore "$app"
cd "$app"
if $discord && $signer; then uv sync --frozen --no-dev --extra discord --extra oracle-signer
elif $discord; then uv sync --frozen --no-dev --extra discord
elif $signer; then uv sync --frozen --no-dev --extra oracle-signer
else uv sync --frozen --no-dev; fi
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 packaging/oracle/technocore-safe-agent-rpc /usr/local/libexec/technocore-safe-agent-rpc
install -o root -g root -m 0644 packaging/oracle/resident.service /etc/systemd/system/technocore-safe-agent-resident.service
if $discord; then install -o root -g root -m 0644 packaging/oracle/discord.service /etc/systemd/system/technocore-safe-agent-discord.service; fi
if $signer; then
  install -d -o technocore-signer -g technocore-signer -m 0700 "$state/signer"
  install -d -o technocore -g technocore-autopilot -m 2770 "$state/observer"
  if [[ -e $state/observer/autopilot-outbox.json ]]; then chgrp technocore-autopilot "$state/observer/autopilot-outbox.json"; chmod 0640 "$state/observer/autopilot-outbox.json"; fi
  install -o root -g root -m 0600 packaging/oracle/signer.env.example "$envdir/signer.env"
  install -o root -g root -m 0755 packaging/oracle/block-technocore-metadata.sh /usr/local/libexec/technocore-safe-agent-block-metadata
  install -o root -g root -m 0644 packaging/oracle/technocore-safe-agent-signer.service /etc/systemd/system/technocore-safe-agent-signer.service
fi
systemctl daemon-reload
echo "Prepared only. Review $envdir/env and packaging/oracle/technocore-safe-agent-rpc.sudoers.example, then explicitly run systemctl enable --now technocore-safe-agent-resident.service if desired. No DID seed is requested or copied."
