#!/usr/bin/env bash
# Review first. This prepares files but never enables or starts a service.
set -euo pipefail
app=/opt/technocore-safe-agent
state=/var/lib/technocore-safe-agent
envdir=/etc/technocore-safe-agent
discord=false
source_repo=${1:-}
[[ ${2:-} == --discord || ${1:-} == --discord ]] && discord=true
[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ -r /etc/os-release ]] && . /etc/os-release
[[ ${ID:-} == ubuntu || ${ID:-} == ol || ${ID_LIKE:-} == *rhel* ]] || { echo "Supported targets: Ubuntu or Oracle Linux." >&2; exit 1; }
command -v git >/dev/null || { echo "Install git first." >&2; exit 1; }
command -v uv >/dev/null || { echo "Install uv first, then rerun: https://docs.astral.sh/uv/" >&2; exit 1; }
[[ -n $source_repo && $source_repo != --discord ]] || { echo "Usage: install.sh REPOSITORY_URL [--discord]" >&2; exit 1; }
id -u technocore >/dev/null 2>&1 || useradd --system --home "$state" --create-home --shell /usr/sbin/nologin technocore
install -d -o technocore -g technocore -m 0750 "$state/observer" "$envdir"
install -o root -g technocore -m 0640 /dev/null "$envdir/env"
if [[ -e $app ]]; then echo "$app already exists; review/update it rather than overwriting." >&2; exit 1; fi
git clone --origin origin "$source_repo" "$app"
chown -R root:technocore "$app"
cd "$app"
if $discord; then uv sync --frozen --no-dev --extra discord; else uv sync --frozen --no-dev; fi
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 packaging/oracle/technocore-safe-agent-rpc /usr/local/libexec/technocore-safe-agent-rpc
install -o root -g root -m 0644 packaging/oracle/resident.service /etc/systemd/system/technocore-safe-agent-resident.service
if $discord; then install -o root -g root -m 0644 packaging/oracle/discord.service /etc/systemd/system/technocore-safe-agent-discord.service; fi
systemctl daemon-reload
echo "Prepared only. Review $envdir/env and packaging/oracle/technocore-safe-agent-rpc.sudoers.example, then explicitly run systemctl enable --now technocore-safe-agent-resident.service if desired. No DID seed is requested or copied."
