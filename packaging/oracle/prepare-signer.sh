#!/usr/bin/env bash
# Prepare the isolated signer on the existing resident VM. Never enable/start it.
set -euo pipefail
app=/opt/technocore-safe-agent
state=/var/lib/technocore-safe-agent
envdir=/etc/technocore-safe-agent
[[ "$#" -eq 0 ]] || { echo "no arguments accepted" >&2; exit 64; }
[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ -d $app/.git ]] || { echo "Expected existing repository at $app." >&2; exit 1; }
command -v uv >/dev/null || { echo "Install uv first." >&2; exit 1; }
id -u technocore >/dev/null 2>&1 || { echo "technocore user is missing." >&2; exit 1; }
getent group technocore-autopilot >/dev/null || groupadd --system technocore-autopilot
usermod -a -G technocore-autopilot technocore
id -u technocore-signer >/dev/null 2>&1 || useradd --system --home /nonexistent --shell /usr/sbin/nologin technocore-signer
usermod -a -G technocore-autopilot technocore-signer
install -d -o technocore-signer -g technocore-signer -m 0700 "$state/signer"
chgrp technocore-autopilot "$state"; chmod 2750 "$state"
install -d -o technocore -g technocore -m 0750 "$state/observer"
install -d -o technocore -g technocore-autopilot -m 2770 "$state/autopilot"
for shared_name in autopilot-outbox.json autopilot-audit.jsonl; do
  legacy=$state/observer/$shared_name; shared=$state/autopilot/$shared_name
  if [[ -e $legacy && -e $shared ]]; then echo "both legacy and dedicated $shared_name exist; refusing to lose state" >&2; exit 1; fi
  if [[ -e $legacy ]]; then [[ -f $legacy ]] || { echo "legacy $shared_name is not a regular file" >&2; exit 1; }; mv -- "$legacy" "$shared"; fi
  if [[ -e $shared ]]; then [[ -f $shared ]] || { echo "shared $shared_name is not a regular file" >&2; exit 1; }; chown technocore:technocore-autopilot "$shared"; chmod 0660 "$shared"; fi
done
for shared_file in "$state/nonces.json" "$state/activities.jsonl"; do
  if [[ ! -e $shared_file ]]; then install -o technocore-signer -g technocore-autopilot -m 0660 /dev/null "$shared_file"; [[ $shared_file == *.json ]] && printf '{}\n' > "$shared_file"; fi
  chgrp technocore-autopilot "$shared_file"; chmod 0660 "$shared_file"
done
if [[ -e $state/verified-did.json ]]; then chown technocore:technocore-autopilot "$state/verified-did.json"; chmod 0640 "$state/verified-did.json"; fi
install -d -o root -g root -m 0755 /usr/local/libexec "$envdir"
# Preserve an operator-configured Vault OCID/DID on repeat preparation.  The
# example is installed only once; this script never enables or starts a unit.
if [[ ! -e $envdir/signer.env ]]; then
  install -o root -g root -m 0600 "$app/packaging/oracle/signer.env.example" "$envdir/signer.env"
fi
install -o root -g root -m 0755 "$app/packaging/oracle/block-technocore-metadata.sh" /usr/local/libexec/technocore-safe-agent-block-metadata
install -o root -g root -m 0755 "$app/packaging/oracle/diagnostic.sh" /usr/local/libexec/technocore-safe-agent-diagnostic
install -o root -g root -m 0644 "$app/packaging/oracle/technocore-safe-agent-metadata-block.service" /etc/systemd/system/technocore-safe-agent-metadata-block.service
install -o root -g root -m 0644 "$app/packaging/oracle/technocore-safe-agent-signer.service" /etc/systemd/system/technocore-safe-agent-signer.service
# Refresh the existing resident unit from this checked-out release.  Discord
# is refreshed only when that optional service is already installed.
install -o root -g root -m 0644 "$app/packaging/oracle/resident.service" /etc/systemd/system/technocore-safe-agent-resident.service
if [[ -e /etc/systemd/system/technocore-safe-agent-discord.service ]]; then
  install -o root -g root -m 0644 "$app/packaging/oracle/discord.service" /etc/systemd/system/technocore-safe-agent-discord.service
fi
cd "$app"
extras=(--extra oracle-signer)
# A pre-existing Discord unit means its optional dependency must survive the
# signer dependency sync.  Do not infer this from untrusted configuration.
if [[ -e /etc/systemd/system/technocore-safe-agent-discord.service ]]; then extras+=(--extra discord); fi
uv sync --frozen --no-dev "${extras[@]}"
systemctl daemon-reload
echo "Prepared only. Fill $envdir/signer.env and review IAM. No service or metadata blocker unit was enabled or started."
