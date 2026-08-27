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
install -d -o technocore -g technocore-autopilot -m 2770 "$state/observer"
if [[ -e $state/observer/autopilot-outbox.json ]]; then chgrp technocore-autopilot "$state/observer/autopilot-outbox.json"; chmod 0660 "$state/observer/autopilot-outbox.json"; fi
for shared_file in "$state/nonces.json" "$state/activities.jsonl"; do
  if [[ ! -e $shared_file ]]; then install -o technocore-signer -g technocore-autopilot -m 0660 /dev/null "$shared_file"; [[ $shared_file == *.json ]] && printf '{}\n' > "$shared_file"; fi
  chgrp technocore-autopilot "$shared_file"; chmod 0660 "$shared_file"
done
install -d -o root -g root -m 0755 /usr/local/libexec "$envdir"
install -o root -g root -m 0600 "$app/packaging/oracle/signer.env.example" "$envdir/signer.env"
install -o root -g root -m 0755 "$app/packaging/oracle/block-technocore-metadata.sh" /usr/local/libexec/technocore-safe-agent-block-metadata
install -o root -g root -m 0644 "$app/packaging/oracle/technocore-safe-agent-signer.service" /etc/systemd/system/technocore-safe-agent-signer.service
cd "$app"
uv sync --frozen --no-dev --extra oracle-signer
systemctl daemon-reload
echo "Prepared only. Fill $envdir/signer.env, review IAM and run the metadata blocker explicitly. The signer service remains disabled and stopped."
