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
install -d -o technocore-signer -g technocore-signer -m 0700 "$state/signer/uv-cache"
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
install -o root -g root -m 0644 "$app/packaging/oracle/technocore-safe-agent-close1-approved-trade.service" /etc/systemd/system/technocore-safe-agent-close1-approved-trade.service
install -o root -g root -m 0644 "$app/packaging/oracle/technocore-safe-agent-close1-batch-trade.service" /etc/systemd/system/technocore-safe-agent-close1-batch-trade.service
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
# Dedicated owner-account ledger; never broaden observer access.
close1=$state/close1
legacy=$state/observer/close1-own-account.json
shared=$close1/close1-own-account.json
for directory in "$state" "$state/observer" "$close1"; do
  if [[ -L $directory || ( -e $directory && ! -d $directory ) ]]; then echo "unsafe Close Call directory" >&2; exit 1; fi
done
for ledger in "$legacy" "$shared"; do
  if [[ -L $ledger || ( -e $ledger && ! -f $ledger ) ]]; then echo "unsafe Close Call ledger" >&2; exit 1; fi
  if [[ -e $ledger && $(stat -c %h -- "$ledger") != 1 ]]; then echo "hard-linked Close Call ledger" >&2; exit 1; fi
done
if [[ -e $legacy && -e $shared ]]; then echo "both legacy and dedicated Close Call ledgers exist; refusing to lose state" >&2; exit 1; fi
install -d -o technocore -g technocore-autopilot -m 2770 "$close1"
if [[ -e $legacy ]]; then
  # Only legacy migration needs quiescence. Resident and isolated oracle signer do
  # not touch this ledger; Close Call watcher and Discord reconciliation can.
  for unit in technocore-safe-agent-close1-standalone-watch.service technocore-safe-agent-discord.service; do
    if systemctl is-active --quiet "$unit"; then echo "stop Close Call ledger users before legacy migration" >&2; exit 1; fi
  done
  mv -n -- "$legacy" "$shared"
  [[ ! -e $legacy ]] || { echo "Close Call migration refused" >&2; exit 1; }
fi
if [[ -e $shared ]]; then
  chown technocore:technocore-autopilot "$shared"
  chmod 0660 "$shared"
else
  runuser -u technocore -- env FLOP_STATE_DIR="$state" PYTHONPATH="$app/src" "$app/.venv/bin/python" -c 'from flop_agent.close1_account_reconciliation import checkpoint_ledger, save_ledger; save_ledger(checkpoint_ledger())'
fi
systemctl daemon-reload
echo "Prepared only. Fill $envdir/signer.env and review IAM. No service or metadata blocker unit was enabled or started."
