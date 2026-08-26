#!/usr/bin/env bash
set -euo pipefail
app=/opt/technocore-safe-agent
state=/var/lib/technocore-safe-agent
envdir=/etc/technocore-safe-agent
id -u technocore >/dev/null 2>&1 || useradd --system --home "$state" --create-home --shell /usr/sbin/nologin technocore
install -d -o technocore -g technocore -m 0750 "$state" "$envdir"
install -m 0600 /dev/null "$envdir/env"
echo "Install the repository at $app, then copy services manually. This script never requests or copies a DID seed."
