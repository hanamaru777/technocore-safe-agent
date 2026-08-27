#!/bin/sh
# Root-only, fixed metadata denial for untrusted observer/RPC accounts.
# Root and the isolated signer are the explicitly trusted operator boundary.
set -eu
[ "$#" -eq 0 ] || { echo "no arguments accepted" >&2; exit 64; }
for account in technocore technocore-rpc; do
  # technocore-rpc is optional during staged deployment.
  if uid=$(id -u "$account" 2>/dev/null); then :; else continue; fi
  case "$uid" in ''|*[!0-9]*) echo "invalid account UID" >&2; exit 1;; esac
  rule="-m owner --uid-owner $uid -d 169.254.169.254/32 -j REJECT"
  if ! iptables -C OUTPUT $rule 2>/dev/null; then iptables -I OUTPUT $rule; fi
done
