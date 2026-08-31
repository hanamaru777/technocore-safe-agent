#!/bin/sh
# Root-only metadata firewall.  Public code must remain safe even when an
# attacker knows the VM uses OCI Instance Principals: only root and the isolated
# signer may reach the instance metadata service.  Every other local UID is
# denied, including interactive/admin-login accounts that are not root.
set -eu
[ "$#" -eq 0 ] || { echo "no arguments accepted" >&2; exit 64; }

metadata=169.254.169.254/32
chain=TECHNOCORE_METADATA
signer_uid=$(id -u technocore-signer 2>/dev/null) || {
  echo "technocore-signer account is required before metadata isolation" >&2
  exit 1
}
case "$signer_uid" in ''|*[!0-9]*) echo "invalid signer UID" >&2; exit 1;; esac

# A dedicated chain lets trusted UIDs RETURN to the caller instead of ACCEPTing
# traffic outright, so unrelated host firewall policy still applies.
iptables -N "$chain" 2>/dev/null || true
iptables -F "$chain"
iptables -A "$chain" -m owner --uid-owner 0 -j RETURN
iptables -A "$chain" -m owner --uid-owner "$signer_uid" -j RETURN
iptables -A "$chain" -j REJECT

if ! iptables -C OUTPUT -d "$metadata" -j "$chain" 2>/dev/null; then
  iptables -I OUTPUT 1 -d "$metadata" -j "$chain"
fi

# Remove the older account-specific rules if this host is being upgraded from
# a previous release.  The dedicated chain above is strictly broader.
for account in technocore technocore-rpc; do
  if uid=$(id -u "$account" 2>/dev/null); then :; else continue; fi
  case "$uid" in ''|*[!0-9]*) echo "invalid account UID" >&2; exit 1;; esac
  while iptables -C OUTPUT -m owner --uid-owner "$uid" -d "$metadata" -j REJECT 2>/dev/null; do
    iptables -D OUTPUT -m owner --uid-owner "$uid" -d "$metadata" -j REJECT
  done
done
