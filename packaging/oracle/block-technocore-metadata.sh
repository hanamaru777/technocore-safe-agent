#!/bin/sh
# Root-only metadata firewall. Public code must remain safe even when an
# attacker knows the VM uses OCI Instance Principals: only root and the isolated
# signer may reach the OCI Instance Metadata Service (IMDS) HTTP endpoint.
#
# OCI also uses 169.254.169.254 for DNS (:53) and NTP (:123). Do not block the
# address wholesale: restrict only IMDS HTTP (:80), otherwise DNS resolution on
# the VM is broken.
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

# Upgrade safely from the earlier broad address-level jump, which also blocked
# OCI DNS/NTP because those services share the same link-local address.
while iptables -C OUTPUT -d "$metadata" -j "$chain" 2>/dev/null; do
  iptables -D OUTPUT -d "$metadata" -j "$chain"
done

# IMDS is the HTTP service on :80. Keep DNS (:53), NTP (:123), and any unrelated
# link-local service reachable while still denying Instance Principal metadata
# to every non-root UID except the isolated signer.
if ! iptables -C OUTPUT -p tcp -d "$metadata" --dport 80 -j "$chain" 2>/dev/null; then
  iptables -I OUTPUT 1 -p tcp -d "$metadata" --dport 80 -j "$chain"
fi

# Remove the older account-specific rules if this host is being upgraded from
# a previous release. The dedicated chain above is strictly broader for IMDS.
for account in technocore technocore-rpc; do
  if uid=$(id -u "$account" 2>/dev/null); then :; else continue; fi
  case "$uid" in ''|*[!0-9]*) echo "invalid account UID" >&2; exit 1;; esac
  while iptables -C OUTPUT -m owner --uid-owner "$uid" -d "$metadata" -j REJECT 2>/dev/null; do
    iptables -D OUTPUT -m owner --uid-owner "$uid" -d "$metadata" -j REJECT
  done
done
