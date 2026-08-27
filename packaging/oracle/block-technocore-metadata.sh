#!/bin/sh
# Root-only, fixed metadata denial for the seedless observer account.
set -eu
[ "$#" -eq 0 ] || { echo "no arguments accepted" >&2; exit 64; }
uid=$(id -u technocore)
rule="-m owner --uid-owner $uid -d 169.254.169.254/32 -j REJECT"
if iptables -C OUTPUT $rule 2>/dev/null; then exit 0; fi
exec iptables -I OUTPUT $rule
