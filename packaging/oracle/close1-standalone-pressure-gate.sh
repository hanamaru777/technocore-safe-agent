#!/bin/sh
set -eu

mem_kb=$(awk '/^MemAvailable:/ {print $2; exit}' /proc/meminfo)
memory_psi=$(awk '/^full / {for (i=1;i<=NF;i++) if ($i ~ /^avg10=/) {split($i,a,"="); print a[2]; exit}}' /proc/pressure/memory)
io_psi=$(awk '/^full / {for (i=1;i<=NF;i++) if ($i ~ /^avg10=/) {split($i,a,"="); print a[2]; exit}}' /proc/pressure/io)

[ -n "$mem_kb" ] && [ -n "$memory_psi" ] && [ -n "$io_psi" ]
awk -v m="$mem_kb" -v mp="$memory_psi" -v ip="$io_psi" \
  'BEGIN { exit !(m >= 131072 && mp <= 30 && ip <= 50) }'
