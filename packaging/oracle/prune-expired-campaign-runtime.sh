#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "--apply" ]]; then
  echo "usage: sudo bash $0 --apply" >&2
  exit 64
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "STOP_NOT_ROOT" >&2
  exit 1
fi

REPO=/opt/technocore-safe-agent
if [[ ! -d "$REPO" ]]; then
  echo "STOP_REPO_MISSING" >&2
  exit 1
fi

PROTECTED_UNITS=(
  technocore-safe-agent-resident.service
  technocore-safe-agent-lobby-capture.service
  technocore-safe-agent-signer.service
  technocore-safe-agent-discord.service
)

SONNET_UNITS=(
  technocore-safe-agent-sonnet-invites.service
  technocore-safe-agent-sonnet-murphy-invite.service
  technocore-safe-agent-sonnet-priority-invites.service
  technocore-safe-agent-sonnet-registration.service
  technocore-safe-agent-sonnet-team-request.service
)

CLOSE1_RESIDENT=technocore-safe-agent-close1-auto-resident.service

declare -A PRE_PID
declare -A PRE_RESTARTS

echo "=== PRECHECK PROTECTED SERVICES ==="
for unit in "${PROTECTED_UNITS[@]}"; do
  active="$(systemctl show "$unit" -p ActiveState --value)"
  pid="$(systemctl show "$unit" -p MainPID --value)"
  restarts="$(systemctl show "$unit" -p NRestarts --value)"
  echo "PRE_PROTECTED=$unit ACTIVE=$active MainPID=$pid NRestarts=$restarts"
  if [[ "$active" != "active" || ! "$pid" =~ ^[1-9][0-9]*$ || ! "$restarts" =~ ^[0-9]+$ ]]; then
    echo "STOP_PROTECTED_BASELINE_INVALID=$unit" >&2
    exit 1
  fi
  PRE_PID["$unit"]="$pid"
  PRE_RESTARTS["$unit"]="$restarts"
done

echo "=== RETIRE ENDED CLOSE CALL RESIDENT ==="
close1_load="$(systemctl show "$CLOSE1_RESIDENT" -p LoadState --value 2>/dev/null || true)"
close1_active="$(systemctl is-active "$CLOSE1_RESIDENT" 2>/dev/null || true)"
close1_enabled="$(systemctl is-enabled "$CLOSE1_RESIDENT" 2>/dev/null || true)"
echo "CLOSE1_PRE LoadState=$close1_load Active=$close1_active Enabled=$close1_enabled"

if [[ "$close1_load" != "not-found" && -n "$close1_load" ]]; then
  systemctl disable --now "$CLOSE1_RESIDENT" >/dev/null 2>&1 || {
    systemctl stop "$CLOSE1_RESIDENT" >/dev/null 2>&1 || true
    systemctl disable "$CLOSE1_RESIDENT" >/dev/null 2>&1 || true
  }
fi

close1_active_post="$(systemctl is-active "$CLOSE1_RESIDENT" 2>/dev/null || true)"
close1_enabled_post="$(systemctl is-enabled "$CLOSE1_RESIDENT" 2>/dev/null || true)"
if [[ "$close1_active_post" == "active" || "$close1_active_post" == "activating" ]]; then
  echo "STOP_CLOSE1_STILL_ACTIVE" >&2
  exit 1
fi
if [[ "$close1_enabled_post" == "enabled" ]]; then
  echo "STOP_CLOSE1_STILL_ENABLED" >&2
  exit 1
fi
echo "CLOSE1_RETIRED=PASS Active=$close1_active_post Enabled=$close1_enabled_post"

echo "=== REMOVE EXPIRED SONNET SYSTEMD UNITS ==="
for unit in "${SONNET_UNITS[@]}"; do
  active="$(systemctl is-active "$unit" 2>/dev/null || true)"
  enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
  echo "SONNET_PRE=$unit Active=$active Enabled=$enabled"

  if [[ "$active" == "active" || "$active" == "activating" ]]; then
    systemctl stop "$unit"
  fi
  if [[ "$enabled" == "enabled" ]]; then
    systemctl disable "$unit"
  fi

  unit_path="/etc/systemd/system/$unit"
  if [[ -L "$unit_path" && "$(readlink -f "$unit_path" 2>/dev/null || true)" == "/dev/null" ]]; then
    echo "SONNET_MASK_PRESERVED=$unit"
  else
    rm -f -- "$unit_path"
    rm -rf -- "/etc/systemd/system/$unit.d"
  fi
  rm -f -- "/etc/systemd/system/multi-user.target.wants/$unit"
  rm -f -- "/etc/systemd/system/timers.target.wants/$unit"
done

systemctl daemon-reload

for unit in "${SONNET_UNITS[@]}"; do
  active="$(systemctl is-active "$unit" 2>/dev/null || true)"
  enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
  if [[ "$active" == "active" || "$active" == "activating" || "$enabled" == "enabled" ]]; then
    echo "STOP_SONNET_UNIT_STILL_LIVE=$unit Active=$active Enabled=$enabled" >&2
    exit 1
  fi
  echo "SONNET_RETIRED=PASS unit=$unit Active=$active Enabled=$enabled"
done

echo "=== CLEAN SAFE REPO CACHES ==="
before_bytes="$(du -sb "$REPO" 2>/dev/null | awk '{print $1}' || echo 0)"

safe_remove_dir() {
  local path="$1"
  local rel="${path#"$REPO"/}"
  [[ "$path" == "$REPO"/* ]] || return 0
  [[ "$path" != "$REPO/.git" && "$path" != "$REPO/.venv" ]] || return 0
  if git -c safe.directory="$REPO" -C "$REPO" ls-files -- "$rel" | grep -q .; then
    echo "CACHE_SKIP_TRACKED=$rel"
    return 0
  fi
  rm -rf -- "$path"
  echo "CACHE_REMOVED=$rel"
}

while IFS= read -r -d '' path; do
  safe_remove_dir "$path"
done < <(
  find "$REPO"     -path "$REPO/.git" -prune -o     -path "$REPO/.venv" -prune -o     -type d \(       -name __pycache__ -o       -name .pytest_cache -o       -name .mypy_cache -o       -name .ruff_cache -o       -name htmlcov     \) -print0
)

for file in "$REPO/.coverage"; do
  if [[ -f "$file" ]]; then
    rel="${file#"$REPO"/}"
    if git -c safe.directory="$REPO" -C "$REPO" ls-files --error-unmatch -- "$rel" >/dev/null 2>&1; then
      echo "CACHE_SKIP_TRACKED=$rel"
    else
      rm -f -- "$file"
      echo "CACHE_REMOVED=$rel"
    fi
  fi
done

after_bytes="$(du -sb "$REPO" 2>/dev/null | awk '{print $1}' || echo 0)"
if [[ "$before_bytes" =~ ^[0-9]+$ && "$after_bytes" =~ ^[0-9]+$ && "$before_bytes" -ge "$after_bytes" ]]; then
  echo "REPO_CACHE_FREED_BYTES=$((before_bytes-after_bytes))"
else
  echo "REPO_CACHE_FREED_BYTES=UNKNOWN"
fi

echo "=== POSTCHECK PROTECTED SERVICES ==="
for unit in "${PROTECTED_UNITS[@]}"; do
  active="$(systemctl show "$unit" -p ActiveState --value)"
  pid="$(systemctl show "$unit" -p MainPID --value)"
  restarts="$(systemctl show "$unit" -p NRestarts --value)"
  echo "POST_PROTECTED=$unit ACTIVE=$active MainPID=$pid NRestarts=$restarts"
  if [[ "$active" != "active" ]]; then
    echo "STOP_PROTECTED_NOT_ACTIVE=$unit" >&2
    exit 1
  fi
  if [[ "$pid" != "${PRE_PID[$unit]}" || "$restarts" != "${PRE_RESTARTS[$unit]}" ]]; then
    echo "STOP_PROTECTED_DRIFT=$unit" >&2
    exit 1
  fi
done

echo "ORACLE_EXPIRED_CAMPAIGN_CLEANUP=PASS"
