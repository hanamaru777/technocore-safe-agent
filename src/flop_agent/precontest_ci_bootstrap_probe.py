"""Challenge-independent read-only proof for the dedicated CI SSH bootstrap.

This module verifies only the fixed forced-command SSH path and Production
executor authorization query. It never installs a control-path receipt and can
never satisfy CONTROL_PATH_REDUNDANCY_GATE by itself.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime

from . import precontest_control_path_capture as direct

NONCE_RE = re.compile(r"[0-9a-f]{32}")


class CiBootstrapProbeError(RuntimeError):
    """Fail-closed CI bootstrap probe error."""


def _nonce(value: object) -> str:
    if not isinstance(value, str) or not NONCE_RE.fullmatch(value):
        raise CiBootstrapProbeError("precontest_ci_bootstrap_nonce_invalid")
    return value


def _require_forced_ssh(nonce: str) -> None:
    if not os.environ.get("SSH_CONNECTION") or not os.environ.get("SSH_CLIENT"):
        raise CiBootstrapProbeError("precontest_ci_bootstrap_ssh_session_missing")
    if os.environ.get("SSH_TTY"):
        raise CiBootstrapProbeError("precontest_ci_bootstrap_tty_forbidden")
    if os.environ.get("SSH_ORIGINAL_COMMAND") != f"bootstrap {nonce}":
        raise CiBootstrapProbeError("precontest_ci_bootstrap_forced_command_mismatch")


def _context_sha(*, head: str, fragment_path: str, nonce: str) -> str:
    material = "\n".join((head, fragment_path, hashlib.sha256(nonce.encode()).hexdigest()))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_bootstrap_probe(nonce: str, *, now: datetime | None = None) -> dict:
    nonce = _nonce(nonce)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_ci_bootstrap_now_timezone_required")
    current = current.astimezone(UTC)

    _require_forced_ssh(nonce)
    head = direct._repo_head()
    systemctl = direct._systemctl_path()
    sudo = direct._sudo_path()
    _loaded, fragment_path = direct._unit_facts(systemctl)
    direct._fixed_start_permission(sudo, systemctl)

    return {
        "status": "BOOTSTRAP_PROOF",
        "authenticated": True,
        "ready": True,
        "binding_capable": False,
        "quota_independent": True,
        "verified_at": current.isoformat(),
        "context_sha256": _context_sha(
            head=head,
            fragment_path=fragment_path,
            nonce=nonce,
        ),
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"status": "blocked", "reason": "nonce_required"}))
        return 2
    try:
        result = build_bootstrap_probe(sys.argv[1])
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
