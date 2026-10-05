"""Read-only probe for a dedicated GitHub Actions forced-command SSH path.

This module proves authenticated reachability and fixed executor authorization only.
It intentionally emits a control-path receipt with ``binding_capable=False`` and
never installs that receipt, starts a service, signs, posts, or accesses signer/Vault
material.  Phase A therefore cannot satisfy CONTROL_PATH_REDUNDANCY_GATE.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime

from . import airdrop_challenge
from . import precontest_control_path_capture as direct
from . import precontest_control_path_proof as control

PATH_ID = "github-actions-fixed-ssh-readonly"
PATH_TYPE = "ci_deploy"
FAILURE_DOMAIN = "github-actions-fixed-ssh"
NONCE_RE = re.compile(r"[0-9a-f]{32}")


class CiControlPathProbeError(RuntimeError):
    """Fail-closed CI forced-command probe error."""


def _nonce(value: object) -> str:
    if not isinstance(value, str) or not NONCE_RE.fullmatch(value):
        raise CiControlPathProbeError("precontest_ci_probe_nonce_invalid")
    return value


def _require_forced_ssh(challenge_id: str, nonce: str) -> None:
    if not os.environ.get("SSH_CONNECTION") or not os.environ.get("SSH_CLIENT"):
        raise CiControlPathProbeError("precontest_ci_probe_ssh_session_missing")
    if os.environ.get("SSH_TTY"):
        raise CiControlPathProbeError("precontest_ci_probe_tty_forbidden")
    expected = f"proof {challenge_id} {nonce}"
    if os.environ.get("SSH_ORIGINAL_COMMAND") != expected:
        raise CiControlPathProbeError("precontest_ci_probe_forced_command_mismatch")


def _nonce_tag(nonce: str) -> str:
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()


def build_readonly_probe(
    challenge_id: str,
    nonce: str,
    *,
    now: datetime | None = None,
) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    nonce = _nonce(nonce)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_ci_probe_now_timezone_required")
    current = current.astimezone(UTC)

    _require_forced_ssh(challenge_id, nonce)
    head = direct._repo_head()
    systemctl = direct._systemctl_path()
    sudo = direct._sudo_path()
    _loaded, fragment_path = direct._unit_facts(systemctl)
    direct._fixed_start_permission(sudo, systemctl)

    unsigned = {
        "schema_version": control.SCHEMA_VERSION,
        "path_id": PATH_ID,
        "path_type": PATH_TYPE,
        "endpoint_fingerprint": direct._endpoint_fingerprint(fragment_path=fragment_path),
        "failure_domain": FAILURE_DOMAIN,
        "authenticated": True,
        "ready": True,
        # Phase A is intentionally non-binding.  A fixed proof command is not
        # equivalent to a command path capable of starting the executor.
        "binding_capable": False,
        "quota_independent": True,
        "verified_at": current.isoformat(),
        "probe_method": (
            f"github-actions-forced-ssh-readonly+repo-head:{head}"
            f"+challenge:{direct._challenge_tag(challenge_id)}"
            f"+nonce:{_nonce_tag(nonce)}"
        ),
    }
    unsigned["receipt_sha256"] = control._receipt_digest(unsigned)
    return control.validate_receipt(unsigned, now=current)


def _safe_summary(receipt: dict) -> dict:
    return {
        "status": "READONLY_PROOF",
        "path_id": receipt["path_id"],
        "path_type": receipt["path_type"],
        "authenticated": receipt["authenticated"],
        "ready": receipt["ready"],
        "binding_capable": receipt["binding_capable"],
        "quota_independent": receipt["quota_independent"],
        "verified_at": receipt["verified_at"],
        "receipt_sha256": receipt["receipt_sha256"],
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(json.dumps({"status": "blocked", "reason": "challenge_id_and_nonce_required"}))
        return 2
    try:
        result = build_readonly_probe(sys.argv[1], sys.argv[2])
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(_safe_summary(result), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
