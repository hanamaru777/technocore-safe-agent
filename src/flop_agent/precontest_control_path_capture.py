"""Read-only capture of a real direct-SSH Production control-path receipt.

This module never opens SSH, starts/restarts a service, signs, posts, or accesses
signer/Vault material. It can only attest the *current* SSH session after
read-only checks prove that the operator path can invoke the one fixed approved
trade executor service. Raw SSH addresses and credentials are never persisted.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import airdrop_challenge
from . import precontest_control_path_proof as control
from . import precontest_readiness

EXECUTOR_UNIT = "technocore-safe-agent-close1-approved-trade.service"
EXPECTED_FRAGMENT = f"/etc/systemd/system/{EXECUTOR_UNIT}"
PATH_ID = "direct-ssh-operator"
FAILURE_DOMAIN = "direct-ssh-operator"
MAX_EXISTING_RECEIPTS = 16


class ControlPathCaptureError(RuntimeError):
    """Fail-closed direct-SSH capture error."""


def _run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ControlPathCaptureError("precontest_control_capture_command_failed") from error


def _require_real_ssh_session() -> None:
    # These variables are supplied by sshd for an authenticated interactive or
    # command session. Their values are deliberately never copied to evidence.
    if not os.environ.get("SSH_CONNECTION") or not os.environ.get("SSH_CLIENT"):
        raise ControlPathCaptureError("precontest_control_capture_ssh_session_missing")


def _repo_head() -> str:
    repo = Path(__file__).resolve().parents[2]
    # Production checkout is root-owned. Command-local safe.directory permits
    # only this read-only query and does not alter global Git configuration.
    result = _run(
        [
            "git",
            "-c",
            f"safe.directory={repo}",
            "-C",
            str(repo),
            "rev-parse",
            "HEAD",
        ]
    )
    head = result.stdout.strip()
    if result.returncode != 0 or len(head) != 40 or any(ch not in "0123456789abcdef" for ch in head):
        raise ControlPathCaptureError("precontest_control_capture_repo_head_invalid")
    return head


def _systemctl_path() -> str:
    value = shutil.which("systemctl")
    if not value or not Path(value).is_absolute():
        raise ControlPathCaptureError("precontest_control_capture_systemctl_missing")
    return value


def _sudo_path() -> str:
    value = shutil.which("sudo")
    if not value or not Path(value).is_absolute():
        raise ControlPathCaptureError("precontest_control_capture_sudo_missing")
    return value


def _unit_facts(systemctl: str) -> tuple[str, str]:
    loaded = _run([systemctl, "show", EXECUTOR_UNIT, "-p", "LoadState", "--value"])
    if loaded.returncode != 0 or loaded.stdout.strip() != "loaded":
        raise ControlPathCaptureError("precontest_control_capture_executor_not_loaded")

    fragment = _run([systemctl, "show", EXECUTOR_UNIT, "-p", "FragmentPath", "--value"])
    fragment_path = fragment.stdout.strip()
    if fragment.returncode != 0 or fragment_path != EXPECTED_FRAGMENT:
        raise ControlPathCaptureError("precontest_control_capture_executor_fragment_invalid")
    return loaded.stdout.strip(), fragment_path


def _fixed_start_permission(sudo: str, systemctl: str) -> None:
    # `sudo -l <command...>` is an authorization query only. It does not run
    # the command. Keeping exact argv here prevents this proof from becoming a
    # generic privileged shell surface.
    result = _run([sudo, "-n", "-l", systemctl, "start", EXECUTOR_UNIT])
    if result.returncode != 0:
        raise ControlPathCaptureError("precontest_control_capture_executor_permission_missing")


def _endpoint_fingerprint(*, fragment_path: str) -> str:
    # Hostname and unit fragment distinguish endpoints without persisting either
    # value in clear text.
    material = f"{socket.gethostname()}\n{fragment_path}\n{EXECUTOR_UNIT}".encode("utf-8")
    return "sha256:" + hashlib.sha256(material).hexdigest()


def _challenge_tag(challenge_id: str) -> str:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    return hashlib.sha256(challenge_id.encode("utf-8")).hexdigest()


def build_direct_ssh_receipt(challenge_id: str, *, now: datetime | None = None) -> dict:
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_control_capture_now_timezone_required")
    current = current.astimezone(UTC)

    _require_real_ssh_session()
    head = _repo_head()
    systemctl = _systemctl_path()
    sudo = _sudo_path()
    _loaded, fragment_path = _unit_facts(systemctl)
    _fixed_start_permission(sudo, systemctl)

    unsigned = {
        "schema_version": control.SCHEMA_VERSION,
        "path_id": PATH_ID,
        "path_type": "direct_ssh",
        "endpoint_fingerprint": _endpoint_fingerprint(fragment_path=fragment_path),
        "failure_domain": FAILURE_DOMAIN,
        "authenticated": True,
        "ready": True,
        "binding_capable": True,
        "quota_independent": True,
        "verified_at": current.isoformat(),
        "probe_method": (
            f"sshd+sudo-list-fixed-executor+repo-head:{head}"
            f"+challenge:{_challenge_tag(challenge_id)}"
        ),
    }
    unsigned["receipt_sha256"] = control._receipt_digest(unsigned)
    return control.validate_receipt(unsigned, now=current)


def _existing_receipts(challenge_id: str, *, now: datetime) -> list[dict]:
    path = control.receipts_path(challenge_id)
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        raise ControlPathCaptureError("precontest_control_capture_receipts_invalid")
    try:
        raw = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ControlPathCaptureError("precontest_control_capture_receipts_invalid") from error
    if not isinstance(raw, list) or len(raw) > MAX_EXISTING_RECEIPTS:
        raise ControlPathCaptureError("precontest_control_capture_receipts_invalid")

    valid: list[dict] = []
    for row in raw:
        try:
            valid.append(control.validate_receipt(row, now=now))
        except control.ControlPathProofError as error:
            # A stale, otherwise-valid receipt must not permanently block a
            # fresh capture. Any other corruption/tamper remains fail-closed.
            if str(error) == "precontest_control_receipt_stale":
                continue
            raise ControlPathCaptureError("precontest_control_capture_existing_receipt_invalid") from error
    return valid


def install_receipt(challenge_id: str, receipt: object, *, now: datetime | None = None) -> dict:
    """Validate and atomically merge one generated direct-SSH receipt.

    This split lets the SSH operator run the read-only probe as itself while a
    state-owner process performs only the final fixed-schema local file write.
    """
    challenge_id = airdrop_challenge.validate_challenge_id(challenge_id)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_control_capture_now_timezone_required")
    current = current.astimezone(UTC)
    try:
        valid = control.validate_receipt(receipt, now=current)
    except control.ControlPathProofError as error:
        raise ControlPathCaptureError("precontest_control_capture_receipt_invalid") from error
    if valid["path_id"] != PATH_ID or valid["path_type"] != "direct_ssh":
        raise ControlPathCaptureError("precontest_control_capture_receipt_path_invalid")
    if not valid["probe_method"].endswith(f"+challenge:{_challenge_tag(challenge_id)}"):
        raise ControlPathCaptureError("precontest_control_capture_receipt_challenge_mismatch")
    if not (
        valid["authenticated"]
        and valid["ready"]
        and valid["binding_capable"]
        and valid["quota_independent"]
    ):
        raise ControlPathCaptureError("precontest_control_capture_receipt_not_ready")

    rows = [row for row in _existing_receipts(challenge_id, now=current) if row["path_id"] != PATH_ID]
    rows.append(valid)
    rows.sort(key=lambda row: row["path_id"])
    precontest_readiness._atomic_write(control.receipts_path(challenge_id), rows)
    return valid


def save_direct_ssh_receipt(challenge_id: str, *, now: datetime | None = None) -> dict:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("precontest_control_capture_now_timezone_required")
    current = current.astimezone(UTC)
    return install_receipt(
        challenge_id,
        build_direct_ssh_receipt(challenge_id, now=current),
        now=current,
    )


def _safe_summary(receipt: dict) -> dict:
    return {
        "status": "captured",
        "path_id": receipt["path_id"],
        "path_type": receipt["path_type"],
        "binding_capable": receipt["binding_capable"],
        "quota_independent": receipt["quota_independent"],
        "verified_at": receipt["verified_at"],
        "receipt_sha256": receipt["receipt_sha256"],
    }


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"probe-ssh", "install-stdin"}:
        print(json.dumps({"status": "blocked", "reason": "usage: probe-ssh|install-stdin challenge_id"}))
        return 2
    mode, challenge_id = sys.argv[1], sys.argv[2]
    try:
        if mode == "probe-ssh":
            # Full receipt is intentionally stdout-only; no state write occurs.
            result = build_direct_ssh_receipt(challenge_id)
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0

        try:
            payload = json.load(sys.stdin)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ControlPathCaptureError("precontest_control_capture_stdin_invalid") from error
        result = install_receipt(challenge_id, payload)
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(_safe_summary(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
