"""R1129 K137 ciphertext-only PRESEED receive, non-activating, fail-closed.

No network, passwords, signing, upstream POST, restore or runtime installation.
The authenticated SSH owner carrier is NOT included. Only encrypted R1001
fragments land under the existing private DISARMED migration directory.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time

ROOT = Path("/var/lib/flop-migration-r1066/disarmed")
EXPECTED_UID = 1000
MIN_RESERVE = 20 * 1024**3
MAX_WIRE_BYTES = 32 * 1024**2
MAX_ELAPSED = 180
ID = re.compile(r"[0-9a-f]{32}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")


class Stop(ValueError):
    pass


def need(test, code):
    if not test:
        raise Stop(code)


def load_receiver():
    path = Path(__file__).with_name("r1084_offhost_ciphertext_stream.py")
    need(path.is_file() and not path.is_symlink(), "DEPENDENCY_UNAVAILABLE")
    spec = importlib.util.spec_from_file_location("r1129_r1084", path)
    need(spec is not None and spec.loader is not None, "DEPENDENCY_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def private_root(root):
    need(root == ROOT and root.is_absolute(), "TARGET_SCOPE_STOP")
    for p in (root, *root.parents):
        need(not p.is_symlink(), "TARGET_LINK_STOP")
    s = root.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid() and
         stat.S_IMODE(s.st_mode) == 0o700, "TARGET_CUSTODY_STOP")


def check_host(machine_sha256):
    need(sys.platform == "linux" and os.geteuid() == EXPECTED_UID and
         EXPECTED_UID > 0, "K137_HOST_STOP")
    need(type(machine_sha256) is str and HEX.fullmatch(machine_sha256),
         "K137_HOST_STOP")
    raw = Path("/etc/machine-id").read_bytes()
    need(1 <= len(raw) <= 128 and
         hashlib.sha256(raw.strip()).hexdigest() == machine_sha256,
         "K137_HOST_STOP")


def receive(incoming, archive_id, machine_sha256):
    """Can run only behind separately authenticated and pinned R987 owner SSH.

    On success retains only encrypted R1001 shards and a final sealed commit.
    The receiver cannot authenticate AES-GCM without an independent recovery
    secret; therefore the receipt is NEVER source/application authority.
    """
    check_host(machine_sha256)
    need(type(archive_id) is str and ID.fullmatch(archive_id),
         "ARCHIVE_ID_STOP")
    private_root(ROOT)
    need(shutil.disk_usage(ROOT).free >= MIN_RESERVE + MAX_WIRE_BYTES +
         1024**3, "TRADEBOT_RESERVE_STOP")
    before = time.monotonic()
    W = load_receiver()
    target = ROOT / ("r1129-" + archive_id)
    need(not target.exists() and not target.is_symlink(), "NEW_TARGET_REQUIRED")

    class BoundedInput:
        def __init__(self):
            self.count = 0
        def read(self, size=-1):
            need(time.monotonic() - before <= MAX_ELAPSED,
                 "TIME_BUDGET_STOP")
            need(type(size) is int and 0 <= size <= W.MAX_DATA,
                 "WIRE_INPUT_BOUND_STOP")
            need(self.count + size <= MAX_WIRE_BYTES + 1,
                 "WIRE_QUOTA_STOP")
            data = incoming.read(size)
            need(type(data) is bytes, "WIRE_TYPE_STOP")
            self.count += len(data)
            need(self.count <= MAX_WIRE_BYTES, "WIRE_QUOTA_STOP")
            return data

    result = W.receive_offhost_ciphertext(
        BoundedInput(), target, quota_bytes=MAX_WIRE_BYTES)
    need(result["operation"] == "OFFHOST_CIPHERTEXT_ONLY" and
         result["aead_verified"] is False and
         result["ciphertext_files"] >= 3, "RECEIPT_STOP")
    return {
        "phase": "R1129",
        "result": "PROVISIONAL_CIPHERTEXT_STORED_ONLY",
        "files": result["ciphertext_files"],
        "bytes": result["ciphertext_bytes"],
        "aead_verified": False,
        "source_complete": False,
        "sqlite_epoch": "NOT_PROVEN",
        "history_finality": "UNKNOWN",
        "signer_portability": "NOT_PROVEN",
        "activated": False,
        "cutover": "NO_GO",
        "oci_retirement": "STRICT_NO_GO",
    }


def main():
    # No standalone owner launcher. Requiring a fixed 3-argument invocation is
    # intentional: do not accept arbitrary paths, actions or program commands.
    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--archive-id", required=True)
    parser.add_argument("--machine-sha256", required=True)
    args = parser.parse_args()
    try:
        report = receive(sys.stdin.buffer, args.archive_id, args.machine_sha256)
    except Exception as ex:
        allowed = {
            "K137_HOST_STOP", "ARCHIVE_ID_STOP", "TARGET_SCOPE_STOP",
            "TARGET_LINK_STOP", "TARGET_CUSTODY_STOP", "TRADEBOT_RESERVE_STOP",
            "NEW_TARGET_REQUIRED", "DEPENDENCY_UNAVAILABLE",
            "TIME_BUDGET_STOP", "WIRE_INPUT_BOUND_STOP", "WIRE_QUOTA_STOP",
            "WIRE_TYPE_STOP", "RECEIPT_STOP",
        }
        code = str(ex) if type(ex) is Stop and str(ex) in allowed else "CIPHERTEXT_RECEIVE_STOP"
        report = {
            "phase": "R1129", "result": "STOP", "code": code,
            "activated": False, "cutover": "NO_GO",
            "oci_retirement": "STRICT_NO_GO",
        }
    sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if report["result"] == "PROVISIONAL_CIPHERTEXT_STORED_ONLY" else 42


if __name__ == "__main__":
    raise SystemExit(main())
