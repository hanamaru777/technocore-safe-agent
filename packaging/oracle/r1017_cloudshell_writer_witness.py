#!/usr/bin/env python3
"""R1017: Cloud Shell -> pinned original OCI R1016 READ-ONLY witness.

ONE bounded pinned SSH command, no OCI state content, no unit stop/start,
no AWS traffic, no secret value in stdout. DRAFT, never a freeze/GO decision.
The downloaded original probe is pinned by immutable git commit AND blob SHA.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import urllib.request

COMMIT = "57f9a1126dd597d17976ead31ddff55c8d8c38bf"
BLOB_SHA = "20cce79795648e345c07aa97e52ceb4b7a149a82"
PROBE_URL = ("https://raw.githubusercontent.com/"
             "hanamaru777/technocore-safe-agent/" + COMMIT +
             "/packaging/oracle/r1016_writer_inventory_readonly.py")
HOST = "140.238.55.171"  # Historic pinned ORIGINAL Oracle guest from R1003.
EXPECTED_ORIGINAL = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
KEY_DIR = ".flop-access-recovery-20261018"
SOURCE_MAX = 32768
OUT_MAX = 4096
TIMEOUT_SECONDS = 58
STOP_TAG = "FLOP_R1017_STOP="
EXPECTED_KEYS = frozenset({
    "FLOP_R1016_STATIC_SERVICE_COUNT",
    "FLOP_R1016_STATIC_TIMER_COUNT",
    "FLOP_R1016_INSTALLED_KNOWN_ROWS",
    "FLOP_R1016_ACTIVE_KNOWN_ROWS",
    "FLOP_R1016_ACTIVE_SIGNER_CANDIDATE_ROWS",
    "FLOP_R1016_ENABLED_TIMER_ROWS",
    "FLOP_R1016_MISSING_STATIC_TEMPLATES",
    "FLOP_R1016_UNKNOWN_FLOP_UNIT_ROWS",
    "FLOP_R1016_CANDIDATE_FLOP_PROCESSES",
    "FLOP_R1016_UNSCOPED_OR_RACED_PROCESSES",
    "FLOP_R1016_CRON_LOCATIONS_PRESENT",
})
EXPECTED_FLAGS = frozenset({
    "FLOP_R1016_PROCESS_SCAN_RACY": "TRUE",
    "FLOP_R1016_CRON_WRITER_DISCOVERY_COMPLETE": "FALSE",
    "FLOP_R1016_ORIGINAL_SOURCE_PIN": "PASS",
    "FLOP_R1016_NO_SOURCE_OR_UNIT_MODIFICATION": "YES",
    "FLOP_R1016_ALL_WRITERS_FENCED": "NO",
    "FLOP_R1016_SIGNER_INFLIGHT_POST_RESOLVED": "NO",
    "FLOP_R1016_CAPTURE_COMMON_EPOCH_PROVEN": "NO",
    "FLOP_R1016_OCI_RETIREMENT": "STRICT_NO_GO",
}.items())


class Stop(Exception):
    pass


def need(ok, reason):
    if not ok:
        raise Stop(reason)


def preflight():
    need(sys.platform == "linux" and os.geteuid() != 0,
         "CLOUDSHELL_LINUX_NONROOT_REQUIRED")
    for path in ("/opt/technocore-safe-agent", "/opt/tradebot-k137",
                 "/opt/tradebot-k137-private", "/opt/flop-shadow"):
        need(not Path(path).exists() and not Path(path).is_symlink(),
             "LIVE_HOST_REFUSED")


def private_custody(file, *, allow_readable=False):
    need(file.is_absolute() and ".." not in file.parts, "CUSTODY_ABSOLUTE_STOP")
    parent = file.parent
    try:
        p = os.lstat(parent)
    except FileNotFoundError:
        raise Stop("CUSTODY_PARENT_MISSING_STOP") from None
    need(stat.S_ISDIR(p.st_mode) and p.st_uid == os.geteuid()
         and not (p.st_mode & 0o077), "CUSTODY_PARENT_STOP")
    try:
        f = os.lstat(file)
    except FileNotFoundError:
        raise Stop("CUSTODY_FILE_MISSING_STOP") from None
    need(stat.S_ISREG(f.st_mode) and f.st_uid == os.geteuid()
         and f.st_nlink == 1 and not (f.st_mode & 0o022)
         and (allow_readable or not (f.st_mode & 0o077)),
         "CUSTODY_FILE_STOP")
    need(0 < f.st_size < 16384, "CUSTODY_FILE_SIZE_STOP")


def checked_source(*, fetcher=urllib.request.urlopen):
    # Never execute a moving branch ref or unverified GitHub response.
    try:
        with fetcher(PROBE_URL, timeout=15) as response:
            raw = response.read(SOURCE_MAX + 1)
            need(not response.read(1), "PROBE_SOURCE_OVERSIZE_STOP")
    except (OSError, ValueError) as exc:
        raise Stop("PINNED_PROBE_FETCH_STOP") from None
    need(0 < len(raw) <= SOURCE_MAX, "PINNED_PROBE_LENGTH_STOP")
    sha = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    need(sha == BLOB_SHA, "PINNED_PROBE_BLOB_STOP")
    need(EXPECTED_ORIGINAL.encode() in raw, "PINNED_SOURCE_CONTEXT_STOP")
    return raw


def ssh_args(source, key, hosts):
    # Only vetted source bytes may enter the remote -c argv; no dynamic input.
    import base64
    encoded = base64.b64encode(source).decode("ascii")
    child = 'import base64;exec(compile(base64.b64decode("' + encoded + '"), "<r1016>", "exec"))'
    remote = "sudo -n /usr/bin/python3 -c " + shlex.quote(child)
    return [
        "ssh", "-F", "/dev/null", "-T",
        "-i", str(key),
        "-o", "UserKnownHostsFile=" + str(hosts),
        "-o", "StrictHostKeyChecking=yes",
        "-o", "HostKeyAlgorithms=ecdsa-sha2-nistp256",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none",
        "-o", "ClearAllForwardings=yes",
        "-o", "PermitLocalCommand=no",
        "-o", "ConnectTimeout=7",
        "-o", "ServerAliveInterval=10",
        "-o", "ServerAliveCountMax=2",
        "ubuntu@" + HOST, remote,
    ]


def bounded_invoke(source, *, executor=subprocess.run):
    home = Path.home()
    base = home / KEY_DIR
    private_custody(base / "new-operator-ecdsa")
    private_custody(base / "known_hosts", allow_readable=True)
    args = ssh_args(source, base / "new-operator-ecdsa", base / "known_hosts")
    try:
        result = executor(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          input=None, check=False, timeout=TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        raise Stop("PINNED_REMOTE_READONLY_FAILED_STOP") from None
    if result.returncode != 0:
        if result.returncode == 255:
            raise Stop("PINNED_SSH_AUTH_OR_NETWORK_STOP")
        if result.returncode == 42 and isinstance(result.stdout, bytes):
            # The guest prints one literal error code, never credentials.
            match = re.fullmatch(
                rb"FLOP_R1016_STOP=([A-Z0-9_]{3,56})\\r?\\n?",
                result.stdout,
            )
            if match:
                raise Stop("ORIGINAL_GUEST_" + match.group(1).decode("ascii"))
        raise Stop("PINNED_GUEST_COMMAND_EXIT_STOP")
    need(isinstance(result.stdout, bytes)
         and 100 < len(result.stdout) <= OUT_MAX,
         "REMOTE_RESPONSE_BOUNDS_STOP")
    return result.stdout


def inspect_output(raw):
    need(type(raw) is bytes and 0 < len(raw) <= OUT_MAX,
         "RESPONSE_BOUND_STOP")
    try:
        text = raw.decode("ascii", "strict")
    except UnicodeError:
        raise Stop("RESPONSE_NONASCII_STOP") from None
    lines = text.splitlines()
    need(len(lines) == len(EXPECTED_KEYS) + len(EXPECTED_FLAGS)
         and text.endswith("\n"), "RESPONSE_LINE_COUNT_STOP")
    fields = {}
    for row in lines:
        need(row.count("=") == 1 and row.startswith("FLOP_R1016_"),
             "RESPONSE_FIELD_FORMAT_STOP")
        key, value = row.split("=", 1)
        need(key not in fields, "RESPONSE_DUPLICATE_STOP")
        fields[key] = value
    need(set(fields) == EXPECTED_KEYS | {key for key, _ in EXPECTED_FLAGS},
         "RESPONSE_FIELD_SET_STOP")
    for key in EXPECTED_KEYS:
        value = fields[key]
        need(re.fullmatch(r"(0|[1-9][0-9]{0,5})", value) is not None,
             "RESPONSE_NUMBER_STOP")
    for key, value in EXPECTED_FLAGS:
        need(fields[key] == value, "RESPONSE_SAFETY_FLAG_STOP")
    need(fields["FLOP_R1016_STATIC_SERVICE_COUNT"] == "19"
         and fields["FLOP_R1016_STATIC_TIMER_COUNT"] == "8",
         "RESPONSE_STATIC_SOURCE_COUNT_STOP")
    return fields


def run():
    preflight()
    original = checked_source()
    raw = bounded_invoke(original)
    fields = inspect_output(raw)
    # Print only bounded counts and hardcoded flags, never command text,
    # credentials, raw response, unknown service names, PIDs or arguments.
    for name in sorted(EXPECTED_KEYS):
        print(name + "=" + fields[name])
    for name, value in sorted(EXPECTED_FLAGS):
        print(name + "=" + value)
    print("FLOP_R1017_CLOUDSHELL_PINNED_ORIGINAL_READONLY=PASS")
    print("FLOP_R1017_NO_GUEST_STATE_OR_UNIT_MUTATION=YES")
    print("FLOP_R1017_NO_WRITER_EPOCH_PROVEN=YES")
    print("FLOP_R1017_OCI_RETIREMENT=STRICT_NO_GO")


if __name__ == "__main__":
    try:
        run()
    except Stop as error:
        # Only source-owned stable STOP codes, never raw remote output,
        # SSH stderr, credentials, sensitive paths, or exception repr.
        reason = str(error)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,110}", reason):
            reason = "UNCLASSIFIED_GUARD_FAILED"
        print(STOP_TAG + reason)
        sys.exit(42)
    except (OSError, ValueError, TypeError, UnicodeError):
        print(STOP_TAG + "LOCAL_RUNTIME_GUARD_FAILED")
        sys.exit(42)
