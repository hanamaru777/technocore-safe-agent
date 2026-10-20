#!/usr/bin/env python3
"""R1024: Cloud Shell -> pinned original OCI R1023 READ-ONLY witness.

ONE bounded pinned SSH command, no OCI state content, no unit stop/start,
no AWS traffic, no secret value in stdout. DRAFT, never a freeze/GO decision.
The downloaded original probe is pinned by immutable git commit AND blob SHA.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import urllib.request

COMMIT = "4f78fc8b4afb14604792e5b2f07f1fecdc131736"
BLOB_SHA = "b4109419c2664ed13182a45d4af994fb63aafb1d"
PROBE_URL = ("https://raw.githubusercontent.com/"
             "hanamaru777/technocore-safe-agent/" + COMMIT +
             "/packaging/oracle/r1023_unit_identity_readonly.py")
HOST = "140.238.55.171"  # Historic pinned ORIGINAL Oracle guest from R1003.
EXPECTED_ORIGINAL = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
KEY_DIR = ".flop-access-recovery-20261018"
SOURCE_MAX = 32768
OUT_MAX = 65536
TIMEOUT_SECONDS = 58
STOP_TAG = "FLOP_R1024_STOP="


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
    validate_source(raw)
    return raw


def validate_source(raw):
    need(type(raw) is bytes and 0 < len(raw) <= SOURCE_MAX, "PINNED_PROBE_LENGTH_STOP")
    sha = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    need(sha == BLOB_SHA, "PINNED_PROBE_BLOB_STOP")
    need(EXPECTED_ORIGINAL.encode() in raw, "PINNED_SOURCE_CONTEXT_STOP")


def ssh_args(source, key, hosts):
    validate_source(source)
    # Only vetted source bytes may enter the remote -c argv; no dynamic input.
    import base64
    encoded = base64.b64encode(source).decode("ascii")
    child = 'import base64;exec(compile(base64.b64decode("' + encoded + '"), "<r1023>", "exec"))'
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
                rb"FLOP_R1023_STOP=([A-Z0-9_]{3,56})\r?\n?",
                result.stdout,
            )
            if match:
                raise Stop("ORIGINAL_GUEST_" + match.group(1).decode("ascii"))
        raise Stop("PINNED_GUEST_COMMAND_EXIT_STOP")
    need(isinstance(result.stdout, bytes)
         and 100 < len(result.stdout) <= OUT_MAX,
         "REMOTE_RESPONSE_BOUNDS_STOP")
    return result.stdout


def inspect_output(raw, source):
    validate_source(source)
    need(type(raw) is bytes and 0 < len(raw) <= OUT_MAX, "RESPONSE_BOUND_STOP")
    # Execute only immutable, blob-verified definitions; never the guest entrypoint.
    namespace = {"__name__": "r1023_schema"}
    exec(compile(source, "<pinned-r1023-schema>", "exec"), namespace)
    try:
        text = raw.decode("ascii", "strict")
        report = json.loads(text)
        need(type(report) is dict and set(report) == {
            "schema_version", "original_head", "static_service_count", "static_timer_count",
            "missing_known", "units", "active_known", "active_signer_candidates", "flags",
        }, "RESPONSE_SCHEMA_STOP")
        need(type(report["schema_version"]) is int and report["schema_version"] == 1
             and report["original_head"] == EXPECTED_ORIGINAL
             and type(report["static_service_count"]) is int
             and report["static_service_count"] == 19
             and type(report["static_timer_count"]) is int
             and report["static_timer_count"] == 8
             and report["flags"] == namespace["FLAGS"], "RESPONSE_FLAGS_STOP")
        expected = namespace["EXPECTED"]
        units = report["units"]
        need(type(units) is list and len(units) <= namespace["MAX_ROWS"], "RESPONSE_UNITS_STOP")
        labels = []
        for row in units:
            need(type(row) is dict and set(row) == {
                "identity", "known", "installed_states", "active_states", "signer_candidate",
            }, "RESPONSE_UNIT_SCHEMA_STOP")
            label = row["identity"]
            need(type(label) is str and (
                label in expected or namespace["SAFE_UNKNOWN"].fullmatch(label)
                or re.fullmatch(r"redacted-sha256-[a-f0-9]{64}", label)),
                "RESPONSE_IDENTITY_STOP")
            need(type(row["known"]) is bool and row["known"] == (label in expected)
                 and type(row["signer_candidate"]) is bool
                 and row["signer_candidate"] == (label in namespace["SIGNERS"]),
                 "RESPONSE_CLASSIFICATION_STOP")
            for field, allowed in (("installed_states", namespace["FILE_STATES"]),
                                   ("active_states", namespace["ACTIVE_STATES"])):
                values = row[field]
                need(type(values) is list and len(values) <= len(allowed)
                     and all(type(item) is str and item in allowed for item in values)
                     and values == sorted(set(values)), "RESPONSE_STATE_STOP")
            need(row["installed_states"] or row["active_states"], "RESPONSE_EMPTY_UNIT_STOP")
            labels.append(label)
        need(labels == sorted(set(labels)), "RESPONSE_DUPLICATE_STOP")
        installed = {row["identity"] for row in units if row["known"] and row["installed_states"]}
        need(report["missing_known"] == sorted(expected - installed), "RESPONSE_MISSING_STOP")
        for field, signer in (("active_known", False), ("active_signer_candidates", True)):
            wanted = [row["identity"] for row in units
                      if row["known"] and (not signer or row["signer_candidate"])
                      and namespace["ACTIVE"].intersection(row["active_states"])]
            need(report[field] == wanted, "RESPONSE_ACTIVE_STOP")
        # Canonical representation also rejects duplicate JSON keys, injected whitespace/data.
        canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        need(raw == canonical.encode("ascii"), "RESPONSE_CANONICAL_STOP")
    except (UnicodeError, ValueError, TypeError, KeyError, RecursionError):
        raise Stop("RESPONSE_FORMAT_STOP") from None
    return report

def run():
    preflight()
    original = checked_source()
    raw = bounded_invoke(original)
    report = inspect_output(raw, original)
    # Re-encode only validated safe identity metadata, never raw SSH output.
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    print("FLOP_R1024_CLOUDSHELL_PINNED_ORIGINAL_READONLY=PASS")
    print("FLOP_R1024_NO_GUEST_STATE_OR_UNIT_MUTATION=YES")
    print("FLOP_R1024_NO_WRITER_EPOCH_PROVEN=YES")
    print("FLOP_R1024_OCI_RETIREMENT=STRICT_NO_GO")


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

