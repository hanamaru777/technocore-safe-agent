"""R1128 bounded PROVISIONAL live-state preseed producer (NO CLI / NO CUTOVER).

Provides a library-only, owner-gated source building block. No executable
operator entrypoint is exposed. It does not stop/modify source writers, grant
archive authority, move DID keys, query downstream finality or activate AWS.
Even a successfully authenticated encrypted stream is NONAUTHORITATIVE.
"""
from __future__ import annotations
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
APP = Path("/opt/technocore-safe-agent")
STATE = Path("/var/lib/technocore-safe-agent")
PROVISIONAL_EPOCH = "PROVISIONAL_LIVE_UNFENCED_NO_REPLAY"
# Explicit exact-file, non-recursive, source-owned subset. No keys, seeds, Vault
# credentials, SQLite, WAL, caches, unknown symlinks or broad user input.
SELECTED = (
    ("state/verified-did.json", 16 * 1024),
    ("state/nonces.json", 1024 * 1024),
    ("state/signer/oracle-signer-receipts.json", 8 * 1024 * 1024),
)
MAX_TOTAL = 16 * 1024 * 1024
MAX_RUNTIME = 120
MIN_AVAILABLE_KIB = 256 * 1024
MEM_FULL_LIMIT = 5.0
IO_FULL_LIMIT = 10.0


class Stop(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Stop(code)


def load(rel, name):
    path = (Path(__file__).parent / rel).resolve()
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None, "PINNED_DEPENDENCY_STOP")
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def _read_small(path, max_size=4096):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_size <= max_size,
             "PRESSURE_UNAVAILABLE")
        data = os.read(fd, max_size + 1)
        need(len(data) <= max_size, "PRESSURE_UNAVAILABLE")
        return data.decode("ascii", "strict")
    finally:
        os.close(fd)


def pressure():
    try:
        mem = _read_small("/proc/meminfo", 16384)
        match = re.search(r"^MemAvailable:\s+(\d+) kB$", mem, re.M)
        need(match and int(match.group(1)) >= MIN_AVAILABLE_KIB,
             "MEMORY_PRESSURE_STOP")
        for kind, threshold in (("memory", MEM_FULL_LIMIT), ("io", IO_FULL_LIMIT)):
            raw = _read_small("/proc/pressure/" + kind)
            row = next((x for x in raw.splitlines() if x.startswith("full ")), None)
            need(row is not None, "PRESSURE_UNAVAILABLE")
            result = re.search(r"(?:^|\s)avg10=([0-9]+(?:\.[0-9]+)?)\b", row)
            need(result is not None and float(result.group(1)) <= threshold,
                 "PRESSURE_STOP")
    except (OSError, UnicodeError, ValueError):
        raise Stop("PRESSURE_UNAVAILABLE") from None


def _file(root, tail):
    return root.joinpath(*tail.split("/"))


def _check_roots(app, state):
    roots = {"app": app, "state": state}
    for root in roots.values():
        need(root.is_absolute(), "SOURCE_SCOPE_STOP")
        for ancestor in (root, *root.parents):
            need(not ancestor.is_symlink(), "SOURCE_SCOPE_STOP")
        need(stat.S_ISDIR(root.lstat().st_mode), "SOURCE_SCOPE_STOP")
    need(app != state and app not in state.parents and state not in app.parents,
         "SOURCE_SCOPE_STOP")
    return roots


def _entry(path, name, T, *, max_size=0):
    s = path.lstat()
    row = {"path": name, "mode": stat.S_IMODE(s.st_mode),
           "uid": s.st_uid, "gid": s.st_gid, "mtime_ns": s.st_mtime_ns,
           "kind": "", "size": 0, "sha256": None, "target": None}
    if max_size == 0:
        need(stat.S_ISDIR(s.st_mode) and not path.is_symlink(),
             "SOURCE_OBJECT_STOP")
        row["kind"] = "directory"
    else:
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and
             not path.is_symlink() and 0 < s.st_size <= max_size,
             "SOURCE_OBJECT_STOP")
        sha = hashlib.sha256()
        for block in T.read_blocks(path, T.fingerprint(s)):
            sha.update(block)
        row.update(kind="file", size=s.st_size, sha256=sha.hexdigest())
    return row, T.fingerprint(s)


def selected_manifest(roots, T):
    need(set(roots) == {"app", "state"}, "SOURCE_SCOPE_STOP")
    # Directory rows match the existing canonical R1066 manifest grammar.
    rows, fingerprints = [], {}
    for name, root in (("app", roots["app"]), ("state", roots["state"]),
                       ("state/signer", roots["state"] / "signer")):
        item, mark = _entry(root, name, T)
        rows.append(item)
        fingerprints[name] = mark
    total = 0
    for name, cap in SELECTED:
        path = _file(roots["state"], name.removeprefix("state/"))
        # No interior path segment may be a symlink.
        for parent in path.parents:
            if parent == roots["state"].parent:
                break
            need(not parent.is_symlink(), "SOURCE_OBJECT_STOP")
        item, mark = _entry(path, name, T, max_size=cap)
        rows.append(item)
        fingerprints[name] = mark
        total += item["size"]
        need(total <= MAX_TOTAL, "READ_LIMIT_STOP")
    manifest = {"version": 1, "source_head": HEAD,
                "epoch": PROVISIONAL_EPOCH, "entries": rows}
    need(len(T.G.canonical(manifest)) <= T.MAX_MANIFEST, "MANIFEST_BOUND_STOP")
    return roots, manifest, fingerprints


def _original_host(scope):
    need(sys.platform == "linux" and os.geteuid() == 0,
         "ORIGINAL_HOST_STOP")
    need(type(scope) is dict and set(scope) ==
         {"expected_machine_sha256", "destination_machine_sha256",
          "independent_trust", "signed_owner_approval"},
         "OWNER_AUTH_REQUIRED")
    for key in ("expected_machine_sha256", "destination_machine_sha256"):
        need(type(scope[key]) is str and
             re.fullmatch(r"[0-9a-f]{64}", scope[key]),
             "OWNER_AUTH_REQUIRED")
    need(scope["expected_machine_sha256"] != scope["destination_machine_sha256"],
         "OWNER_AUTH_REQUIRED")
    G = load("r1063_release_gates.py", "r1128_signed_release")
    trust = scope["independent_trust"]
    need(isinstance(trust, G.Trust), "OWNER_AUTH_REQUIRED")
    G.context_valid(trust.context)
    need(trust.context["host"] == scope["expected_machine_sha256"] and
         trust.context["destination"] == scope["destination_machine_sha256"] and
         trust.context["source_head"] == HEAD, "OWNER_AUTH_REQUIRED")
    # This is an independently signed owner authorization for source DATA
    # export to a specifically identified offhost destination. The trust keys
    # cannot originate from the source data, approval packet or an SSH response.
    binding = G.sha({
        "purpose": "provisional_preseed_ciphertext_only",
        "source": scope["expected_machine_sha256"],
        "destination": scope["destination_machine_sha256"],
        "source_head": HEAD,
        "files": [name for name, _ in SELECTED],
        "max_plaintext_bytes": MAX_TOTAL,
        "non_authoritative": True,
    })
    G.authorization(scope["signed_owner_approval"],
                    "provisional_preseed_offhost", binding, trust,
                    int(time.time()))
    got = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
    need(got == scope["expected_machine_sha256"], "ORIGINAL_HOST_STOP")
    p = subprocess.run(
        ["/usr/bin/git", "-c", "safe.directory=" + str(APP), "-C", str(APP),
         "rev-parse", "--verify", "HEAD"], capture_output=True,
        stdin=subprocess.DEVNULL, timeout=5, check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": "/nonexistent",
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
             "GIT_OPTIONAL_LOCKS": "0"})
    need(p.returncode == 0 and p.stdout == (HEAD + "\n").encode(),
         "SOURCE_HEAD_STOP")

def preseed_live_to_stream(scope, recovery, output):
    """Never publish a live evidence GO; ciphertext-only output, no disk writes.

    This is an internal library entrypoint, deliberately NOT an operator CLI.
    Until a separately audited authenticated SSH wrapper + offhost NTFS sink +
    real owner approval exist, it is NOT runnable end-to-end in production.
    """
    _original_host(scope)
    need(type(recovery) is bytes and 32 <= len(recovery) <= 1024,
         "RECOVERY_STOP")
    need(not hasattr(output, "isatty") or not output.isatty(),
         "OUTPUT_TTY_STOP")
    start = time.monotonic()
    T = load("r1066_transfer.py", "r1128_transfer")
    W = load("r1084_offhost_ciphertext_stream.py", "r1128_stream")
    roots = _check_roots(APP, STATE)

    def guard():
        need(time.monotonic() - start <= MAX_RUNTIME, "TIME_BUDGET_STOP")
        pressure()

    def census():
        guard()
        _, manifest, ids = selected_manifest(roots, T)
        guard()
        return roots, manifest, ids

    roots, manifest, ids = census()

    class GuardedOutput:
        def isatty(self):
            return False
        def write(self, data):
            guard()
            return output.write(data)

    # Reuse the R1084 R1001-compatible AEAD/framed ciphertext. T.pack
    # double-checks exact source bytes and metadata, and incomplete archives
    # never carry an authenticated final commit.
    W.seal_manifest_to_stream(roots, manifest, ids, recovery, GuardedOutput(),
                              recensus=census)
    guard()
    return {"phase": "R1128", "mode": PROVISIONAL_EPOCH,
            "ciphertext_only": True, "source_complete": False,
            "common_sqlite_epoch": "NOT_PROVEN",
            "history_finality": "UNKNOWN",
            "signer_portability": "NOT_PROVEN",
            "cutover": "NO_GO", "oci_retirement": "STRICT_NO_GO"}
