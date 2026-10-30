"""R1089 owner coordinator and fixed source/restore peer. No cutover authority.

Public code may be staged in a peer's private temporary directory. Recovery
material travels only in process memory and the already pinned SSH channel.
The source requires an EXISTING independently approved, continuously renewed
admission fence; this program never silently stops services to manufacture one.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time


def load(leaf):
    spec = importlib.util.spec_from_file_location("r1089_" + leaf[:-3], Path(__file__).with_name(leaf))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


W = load("r1084_offhost_ciphertext_stream.py")
T, G, C = W.T, W.T.G, W.T.C
D = load("r1086_k137_disarmed_stream_restore.py")
SSH = load("r1066_ciphertext_ssh_relay.py")
SOURCE_ROOTS = {"app": Path("/opt/technocore-safe-agent"), "state": Path("/var/lib/technocore-safe-agent")}
ADMISSION = Path("/run/flop-migration-r1089/admission.json")
MAGIC = b"FLOPR189"
META = b"FLOPAD89"
LIMIT = 4 * 1024**2
GIB = 1024**3
BUNDLE_FILES = (
    "migration/r1089_migration.py", "migration/r1066_transfer.py",
    "migration/r1066_sealed_dependency.py", "migration/r1063_release_gates.py",
    "migration/r1084_offhost_ciphertext_stream.py", "migration/r1086_k137_disarmed_stream_restore.py",
    "migration/r1066_ciphertext_ssh_relay.py", "archive/r1052_offline_writer_route_contract.py",
    "archive/r1050_offhost_sixfile_audit.py", "archive/verify-capture-backup-images.py",
)
SAFE_CODES = frozenset({"OWNER_APPROVAL_REQUIRED", "SOURCE_ADMISSION_REQUIRED", "SOURCE_FENCE_LOST",
    "POST_FINALITY_REQUIRED", "CAPACITY_STOP", "DID_MISMATCH", "SOURCE_SCOPE_STOP", "ARCHIVE_INCOMPLETE",
    "ARCHIVE_AUTHENTICATION_STOP", "RESTORE_STOP", "SOURCE_TRANSFER_STOP", "CUSTODY_STOP", "PLAN_STOP",
    "MIGRATION_GUARD_STOP", "REMOTE_RUNTIME_REQUIRED"})


class Stop(ValueError):
    pass


def need(value, code="PLAN_STOP"):
    if not value:
        raise Stop(code)


def exact(stream, size):
    need(type(size) is int and 0 <= size <= LIMIT)
    out = bytearray()
    while len(out) < size:
        part = stream.read(size - len(out))
        need(type(part) is bytes and part, "ARCHIVE_INCOMPLETE")
        out.extend(part)
    return bytes(out)


def decode(raw):
    need(type(raw) is bytes and len(raw) <= LIMIT)
    return json.loads(raw, object_pairs_hook=G._pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Stop("PLAN_STOP")))


def frame_write(stream, marker, value):
    raw = G.canonical(value)
    need(len(raw) <= LIMIT)
    W._write_all(stream, marker + struct.pack(">I", len(raw)) + raw)
    stream.flush()


def frame_read(stream, marker):
    seen = exact(stream, len(marker))
    if seen == b"FLOPERR9":
        error = decode(exact(stream, struct.unpack(">I", exact(stream, 4))[0]))
        G.shape(error,"code")
        raise Stop(error["code"] if error["code"] in SAFE_CODES else "MIGRATION_GUARD_STOP")
    need(seen == marker)
    return decode(exact(stream, struct.unpack(">I", exact(stream, 4))[0]))


def trust_from(value):
    G.shape(value, "context keys source_key_ids")
    G.context_valid(value["context"])
    need(type(value["keys"]) is list and 1 <= len(value["keys"]) <= 16)
    keys = {}
    for row in value["keys"]:
        G.shape(row, "public_hex roles")
        need(type(row["public_hex"]) is str and G.HEX.fullmatch(row["public_hex"]))
        raw = bytes.fromhex(row["public_hex"])
        kid = hashlib.sha256(raw).hexdigest()
        need(kid not in keys and type(row["roles"]) is list and row["roles"] and
             set(row["roles"]) <= set(G.ROLES.values()) | {"owner", "upstream", "source"})
        keys[kid] = (raw, frozenset(row["roles"]))
    need(type(value["source_key_ids"]) is list)
    for kid in value["source_key_ids"]:
        G.digest(kid)
    return G.Trust(value["context"], keys, frozenset(value["source_key_ids"]))


def authorizations(plan, now):
    """R1063 authenticates real evidence; no synthetic production fallback."""
    G.shape(plan, "schema_version run_id offhost_parent quota_bytes expected_did trust packets approval")
    need(type(plan["schema_version"]) is int and plan["schema_version"] == 1 and re.fullmatch(r"[0-9a-f]{32}", plan["run_id"]))
    need(type(plan["offhost_parent"]) is str and len(plan["offhost_parent"]) <= 1024)
    G.integer(plan["quota_bytes"], GIB, W.MAX_STREAM_BYTES)
    need(type(plan["expected_did"]) is str and re.fullmatch(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}", plan["expected_did"]))
    trust = trust_from(plan["trust"])
    need(hashlib.sha256(plan["expected_did"].encode("ascii")).hexdigest() == trust.context["did"], "DID_MISMATCH")
    session = {"approval": plan["approval"], "binding": G.sha({k: v for k, v in plan.items() if k != "approval"})}
    owner = G.verify(plan["approval"], "owner", trust)
    G.shape(owner, "action context binding approved_at expires_at")
    need(owner["action"] == "preserve_restore" and owner["context"] == trust.context and
         owner["binding"] == session["binding"] and type(owner["approved_at"]) is int and
         type(owner["expires_at"]) is int and owner["approved_at"] <= now < owner["expires_at"]
         <= owner["approved_at"] + 14400, "OWNER_APPROVAL_REQUIRED")
    need(type(plan["packets"]) is list and len(plan["packets"]) <= 9)
    packets, evidence = {}, {}
    for p in plan["packets"]:
        name = p["body"]["gate"]
        need(name in G.GATES and name not in packets)
        packets[name] = p
    # Preservation is distinct from activation: no claim that G3/G6/G7/G8 pass.
    # Preserve every existing individual R1063 contract for the admission subset.
    for gate in ("G0", "G1", "G2", "G4", "G5"):
        need(gate in packets, "POST_FINALITY_REQUIRED" if gate == "G5" else "SOURCE_ADMISSION_REQUIRED")
        # Owner binds the fresh starting evidence. During a long transfer the
        # source independently renews G4 every <=30s, rechecks kernel admission
        # and exact ledger digest. Destination measures free space again now.
        # Old initial packets never become a fresh release assessment.
        at_start = owner["approved_at"]
        e = G.authenticate(packets[gate], gate, trust, at_start)
        checked = G.check_gate(gate, e, evidence, packets, trust, at_start,
                               preservation_session=session if gate == "G4" else None)
        if gate == "G5":
            need(all(r["status"] == "PASS" for r in checked), "POST_FINALITY_REQUIRED")
        evidence[gate] = e
    need(plan["quota_bytes"] >= evidence["G2"]["encrypted_peak_bytes"], "CAPACITY_STOP")
    return trust, evidence


def state_ledger_digest(manifest):
    """Bind ALL non-SQLite state objects, not merely four selected ledgers.

    Includes five-route receipts/pending records, activities, nonce and verified
    DID state. Paths never leave the encrypted manifest; only this digest does.
    """
    def sqlite_file(name):
        return any(name == n + suffix for n in G.DATABASES for suffix in ("", "-wal", "-shm"))
    return G.sha([r for r in manifest["entries"] if r["path"].startswith("state/")
                  and not sqlite_file(r["path"].rsplit("/", 1)[-1])])


def _source_mount_namespace():
    """Fail closed when a private RO bind view could mask writable host paths.

    Linux RO is a per-mount flag. A read-only bind in a private namespace
    does not stop the original writer in PID1's mount namespace. This is only
    a necessary guard; signed G4 all-launcher admission is still mandatory.
    """
    try:
        current = os.stat("/proc/self/ns/mnt")
        original = os.stat("/proc/1/ns/mnt")
    except OSError:
        raise Stop("SOURCE_FENCE_LOST") from None
    identity = current.st_dev, current.st_ino
    need(identity == (original.st_dev, original.st_ino), "SOURCE_FENCE_LOST")
    return identity


class SourceGuard:
    """Checks an externally held fence. No claim that systemctl stop is a fence.

    Admission holder must maintain read-only original mounts and authenticated
    G4 renewal through the entire stream. Root/admin remains a trusted operator.
    A missing/unreadable/raced process or an old writable file/directory handle
    blocks export. The program itself has read-only handles to original data.
    """
    def __init__(self, plan, roots=SOURCE_ROOTS, admission=ADMISSION):
        self.plan, self.roots, self.admission = plan, roots, admission
        self.last_scan = 0.0
        self.trust, self.evidence = authorizations(plan, int(time.time()))
        self.barrier = self.evidence["G4"]["barrier_digest"]
        need(sys.platform == "linux" and os.geteuid() == 0, "SOURCE_SCOPE_STOP")
        need(self.roots == SOURCE_ROOTS, "SOURCE_SCOPE_STOP")
        actual_machine = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
        need(actual_machine == self.trust.context["host"], "SOURCE_SCOPE_STOP")
        head = subprocess.run(["/usr/bin/git", "-c", "safe.directory=" + str(SOURCE_ROOTS["app"]),
                               "-C", str(SOURCE_ROOTS["app"]), "rev-parse", "--verify", "HEAD"],
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
                              env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_OPTIONAL_LOCKS": "0",
                                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"})
        need(head.returncode == 0 and head.stdout == (T.HEAD + "\n").encode(), "SOURCE_SCOPE_STOP")

    def check(self, full=False):
        now = int(time.time())
        # Renewal is root-owned and separately signed. It cannot invent the
        # expected barrier, generation, keys, coverage or owner authorization.
        p = self.admission
        try:
            s, d = p.lstat(), p.parent.lstat()
        except OSError:
            raise Stop("SOURCE_ADMISSION_REQUIRED") from None
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
             stat.S_IMODE(s.st_mode) == 0o600 and not p.is_symlink() and
             stat.S_ISDIR(d.st_mode) and d.st_uid == 0 and
             stat.S_IMODE(d.st_mode) == 0o700 and not p.parent.is_symlink(), "SOURCE_ADMISSION_REQUIRED")
        need(0 < s.st_size <= G.MAX_PACKET_BYTES, "SOURCE_ADMISSION_REQUIRED")
        packet = decode(p.read_bytes())
        e = G.authenticate(packet, "G4", self.trust, now)
        G.check_gate("G4", e, {}, {"G4": packet}, self.trust, now,
                     preservation_session={"approval":self.plan["approval"],
                         "binding":G.sha({k:v for k,v in self.plan.items() if k!="approval"})})
        need(e["barrier_digest"] == self.barrier and e["fence_start"] == self.evidence["G4"]["fence_start"], "SOURCE_FENCE_LOST")
        # A private read-only bind mount proves only this process's view.
        # Require the original init namespace, and re-check after proc census.
        mount_identity = _source_mount_namespace()
        for root in self.roots.values():
            need(not root.is_symlink() and root.is_dir() and
                 os.statvfs(root).f_flag & os.ST_RDONLY, "SOURCE_FENCE_LOST")
        if full or time.monotonic() - self.last_scan >= 5:
            self.scan_descriptors()
            self.last_scan = time.monotonic()
        need(_source_mount_namespace() == mount_identity, "SOURCE_FENCE_LOST")

    def scan_descriptors(self):
        pids = [p for p in Path("/proc").iterdir() if p.name.isdigit()]
        need(len(pids) <= 4096, "SOURCE_FENCE_LOST")
        count = 0
        for proc in pids:
            # Do not turn permission/race/oversize into evidence of absence.
            for fd in (proc / "fd").iterdir():
                count += 1
                need(count <= 65536, "SOURCE_FENCE_LOST")
                target = os.readlink(fd)
                relevant = any(target == str(r) or target.startswith(str(r) + "/") for r in self.roots.values())
                if not relevant:
                    continue
                with (proc / "fdinfo" / fd.name).open("rb") as f:
                    info = f.read(4097)
                need(len(info) <= 4096, "SOURCE_FENCE_LOST")
                flags = re.findall(rb"^flags:\s+([0-7]+)$", info, re.M)
                need(len(flags) == 1, "SOURCE_FENCE_LOST")
                need(not stat.S_ISDIR(fd.stat().st_mode) and
                     int(flags[0], 8) & os.O_ACCMODE == os.O_RDONLY, "SOURCE_FENCE_LOST")

    def census(self):
        self.check(full=True)
        roots, manifest, identities = T._census_roots(
            self.roots, T.HEAD, epoch="FROZEN:" + self.barrier)
        # External hardlink aliases could bypass a per-path read-only mount.
        links = {}
        for row in manifest["entries"]:
            if row["kind"] in ("file", "hardlink"):
                p = T.resolve_source(roots, row["path"])
                s = p.lstat()
                key = s.st_dev, s.st_ino
                links[key] = (links.get(key, (0, s.st_nlink))[0] + 1, s.st_nlink)
        need(all(a == b for a, b in links.values()), "SOURCE_FENCE_LOST")
        self.check(full=True)
        return roots, manifest, identities


def source_export(plan, recovery, output):
    guard = SourceGuard(plan)
    roots, manifest, identities = guard.census()
    need(state_ledger_digest(manifest) == guard.evidence["G5"]["inventory_digest"], "POST_FINALITY_REQUIRED")
    need(any(r["path"] == "state/verified-did.json" and r["kind"] == "file" and
             0 < r["size"] <= 16384 for r in manifest["entries"]), "DID_MISMATCH")
    verified = decode((roots["state"] / "verified-did.json").read_bytes())
    need(verified.get("did") == plan["expected_did"], "DID_MISMATCH")
    source_bytes = sum(r["size"] for r in manifest["entries"])
    need(source_bytes == guard.evidence["G2"]["source_bytes"], "CAPACITY_STOP")
    cursors = []
    for row in manifest["entries"]:
        if row["kind"] == "file" and row["path"].rsplit("/", 1)[-1] in G.DATABASES:
            db = T.resolve_source(roots, row["path"])
            with contextlib.closing(sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)) as c:
                c.execute("PRAGMA trusted_schema=OFF")
                need(c.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "SOURCE_SCOPE_STOP")
                cursors.append(list(c.execute("SELECT count(*),coalesce(max(seq),0) FROM messages").fetchone()))
    need(len(cursors) == 2, "SOURCE_SCOPE_STOP")
    meta = {"schema_version": 1, "epoch": manifest["epoch"], "manifest_sha256": G.sha(manifest),
            "files": len(manifest["entries"]), "bytes": source_bytes,
            "symlinks": sum(r["kind"] == "symlink" for r in manifest["entries"]),
            "sqlite_cursors": cursors, "ledger_sha256": state_ledger_digest(manifest)}
    frame_write(output, META, meta)

    class CheckedOutput:
        def isatty(self):
            return False

        def write(self, data):
            guard.check()
            return output.write(data)

    W.seal_manifest_to_stream(roots, manifest, identities, recovery, CheckedOutput(), recensus=guard.census)
    output.flush()


class LockedArchive:
    """Two-pass R1001 reader. Windows locks deny write/delete sharing.

    R1088 owns NTFS ACL validation; never substitute POSIX chmod for that check.
    Handles remain held from BEFORE validation through the last plaintext byte.
    """
    def __init__(self, archive, *, windows_validator=None):
        self.root, self.files, self.pin, self.path_pin = Path(archive), {}, {}, {}
        self.verified = False
        try:
            names = sorted(p.name for p in self.root.iterdir())
            need(3 <= len(names) <= C.MAX_PARTS + 2, "CUSTODY_STOP")
            expected = {"header.bin", "commit.bin"} | {f"part-{i:04d}.bin" for i in range(len(names) - 2)}
            need(set(names) == expected, "ARCHIVE_INCOMPLETE")
            if os.name != "nt":
                T.private_dir(self.root)
            for name in names:
                path = self.root / name
                s = path.lstat()
                need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and
                     0 < s.st_size <= C.SHARD_LIMIT + 4096, "CUSTODY_STOP")
                if os.name == "nt":
                    f = self.windows_open(path)
                else:
                    need(s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o600, "CUSTODY_STOP")
                    f = os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb")
                self.files[name] = f
                self.pin[name] = T.fingerprint(os.fstat(f.fileno()))
                self.path_pin[name] = T.fingerprint(path.lstat())
                # Windows CRT fstat and Python lstat expose different ctime
                # semantics. Require the SAME file identity/size/mtime/mode,
                # then pin and recheck each representation independently.
                indexes = (0, 1, 2, 3, 5) if os.name == "nt" else range(6)
                need(all(self.pin[name][i] == self.path_pin[name][i] for i in indexes), "CUSTODY_STOP")
            if os.name == "nt":
                need(callable(windows_validator), "CUSTODY_STOP")
                windows_validator(self.root)
            self.check()
        except Exception:
            self.close()
            raise

    @staticmethod
    def windows_open(path):
        import ctypes
        from ctypes import wintypes
        import msvcrt
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        # GENERIC_READ, FILE_SHARE_READ only, OPEN_EXISTING, OPEN_REPARSE_POINT.
        handle = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
        need(handle not in (None, ctypes.c_void_p(-1).value), "CUSTODY_STOP")
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except Exception:
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel.CloseHandle(handle)
            raise
        return os.fdopen(fd, "rb")

    def check(self):
        need(set(p.name for p in self.root.iterdir()) == set(self.files), "CUSTODY_STOP")
        for name, f in self.files.items():
            need(T.fingerprint(os.fstat(f.fileno())) == self.pin[name] and
                 T.fingerprint((self.root / name).lstat()) == self.path_pin[name], "CUSTODY_STOP")

    @contextlib.contextmanager
    def opened(self, name, limit):
        need(name in self.files and self.pin[name][2] <= limit, "CUSTODY_STOP")
        f = self.files[name]
        f.seek(0)
        yield f

    def blocks(self, recovery):
        yield from T._decrypt_regular(self.root, recovery, self.opened)

    def verify(self, recovery):
        self.check()
        reader = T.Reader(self.blocks(recovery))
        length = int.from_bytes(reader.read(8), "big")
        need(0 < length <= T.MAX_MANIFEST, "ARCHIVE_AUTHENTICATION_STOP")
        manifest = decode_manifest(reader.read(length))
        G.shape(manifest,"version source_head epoch entries")
        rows, total, _ = D.validate_manifest(manifest, preserve_inert_links=True)
        need(manifest["version"] == 1 and manifest["source_head"] == T.HEAD and
             re.fullmatch(r"FROZEN:[0-9a-f]{64}", manifest["epoch"]), "ARCHIVE_AUTHENTICATION_STOP")
        for row in rows.values():
            if row["kind"] == "file":
                sha, left = hashlib.sha256(), row["size"]
                while left:
                    data = reader.read(min(T.CHUNK, left))
                    sha.update(data)
                    left -= len(data)
                need(sha.hexdigest() == row["sha256"], "ARCHIVE_AUTHENTICATION_STOP")
        reader.finish()  # consumes every part and authenticates entire FINAL
        self.check()
        self.verified = True
        return manifest, {"manifest_sha256": G.sha(manifest), "epoch": manifest["epoch"],
                          "files": len(rows), "bytes": total,
                          "symlinks": sum(r["kind"] == "symlink" for r in rows.values()),
                          "ledger_sha256": state_ledger_digest(manifest)}

    def stream(self, recovery, output):
        # Call only after verify() and before releasing any held file handles.
        need(self.verified, "ARCHIVE_AUTHENTICATION_STOP")
        self.check()
        sha, total = hashlib.sha256(), 0
        for data in self.blocks(recovery):
            W._write_all(output, data)
            sha.update(data)
            total += len(data)
        output.flush()
        self.check()
        return sha.hexdigest(), total

    def close(self):
        for f in self.files.values():
            f.close()
        self.files.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def decode_manifest(raw):
    need(len(raw) <= T.MAX_MANIFEST)
    return json.loads(raw, object_pairs_hook=G._pairs)


def minimal_env():
    if os.name == "nt":
        import ctypes
        buffer = ctypes.create_unicode_buffer(32768)
        # Ask Windows for the actual local profile, not inherited TEMP or a
        # shell expansion. Add-Type needs a writable compiler scratch path.
        need(ctypes.windll.shell32.SHGetFolderPathW(None, 0x1C, None, 0, buffer) == 0, "CUSTODY_STOP")
        temporary = Path(buffer.value) / "Temp"
        need(temporary.is_dir() and not temporary.is_symlink() and
             not temporary.lstat().st_file_attributes & 0x400, "CUSTODY_STOP")
        result = {k: os.environ[k] for k in ("SystemRoot", "ProgramData") if k in os.environ}
        result.update(TEMP=str(temporary), TMP=str(temporary))
        return result
    return {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C"}


def bounded_result(process, limit=65536):
    raw = bytearray()
    while len(raw) <= limit:
        part = process.stdout.read(min(4096, limit + 1 - len(raw)))
        if not part:
            break
        raw.extend(part)
    need(len(raw) <= limit and process.wait(timeout=15) == 0, "RESTORE_STOP")
    return decode(bytes(raw))


@contextlib.contextmanager
def child(argv, *, stdin=subprocess.PIPE, timeout=14400):
    p = subprocess.Popen(argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         env=minimal_env(), close_fds=True, bufsize=0)
    timer = threading.Timer(timeout, p.kill)
    timer.daemon = True
    timer.start()
    try:
        yield p
    finally:
        timer.cancel()
        if p.poll() is None:
            p.kill()
        p.wait()
        for f in (p.stdin, p.stdout):
            if f is not None:
                f.close()


def windows_custody(root):
    ps = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    with child([str(ps), "-NoProfile", "-NonInteractive", "-File",
                str(Path(__file__).with_name("r1088_windows_ciphertext_custody.ps1")),
                "-ArchiveRoot", str(root)], stdin=subprocess.DEVNULL, timeout=60) as p:
        r = bounded_result(p)
        need(r == {"operation": "NTFS_PRIVATE_CIPHERTEXT_ARCHIVE", "aead_verified": False,
                   "source_epoch": "NOT_PROVEN", "cutover": "NO_GO"}, "CUSTODY_STOP")


def bundle():
    root = Path(__file__).parents[1]
    result = {}
    for name in BUNDLE_FILES:
        raw = (root / name).read_bytes().replace(b"\r\n", b"\n")
        need(len(raw) <= 128 * 1024)
        result[name] = raw.decode("utf8")
    need(len(G.canonical(result)) <= LIMIT)
    return result


def bootstrap(expected_bundle_sha256):
    G.digest(expected_bundle_sha256)
    # Fixed program, stdin framing. No command, path or Python expression from
    # enrollment becomes remote shell code. The only interpolation is hex SHA.
    return '''import sys,struct,json,hashlib,tempfile,pathlib,os,importlib.util
def read(n):
 b=bytearray()
 while len(b)<n:
  x=sys.stdin.buffer.read(n-len(b))
  if not x: raise ValueError()
  b.extend(x)
 return bytes(b)
try:
 if read(8)!=b'FLOPR189': raise ValueError()
 n=struct.unpack('>I',read(4))[0]
 if not 0<n<=4194304: raise ValueError()
 control=json.loads(read(n))
 sources=control['sources']
 encoded=json.dumps(sources,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
 if hashlib.sha256(encoded).hexdigest()!=''' + repr(expected_bundle_sha256) + ''': raise ValueError()
 request=control['request']
 if hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes().strip()).hexdigest()!=request['machine_sha256']: raise ValueError()
 if os.geteuid()!=request['uid']: raise ValueError()
 with tempfile.TemporaryDirectory(prefix='flop-r1089-public-code-') as directory:
  root=pathlib.Path(directory)
  for name,text in sources.items():
   parts=name.split('/')
   if len(parts)!=2 or parts[0] not in ('migration','archive') or any(x in ('','.','..') for x in parts): raise ValueError()
   p=root/name;p.parent.mkdir(exist_ok=True);p.write_text(text,encoding='utf8')
  spec=importlib.util.spec_from_file_location('r1089_peer',root/'migration/r1089_migration.py')
  m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  m.peer(request,sys.stdin.buffer,sys.stdout.buffer)
except Exception as error:
 module=locals().get('m')
 code=str(error) if module and type(error) is module.Stop and str(error) in module.SAFE_CODES else ('REMOTE_RUNTIME_REQUIRED' if type(error) is ModuleNotFoundError else 'MIGRATION_GUARD_STOP')
 raw=json.dumps({'code':code},separators=(',',':')).encode('ascii')
 sys.stdout.buffer.write(b'FLOPERR9'+struct.pack('>I',len(raw))+raw);sys.stdout.buffer.flush()
 sys.exit(42)
'''


def remote_argv(base, operation, sources):
    need(operation in ("source", "capacity", "restore"))
    code = bootstrap(G.sha(sources))
    import shlex
    if operation == "source":
        command = ["sudo", "-n", "/opt/technocore-safe-agent/.venv/bin/python", "-I", "-B", "-c", code]
    else:
        command = ["sudo", "-n", "/usr/bin/systemd-run", "--quiet", "--pipe", "--wait", "--collect",
                   "--unit=flop-r1089-disarmed-migration.service", "--property=User=ubuntu", "--property=Group=ubuntu",
                   "--property=MemoryMax=256M", "--property=TasksMax=64", "--property=CPUQuota=50%",
                   "--property=NoNewPrivileges=yes", "--property=ProtectSystem=strict", "--property=ProtectHome=yes",
                   "--property=PrivateTmp=yes", "--property=PrivateDevices=yes", "--property=CapabilityBoundingSet=",
                   "--property=ReadWritePaths=/var/lib/flop-migration-r1066",
                   "/usr/bin/python3", "-I", "-B", "-c", code]
    return [*base, " ".join(shlex.quote(x) for x in command)]


def peer(request, incoming, outgoing):
    mode = request["operation"]
    need(mode in ("source", "capacity", "restore"))
    if mode == "source":
        recovery = bytearray(exact(incoming, struct.unpack(">I", exact(incoming, 4))[0]))
        try:
            need(32 <= len(recovery) <= 1024)
            source_export(request["plan"], bytes(recovery), outgoing)
        finally:
            recovery[:] = b"\0" * len(recovery)
        return
    need(os.geteuid() > 0 and hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest() == request["machine_sha256"])
    parent = D.ROOT.parent
    s = parent.lstat()
    need(not parent.is_symlink() and stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid()
         and stat.S_IMODE(s.st_mode) == 0o700, "CUSTODY_STOP")
    # Sandbox must actually deny writes to every known protected directory.
    for path in T.BLOCKED_ROOTS[2:]:
        need(not os.access(path, os.W_OK), "RESTORE_STOP")
    free = shutil.disk_usage(parent).free
    required = request["source_bytes"] + D.SQLITE_ALLOWANCE + D.RESERVE
    if mode == "capacity":
        resumable = resume_present(request["resume"])
        # A valid partial target may already contain most of the source bytes.
        # Do not require space for a SECOND complete copy. The restorer checks
        # exact remaining bytes against the authenticated manifest before write.
        minimum = D.SQLITE_ALLOWANCE + D.RESERVE if resumable else required
        need(free >= minimum, "CAPACITY_STOP")
        frame_write(outgoing, META, {"status": "CAPACITY_PRECHECK_ONLY" if resumable else "CAPACITY_VERIFIED_NOW",
                                    "free_bytes": free, "required_bytes": minimum, "runtime_started": False})
        return
    plan = request["plan"]
    trust, evidence = authorizations(plan, int(time.time()))
    need(trust.context["destination"] == request["machine_sha256"] and request["meta"]["bytes"] == evidence["G2"]["source_bytes"], "RESTORE_STOP")
    if not D.ROOT.exists():
        D.ROOT.mkdir(mode=0o700)
    r = D.restore_stream(incoming, plan["run_id"], request["machine_sha256"], request["uid"],
                         quota_bytes=request["source_bytes"], expected_epoch=request["meta"]["epoch"],
                         expected_manifest_sha256=request["meta"]["manifest_sha256"],
                         expected_cursors=request["meta"]["sqlite_cursors"],
                         preserve_inert_links=True, resume=True)
    need([list(v) for v in r["sqlite_cursors"]] == request["meta"]["sqlite_cursors"] and
         r["symlinks"] == request["meta"]["symlinks"] and r["files"] == request["meta"]["files"], "RESTORE_STOP")
    frame_write(outgoing, META, r)


def resume_present(value):
    G.shape(value,"id manifest_sha256")
    need(type(value["id"]) is str and re.fullmatch(r"[0-9a-f]{32}",value["id"]),"RESTORE_STOP")
    G.digest(value["manifest_sha256"])
    target=D.ROOT/value["id"]
    if not target.exists():
        need(not target.is_symlink(),"RESTORE_STOP")
        return False
    D.private_parent(D.ROOT)
    s=target.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and
         stat.S_IMODE(s.st_mode)==0o700 and not target.is_symlink(),"RESTORE_STOP")
    receipt=target/"DISARMED-STREAM-RECEIPT.json"
    proof=receipt if receipt.exists() else target/"DISARMED-STREAM-INCOMPLETE.json"
    s=proof.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and
         stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=8192 and not proof.is_symlink(),"RESTORE_STOP")
    need(decode(proof.read_bytes()).get("manifest_sha256")==value["manifest_sha256"],"RESTORE_STOP")
    return True


def send_request(p, sources, request, recovery=None):
    frame_write(p.stdin, MAGIC, {"sources": sources, "request": request})
    if recovery is not None:
        need(32 <= len(recovery) <= 1024)
        W._write_all(p.stdin, struct.pack(">I", len(recovery)) + recovery)
        p.stdin.flush()
    if request["operation"] != "restore":
        p.stdin.close()
        p.stdin = None


def checkpoint(parent, name, value):
    path = parent / name
    temporary = parent / (name + ".pending")
    need(not path.is_symlink() and not temporary.exists(), "CUSTODY_STOP")
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(G.canonical(value)); f.flush(); os.fsync(f.fileno())
    os.replace(temporary, path)


def owner(control, recovery):
    """One invocation: authenticated source -> R1085 -> AEAD -> pinned R1086.

    Existing ciphertext survives every failure. A completed archive is reused;
    an interrupted encryption is never continued with a reused nonce domain.
    An incomplete inert destination resumes only after byte-prefix comparison.
    """
    G.shape(control, "plan endpoints ssh oci_key oci_hosts k137_hosts")
    plan = control["plan"]
    trust, evidence = authorizations(plan, int(time.time()))
    need(os.name == "nt", "CUSTODY_STOP")
    parent = Path(plan["offhost_parent"])
    archive = parent / plan["run_id"]
    # Enrollment/NTFS parent checks happen in the pinned PS wrapper, again in
    # R1085 before it creates anything, and on every ciphertext file in R1088.
    sources = bundle()
    src_endpoint, dst_endpoint = control["endpoints"]["oci"], control["endpoints"]["k137"]
    need(src_endpoint["machine_sha256"] == trust.context["host"] and
         dst_endpoint["machine_sha256"] == trust.context["destination"] and
         dst_endpoint["user"] == "ubuntu" and dst_endpoint["uid"] == 1000, "SOURCE_SCOPE_STOP")
    src = SSH.ssh_base(control["ssh"], src_endpoint["host"], src_endpoint["user"], control["oci_key"],
                       control["oci_hosts"], hashlib.sha256(Path(control["oci_hosts"]).read_bytes()).hexdigest(), source=True)
    dst = SSH.ssh_base(control["ssh"], dst_endpoint["host"], dst_endpoint["user"], dst_endpoint["identity_file"],
                       control["k137_hosts"], hashlib.sha256(Path(control["k137_hosts"]).read_bytes()).hexdigest())
    # Each endpoint keeps its independently pinned host-key algorithm.
    # No executable known-host lookup, inherited config or TOFU fallback.
    for argv, endpoint in ((src, src_endpoint), (dst, dst_endpoint)):
        algorithm = endpoint["host_key"].split(" ")[0]
        need(algorithm in ("ssh-ed25519", "ecdsa-sha2-nistp256"), "CUSTODY_STOP")
        argv[1:1] = ["-o", "HostKeyAlgorithms=" + algorithm, "-o", "KnownHostsCommand=none"]
        for i, value in enumerate(argv):
            if value.startswith("UserKnownHostsFile="):
                path = value.split("=",1)[1].replace("\\","/")
                need(not any(c in path for c in ('"','\n','\r')), "CUSTODY_STOP")
                argv[i] = 'UserKnownHostsFile="' + path + '"'
    ps = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    source_bytes = evidence["G2"]["source_bytes"]
    dst_request = {"operation": "capacity", "machine_sha256": trust.context["destination"],
                   "uid": 1000, "source_bytes": source_bytes}
    check_name = "r1089-" + plan["run_id"] + ".json"
    record = parent / check_name
    if record.exists():
        need(record.stat().st_size <= 16384 and not record.is_symlink(), "CUSTODY_STOP")
        saved = decode(record.read_bytes())
        need(saved["context"] == trust.context, "CUSTODY_STOP")
        meta = saved["meta"]
    else:
        need(not archive.exists(), "ARCHIVE_INCOMPLETE")
        # Quota includes every original byte + all manifest/framing overhead.
        need(shutil.disk_usage(parent).free >= plan["quota_bytes"] + GIB, "CAPACITY_STOP")
        request = {"operation": "source", "machine_sha256": trust.context["host"], "uid": 0, "plan": plan}
        with child(remote_argv(src, "source", sources)) as p:
            send_request(p, sources, request, recovery)
            meta = frame_read(p.stdout, META)
            validate_meta(meta, evidence)
            checkpoint(parent, check_name, {"context": trust.context, "phase": "receiving", "meta": meta})
            receive = [ps, "-NoProfile", "-NonInteractive", "-File",
                       str(Path(__file__).with_name("r1085_windows_offhost_sink.ps1")),
                       "-ExistingPrivateNtfsParent", str(parent), "-NewArchiveFolder", plan["run_id"],
                       "-QuotaBytes", str(plan["quota_bytes"]), "-AllowCiphertextOnly"]
            with child(receive, stdin=p.stdout) as sink:
                result = bounded_result(sink)
                need(result["operation"] == "CIPHERTEXT_ONLY_NOT_AEAD_VERIFIED", "SOURCE_TRANSFER_STOP")
                need(p.wait(timeout=30) == 0, "SOURCE_TRANSFER_STOP")
    validate_meta(meta, evidence)
    with LockedArchive(archive, windows_validator=windows_custody) as held:
        manifest, verified = held.verify(recovery)
        need(all(verified[k] == meta[k] for k in verified), "ARCHIVE_AUTHENTICATION_STOP")
        # The real public DID record must survive exactly, not just a supplied
        # expected fingerprint. Its hash participates in the bound state digest.
        need(any(r["path"] == "state/verified-did.json" and r["kind"] == "file" for r in manifest["entries"]), "DID_MISMATCH")
        checkpoint(parent, check_name, {"context": trust.context, "phase": "aead_verified", "meta": meta})
        # Preserve the independently authenticated backup even when K137 is
        # too small. Measure CURRENT capacity just before restoration, never
        # weaken its reserve and never place a ciphertext duplicate there.
        with child(remote_argv(dst, "capacity", sources), timeout=90) as p:
            send_request(p, sources, {**dst_request,"resume":{"id":plan["run_id"],"manifest_sha256":meta["manifest_sha256"]}})
            capacity = frame_read(p.stdout, META)
            need(p.wait(timeout=15) == 0 and p.stdout.read(1) == b"", "CAPACITY_STOP")
        G.shape(capacity, "status free_bytes required_bytes runtime_started")
        minimum = D.SQLITE_ALLOWANCE + D.RESERVE
        need(capacity["status"] in ("CAPACITY_VERIFIED_NOW","CAPACITY_PRECHECK_ONLY") and capacity["runtime_started"] is False and
             type(capacity["free_bytes"]) is int and type(capacity["required_bytes"]) is int and
             capacity["required_bytes"] >= minimum and capacity["free_bytes"] >= capacity["required_bytes"] and
             (capacity["status"] != "CAPACITY_VERIFIED_NOW" or capacity["required_bytes"] == source_bytes + minimum),
             "CAPACITY_STOP")
        request = {**dst_request, "operation": "restore", "plan": plan, "meta": meta}
        with child(remote_argv(dst, "restore", sources)) as p:
            send_request(p, sources, request)
            held.stream(recovery, p.stdin)
            p.stdin.close(); p.stdin = None
            result = frame_read(p.stdout, META)
            need(p.wait(timeout=30) == 0 and p.stdout.read(1) == b"", "RESTORE_STOP")
        need(result["manifest_sha256"] == meta["manifest_sha256"] and result["bytes"] == meta["bytes"] and
             result["files"] == meta["files"] and result["symlinks"] == meta["symlinks"] and
             result["sqlite_cursors"] == meta["sqlite_cursors"] and result["cutover"] == "NO_GO", "RESTORE_STOP")
        checkpoint(parent, check_name, {"context": trust.context, "phase": "disarmed_restored", "meta": meta})
    return {"task": "R1089", "operation": "PRESERVED_AND_DISARMED_RESTORED", "backup_aead": "VERIFIED",
            "restored_manifest": "MATCH", "sqlite_cursors": "MATCH", "files": meta["files"], "bytes": meta["bytes"],
            "symlinks": meta["symlinks"], "post_and_nonce_state": "BOUND_AND_PRESERVED_NO_REPLAY",
            "source_epoch": "FROZEN_SCOPE_NOT_RELEASE_G6", "signer_portability": "NOT_PROVEN",
            "runtime_dependencies": "NOT_ACTIVATED", "tradebot_impact": "SANDBOX_ENFORCED_NOT_LIVE_ACCEPTANCE",
            "cutover": "NO_GO", "oci_retirement": "STRICT_NO_GO"}


def validate_meta(meta, evidence):
    G.shape(meta, "schema_version epoch manifest_sha256 files bytes symlinks sqlite_cursors ledger_sha256")
    need(meta["schema_version"] == 1 and meta["epoch"] == "FROZEN:" + evidence["G4"]["barrier_digest"] and
         meta["ledger_sha256"] == evidence["G5"]["inventory_digest"] and
         meta["bytes"] == evidence["G2"]["source_bytes"], "POST_FINALITY_REQUIRED")
    G.digest(meta["manifest_sha256"])
    G.integer(meta["files"], 2, T.MAX_ARCHIVE_ENTRIES)
    G.integer(meta["symlinks"], 0, meta["files"])
    need(type(meta["sqlite_cursors"]) is list and len(meta["sqlite_cursors"]) == 2)
    for row in meta["sqlite_cursors"]:
        need(type(row) is list and len(row) == 2)
        for n in row: G.integer(n)


def main():
    recovery = bytearray()
    try:
        need(sys.argv[1:] in (["--owner"], ["--check-plan"]))
        control = frame_read(sys.stdin.buffer, MAGIC)
        if sys.argv[1:] == ["--check-plan"]:
            authorizations(control["plan"], int(time.time()))
            print('{"operation":"OWNER_SESSION_VERIFIED","cutover":"NO_GO"}')
            return 0
        length = struct.unpack(">I", exact(sys.stdin.buffer, 4))[0]
        need(32 <= length <= 1024)
        recovery.extend(exact(sys.stdin.buffer, length))
        need(sys.stdin.buffer.read(1) == b"")
        report = owner(control, bytes(recovery))
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        code = str(error) if type(error) is Stop and str(error) in SAFE_CODES else "MIGRATION_GUARD_STOP"
        print(json.dumps({"task": "R1089", "operation": "BLOCKED", "code": code,
                          "cutover": "NO_GO", "oci_retirement": "STRICT_NO_GO"}, separators=(",", ":")))
        return 42
    finally:
        recovery[:] = b"\0" * len(recovery)


if __name__ == "__main__":
    raise SystemExit(main())
