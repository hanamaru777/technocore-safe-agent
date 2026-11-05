"""R1161 public-only helper. No SSH, credential selection, or custody access.

The unproven original Oracle anchor is deliberately NOT an operator parameter.
An independently audited archive must be pinned in a later source review.
"""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import types

BASE = "75ce50b1071e543774ba7235e063beaf308c8bea"
ROOT = Path(__file__).resolve().parents[2]
ORIGINAL_ED25519_SHA256 = ("13d1b2a7d68149dee58c74efb895d1fc064" "a818bcb21ecf684867e0fb9f2f626")
ORIGINAL_ECDSA_SHA256 = ("480a09f121116217ea70dff5c050b3e951" "c69a90b80486dddf80f4181ba9ae48")
# None is a hard trust STOP, not TOFU. No issue URL or caller digest enables it.
PINNED_ORIGINAL_EVIDENCE_SHA256 = None
FROZEN = {
    "packaging/migration/r1159_m2_bootstrap.py": "8c9f38b7ff6000900fa5f6fb8710132b41794f3e",
    "packaging/migration/r1066_preflight_readonly.py": "9f5f90ed6ad22a253b18c1510ec2651a117a01bc",
    "src/flop_agent/public_record.py": "0fe041f16f3d156cea3240b6b0410b3d7084ef36",
    "packaging/windows/r1159_authenticated_m2_bootstrap.ps1": "48029e5c61c51a8edf3993130b7014c11f68b077",
    "packaging/windows/r1138_lightsail_pem_single_acl_and_readonly_ssh.ps1": "317b245bca0161ad3827318892b12cbb24fc4cab",
    "packaging/migration/r1079_profile_ssh_transport.cs": "b150af9fe7a335bc6c02e8fc1e5451599d124a97",
    "packaging/migration/r1155_source_pins.json": "e1ac08ced545205772808e403dbae1fba6dd8331",
}
SAFE = frozenset(("R1161_SCHEMA_STOP", "SOURCE_PIN_STOP", "K137_BOOT_SCOPE_STOP",
    "K137_GUEST_STOP", "K137_LOGIN_CGROUP_UNBOUNDED", "ORIGINAL_ED25519_INDEPENDENT_TRUST_REQUIRED",
    "ORIGINAL_HOST_KEY_STOP", "ORIGINAL_CROSSCERT_STOP", "PLAN_EXPIRED_STOP", "K137_ADMISSION_REQUIRED"))


def need(ok, code="R1161_SCHEMA_STOP"):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def strict(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 32768)
    def pairs(rows):
        result = {}
        for k, v in rows:
            need(k not in result)
            result[k] = v
        return result
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False))


def shape(value, fields):
    need(type(value) is dict and set(value) == set(fields.split()))


def digest(value):
    need(type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value))
    return value


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def source(path):
    p = ROOT / path
    need(not p.is_symlink() and p.stat().st_size <= 524288, "SOURCE_PIN_STOP")
    return p.read_bytes().replace(b"\r\n", b"\n")


def dependencies():
    # The existing, immutable manifest is checked BEFORE parsing or importing it.
    need(blob(source("packaging/migration/r1155_source_pins.json")) ==
         FROZEN["packaging/migration/r1155_source_pins.json"], "SOURCE_PIN_STOP")
    pins = dict(strict(source("packaging/migration/r1155_source_pins.json")))
    pins.update(FROZEN)
    # Local Git objects only; no fetch, hooks, shell, or inherited Git overrides.
    env = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0"}
    for name in ("SystemRoot", "ProgramData"):
        if name in os.environ:
            env[name] = os.environ[name]
    # R1079 intentionally removes PATH. Use the prepared local Git installation;
    # never fall back to caller-controlled PATH or download another executable.
    git = r"C:\Program Files\Git\cmd\git.exe" if os.name == "nt" else "/usr/bin/git"
    r = subprocess.run([git, "ls-tree", "-r", BASE, "--", *sorted(pins)], cwd=ROOT,
                       env=env, capture_output=True, timeout=10, check=False)
    need(r.returncode == 0 and not r.stderr and len(r.stdout) <= 32768, "SOURCE_PIN_STOP")
    tree = {}
    for line in r.stdout.decode("ascii").splitlines():
        meta, path = line.split("\t")
        mode, kind, oid = meta.split()
        need(mode == "100644" and kind == "blob", "SOURCE_PIN_STOP")
        tree[path] = oid
    need(tree == pins, "SOURCE_PIN_STOP")
    for path, pin in pins.items():
        need(blob(source(path)) == pin, "SOURCE_PIN_STOP")
    m = types.ModuleType("r1161_frozen_r1159")
    m.__file__ = str(ROOT / "packaging/migration/r1159_m2_bootstrap.py")
    exec(compile(source("packaging/migration/r1159_m2_bootstrap.py"), "<frozen-r1159>", "exec"), m.__dict__)
    return m


def plan(value, now):
    shape(value, "version challenge expires_at k137_boot_sha256 k137_scope_sha256 tradebot_cgroup_sha256 consent")
    need(type(value["version"]) is int and value["version"] == 1)
    for k in ("challenge", "k137_boot_sha256", "k137_scope_sha256", "tradebot_cgroup_sha256"):
        digest(value[k])
    need(type(value["expires_at"]) is int and now < value["expires_at"] <= now + 600, "PLAN_EXPIRED_STOP")
    need(value["consent"] == "READ_ONLY_R1161_NO_M2_NO_HOLD")
    return value


# Added around the exact frozen guest; no replacement of the old probe.
K137_GUARD = '''
original_probe=probe
def probe(role,challenge,R,decode,source_blobs):
    report=original_probe(role,challenge,R,decode,source_blobs)
    need(sha(R.read_small('/etc/machine-id',64).strip())==report['machine_sha256'],'M2_MACHINE_MISMATCH')
    raw=R.read_small('/proc/self/cgroup')
    need(sha(raw)==report['cgroup']['raw_sha256'],'M2_CGROUP_CHANGED')
    scope=raw.decode('ascii').strip()[3:]
    need(sha(scope.encode())!=report['tradebot']['cgroup_sha256'],'M2_CGROUP_MEMBERSHIP_UNVERIFIED')
    members=R.read_small('/sys/fs/cgroup'+scope+'/cgroup.procs',65536).splitlines()
    need(0<len(members)<=report['cgroup']['pids_max'] and len(set(members))==len(members),'K137_LOGIN_CGROUP_UNBOUNDED')
    need(tradebot_evidence(R)==report['tradebot'],'M2_TRADEBOT_CAP_CHANGED')
    return report
'''


def k137_guest(m, challenge):
    digest(challenge)
    code = m.guest_source("k137", challenge).decode()
    # Keep the frozen probe and primitives verbatim. Omit only three unused
    # Oracle-only DID/public-file readers from this fixed-role K137 payload.
    # This leaves room for the stronger guard under R1079's unchanged ceiling.
    omitted = [n for n in ast.parse(code).body if isinstance(n, ast.FunctionDef) and
               n.name in {"public_file", "public_did", "did_identity"}]
    need(len(omitted) == 3, "SOURCE_PIN_STOP")
    for node in omitted:
        segment = ast.get_source_segment(m.guest_source("k137", challenge).decode(), node)
        need(code.count(segment) == 1, "SOURCE_PIN_STOP")
        code = code.replace(segment, "", 1)
    marker = "\ntry:\n result=probe("
    need(code.count(marker) == 1, "SOURCE_PIN_STOP")
    code = code.replace(marker, "\n" + K137_GUARD + marker)
    need(len(code.encode()) <= 16384)
    compile(code, "<r1161-k137>", "exec")
    return code.encode()


def k137_report(m, p, raw, now):
    plan(p, now)
    v = strict(raw)
    if type(v) is dict and v.get("code") == "K137_LOGIN_CGROUP_UNBOUNDED":
        need(False, "K137_LOGIN_CGROUP_UNBOUNDED")
    _, sources, pins = m.sources()
    R = types.ModuleType("r1161_preflight")
    exec(compile(sources["preflight"], "<frozen-r1066>", "exec"), R.__dict__)
    try:
        m.validate_report(v, "k137", p["challenge"], pins, R, None, now)
    except Exception:
        need(False, "K137_GUEST_STOP")
    need(v["boot_runtime_sha256"] == p["k137_boot_sha256"] and
         v["cgroup"]["raw_sha256"] == p["k137_scope_sha256"] and
         v["tradebot"]["cgroup_sha256"] == p["tradebot_cgroup_sha256"], "K137_BOOT_SCOPE_STOP")
    return v


def original_authority():
    need(PINNED_ORIGINAL_EVIDENCE_SHA256 is not None,
         "ORIGINAL_ED25519_INDEPENDENT_TRUST_REQUIRED")
    return digest(PINNED_ORIGINAL_EVIDENCE_SHA256)


def original_host(m, text):
    # A single fixed, literal IP entry. No aliases, markers, hashes, comments,
    # additional algorithms, option tokens, or hostname-controlled routing.
    need(type(text) is str and len(text) <= 1024, "ORIGINAL_HOST_KEY_STOP")
    need(re.fullmatch(r"140\.238\.55\.171 ssh-ed25519 [A-Za-z0-9+/]+={0,2}\n?", text),
         "ORIGINAL_HOST_KEY_STOP")
    key = text.rstrip("\n").split(" ", 1)[1]
    try:
        need(m.host_key(key, "ssh-ed25519") == ORIGINAL_ED25519_SHA256, "ORIGINAL_HOST_KEY_STOP")
    except Exception:
        need(False, "ORIGINAL_HOST_KEY_STOP")
    return key


def authorize_original(m, raw):
    anchor = original_authority()
    value = strict(raw)
    need(sha(canonical(value)) == anchor, "ORIGINAL_ED25519_INDEPENDENT_TRUST_REQUIRED")
    shape(value, "kind known_hosts independent_archive_sha256 reference")
    need(value["kind"] == "PREVIOUSLY_AUTHENTICATED_ORIGINAL_GUEST_SSHD_ARCHIVE",
         "ORIGINAL_ED25519_INDEPENDENT_TRUST_REQUIRED")
    digest(value["independent_archive_sha256"])
    need(type(value["reference"]) is str and 0 < len(value["reference"]) <= 200)
    return original_host(m, value["known_hosts"])


def oracle_probe(challenge):
    """Fixed unprivileged read of ONLY the public ECDSA file."""
    import stat
    digest(challenge)
    p = Path("/etc/ssh/ssh_host_ecdsa_key.pub")
    for parent in p.parents:
        s = parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
             "ORIGINAL_CROSSCERT_STOP")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and
             not before.st_mode & 0o022 and 1 <= before.st_size <= 1024, "ORIGINAL_CROSSCERT_STOP")
        raw = os.read(fd, 1025)
        after = os.fstat(fd)
        need(len(raw) == before.st_size and
             (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "ORIGINAL_CROSSCERT_STOP")
    finally:
        os.close(fd)
    fields = raw.decode("ascii", "strict").strip().split()
    need(2 <= len(fields) <= 3 and fields[0] == "ecdsa-sha2-nistp256", "ORIGINAL_CROSSCERT_STOP")
    key = fields[0] + " " + fields[1]
    wire = base64.b64decode(fields[1], validate=True)
    need(sha(wire) == ORIGINAL_ECDSA_SHA256, "ORIGINAL_CROSSCERT_STOP")
    return dict(challenge=challenge, observed_at=int(time.time()), public_key=key,
                public_path="/etc/ssh/ssh_host_ecdsa_key.pub", read_only=True)


def oracle_guest(challenge):
    original_authority()
    digest(challenge)
    tree = ast.parse(source("packaging/migration/r1161_readonly_admission.py").decode())
    wanted = {"need", "digest", "sha", "oracle_probe"}
    parts = [ast.get_source_segment(source("packaging/migration/r1161_readonly_admission.py").decode(), n)
             for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    need(len(parts) == len(wanted), "SOURCE_PIN_STOP")
    code = "import os,re,sys,json,time,hashlib,base64\nfrom pathlib import Path\n"
    code += "ORIGINAL_ECDSA_SHA256=" + repr(ORIGINAL_ECDSA_SHA256) + "\n" + "\n\n".join(parts)
    code += "\ntry:\n print(json.dumps(oracle_probe(" + repr(challenge) + ")))\n"
    code += "except Exception:\n print('{\"code\":\"ORIGINAL_CROSSCERT_STOP\"}');sys.exit(42)\n"
    compile(code, "<r1161-original>", "exec")
    need(len(code.encode()) <= 8192)
    return code.encode()


def receipt(m, p, kraw, now, *, oraw=None, evidence=None):
    k = k137_report(m, p, kraw, now)
    result = dict(task="R1161", code="K137_BOUND_READONLY_ADMISSION_PASS", challenge=p["challenge"],
                  observed_at=k["observed_at"], expires_at=min(p["expires_at"], k["observed_at"] + 180),
                  plan_sha256=sha(canonical(p)), report_sha256=sha(p["challenge"].encode() + kraw),
                  guest_sha256=sha(k137_guest(m, p["challenge"])),
                  k137_host_key_sha256=m.host_key(m.K137_KEY, "ssh-ed25519"),
                  source_base=BASE, helper_blob=blob(source("packaging/migration/r1161_readonly_admission.py")),
                  entry_blob=blob(source("packaging/windows/r1161_k137_first_readonly.ps1")),
                  cutover="NO_GO", oci_retirement="STRICT_NO_GO", m2="NOT_AUTHORIZED")
    need(now < result["expires_at"], "PLAN_EXPIRED_STOP")
    if oraw is not None:
        authorize_original(m, evidence)
        v = strict(oraw)
        shape(v, "challenge observed_at public_key public_path read_only")
        need(v["challenge"] == sha(b"R1161-original:" + p["challenge"].encode()) and
             type(v["observed_at"]) is int and k["observed_at"] <= v["observed_at"] <= now + 5 and
             v["public_path"] == "/etc/ssh/ssh_host_ecdsa_key.pub" and v["read_only"] is True,
             "ORIGINAL_CROSSCERT_STOP")
        need(m.host_key(v["public_key"], "ecdsa-sha2-nistp256") == ORIGINAL_ECDSA_SHA256,
             "ORIGINAL_CROSSCERT_STOP")
        result.update(code="ORIGINAL_GUEST_ED25519_ECDSA_CROSSCERT_PASS",
                      original_ed25519_sha256=ORIGINAL_ED25519_SHA256,
                      original_ecdsa_sha256=ORIGINAL_ECDSA_SHA256,
                      independent_evidence_sha256=original_authority(),
                      original_report_sha256=sha(p["challenge"].encode() + oraw),
                      original_guest_sha256=sha(oracle_guest(v["challenge"])))
    body = canonical(result)
    return dict(body=result, sha256=sha(body))


def decode(value):
    need(type(value) is str and len(value) <= 12000)
    return base64.b64decode(value, validate=True)


def main():
    try:
        need(len(sys.argv) == 2)
        operation = sys.argv[1]
        m = dependencies()
        v = strict(sys.stdin.buffer.read(32769))
        now = int(time.time())
        if operation == "--check":
            plan(v, now)
            result = dict(code="R1161_PUBLIC_PLAN_PASS", k137_key=m.K137_KEY)
        elif operation == "--guest-k137":
            plan(v, now)
            sys.stdout.buffer.write(k137_guest(m, v["challenge"]))
            return 0
        elif operation == "--trust-status":
            original_authority()
            result = dict(code="ORIGINAL_SOURCE_ANCHOR_PRESENT")
        elif operation == "--authorize-original":
            result = dict(key=authorize_original(m, decode(v["evidence"])))
        elif operation == "--guest-original":
            plan(v, now)
            sys.stdout.buffer.write(oracle_guest(sha(b"R1161-original:" + v["challenge"].encode())))
            return 0
        else:
            need(operation in ("--receipt-k137", "--receipt-original"))
            shape(v, "plan k137" if operation == "--receipt-k137" else "plan k137 original evidence")
            result = receipt(m, v["plan"], decode(v["k137"]), now,
                             **({"oraw": decode(v["original"]), "evidence": decode(v["evidence"])}
                                if operation == "--receipt-original" else {}))
        sys.stdout.buffer.write(canonical(result))
        return 0
    except Exception as error:
        code = str(error) if type(error) is ValueError and str(error) in SAFE else "R1161_SCHEMA_STOP"
        print(json.dumps(dict(code=code, cutover="NO_GO", oci_retirement="STRICT_NO_GO")))
        return 42


if __name__ == "__main__":
    raise SystemExit(main())
