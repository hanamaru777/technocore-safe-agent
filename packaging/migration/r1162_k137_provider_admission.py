"""Owner-invoked Linux/AWS CloudShell candidate. Default/import is offline.

No Windows PEM, capsule, Oracle path, input AWS JSON, or remote command override.
Production use needs separate owner approval; Codex must never use --execute.
"""
import ast
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types

ROOT = Path(__file__).resolve().parents[2]
BASE = "a2883f6b5ae61ec49ba9805f2eb1b9a8802226a3"
REFERENCE = "2ff11656123c99117e59958f4d0b46a024159c5e"
MANIFEST_BLOB = "06b177340cd24eca1015dbd8b0e25fe5e2a90735"
INSTANCE = "tradebot-k137"
REGION = "ap-northeast-1"
HOST = "52.198.96.243"
ENDPOINT = "https://lightsail.ap-northeast-1.amazonaws.com"
APPROVAL = "CREATE_ONE_K137_TRANSIENT_SERVICE_R1162_NO_M2_NO_HOLD"
REMOTE = (
    "sudo -n /usr/bin/systemd-run --system --quiet --pipe --wait --collect "
    "--unit=flop-r1162-admission.service --service-type=exec "
    "--property=User=ubuntu --property=Group=ubuntu "
    "--property=MemoryMax=256M --property=MemorySwapMax=0 --property=TasksMax=64 "
    "--property=CPUQuota=50% --property=CPUQuotaPeriodSec=100ms "
    "--property=NoNewPrivileges=yes --property=ProtectSystem=strict "
    "--property=ProtectHome=yes --property=PrivateTmp=yes "
    "--property=RuntimeMaxSec=45s --property=TimeoutStartSec=15s "
    "--property=TimeoutStopSec=5s --property=KillMode=control-group "
    "--property=SendSIGKILL=yes --property=Restart=no "
    "/usr/bin/python3 -I -B -")
PUBLIC_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C"}


class Stop(Exception):
    """Only literal, redacted status codes reach stdout."""


def need(ok, code="R1162_UNVERIFIED_STOP"):
    if not ok:
        raise Stop(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def strict(raw):
    need(isinstance(raw, (bytes, bytearray)) and 0 < len(raw) <= 131072, "INPUT_BOUND_STOP")
    def pairs(rows):
        out = {}
        for k, v in rows:
            need(k not in out, "DUPLICATE_JSON_STOP")
            out[k] = v
        return out
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, "JSON_STOP"))


def shape(value, fields):
    need(type(value) is dict and set(value) == set(fields.split()), "SCHEMA_STOP")


def digest(value):
    need(type(value) is str and re.fullmatch("[a-f0-9]{64}", value), "SCHEMA_STOP")
    return value


def integer(value, low, high):
    need(type(value) is int and low <= value <= high, "SCHEMA_STOP")
    return value


def bounded(argv, data=b"", *, limit=8192, timeout=10, provider=False):
    """Bound stdout in memory; discard diagnostics; reap own local process group.

    AWS stdout is sensitive and is never forwarded. SSH gets only PUBLIC_ENV.
    No shell, inherited AWS environment in SSH, or retry.
    """
    need(len(data) <= 32768 and 1 <= limit <= 131072 and 1 <= timeout <= 75, "PROCESS_BOUND_STOP")
    p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, env=None if provider else PUBLIC_ENV,
                         start_new_session=(os.name == "posix"))
    output = bytearray()
    failed = []
    def kill():
        if p.poll() is None:
            if os.name == "posix":
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                p.kill()
    def read():
        try:
            while True:
                block = p.stdout.read(4096)
                if not block:
                    break
                if len(output) + len(block) > limit:
                    failed.append(True)
                    kill()
                    break
                output.extend(block)
        except Exception:
            failed.append(True)
    def write():
        try:
            p.stdin.write(data)
            p.stdin.close()
        except Exception:
            failed.append(True)
    threads = [threading.Thread(target=read, daemon=True), threading.Thread(target=write, daemon=True)]
    try:
        for t in threads:
            t.start()
        try:
            result = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise Stop("PROCESS_AMBIGUOUS_NO_RETRY") from None
        for t in threads:
            t.join(2)
        need(not failed and not any(t.is_alive() for t in threads), "PROCESS_AMBIGUOUS_NO_RETRY")
        need(result == 0, "PROCESS_REJECTED_NO_RETRY")
        answer = output[:]
        return answer
    finally:
        kill()
        try:
            p.wait(timeout=3)
            for t in threads:
                if t.ident is not None:
                    t.join(2)
            need(not any(t.is_alive() for t in threads), "LOCAL_PROCESS_CLEANUP_STOP")
        finally:
            p.stdin.close()
            p.stdout.close()
            output[:] = b"\0" * len(output)


def source(name):
    p = ROOT / name
    need(not p.is_symlink() and 0 < p.stat().st_size <= 65536, "SOURCE_PIN_STOP")
    return p.read_bytes().replace(b"\r\n", b"\n")


def sources():
    manifest_path = "packaging/migration/r1162_source_pins.json"
    raw = source(manifest_path)
    need(blob(raw) == MANIFEST_BLOB, "SOURCE_PIN_STOP")
    manifest = strict(raw)
    shape(manifest, "base reference frozen guest")
    need(manifest["base"] == BASE and manifest["reference"] == REFERENCE, "SOURCE_PIN_STOP")
    pins = manifest["frozen"]
    need(type(pins) is dict and len(pins) == 3, "SOURCE_PIN_STOP")
    # Never fetch, invoke R1071, or import old owner/custody entrypoints.
    git = r"C:\Program Files\Git\cmd\git.exe" if os.name == "nt" else "/usr/bin/git"
    clean_env = dict(PUBLIC_ENV)
    if os.name == "nt" and "SystemRoot" in os.environ:
        clean_env["SystemRoot"] = os.environ["SystemRoot"]
    clean_env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_NO_REPLACE_OBJECTS="1")
    r = subprocess.run([git, "ls-tree", "-r", BASE, "--", *sorted(pins)], cwd=ROOT,
                       env=clean_env, capture_output=True, timeout=10, check=False)
    need(r.returncode == 0 and not r.stderr and len(r.stdout) <= 8192, "SOURCE_PIN_STOP")
    tree = {}
    for line in r.stdout.decode("ascii").splitlines():
        meta, path = line.split("\t")
        mode, kind, oid = meta.split()
        need(mode == "100644" and kind == "blob", "SOURCE_PIN_STOP")
        tree[path] = oid
    need(tree == pins, "SOURCE_PIN_STOP")
    for name, pin in {**pins, **manifest["guest"]}.items():
        need(blob(source(name)) == pin, "SOURCE_PIN_STOP")
    ref_path = "packaging/migration/r1071_aws_cloudshell_bounded_scope_readonly.sh"
    r = subprocess.run([git, "ls-tree", REFERENCE, "--", ref_path], cwd=ROOT, env=clean_env,
                       capture_output=True, timeout=10, check=False)
    need(r.returncode == 0 and r.stdout.decode().strip() ==
         "100644 blob " + pins[ref_path] + "\t" + ref_path, "SOURCE_PIN_STOP")
    return manifest


class Wire:
    def __init__(self, raw):
        self.raw, self.offset = raw, 0

    def take(self, size):
        need(0 <= size <= 32768 and self.offset + size <= len(self.raw), "SSH_WIRE_STOP")
        value = self.raw[self.offset:self.offset + size]
        self.offset += size
        return value

    def number(self, size):
        return int.from_bytes(self.take(size), "big")

    def string(self):
        return self.take(self.number(4))

    def done(self):
        need(self.offset == len(self.raw), "SSH_WIRE_STOP")


def string(raw):
    return struct.pack(">I", len(raw)) + raw


def public_line(text):
    need(type(text) is str and text.isascii() and len(text) <= 32768, "SSH_KEY_STOP")
    parts = text.strip().split(" ")
    need(len(parts) == 2 and re.fullmatch("[A-Za-z0-9+/]+={0,2}", parts[1]), "SSH_KEY_STOP")
    raw = base64.b64decode(parts[1], validate=True)
    need(len(raw) <= 16384, "SSH_KEY_STOP")
    return parts[0], raw


def public_fields(r, algorithm):
    if algorithm == b"ssh-ed25519":
        fields = [r.string()]
        need(len(fields[0]) == 32, "SSH_KEY_STOP")
    elif algorithm == b"ssh-rsa":
        fields = [r.string(), r.string()]
        e, n = (int.from_bytes(x, "big", signed=True) for x in fields)
        need(3 <= e <= 2**32 and e % 2 and 2048 <= n.bit_length() <= 8192, "SSH_KEY_STOP")
    else:
        need(algorithm == b"ecdsa-sha2-nistp256", "SSH_KEY_STOP")
        fields = [r.string(), r.string()]
        need(fields[0] == b"nistp256" and len(fields[1]) == 65 and fields[1][0] == 4, "SSH_KEY_STOP")
    return string(algorithm) + b"".join(string(x) for x in fields)


def certificate(text, now):
    algorithm, raw = public_line(text)
    suffix = "-cert-v01@openssh.com"
    need(algorithm.endswith(suffix), "CERTIFICATE_STOP")
    plain_algorithm = algorithm[:-len(suffix)].encode()
    r = Wire(raw)
    need(r.string() == algorithm.encode() and 0 < len(r.string()) <= 256, "CERTIFICATE_STOP")
    public = public_fields(r, plain_algorithm)
    r.number(8)  # serial, never published
    need(r.number(4) == 1, "CERTIFICATE_STOP")  # user certificate, never a host cert
    need(len(r.string()) <= 1024, "CERTIFICATE_STOP")
    principals = Wire(r.string())
    need(principals.string() == b"ubuntu", "CERTIFICATE_PRINCIPAL_STOP")
    principals.done()
    start, end = r.number(8), r.number(8)
    need(now - 3660 <= start <= now and now + 75 < end <= now + 3600 and end - start <= 3660,
         "CERTIFICATE_EXPIRY_STOP")
    need(r.string() == b"", "CERTIFICATE_CRITICAL_OPTION_STOP")
    extensions = Wire(r.string())
    seen = set()
    while extensions.offset < len(extensions.raw):
        name, value = extensions.string(), extensions.string()
        need(name in {b"permit-X11-forwarding", b"permit-agent-forwarding", b"permit-port-forwarding",
                      b"permit-pty", b"permit-user-rc"} and name not in seen and value == b"",
             "CERTIFICATE_EXTENSION_STOP")
        seen.add(name)
    need(r.string() == b"", "CERTIFICATE_STOP")
    ca = Wire(r.string())
    public_fields(ca, ca.string())
    ca.done()
    signature = Wire(r.string())
    need(signature.string() in (b"ssh-ed25519", b"ecdsa-sha2-nistp256", b"rsa-sha2-256", b"rsa-sha2-512")
         and len(signature.string()) > 0, "CERTIFICATE_SIGNATURE_STOP")
    signature.done()
    r.done()
    return public, end


def put(folder, name, data):
    need(name in ("identity", "identity-cert.pub", "known_hosts", "ATTEMPTED.json"), "CUSTODY_STOP")
    fd = os.open(folder / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and
             info.st_uid == os.geteuid() and info.st_nlink == 1, "CUSTODY_STOP")
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            need(count > 0, "CUSTODY_STOP")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def provider_args(aws):
    return [str(aws), "lightsail", "get-instance-access-details", "--instance-name", INSTANCE,
            "--protocol", "ssh", "--region", REGION, "--endpoint-url", ENDPOINT,
            "--ca-bundle", "/etc/pki/tls/certs/ca-bundle.crt", "--output", "json", "--no-cli-pager",
            "--no-cli-auto-prompt", "--cli-connect-timeout", "5", "--cli-read-timeout", "10"]


def provider_time(value, code):
    # AWS CLI v2 defaults to ISO8601; wire timestamps may be numeric.
    if type(value) is str:
        try:
            date = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
            need(date.tzinfo is not None, code)
            value = date.timestamp()
        except (ValueError, OverflowError, OSError):
            raise Stop(code) from None
    need(type(value) in (int, float), code)
    return float(value)


def credentials(raw, folder, keygen, expected_key, now):
    value = strict(raw)
    shape(value, "accessDetails")
    a = value["accessDetails"]
    need(type(a) is dict and a.get("instanceName") == INSTANCE and a.get("protocol") == "ssh" and
         a.get("ipAddress") == HOST and a.get("username") == "ubuntu", "PROVIDER_BINDING_STOP")
    keys = a.get("hostKeys")
    need(type(keys) is list and 1 <= len(keys) <= 8 and all(type(x) is dict for x in keys), "HOSTKEY_STOP")
    algorithms = [x.get("algorithm") for x in keys]
    need(all(type(x) is str for x in algorithms) and len(set(algorithms)) == len(algorithms), "HOSTKEY_STOP")
    selected = [x for x in keys if x.get("algorithm") == "ssh-ed25519"]
    need(len(selected) == 1, "HOSTKEY_STOP")
    host = selected[0]
    pub = host.get("publicKey")
    need(type(pub) is str and len(pub) <= 1024, "HOSTKEY_STOP")
    pub = pub if pub.startswith("ssh-ed25519 ") else "ssh-ed25519 " + pub
    algorithm, wire = public_line(pub)
    r = Wire(wire)
    need(algorithm == "ssh-ed25519" and public_fields(r, r.string()) == wire and
         pub == expected_key, "HOSTKEY_STOP")
    r.done()
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).decode().rstrip("=")
    need(host.get("fingerprintSHA256") == fingerprint, "HOSTKEY_STOP")
    witnessed = provider_time(host.get("witnessedAt"), "HOSTKEY_PROVENANCE_STOP")
    need(0 < witnessed <= now + 5, "HOSTKEY_PROVENANCE_STOP")
    cert = a.get("certKey")
    public, expires = certificate(cert, now)
    expiry = a.get("expiresAt")
    if expiry is not None:
        expiry = provider_time(expiry, "CERTIFICATE_EXPIRY_STOP")
        need(now + 75 < expiry <= now + 3600, "CERTIFICATE_EXPIRY_STOP")
        expires = min(expires, int(expiry))
    private = a.pop("privateKey", None)
    need(type(private) is str and private.isascii() and 64 <= len(private) <= 65536 and
         "\0" not in private, "TEMPORARY_CREDENTIAL_STOP")
    temporary = bytearray((private.strip() + "\n").encode("ascii"))
    try:
        put(folder, "identity", temporary)
    finally:
        temporary[:] = b"\0" * len(temporary)
        private = None
    put(folder, "identity-cert.pub", (cert.strip() + "\n").encode("ascii"))
    put(folder, "known_hosts", (HOST + " " + pub + "\n").encode("ascii"))
    # OpenSSH validates the actual private serialization and certificate's
    # cryptographic signature. Its CA trust here comes ONLY from AWS TLS, not
    # from a self-signed packet supplied to this program.
    derived = bounded([str(keygen), "-y", "-P", "", "-f", str(folder / "identity")])
    try:
        _, derived_wire = public_line(bytes(derived).decode("ascii").strip())
        need(derived_wire == public, "CERTIFICATE_KEY_MISMATCH_STOP")
    finally:
        derived[:] = b"\0" * len(derived)
    checked = bounded([str(keygen), "-L", "-f", str(folder / "identity-cert.pub")])
    checked[:] = b"\0" * len(checked)
    return dict(operation="Lightsail.GetInstanceAccessDetails", region=REGION, instance=INSTANCE,
                host=HOST, user="ubuntu", host_key_sha256=sha(wire),
                witnessed_at=witnessed, expires_at=expires)


def ssh_args(ssh, folder):
    return [str(ssh), "-F", "/dev/null", "-T", "-i", str(folder / "identity"),
            "-o", "CertificateFile=" + str(folder / "identity-cert.pub"),
            "-o", "UserKnownHostsFile=" + str(folder / "known_hosts"),
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes",
            "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "IdentityAgent=none",
            "-o", "PubkeyAcceptedAlgorithms=ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com",
            "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no", "-o", "GSSAPIAuthentication=no",
            "-o", "HostbasedAuthentication=no", "-o", "UpdateHostKeys=no",
            "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
            "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "PermitLocalCommand=no",
            "-o", "KnownHostsCommand=none", "-o", "CanonicalizeHostname=no",
            "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=7",
            "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
            "-o", "LogLevel=ERROR", "ubuntu@" + HOST, REMOTE]


def guest_source(request):
    preflight = source("packaging/migration/r1066_preflight_readonly.py")
    bootstrap = source("packaging/migration/r1159_m2_bootstrap.py").decode()
    funcs = [n for n in ast.parse(bootstrap).body if isinstance(n, ast.FunctionDef) and n.name == "tradebot_evidence"]
    need(len(funcs) == 1, "SOURCE_PIN_STOP")
    code = "import types\nR=types.ModuleType('frozen_r1066')\nexec(compile(" + repr(preflight.decode()) + ",'<frozen-r1066>','exec'),R.__dict__)\n"
    code += source("packaging/migration/r1162_k137_bounded_guest.py").decode() + "\n"
    code += ast.get_source_segment(bootstrap, funcs[0]) + "\nrun(" + repr(request) + ")\n"
    need(len(code.encode()) <= 32768, "SOURCE_PIN_STOP")
    compile(code, "<r1162-bounded-guest>", "exec")
    return code.encode()


def validate_report(raw, request, now, machine, head):
    v = strict(raw)
    shape(v, "task verdict ssh_login_prebounded challenge expires_at observed_at source_blobs provider_sha256 machine_sha256 boot_sha256 cgroup sandbox_sha256 tradebot head free_bytes uid gid landing m2 cutover oci_retirement")
    need(v["task"] == "R1162" and v["verdict"] == "K137_PAYLOAD_BOUNDED" and v["ssh_login_prebounded"] is False)
    for key in request:
        need(v[key] == request[key], "REPORT_BINDING_STOP")
    integer(v["observed_at"], now - 180, now + 5)
    need(now < v["expires_at"] <= now + 180, "REPORT_EXPIRED_STOP")
    need(v["machine_sha256"] == machine and v["head"] == head and
         type(v["uid"]) is int and v["uid"] == 1000 and type(v["gid"]) is int and v["gid"] == 1000)
    for k in ("boot_sha256", "sandbox_sha256"):
        digest(v[k])
    need(v["landing"] == "READ_ONLY_0700" and v["m2"] == "NO_GO" and
         v["cutover"] == "NO_GO" and v["oci_retirement"] == "STRICT_NO_GO")
    integer(v["free_bytes"], 21 * 1024**3, 2**60)
    cg = v["cgroup"]
    shape(cg, "scope_sha256 memory_max pids_max cpu_quota cpu_period swap_max")
    digest(cg["scope_sha256"])
    integer(cg["memory_max"], 1, 256 * 1024**2)
    integer(cg["pids_max"], 1, 64)
    integer(cg["cpu_period"], 1, 1000000)
    integer(cg["cpu_quota"], 1, cg["cpu_period"] // 2)
    integer(cg["swap_max"], 0, 0)
    target = v["tradebot"]
    shape(target, "unit active memory_high memory_max cgroup_sha256")
    need(target["unit"] == "k137q-public-k58.service" and target["active"] is True and
         type(target["memory_high"]) is int and target["memory_high"] == 1000 * 1024**2 and
         type(target["memory_max"]) is int and target["memory_max"] == 1200 * 1024**2)
    digest(target["cgroup_sha256"])
    return v


def secure_tool(path):
    p = Path(path).resolve(strict=True)
    for parent in (p, *p.parents):
        info = parent.stat()
        need(info.st_uid == 0 and not info.st_mode & 0o022, "LOCAL_TOOL_STOP")
    need(p.is_file() and os.access(p, os.X_OK), "LOCAL_TOOL_STOP")
    return p


def new_attempt(folder, challenge, now):
    # The default is ~/.flop-r1162 in the authenticated local Unix account.
    # No caller-supplied path is accepted by the CLI.
    for p in (folder.parent, *folder.parent.parents):
        info = p.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid()) and
             not info.st_mode & 0o022, "ATTEMPT_PATH_STOP")
    try:
        folder.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = folder.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
         stat.S_IMODE(info.st_mode) == 0o700, "ATTEMPT_PATH_STOP")
    try:
        put(folder, "ATTEMPTED.json", canonical(dict(task="R1162", challenge=challenge,
            attempted_at=now, no_automatic_retry=True, m2="NO_GO")))
    except FileExistsError:
        raise Stop("ATTEMPT_ALREADY_CONSUMED") from None


def cleanup(folder):
    # Only the three files this attempt could have created. Never recursive.
    for name in ("identity", "identity-cert.pub", "known_hosts"):
        p = folder / name
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    folder.rmdir()
    need(not folder.exists(), "TEMPORARY_CLEANUP_STOP")


def owner_run(manifest, aws, ssh, keygen, state):
    challenge = secrets.token_hex(32)
    started = int(time.time())
    new_attempt(state, challenge, started)  # BEFORE AWS or any hosted connection
    temporary = None
    raw = bytearray()
    answer = None
    failure = "ATTEMPT_AMBIGUOUS_NO_RETRY"
    try:
        temporary = Path(tempfile.mkdtemp(prefix="flop-r1162-", dir="/tmp"))
        need(stat.S_IMODE(temporary.stat().st_mode) == 0o700, "TEMPORARY_CUSTODY_STOP")
        # Process-local nonsecret CLI configuration; do not inspect or copy AWS
        # credentials/environment. Existing CloudShell auth is consumed by AWS CLI.
        for key, value in dict(PATH="/usr/local/bin:/usr/bin:/bin", AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard", AWS_PAGER="",
                               AWS_CLI_AUTO_PROMPT="off", AWS_CONFIG_FILE="/dev/null",
                               AWS_SHARED_CREDENTIALS_FILE="/dev/null", AWS_EC2_METADATA_DISABLED="true").items():
            os.environ[key] = value
        raw = bounded(provider_args(aws), limit=131072, timeout=30, provider=True)
        bootstrap = types.ModuleType("public_frozen_r1159")
        bootstrap.__file__ = str(ROOT / "packaging/migration/r1159_m2_bootstrap.py")
        exec(compile(source("packaging/migration/r1159_m2_bootstrap.py"), "<frozen-r1159>", "exec"), bootstrap.__dict__)
        public = credentials(raw, temporary, keygen, bootstrap.K137_KEY, int(time.time()))
        raw[:] = b"\0" * len(raw)
        expires = min(started + 180, public["expires_at"] - 5)
        need(int(time.time()) + 75 < expires, "CREDENTIAL_WINDOW_STOP")
        provenance = sha(canonical(dict(challenge=challenge, provider=public)))
        pins = {**manifest["frozen"], **manifest["guest"],
                "packaging/migration/r1162_k137_provider_admission.py": blob(source("packaging/migration/r1162_k137_provider_admission.py"))}
        request = dict(challenge=challenge, expires_at=expires, source_blobs=pins, provider_sha256=provenance)
        payload = guest_source(request)
        raw = bounded(ssh_args(ssh, temporary), payload, limit=8192, timeout=75)
        report = validate_report(raw, request, int(time.time()), bootstrap.K137_MACHINE,
                                 "3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e")
        answer = dict(task="R1162", verdict="K137_PAYLOAD_BOUNDED", ssh_login_prebounded=False,
                      challenge=challenge, observed_at=report["observed_at"], expires_at=expires,
                      source_base=BASE, reference_commit=REFERENCE, source_blobs=pins,
                      provider_operation=public["operation"], provider_sha256=provenance,
                      provider_witnessed_at=public["witnessed_at"],
                      credential_expires_at=public["expires_at"],
                      host_key_sha256=public["host_key_sha256"], head=report["head"],
                      guest_sha256=sha(payload), report_sha256=sha(challenge.encode() + raw),
                      boot_sha256=report["boot_sha256"], scope_sha256=report["cgroup"]["scope_sha256"],
                      tradebot_sha256=sha(canonical(report["tradebot"])), caps=report["cgroup"],
                      m2="NO_GO", cutover="NO_GO", oci_retirement="STRICT_NO_GO")
    except Stop as error:
        failure = str(error)
    except BaseException:
        failure = "ATTEMPT_AMBIGUOUS_NO_RETRY"
    finally:
        raw[:] = b"\0" * len(raw)
        if temporary is not None:
            try:
                cleanup(temporary)
            except BaseException:
                answer, failure = None, "TEMPORARY_CLEANUP_STOP"
    if answer is None:
        raise Stop(failure)
    need(int(time.time()) < answer["expires_at"], "REPORT_EXPIRED_STOP")
    return dict(body=answer, sha256=sha(canonical(answer)))


def main():
    try:
        need(sys.argv[1:] == ["--execute"], "EXPLICIT_OWNER_EXECUTION_REQUIRED")
        need(sys.platform == "linux" and sys.version_info >= (3, 9) and os.geteuid() != 0, "OWNER_LINUX_SESSION_REQUIRED")
        import pwd
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.umask(0o077)
        for key in ("AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_LIGHTSAIL", "AWS_CA_BUNDLE",
                    "AWS_DATA_PATH", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME", "AWS_WEB_IDENTITY_TOKEN_FILE",
                    "AWS_PROFILE", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME"):
            need(key not in os.environ, "UNSAFE_SESSION_OVERRIDE_STOP")
        manifest = sources()
        aws_path = "/usr/local/bin/aws" if Path("/usr/local/bin/aws").exists() else "/usr/bin/aws"
        aws, ssh, keygen = (secure_tool(p) for p in (aws_path, "/usr/bin/ssh", "/usr/bin/ssh-keygen"))
        ca = Path("/etc/pki/tls/certs/ca-bundle.crt").resolve(strict=True)
        for p in (ca, *ca.parents):
            need(p.stat().st_uid == 0 and not p.stat().st_mode & 0o022, "AWS_TLS_PREREQUISITE_STOP")
        need(ca.is_file() and sys.stdin.isatty(), "OWNER_APPROVAL_REQUIRED")
        print("Type " + APPROVAL + ": ", file=sys.stderr, end="", flush=True)
        need(input() == APPROVAL, "OWNER_APPROVAL_REQUIRED")
        def interrupted(_signum, _frame):
            raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM, interrupted)
        state = Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".flop-r1162"
        need(ROOT != state and state not in ROOT.parents and ROOT not in state.parents, "ATTEMPT_PATH_STOP")
        result = owner_run(manifest, aws, ssh, keygen, state)
        print(canonical(result).decode())
        return 0
    except BaseException as error:
        code = str(error) if type(error) is Stop and re.fullmatch("[A-Z0-9_]{4,64}", str(error)) else "R1162_UNVERIFIED_STOP"
        print(json.dumps(dict(task="R1162", code=code, m2="NO_GO", cutover="NO_GO",
                             ssh_login_prebounded=False, oci_retirement="STRICT_NO_GO")))
        return 42


if __name__ == "__main__":
    raise SystemExit(main())
