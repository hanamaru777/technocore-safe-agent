"""R1066 ciphertext-only two-host SSH relay. This does not archive live state,
restore plaintext, activate an agent, authorize cutover, or retire OCI.
Requires separately verified existing credentials/host keys, an already sealed
root-owned OCI archive and an already private, bounded K137 quarantine.
The exact reviewed r1066_ciphertext_pipe source runs in remote Python memory.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import threading

PIPE_BLOB = "f87ae504c092ca941345bc0052b27e72c932a00c"
LIMIT = 65536
CHUNK = 1024 * 1024
EMPTY = hashlib.sha256(b"").hexdigest()
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")

class Stop(ValueError):
    pass

def need(condition, code):
    if not condition:
        raise Stop(code)

def parse_json(data):
    need(type(data) is bytes and 0 < len(data) <= LIMIT, "CONTROL_SIZE_STOP")
    def strict(pairs):
        result = {}
        for k, v in pairs:
            need(k not in result, "DUPLICATE_JSON_STOP")
            result[k] = v
        return result
    return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=strict)

def pinned_guest(path):
    data = Path(path).read_bytes()
    blob = b"blob " + str(len(data)).encode() + b"\0" + data
    need(hashlib.sha1(blob).hexdigest() == PIPE_BLOB, "GUEST_PIN_STOP")
    # Encoded audited public source code, never private keys or archive bytes.
    return ("import base64;exec(compile(base64.b64decode('" +
            base64.b64encode(data).decode("ascii") +
            "'),'<r1066-ciphertext>', 'exec'))")

def ssh_base(binary, host, user, identity, known_hosts, pin, *, source=False):
    try:
        ip = ipaddress.IPv4Address(host)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise Stop("HOST_STOP") from exc
    need(ip.is_global and str(ip) == host, "HOST_STOP")
    need(re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", user) is not None, "USER_STOP")
    need((source and host == "140.238.55.171" and user == "ubuntu") or
         (not source and host != "140.238.55.171" and user != "root"),
         "HOST_ROLE_STOP")
    need(type(pin) is str and HEX64.fullmatch(pin), "HOST_PIN_STOP")
    known = Path(known_hosts)
    need(known.is_file() and 10 < known.stat().st_size <= 4096,
         "HOST_PIN_STOP")
    data = known.read_bytes()
    need(hashlib.sha256(data).hexdigest() == pin, "HOST_PIN_STOP")
    lines = data.decode("ascii", "strict").splitlines()
    need(len(lines) == 1 and re.fullmatch(
        re.escape(host) + r" (ssh-ed25519|ecdsa-sha2-nistp256) [A-Za-z0-9+/]+={0,2}",
        lines[0]) is not None, "HOST_PIN_STOP")
    key = Path(identity)
    need(key.is_file() and 0 < key.stat().st_size <= 65536, "IDENTITY_STOP")
    if os.name != "nt":
        need(not (key.stat().st_mode & 0o077), "IDENTITY_ACL_STOP")
    need(Path(binary).is_file(), "SSH_BINARY_STOP")
    null = "NUL" if os.name == "nt" else "/dev/null"
    return [str(binary), "-F", null, "-T", "-i", str(key),
            "-o", "UserKnownHostsFile=" + str(known),
            "-o", "GlobalKnownHostsFile=" + null,
            "-o", "StrictHostKeyChecking=yes",
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no", "-o", "GSSAPIAuthentication=no",
            "-o", "HostbasedAuthentication=no", "-o", "UpdateHostKeys=no",
            "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no", "-o", "PermitLocalCommand=no",
            "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
            "-o", "CanonicalizeHostname=no", "-o", "ConnectionAttempts=1",
            "-o", "ConnectTimeout=7", "-o", "ServerAliveInterval=10",
            "-o", "ServerAliveCountMax=2", user + "@" + host]

def remote(base, guest, args, *, source=False):
    fixed = ["/usr/bin/python3", "-I", "-B", "-c", guest, *args]
    if source:
        fixed = ["sudo", "-n", *fixed]
    return [*base, " ".join(shlex.quote(a) for a in fixed)]

def short_run(args, data=None, *, timeout=90):
    need(data is None or (type(data) is bytes and len(data) <= LIMIT),
         "INPUT_SIZE_STOP")
    proc = None
    timer = None
    try:
        proc = subprocess.Popen(args, stdin=subprocess.PIPE if data is not None else
                                subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        timer = threading.Timer(timeout, proc.kill)
        timer.daemon = True
        timer.start()
        if data is not None:
            proc.stdin.write(data)
            proc.stdin.close()
        result = proc.stdout.read(LIMIT + 1)
        need(len(result) <= LIMIT, "OUTPUT_SIZE_STOP")
        need(proc.wait(timeout=15) == 0, "REMOTE_CONTROL_STOP")
        return result
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Stop("REMOTE_CONTROL_STOP") from exc
    finally:
        if timer is not None:
            timer.cancel()
        if proc is not None:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            if proc.stdout is not None:
                proc.stdout.close()

def control(base, guest, args, *, source=False, data=None):
    return parse_json(short_run(remote(base, guest, args, source=source), data))

def inventory(src, guest, root, aid):
    need(type(aid) is str and HEX32.fullmatch(aid), "ARCHIVE_ID_STOP")
    need(type(root) is str and re.fullmatch(r"/[A-Za-z0-9_./-]{1,255}", root)
         and all(p not in ("", ".", "..") for p in root[1:].split("/")),
         "SOURCE_PATH_STOP")
    result = control(src, guest, ["inventory", "--archive-id", aid,
                                 "--source", root], source=True)
    need(type(result) is dict and set(result) ==
         {"schema_version", "archive_id", "files"} and
         type(result["schema_version"]) is int and
         result["schema_version"] == 1 and result["archive_id"] == aid and
         type(result["files"]) is list, "INVENTORY_STOP")
    rows = result["files"]
    need(3 <= len(rows) <= 258, "PARTS_STOP")
    expected = ["header.bin", *("part-%04d.bin" % i
                                for i in range(len(rows) - 2)), "commit.bin"]
    need([r.get("name") if type(r) is dict else None for r in rows] == expected,
         "PART_SEQUENCE_STOP")
    total = 0
    for row in rows:
        need(type(row) is dict and set(row) == {"name", "bytes", "sha256"}
             and type(row["bytes"]) is int and
             0 < row["bytes"] <= 128 * 1024**2 + 4096 and
             type(row["sha256"]) is str and HEX64.fullmatch(row["sha256"]),
             "INVENTORY_ROW_STOP")
        total += row["bytes"]
    need(total <= 32 * 1024**3, "TOTAL_BYTES_STOP")
    return result

def relay_file(src, dst, guest, root, aid, row, *, timeout=900):
    name, size, digest = row["name"], row["bytes"], row["sha256"]
    state = control(dst, guest, ["status", "--archive-id", aid, "--file", name])
    need(type(state) is dict and set(state) == {"state", "offset", "sha256"}
         and state["state"] in ("ABSENT", "PARTIAL", "COMPLETE") and
         type(state["offset"]) is int and 0 <= state["offset"] <= size and
         type(state["sha256"]) is str and HEX64.fullmatch(state["sha256"]),
         "OFFSET_STOP")
    if state["state"] == "COMPLETE":
        need(state["offset"] == size and state["sha256"] == digest,
             "EXISTING_FILE_MISMATCH")
        return
    pos = state["offset"]
    need(pos < size and (state["state"] != "ABSENT" or
         (pos == 0 and state["sha256"] == EMPTY)), "PARTIAL_STOP")
    recv = remote(dst, guest, ["receive", "--archive-id", aid,
                  "--file", name, "--bytes", str(size), "--sha256", digest,
                  "--offset", str(pos), "--prefix-sha256", state["sha256"]])
    send = remote(src, guest, ["send", "--archive-id", aid, "--source", root,
                  "--file", name, "--bytes", str(size), "--sha256", digest,
                  "--offset", str(pos)], source=True)
    sender = receiver = None
    expired = threading.Event()
    def kill_pair():
        expired.set()
        for proc in (sender, receiver):
            if proc is not None and proc.poll() is None:
                proc.kill()
    timer = threading.Timer(timeout, kill_pair)
    timer.daemon = True
    try:
        receiver = subprocess.Popen(recv, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL)
        sender = subprocess.Popen(send, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL)
        timer.start()
        remaining = size - pos
        while remaining:
            data = sender.stdout.read(min(CHUNK, remaining))
            need(bool(data) and len(data) <= remaining, "SOURCE_SHORT_STOP")
            receiver.stdin.write(data)
            remaining -= len(data)
        need(sender.stdout.read(1) == b"", "SOURCE_LONG_STOP")
        receiver.stdin.close()
        sender.stdout.close()
        need(sender.wait(timeout=15) == 0, "SOURCE_EXIT_STOP")
        receipt = parse_json(receiver.stdout.read(LIMIT + 1))
        need(receiver.wait(timeout=15) == 0 and
             receipt.get("operation") == "CIPHERTEXT_STAGED_ONLY"
             and receipt.get("bytes") == size
             and receipt.get("cutover") == "NO_GO"
             and receipt.get("oci_retirement") == "STRICT_NO_GO",
             "RECEIVER_RECEIPT_STOP")
        need(not expired.is_set(), "TRANSFER_TIMEOUT_STOP")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Stop("TRANSFER_IO_STOP") from exc
    finally:
        timer.cancel()
        for proc in (sender, receiver):
            if proc is not None:
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
                for stream in (proc.stdin, proc.stdout):
                    if stream is not None:
                        try:
                            stream.close()
                        except (OSError, ValueError):
                            # A failed receiver may close its pipe before the
                            # controller's finally block. Preserve STOP.
                            pass

def relay(src, dst, guest, root, aid, *, k137_free_bytes=None):
    inv = inventory(src, guest, root, aid)
    if k137_free_bytes is not None:
        need(type(k137_free_bytes) is int and k137_free_bytes >= 0,
             "DISK_EVIDENCE_STOP")
        encrypted_bytes = sum(row["bytes"] for row in inv["files"])
        # Conservative bound for BOTH ciphertext and later DISARMED restore,
        # plus 10 GiB reserved for the protected colocated TradeBot.
        need(k137_free_bytes >= encrypted_bytes * 2 + 10 * 1024**3,
             "K137_PROTECTED_DISK_HEADROOM_STOP")
    ack = control(dst, guest, ["init", "--archive-id", aid])
    need(ack.get("operation") == "CIPHERTEXT_QUARANTINE_ONLY"
         and ack.get("cutover") == "NO_GO", "INIT_STOP")
    for row in inv["files"]:
        relay_file(src, dst, guest, root, aid, row)
    raw = json.dumps(inv, separators=(",", ":")).encode()
    receipt = control(dst, guest, ["verify", "--archive-id", aid], data=raw)
    need(receipt.get("operation") == "CIPHERTEXT_MIRROR_BYTES_EQUAL_ONLY"
         and receipt.get("files") == len(inv["files"])
         and receipt.get("cutover") == "NO_GO"
         and receipt.get("oci_retirement") == "STRICT_NO_GO", "MIRROR_STOP")
    return {"result": "CIPHERTEXT_MIRROR_BYTES_EQUAL_ONLY",
            "files": len(inv["files"]), "source_epoch": "NOT_PROVEN",
            "plaintext_restore": "NOT_PERFORMED",
            "did_signer": "NOT_PROVEN", "cutover": "NO_GO",
            "oci_retirement": "STRICT_NO_GO"}

def main(args=None):
    parser = argparse.ArgumentParser()
    for k in ("ssh", "source-root", "archive-id", "oci-identity",
              "oci-known-hosts", "oci-known-hosts-sha256", "k137-host",
              "k137-user", "k137-identity", "k137-known-hosts",
              "k137-known-hosts-sha256"):
        parser.add_argument("--" + k, required=True)
    parser.add_argument("--k137-free-bytes", type=int, required=True)
    parser.add_argument("--allow-disarmed-ciphertext-transfer",
                        action="store_true")
    opts = parser.parse_args(args)
    try:
        need(opts.allow_disarmed_ciphertext_transfer, "AUTHORIZATION_STOP")
        guest = pinned_guest(Path(__file__).with_name("r1066_ciphertext_pipe.py"))
        src = ssh_base(opts.ssh, "140.238.55.171", "ubuntu", opts.oci_identity,
                       opts.oci_known_hosts, opts.oci_known_hosts_sha256,
                       source=True)
        dst = ssh_base(opts.ssh, opts.k137_host, opts.k137_user,
                       opts.k137_identity, opts.k137_known_hosts,
                       opts.k137_known_hosts_sha256)
        print(json.dumps(relay(src, dst, guest, opts.source_root,
                               opts.archive_id, k137_free_bytes=opts.k137_free_bytes),
                         sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({"result": "STOP", "cutover": "NO_GO",
                          "oci_retirement": "STRICT_NO_GO"}))
        return 42

if __name__ == "__main__":
    raise SystemExit(main())
