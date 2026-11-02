"""Offline R1151 admission + real audited crypto; no SSH/owner operations.

Keys and file bodies here are fresh synthetic fixtures, never production data.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging/migration/r1151_preseed_owner_bridge.py"
spec = importlib.util.spec_from_file_location("r1151_test", SCRIPT)
B = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = B
spec.loader.exec_module(B)
WINDOWS = sys.platform == "win32"
POSIX = pytest.mark.skipif(os.name != "posix", reason="audited Linux filesystem receiver")


def h(value):
    return hashlib.sha256(value.encode()).hexdigest()


def pub(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def packet(G, key, body):
    return dict(signer=hashlib.sha256(pub(key)).hexdigest(), body=body,
                signature=key.sign(G.DOMAIN + G.canonical(body)).hex())


@pytest.fixture
def admission():
    owner, witness, source = (Ed25519PrivateKey.generate() for _ in range(3))
    now = int(time.time())
    context = dict(campaign=h("synthetic campaign"), host=h("synthetic original"),
                   destination=B.K137, did=h("synthetic did"), source_head=B.HEAD, generation=1)
    report = dict(phase="R1139", result="SOURCE_PRESEED_METADATA_READY", action="READ_ONLY",
                  source_head=B.HEAD, machine_sha256=context["host"],
                  files={name: dict(exists=True, regular=True, single_link=True, within_limit=True, size_bytes=64)
                         for name in ("verified-did", "nonces", "signer-receipts")},
                  data_bytes_exported=0, common_sqlite_epoch="NOT_PROVEN", source_archive="NO_GO",
                  cutover="NO_GO", oci_retirement="STRICT_NO_GO")
    profile = dict(version=1, context=context, owner_public_hex=pub(owner).hex(),
                   witness_public_hex=pub(witness).hex(),
                   excluded_key_ids=[hashlib.sha256(pub(source)).hexdigest()],
                   source_ssh_fingerprint=h("synthetic ecdsa"), destination_ssh_fingerprint=B.K137_KEY,
                   source_metadata_enrollment_digest=B.sha(report))
    enrolled = B.Enrollment(profile, B.sha(profile))
    G = enrolled.G
    request = dict(archive_id="0123456789abcdef" * 2, metadata_report=report)
    request["metadata_proof"] = packet(G, witness, dict(kind="R1151_INDEPENDENT_METADATA", context=context,
        archive_id=request["archive_id"], report_sha256=B.sha(report), observed_at=now-2, expires_at=now+240))
    request["source_approval"] = packet(G, owner, dict(action="provisional_preseed_offhost", context=context,
        binding=B.source_binding(enrolled), approved_at=now-2, expires_at=now+240))
    request["transfer_approval"] = packet(G, owner, dict(action="r1151_preseed_once", context=context,
        binding=B.transfer_binding(enrolled, request), approved_at=now-2, expires_at=now+240))
    return SimpleNamespace(enrolled=enrolled, profile=profile, request=request, now=now,
                           owner=owner, witness=witness, source=source)


def test_independent_dual_grants_preserve_old_authorization_and_new_archive_binding(admission):
    a = admission
    assert B.validate(a.enrolled, a.request, now=a.now)["archive_id"] == a.request["archive_id"]
    a.enrolled.G.authorization(a.request["source_approval"], "provisional_preseed_offhost",
                              B.source_binding(a.enrolled), a.enrolled.trust, a.now)
    assert B.selected() == ["state/verified-did.json", "state/nonces.json", "state/signer/oracle-signer-receipts.json"]
    assert B.MAX_WIRE == 32*1024**2
    # A valid synthetic proof does not enroll a real immutable remote runtime.
    result = B.readiness(a.profile, B.sha(a.profile), a.request, now=a.now)
    assert result["code"] == "INDEPENDENT_SOURCE_RUNTIME_NOT_ENROLLED"
    assert result["ready_for_owner_call"] is False and result["source_bytes_transferred"] == 0


def test_missing_original_identity_stops_without_loading_code(monkeypatch):
    monkeypatch.setattr(B, "load", lambda _: pytest.fail("must stop before loading dependencies"))
    assert B.readiness()["code"] == "SOURCE_IDENTITY_STOP"


@pytest.mark.parametrize("field,value", [
    ("destination_ssh_fingerprint", "f"*64), ("owner_public_hex", "a"*64),
    ("source_ssh_fingerprint", "f"*64), ("version", 2),
])
def test_independently_pinned_enrollment_tamper_rejected(admission, field, value):
    a = admission
    changed = copy.deepcopy(a.profile); changed[field] = value
    with pytest.raises(B.Stop, match="ENROLLMENT_PIN_STOP"):
        B.Enrollment(changed, B.sha(a.profile))


@pytest.mark.parametrize("field", ["destination", "source_head"])
def test_wrong_fixed_destination_or_source_head_even_with_profile_hash(admission, field):
    changed = copy.deepcopy(admission.profile)
    changed["context"][field] = "f"*(40 if field == "source_head" else 64)
    with pytest.raises((B.Stop, admission.enrolled.G.Deny)):
        B.Enrollment(changed, B.sha(changed))


def test_source_or_same_owner_witness_key_cannot_self_enroll(admission):
    for field in ("excluded", "same"):
        changed = copy.deepcopy(admission.profile)
        if field == "excluded": changed["excluded_key_ids"].append(hashlib.sha256(pub(admission.owner)).hexdigest())
        else: changed["witness_public_hex"] = changed["owner_public_hex"]
        with pytest.raises(B.Stop, match="INDEPENDENT_OWNER_ENROLLMENT_STOP"):
            B.Enrollment(changed, B.sha(changed))


@pytest.mark.parametrize("change", ["archive", "signature", "metadata", "expiry", "proof", "extra", "authority"])
def test_untrusted_grant_or_metadata_never_admits_export(admission, change):
    a = admission; request = copy.deepcopy(a.request)
    if change == "archive": request["archive_id"] = "f"*32
    if change == "signature": request["source_approval"]["signature"] = "0"*128
    if change == "metadata": request["metadata_report"]["files"]["nonces"]["size_bytes"] += 1
    if change == "expiry": request["transfer_approval"]["body"]["expires_at"] = a.now-1
    if change == "proof": request["metadata_proof"] = packet(a.enrolled.G, a.owner, request["metadata_proof"]["body"])
    if change == "extra": request["arbitrary_command"] = "NEVER_EXECUTE"
    if change == "authority": request["metadata_report"]["cutover"] = "GO"
    with pytest.raises(B.Stop): B.validate(a.enrolled, request, now=a.now)


@pytest.mark.parametrize("offset", [-1000, 300, 10000])
def test_freshness_and_future_rejection(admission, offset):
    with pytest.raises(B.Stop):
        B.validate(admission.enrolled, admission.request, now=admission.now+offset)


def test_binary_frame_exact_null_bytes_and_wipe_on_both_paths(admission):
    a = admission; recovery = bytearray(bytes(range(48)))
    wire = B.pack_request(a.enrolled, a.request, recovery, now=a.now)
    assert not any(recovery) and wire[:8] == b"R1151S01"
    class Partial(io.BytesIO):
        def read(self, n=-1): return super().read(min(n, 7))
    request, material = B.unpack_request(Partial(wire))
    assert request == a.request and material == bytes(range(48))
    material[:] = b"\0"*len(material)
    invalid = copy.deepcopy(a.request); invalid["archive_id"] = "BAD"
    recovery = bytearray(os.urandom(48))
    with pytest.raises(B.Stop): B.pack_request(a.enrolled, invalid, recovery, now=a.now)
    assert not any(recovery)


@pytest.mark.parametrize("change", ["short", "truncated", "trailing", "large", "duplicate"])
def test_control_framing_fails_closed(admission, change):
    a = admission
    wire = bytes(B.pack_request(a.enrolled, a.request, bytearray(os.urandom(48)), now=a.now))
    if change == "short": wire = b"bad"
    if change == "truncated": wire = wire[:-7]
    if change == "trailing": wire += b"x"
    if change == "large": wire = B.MAGIC + struct.pack(">I", B.MAX_CONTROL+1)
    if change == "duplicate":
        raw = b'{"x":1,"x":2}'
        wire = B.MAGIC+struct.pack(">I", len(raw))+raw+struct.pack(">I", 48)+b"x"*48
    with pytest.raises(B.Stop): B.unpack_request(io.BytesIO(wire))


def receipt():
    return dict(phase="R1129", result="PROVISIONAL_CIPHERTEXT_STORED_ONLY", files=3, bytes=1024,
        aead_verified=False, source_complete=False, sqlite_epoch="NOT_PROVEN", history_finality="UNKNOWN",
        signer_portability="NOT_PROVEN", activated=False, cutover="NO_GO", oci_retirement="STRICT_NO_GO")


@pytest.mark.parametrize("field,value", [("source_complete", True), ("activated", True), ("aead_verified", True),
    ("bytes", 2049), ("phase", "R1151"), ("extra", "private")])
def test_recipient_forgery_or_forwarded_byte_mismatch_rejected(field, value):
    r = receipt(); r[field] = value
    with pytest.raises(Exception): B.checked_receipt(B.canonical(r), 2048)


def test_recipient_receipt_remains_ciphertext_only():
    result = B.checked_receipt(B.canonical(receipt()), 2048)
    assert not result["ready_for_owner_call"] and not result["aead_verified"]
    assert result["oci_retirement"] == "STRICT_NO_GO"


def synthetic_source(admission, tmp_path, monkeypatch):
    # Real audited R1128/R1084 crypto, but ONLY newly created synthetic roots.
    P, M, R = B.load("P"), B.load("M"), B.load("R")
    cache = {"P": P, "M": M, "R": R}; original_load = B.load
    monkeypatch.setattr(B, "load", lambda name: cache[name] if name in cache else original_load(name))
    app, state = tmp_path/"synthetic-app", tmp_path/"synthetic-state"
    app.mkdir(mode=0o700); state.mkdir(mode=0o700); (state/"signer").mkdir(mode=0o700)
    for relative in ("verified-did.json", "nonces.json", "signer/oracle-signer-receipts.json"):
        (state/relative).write_bytes(b"SYNTHETIC-THREE-FILE-ONLY"+b"\0"*40)
    (state/"excluded.data").write_bytes(b"MUST-NEVER-BE-EXPORTED")
    monkeypatch.setattr(P, "APP", app); monkeypatch.setattr(P, "STATE", state)
    monkeypatch.setattr(P, "_original_host", lambda scope: None)
    monkeypatch.setattr(P, "_mount_guard", lambda: None); monkeypatch.setattr(P, "pressure", lambda: None)
    monkeypatch.setattr(M, "inventory", lambda: copy.deepcopy(admission.request["metadata_report"]))
    return P, M, R, state


@POSIX
def test_three_file_real_crypto_to_private_r1129_independent_decrypt(admission, tmp_path, monkeypatch):
    a = admission
    P, M, R, state = synthetic_source(a, tmp_path, monkeypatch)
    before = {p.relative_to(state): p.read_bytes() for p in state.rglob("*") if p.is_file()}
    recovery = os.urandom(48)
    frame = B.pack_request(a.enrolled, a.request, bytearray(recovery), now=a.now)
    wire = io.BytesIO(); B.produce(a.enrolled, io.BytesIO(frame), wire, now=a.now)
    cipher = wire.getvalue()
    assert cipher[:8] == b"FLOPST01" and b"SYNTHETIC-THREE-FILE-ONLY" not in cipher
    root = tmp_path/"private-disarmed"; root.mkdir(mode=0o700)
    monkeypatch.setattr(R, "ROOT", root)
    monkeypatch.setattr(R, "check_host", lambda value: R.need(value == B.K137, "K137_HOST_STOP"))
    monkeypatch.setattr(R.shutil, "disk_usage", lambda _: SimpleNamespace(free=64*1024**3))
    result = B.receive(a.enrolled, a.request, io.BytesIO(cipher), now=a.now)
    summary = B.checked_receipt(B.canonical(result), len(cipher))
    assert summary["aead_verified"] is False and result["source_complete"] is False
    T = P.load("r1066_transfer.py", "r1151_independent_decrypt")
    plain = b"".join(T.decrypt(root/("r1129-"+a.request["archive_id"]), recovery))
    assert b"SYNTHETIC-THREE-FILE-ONLY" in plain and b"MUST-NEVER-BE-EXPORTED" not in plain
    assert {p.relative_to(state): p.read_bytes() for p in state.rglob("*") if p.is_file()} == before
    with pytest.raises(R.Stop, match="NEW_TARGET_REQUIRED"):
        B.receive(a.enrolled, a.request, io.BytesIO(cipher), now=a.now)
    # Accepted reserve threshold remains unchanged; no fallback/resize.
    monkeypatch.setattr(R.shutil, "disk_usage", lambda _: SimpleNamespace(free=20*1024**3))
    with pytest.raises(R.Stop, match="TRADEBOT_RESERVE_STOP"):
        B.receive(a.enrolled, a.request, io.BytesIO(cipher), now=a.now)


@POSIX
def test_source_symlink_and_destination_symlink_fail_closed(admission, tmp_path, monkeypatch):
    a = admission; P, M, R, state = synthetic_source(a, tmp_path, monkeypatch)
    target = state/"nonces.json"; target.unlink(); target.symlink_to(state/"excluded.data")
    output = io.BytesIO()
    with pytest.raises(P.Stop, match="SOURCE_OBJECT_STOP"):
        B.produce(a.enrolled, io.BytesIO(B.pack_request(a.enrolled, a.request, bytearray(os.urandom(48)), now=a.now)), output, now=a.now)
    assert not output.getvalue()
    real = tmp_path/"real-disarmed"; real.mkdir(mode=0o700)
    link = tmp_path/"link-disarmed"; link.symlink_to(real, target_is_directory=True)
    monkeypatch.setattr(R, "ROOT", link)
    monkeypatch.setattr(R, "check_host", lambda _: None)
    with pytest.raises(R.Stop, match="TARGET_LINK_STOP"):
        B.receive(a.enrolled, a.request, io.BytesIO(b""), now=a.now)


@pytest.mark.parametrize("reason", ["SOURCE_HEAD_STOP", "MOUNT_DEVICE_STOP", "ORIGINAL_HOST_STOP"])
def test_original_guard_failure_before_metadata_or_output(admission, monkeypatch, reason):
    a = admission; P = B.load("P")
    def stop(_): raise P.Stop(reason)
    monkeypatch.setattr(P, "_original_host", stop)
    monkeypatch.setattr(B, "load", lambda name: P if name == "P" else pytest.fail("no later dependency"))
    # Validate uses source_binding; retain its exact immutable value first.
    binding = B.source_binding(a.enrolled)
    monkeypatch.setattr(B, "source_binding", lambda _: binding)
    output = io.BytesIO()
    frame = B.pack_request(a.enrolled, a.request, bytearray(os.urandom(48)), now=a.now)
    with pytest.raises(P.Stop, match=reason): B.produce(a.enrolled, io.BytesIO(frame), output, now=a.now)
    assert not output.getvalue()


def test_stale_changed_source_metadata_stops_before_producer(admission, monkeypatch):
    a = admission; P, M = B.load("P"), B.load("M")
    changed = copy.deepcopy(a.request["metadata_report"]); changed["files"]["nonces"]["size_bytes"] += 1
    monkeypatch.setattr(M, "inventory", lambda: changed)
    monkeypatch.setattr(P, "_original_host", lambda _: None)
    monkeypatch.setattr(P, "preseed_live_to_stream", lambda *args: pytest.fail("no export after changed metadata"))
    original_load = B.load
    monkeypatch.setattr(B, "load", lambda name: {"P": P, "M": M}.get(name) or original_load(name))
    frame = B.pack_request(a.enrolled, a.request, bytearray(os.urandom(48)), now=a.now)
    with pytest.raises(B.Stop, match="SOURCE_METADATA_CHANGED_STOP"):
        B.produce(a.enrolled, io.BytesIO(frame), io.BytesIO(), now=a.now)


def test_pins_cover_accepted_source_and_native_dependencies():
    pins = json.loads((SCRIPT.with_name("r1151_source_pins.json")).read_text())
    for name, expected in pins.items():
        raw = (ROOT/name).read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest() == expected, name
    assert pins["packaging/migration/r1128_provisional_preseed.py"] == "2b774c4e83f827f93de94d91258413182080fab0"


def test_readiness_cli_never_opens_ssh_or_reports_authority():
    output = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT)], capture_output=True, timeout=10)
    assert output.returncode == 42 and output.stderr == b""
    assert json.loads(output.stdout)["code"] == "SOURCE_IDENTITY_STOP"
    source = SCRIPT.read_text()
    assert "subprocess" not in source and "socket" not in source
    ps = (ROOT/"packaging/windows/r1151_preseed_owner_onepass.ps1").read_text()
    assert "ssh.exe" not in ps and "Read-Host" not in ps and "Unprotect-R1027" not in ps


def test_untrusted_cli_input_never_echoes_raw_data():
    canary = b"SYNTHETIC-PRIVATE-CONTROL-DO-NOT-ECHO"
    raw = B.PUBLIC_MAGIC + struct.pack(">I", len(canary)) + canary
    output = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT), "--readiness"],
                            input=raw, capture_output=True, timeout=10)
    assert output.returncode == 42 and output.stderr == b""
    assert canary not in output.stdout
    assert json.loads(output.stdout)["code"] == "PUBLIC_ADMISSION_STOP"


def test_no_ssh_authentication_fallback_is_added():
    # Reference-only custody. These scripts are pinned, NEVER invoked here.
    for name, algorithm in (("r1126_original_root_mount_readonly.ps1", "ecdsa-sha2-nistp256"),
                            ("r1136_k137_readonly_ssh_diagnostic.ps1", "ssh-ed25519")):
        code = (ROOT/"packaging/windows"/name).read_text(encoding="utf8")
        for guard in ("StrictHostKeyChecking=yes", "HostKeyAlgorithms="+algorithm,
                      "BatchMode=yes", "IdentitiesOnly=yes", "ClearAllForwardings=yes",
                      "ForwardAgent=no", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                      "IdentityAgent=none", "ProxyCommand=none", "ProxyJump=none", "GlobalKnownHostsFile=NUL"):
            assert guard in code


@pytest.mark.parametrize("size", [0, 1048577])
def test_control_bound_rejected_before_body_read(size):
    with pytest.raises(B.Stop, match="PUBLIC_INPUT_BOUND_STOP"):
        B.unpack_request(io.BytesIO(B.MAGIC+struct.pack(">I", size)))


@pytest.mark.skipif(not WINDOWS, reason="native Windows PowerShell 5.1")
def test_windows_default_stop_precedes_credentials_and_python():
    output = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
        str(ROOT/"packaging/windows/r1151_preseed_owner_onepass.ps1")], capture_output=True, timeout=15)
    assert output.returncode == 42 and output.stderr == b""
    assert json.loads(output.stdout)["code"] == "SOURCE_IDENTITY_STOP"


@pytest.mark.skipif(not WINDOWS, reason="native Windows PowerShell 5.1")
def test_native_ps51_framing_acl_replay_and_mock_binary_peers(admission, tmp_path):
    a = admission
    profile, request = tmp_path/"enrollment.json", tmp_path/"request.json"
    profile.write_bytes(B.canonical(a.profile)); request.write_bytes(B.canonical(a.request))
    output = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
        str(ROOT/"tests/windows/r1151_native_owner_contract.ps1"),
        "-EnrollmentFile", str(profile), "-EnrollmentSha256", B.sha(a.profile),
        "-RequestFile", str(request), "-RequestSha256", B.sha(a.request)],
        capture_output=True, timeout=45, cwd=ROOT)
    assert output.returncode == 0, output.stdout.decode(errors="replace") + output.stderr.decode(errors="replace")
    assert output.stdout.strip() == b"R1151_NATIVE_OFFLINE=PASS"
