"""Focused R1066 SSH relay transport checks; never contacts a real host."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "packaging/migration/r1066_ciphertext_ssh_relay.py"
spec = importlib.util.spec_from_file_location("r1066_ciphertext_ssh_relay", SOURCE)
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
AID = "ab" * 16

def samples():
    rows = [(n, b) for n, b in (("header.bin", b"H"), ("part-0000.bin", b"B"),
                                 ("commit.bin", b"C"))]
    return {"schema_version": 1, "archive_id": AID,
            "files": [{"name": n, "bytes": len(b),
                       "sha256": hashlib.sha256(b).hexdigest()} for n, b in rows]}

def test_pipe_guest_exact_git_blob_pin():
    path = SOURCE.with_name("r1066_ciphertext_pipe.py")
    guest = relay.pinned_guest(path)
    assert guest.startswith("import base64;exec(compile(")
    with pytest.raises(relay.Stop, match="GUEST_PIN_STOP"):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "fake.py"
            fake.write_text("print(42)", encoding="utf-8")
            relay.pinned_guest(fake)

def test_real_local_binary_subprocess_pair_without_network(monkeypatch):
    payload = bytes.fromhex("00ff80a500fe")
    row = {"name":"part-0000.bin","bytes":len(payload),
           "sha256":hashlib.sha256(payload).hexdigest()}
    monkeypatch.setattr(relay, "control", lambda *a, **k:
                        {"state":"ABSENT","offset":0,"sha256":relay.EMPTY})
    def fake_ssh(base, guest, arguments, *, source=False):
        if source:
            return [sys.executable, "-c",
                    "import sys;sys.stdout.buffer.write(bytes.fromhex('" +
                    payload.hex() + "'))"]
        receipt = json.dumps({"operation":"CIPHERTEXT_STAGED_ONLY",
                              "bytes":len(payload),"cutover":"NO_GO",
                              "oci_retirement":"STRICT_NO_GO"})
        script = ("import sys;data=sys.stdin.buffer.read();"
                  "assert data==bytes.fromhex('" + payload.hex() + "');"
                  "sys.stdout.write(" + repr(receipt) + ")")
        return [sys.executable, "-c", script]
    monkeypatch.setattr(relay, "remote", fake_ssh)
    relay.relay_file(["OCI"], ["K137"], "CODE", "/private/sealed",
                     AID, row, timeout=5)

@pytest.mark.parametrize("status", [
    {"state":"COMPLETE","offset":1,"sha256":relay.EMPTY},
    {"state":"ABSENT","offset":1,"sha256":relay.EMPTY},
    {"state":"PARTIAL","offset":2,"sha256":"INVALID"},
    {"state":"COMPLETE","offset":0,"sha256":relay.EMPTY},
])
def test_wrong_resume_never_executes_sender(monkeypatch, status):
    monkeypatch.setattr(relay, "control", lambda *a, **k:status)
    monkeypatch.setattr(relay, "remote",
                        lambda *a, **k:pytest.fail("remote started after invalid offset"))
    with pytest.raises(relay.Stop):
        relay.relay_file(["src"], ["dest"], "CODE", "/private/sealed",
                         AID, samples()["files"][1])

def test_sender_wrong_length_cannot_get_success_receipt(monkeypatch):
    monkeypatch.setattr(relay, "control", lambda *a, **k:
                        {"state":"ABSENT","offset":0,"sha256":relay.EMPTY})
    def bad_source(base, guest, args, *, source=False):
        if source:
            return [sys.executable, "-c",
                    "import sys;sys.stdout.buffer.write(b'TWO-BYTES')"]
        return [sys.executable, "-c",
                "import sys;sys.stdin.buffer.read();sys.exit(42)"]
    monkeypatch.setattr(relay, "remote", bad_source)
    with pytest.raises(relay.Stop):
        relay.relay_file(["src"], ["dst"], "CODE", "/private/sealed",
                         AID, samples()["files"][1], timeout=5)

def test_source_inventory_order_is_not_self_authorizing(monkeypatch):
    inv = samples()
    inv["files"][1]["name"] = "part-0001.bin"
    monkeypatch.setattr(relay, "control", lambda *a, **k: inv)
    with pytest.raises(relay.Stop, match="PART_SEQUENCE_STOP"):
        relay.inventory(["oci"], "CODE", "/private/sealed", AID)

def test_transfer_orders_header_parts_commit_and_full_mirror(monkeypatch):
    inv = samples()
    calls = []
    def control(base, guest, args, *, source=False, data=None):
        calls.append(args[0])
        if args[0] == "inventory": return inv
        if args[0] == "init":
            return {"operation":"CIPHERTEXT_QUARANTINE_ONLY","cutover":"NO_GO"}
        if args[0] == "verify":
            assert json.loads(data) == inv
            return {"operation":"CIPHERTEXT_MIRROR_BYTES_EQUAL_ONLY",
                    "files":3, "cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}
        pytest.fail("unexpected remote control command")
    monkeypatch.setattr(relay, "control", control)
    monkeypatch.setattr(relay, "relay_file",
                        lambda src, dst, guest, root, aid, row:
                        calls.append(row["name"]))
    report = relay.relay(["oci"], ["k137"], "CODE", "/private/sealed", AID)
    assert calls == ["inventory", "init", "header.bin", "part-0000.bin",
                     "commit.bin", "verify"]
    assert report["cutover"] == "NO_GO"
    assert report["oci_retirement"] == "STRICT_NO_GO"

def test_output_bound_real_child_is_stopped_not_buffered_unbounded():
    with pytest.raises(relay.Stop, match="OUTPUT_SIZE_STOP"):
        relay.short_run([sys.executable, "-c",
                         "import sys;sys.stdout.buffer.write(b'A'*70000)"],
                        timeout=5)

def test_no_implicit_owner_action_or_secret_handling_in_code():
    text = SOURCE.read_text(encoding="utf-8")
    for forbidden in ("oci instance delete", "terraform destroy",
                      "wallet.private_key", "oci.vault", "systemctl restart",
                      "ssh-keyscan", "R987 V2 recovery code"):
        assert forbidden not in text
    assert "--allow-disarmed-ciphertext-transfer" in text
