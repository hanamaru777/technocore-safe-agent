"""R1129 isolated K137 ciphertext receiver: offline synthetic tests only."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "packaging/migration/r1129_k137_ciphertext_receive.py"
spec = importlib.util.spec_from_file_location("r1129_k137", PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def setup_receiver(tmp_path, monkeypatch):
    parent = tmp_path / "disarmed"
    parent.mkdir(mode=0o700)
    monkeypatch.setattr(mod, "ROOT", parent)
    monkeypatch.setattr(mod, "EXPECTED_UID", os.geteuid())
    monkeypatch.setattr(mod, "MIN_RESERVE", 0)
    return parent


def valid_stream(tmp_path, monkeypatch):
    # R1084 real encrypted framing from synthetic, separately controlled
    # application/state roots; never uses a real source secret.
    src, dst = tmp_path / "app", tmp_path / "state"
    src.mkdir(mode=0o700)
    dst.mkdir(mode=0o700)
    (dst / "signer").mkdir(mode=0o700)
    (dst / "verified-did.json").write_bytes(b'{"did":"synthetic"}')
    (dst / "nonces.json").write_bytes(b'{"n":1}')
    (dst / "signer/oracle-signer-receipts.json").write_bytes(b'{"receipts":{}}')
    r1128 = ROOT / "packaging/migration/r1128_provisional_preseed.py"
    sp = importlib.util.spec_from_file_location("r1129_test_producer", r1128)
    P = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(P)
    monkeypatch.setattr(P, "APP", src)
    monkeypatch.setattr(P, "STATE", dst)
    monkeypatch.setattr(P, "_original_host", lambda scope: None)
    monkeypatch.setattr(P, "_mount_guard", lambda: None)
    monkeypatch.setattr(P, "pressure", lambda: None)
    stream = io.BytesIO()
    P.preseed_live_to_stream({}, b"synthetic-independent-recovery-secret-64bytes", stream)
    return stream.getvalue()


def test_real_encrypted_preseed_receipt_cannot_activate(tmp_path, monkeypatch):
    if os.name != "posix": pytest.skip("posix-only receiver")
    parent = setup_receiver(tmp_path, monkeypatch)
    data = valid_stream(tmp_path, monkeypatch)
    host = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
    report = mod.receive(io.BytesIO(data), "a" * 32, host)
    assert report["result"] == "PROVISIONAL_CIPHERTEXT_STORED_ONLY"
    assert report["aead_verified"] is False
    assert report["source_complete"] is False
    assert report["cutover"] == "NO_GO"
    assert report["activated"] is False
    files = {x.name for x in (parent / ("r1129-" + "a" * 32)).iterdir()}
    assert {"header.bin", "commit.bin", "part-0000.bin"} <= files
    assert not any(x.name.endswith(".pending") for x in
                   (parent / ("r1129-" + "a" * 32)).iterdir())


def test_wrong_host_and_unapproved_target_stop_before_write(tmp_path, monkeypatch):
    if os.name != "posix": pytest.skip("posix-only receiver")
    parent = setup_receiver(tmp_path, monkeypatch)
    source = io.BytesIO(b"untrusted")
    with pytest.raises(mod.Stop, match="K137_HOST_STOP"):
        mod.receive(source, "b" * 32, "f" * 64)
    assert list(parent.iterdir()) == []
    host = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
    with pytest.raises(mod.Stop, match="ARCHIVE_ID_STOP"):
        mod.receive(source, "../bad", host)
    assert list(parent.iterdir()) == []


def test_bad_stream_does_not_create_completed_archive(tmp_path, monkeypatch):
    if os.name != "posix": pytest.skip("posix-only receiver")
    parent = setup_receiver(tmp_path, monkeypatch)
    host = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
    with pytest.raises(Exception):
        mod.receive(io.BytesIO(b"FLOPST01\x00"), "c" * 32, host)
    child = parent / ("r1129-" + "c" * 32)
    assert not (child / "commit.bin").exists()


def test_existing_ciphertext_never_overwritten(tmp_path, monkeypatch):
    if os.name != "posix": pytest.skip("posix-only receiver")
    parent = setup_receiver(tmp_path, monkeypatch)
    name = "r1129-" + "d" * 32
    target = parent / name
    target.mkdir()
    (target / "header.bin").write_bytes(b"existing")
    host = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
    with pytest.raises(mod.Stop, match="NEW_TARGET_REQUIRED"):
        mod.receive(io.BytesIO(b"anything"), "d" * 32, host)
    assert (target / "header.bin").read_bytes() == b"existing"


def test_tampered_stream_cannot_commit(tmp_path, monkeypatch):
    if os.name != "posix": pytest.skip("posix-only receiver")
    parent = setup_receiver(tmp_path, monkeypatch)
    wire = bytearray(valid_stream(tmp_path, monkeypatch))
    wire[len(wire)//2] ^= 1
    host = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
    with pytest.raises(Exception):
        mod.receive(io.BytesIO(wire), "e" * 32, host)
    assert not (parent / ("r1129-" + "e" * 32) / "commit.bin").exists()


def test_cli_never_activates_or_reads_signing_material():
    source = PATH.read_text(encoding="utf8")
    assert "tradebot" not in source.lower().replace("tradebot_reserve_stop", "")
    assert "systemctl" not in source and "vault" not in source.lower()
    assert "subprocess.Popen" not in source
    assert '"/var/lib/flop-migration-r1066/disarmed"' in source
    assert "MIN_RESERVE = 20 * 1024**3" in source
