"""R1084 binary stream integration fixtures. No SSH, real hosts or live services."""
import importlib.util
import io
import os
from pathlib import Path
import sqlite3
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging/migration/r1084_offhost_ciphertext_stream.py"
spec = importlib.util.spec_from_file_location("r1084_stream_test", SOURCE)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
POSIX = pytest.mark.skipif(os.name != "posix", reason="POSIX private-directory custody only")


@pytest.fixture
def offline(tmp_path):
    os.chmod(tmp_path, 0o700)
    app, state = tmp_path / "offline-app", tmp_path / "offline-state"
    app.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    (app / "binary.dat").write_bytes(bytes(range(256)) * 9000)
    (app / "internal").symlink_to("binary.dat")
    (state / "nonce.json").write_bytes(b"synthetic-nonce-record")
    for db in m.T.G.DATABASES:
        with sqlite3.connect(state / db) as conn:
            conn.execute("CREATE TABLE messages(seq INTEGER PRIMARY KEY, text TEXT)")
            conn.execute("INSERT INTO messages VALUES (1, 'offline fixture')")
    return tmp_path, app, state, os.urandom(48)


@POSIX
def test_real_encrypted_wire_roundtrip_and_disarmed_restore(offline):
    root, app, state, recovery = offline
    output = io.BytesIO()
    source_receipt = m.seal_offline_to_stream(app, state, recovery, output,
                                              source_head=m.T.HEAD)
    assert source_receipt["source_epoch"] == "PROVISIONAL_UNFENCED"
    assert source_receipt["cutover"] == "NO_GO"
    assert not (root / "archive").exists()
    archive = root / "archive"
    receipt = m.receive_offhost_ciphertext(io.BytesIO(output.getvalue()), archive,
                                           quota_bytes=32 * 1024**2)
    assert receipt["operation"] == "OFFHOST_CIPHERTEXT_ONLY"
    assert receipt["aead_verified"] is False
    assert "commit.bin" in [p.name for p in archive.iterdir()]
    # Independently authenticated by the EXISTING R1066 AES-GCM decoder.
    assert sum(len(b) for b in m.T.decrypt(archive, recovery)) > 2_300_000
    result = m.T.restore(archive, root / "restored", recovery, quota=32 * 1024**2)
    assert result["operation"] == "verified"
    assert result["common_sqlite_epoch"] == "unknown"
    assert (root / "restored/app/binary.dat").read_bytes() == (app / "binary.dat").read_bytes()
    assert (root / "restored/app/internal").readlink() == Path("binary.dat")


@POSIX
@pytest.mark.parametrize("failure", ["truncated", "wrong_header", "wrong_frame_hash",
                                     "quota", "extra", "destination_exists"])
def test_unfinished_or_tampered_wire_never_becomes_authenticated(offline, failure):
    root, app, state, recovery = offline
    output = io.BytesIO()
    m.seal_offline_to_stream(app, state, recovery, output, source_head=m.T.HEAD)
    wire = bytearray(output.getvalue())
    target = root / "received"
    quota = 32 * 1024**2
    if failure == "truncated": wire = wire[:-11]
    if failure == "wrong_header": wire[0] ^= 1
    if failure == "wrong_frame_hash": wire[-55] ^= 1
    if failure == "quota": quota = 10
    if failure == "extra": wire.extend(b"extra")
    if failure == "destination_exists": target.mkdir(mode=0o700)
    with pytest.raises((m.Stop, m.T.Stop, OSError)):
        m.receive_offhost_ciphertext(io.BytesIO(wire), target, quota_bytes=quota)
    if failure != "destination_exists" and target.exists():
        assert not (target / "DISARMED-RESTORE-RECEIPT.json").exists()
    if failure == "truncated":
        # A full encrypted commit is NOT promoted before terminal wire EOF.
        assert not (target / "commit.bin").exists()


@POSIX
def test_source_drift_cannot_write_final_commit_to_wire(offline, monkeypatch):
    root, app, state, recovery = offline
    real = m.T.pack

    def drifting(*args):
        iterator = iter(real(*args))
        yield next(iterator)
        (app / "binary.dat").write_bytes(b"mutated")
        yield from iterator
    monkeypatch.setattr(m.T, "pack", drifting)
    with pytest.raises(m.T.Stop, match="SOURCE_DRIFT"):
        m.seal_offline_to_stream(app, state, recovery, io.BytesIO(),
                                  source_head=m.T.HEAD)


def test_no_live_oci_source_or_windows_acl_bypass(tmp_path):
    with pytest.raises((m.T.Stop, OSError)):
        m.T.offline_source(Path("/var/lib/technocore-safe-agent"))
    assert m.T.HEAD
    assert m.T.MAX_ARCHIVE_ENTRIES == 100000
    assert m.T.MAX_ARCHIVE_DEPTH == 48
    assert "LIVE_SOURCE_FENCE_UNPROVEN" in (ROOT / "packaging/migration/r1066_transfer.py").read_text()


@POSIX
def test_r1084_partial_output_stream_is_never_silent_truncation(offline):
    root, app, state, recovery = offline
    class PartialSink(io.BytesIO):
        def write(self, data):
            return super().write(data[:5])
    sink = PartialSink()
    m.seal_offline_to_stream(app, state, recovery, sink, source_head=m.T.HEAD)
    stage = root / "shortwrites"
    m.receive_offhost_ciphertext(io.BytesIO(sink.getvalue()), stage,
                                 quota_bytes=32 * 1024**2)
    assert sum(len(b) for b in m.T.decrypt(stage, recovery)) > 2_300_000


@POSIX
def test_r1084_receiver_refuses_protected_root_before_creating_files(offline, monkeypatch):
    root = offline[0]
    protected = root / "do-not-touch"
    protected.mkdir(mode=0o700)
    (protected / "keep").write_text("keep")
    monkeypatch.setattr(m.T, "BLOCKED_ROOTS", (str(protected),))
    with pytest.raises(m.Stop, match="PROTECTED_TARGET_STOP"):
        m.receive_offhost_ciphertext(io.BytesIO(m.MAGIC), protected / "archive",
                                     quota_bytes=32 * 1024**2)
    assert not (protected / "archive").exists()
    assert (protected / "keep").read_text() == "keep"
