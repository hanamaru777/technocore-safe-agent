"""R1015 source-only tests: no host SSH, no paid cloud, no real state reads."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "packaging/archive/r1015_stream_transport.py"
SPEC = importlib.util.spec_from_file_location("r1015_stream_transport", SCRIPT)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class Feed(io.BytesIO):
    def fileno(self):
        return 0


@pytest.fixture
def storage(tmp_path, monkeypatch):
    monkeypatch.setattr(m.os, "isatty", lambda unused: False)
    monkeypatch.setattr(m, "receiver_host_guard", lambda: None)
    # GitHub ephemeral runner does not have K137's real 20GiB free-space floor.
    # Production ENFORCEMENT is tested in a separate synthetic pressure case.
    monkeypatch.setattr(m, "enough_space", lambda d, n, f: None)
    recovery_key_path = tmp_path / "archive-key-private"
    recovery_key_path.write_text("a" * 64 + "\n")
    recovery_key_path.chmod(0o600)
    return tmp_path, recovery_key_path


def sealed(storage, plain):
    folder, recovery_key_path = storage
    out = io.BytesIO()
    info = m.seal_stream(Feed(plain), out, recovery_key_path, len(plain),
                         hashlib.sha256(plain).hexdigest())
    return out.getvalue(), info


def test_roundtrip_interoperates_with_original_r1001_verify(storage, capsys):
    folder, recovery_key_path = storage
    plain = os.urandom(2 * 1024 * 1024 + 731)
    payload, info = sealed(storage, plain)
    archive = folder / "new-archive"
    result = m.receive_stream(io.BytesIO(payload), archive)
    assert result["parts"] == info["parts"]
    assert result["plaintext_not_written"] is True
    assert result["restore_and_source_epoch_not_proven"] is True
    assert sorted(p.name for p in archive.iterdir()) == sorted(
        ["header.bin", "commit.bin"] +
        [f"part-{i:04d}.bin" for i in range(info["parts"])])
    assert (archive / "header.bin").read_bytes().startswith(b"FLOPENV1")
    for path in archive.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert plain[:256] not in path.read_bytes()
    m.FORMAT.verify(archive, recovery_key_path)
    out = capsys.readouterr().out
    assert "AUTHENTICATED_CIPHERTEXT_ROUNDTRIP=PASS" in out
    assert "WRITER_EPOCH_NOT_PROVEN=YES" in out


def test_multiple_bounded_parts_use_real_encrypted_frames(storage, monkeypatch):
    monkeypatch.setattr(m.FORMAT, "SHARD_LIMIT", m.FORMAT.CHUNK_BYTES + 4096)
    plain = os.urandom(3 * m.FORMAT.CHUNK_BYTES + 100)
    payload, info = sealed(storage, plain)
    assert info["parts"] >= 2
    folder, recovery_key_path = storage
    archive = folder / "multi-archive"
    assert m.receive_stream(io.BytesIO(payload), archive)["parts"] == info["parts"]
    m.FORMAT.verify(archive, recovery_key_path)


def test_expected_source_pin_required_before_authenticated_commit(storage):
    folder, recovery_key_path = storage
    plain = b"synthetic-private-source" * 100
    for count, digest in [(len(plain)-1, hashlib.sha256(plain).hexdigest()),
                          (len(plain), "0" * 64)]:
        out = io.BytesIO()
        with pytest.raises(m.Stop, match="SOURCE_"):
            m.seal_stream(Feed(plain), out, recovery_key_path, count, digest)
        assert b"FLOPCMT1" not in out.getvalue()
        with pytest.raises(m.Stop):
            m.receive_stream(io.BytesIO(out.getvalue()), folder / ("fail" + str(count)))


def test_sender_rejects_empty_and_malformed_external_digest(storage):
    _, recovery_key_path = storage
    for expected, digest in [(0, "a"*64), (12, "A"*64), (12, "")]:
        with pytest.raises(m.Stop, match="EXPECTED_"):
            m.seal_stream(Feed(b"abc"), io.BytesIO(), recovery_key_path, expected, digest)


def test_wrong_wire_magic_never_creates_destination(storage):
    folder, _ = storage
    target = folder / "no-write"
    with pytest.raises(m.Stop, match="WIRE_MAGIC_STOP"):
        m.receive_stream(io.BytesIO(b"BADSTART"), target)
    assert not target.exists()


def test_corrupted_cipher_frame_is_rejected_before_part_commit(storage):
    folder, _ = storage
    wire, _ = sealed(storage, os.urandom(m.FORMAT.CHUNK_BYTES + 17))
    damaged = bytearray(wire)
    offset = len(m.MAGIC)
    while offset < len(damaged):
        kind, size = m.PACKET.unpack(damaged[offset:offset+m.PACKET.size])
        offset += m.PACKET.size
        if kind == b"F":
            damaged[offset + size - 1] ^= 3
            break
        offset += size
    else:
        raise AssertionError("Expected encrypted frame")
    target = folder / "corrupt"
    with pytest.raises(m.Stop, match="PART_DIGEST_STOP"):
        m.receive_stream(io.BytesIO(damaged), target)
    assert not (target / "commit.bin").exists()


def test_truncated_wire_never_completes(storage):
    folder, _ = storage
    wire, _ = sealed(storage, b"fixture-input" * 222)
    for tail in [wire[:len(m.MAGIC)+m.PACKET.size+4],
                 wire[:-m.PACKET.size], wire[:-1]]:
        with pytest.raises(m.Stop, match="WIRE_TRUNCATED_STOP"):
            m.receive_stream(io.BytesIO(tail), folder / ("part-" + str(len(tail))))


def test_trailing_unexpected_bytes_rejected(storage):
    folder, _ = storage
    wire, _ = sealed(storage, b"fixture-input" * 100)
    with pytest.raises(m.Stop, match="TRAILING_WIRE_BYTES_STOP"):
        m.receive_stream(io.BytesIO(wire + b"extra"), folder / "extra")


def test_existing_target_never_overwritten(storage):
    folder, _ = storage
    wire, _ = sealed(storage, b"fixture-input" * 123)
    path = folder / "existing"
    path.mkdir(mode=0o700)
    (path / "protected").write_text("keep")
    with pytest.raises(FileExistsError):
        m.receive_stream(io.BytesIO(wire), path)
    assert (path / "protected").read_text() == "keep"


def test_refuse_symlinked_directory_and_nonprivate_parent(storage):
    folder, _ = storage
    wire, _ = sealed(storage, b"fixture-input" * 123)
    target = folder / "elsewhere"
    target.mkdir()
    link = folder / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(m.Stop, match="PARENT_SYMLINK_STOP"):
        m.receive_stream(io.BytesIO(wire), link / "archive")
    exposed = folder / "exposed"
    exposed.mkdir(mode=0o755)
    with pytest.raises(m.Stop, match="PARENT_CUSTODY_STOP"):
        m.receive_stream(io.BytesIO(wire), exposed / "archive")


def test_disk_floor_fail_closed_when_free_space_would_cross_reserve(monkeypatch):
    monkeypatch.setattr(m.os, "fstatvfs",
                        lambda fd: SimpleNamespace(f_bavail=100, f_frsize=4096))
    with pytest.raises(m.Stop, match="DISK_FLOOR_STOP"):
        m.enough_space(1, 1, m.FLOOR_BYTES)
    monkeypatch.setattr(m, "receiver_host_guard", lambda: None)
    with pytest.raises(m.Stop, match="DISK_FLOOR_MINIMUM_STOP"):
        m.receive_stream(io.BytesIO(b""), Path("/tmp/dummy"),
                         floor=m.FLOOR_BYTES - 1)


def test_receiver_refuses_missing_or_symlinked_k137_markers(monkeypatch):
    monkeypatch.setattr(m.os, "geteuid", lambda: 10001)
    original_lstat = os.lstat
    names = ("/opt/tradebot-k137-private", "/opt/flop-shadow")
    for missing in names:
        with monkeypatch.context() as patch:
            def fake_lstat(path, *a, **kw):
                if str(path) == missing:
                    raise FileNotFoundError()
                if str(path) in names:
                    return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700)
                return original_lstat(path, *a, **kw)
            patch.setattr(m.os, "lstat", fake_lstat)
            with pytest.raises(m.Stop, match="K137_REQUIRED_MARKER_STOP"):
                m.receiver_host_guard()
    with monkeypatch.context() as patch:
        def fake_symlink(path, *a, **kw):
            if str(path) in names:
                return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777)
            return original_lstat(path, *a, **kw)
        patch.setattr(m.os, "lstat", fake_symlink)
        with pytest.raises(m.Stop, match="K137_REQUIRED_MARKER_STOP"):
            m.receiver_host_guard()


def test_receiver_refuses_original_oracle_runtime_even_with_markers(monkeypatch):
    monkeypatch.setattr(m.os, "geteuid", lambda: 10001)
    original_lstat = os.lstat
    original_exists = m.Path.exists
    with monkeypatch.context() as patch:
        patch.setattr(m.os, "lstat", lambda path, *a, **kw:
                      SimpleNamespace(st_mode=stat.S_IFDIR | 0o700)
                      if str(path) in ("/opt/tradebot-k137-private", "/opt/flop-shadow")
                      else original_lstat(path, *a, **kw))
        patch.setattr(m.Path, "exists", lambda self:
                      True if str(self) == "/opt/technocore-safe-agent"
                      else original_exists(self))
        with pytest.raises(m.Stop, match="ORIGINAL_OCI_RUNTIME_REFUSED"):
            m.receiver_host_guard()


def test_no_network_shell_mutation_or_live_service_calls():
    content = SCRIPT.read_text()
    compile(content, str(SCRIPT), "exec")
    for bad in ("subprocess.", "paramiko", "systemctl", "os.system(",
                "shutil.rmtree", "os.remove(", "os.unlink(", "SIGN_SEED"):
        assert bad not in content
    assert "DISK_FLOOR_STOP" in content
    assert "SOURCE_PIN_MISMATCH_STOP" in content
    assert "R1001" in content
