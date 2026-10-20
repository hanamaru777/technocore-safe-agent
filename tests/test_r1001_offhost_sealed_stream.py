"""R1001: no OCI/AWS calls, no secrets, no network, pure local tamper tests."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "packaging/archive/offhost-sealed-stream.py"


def call(*args: str, data: bytes | None = None):
    return subprocess.run([sys.executable, "-I", str(SCRIPT), *args], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=25, check=False)


@pytest.fixture
def context(tmp_path):
    priv = tmp_path / "private"
    priv.mkdir(mode=0o700)
    sec = priv / "code"
    arch = priv / "archive"
    r = call("init-secret", "--secret-file", str(sec))
    assert r.returncode == 0, r.stdout
    assert b"SECRET_BYTES_NOT_PRINTED=YES" in r.stdout
    assert sec.stat().st_mode & 0o777 == 0o600
    assert len(sec.read_bytes().strip()) == 64
    return priv, sec, arch


def filled(context, data=b"IMPORTANT payload\n" * 2000):
    _, sec, arch = context
    r = call("seal", "--archive-dir", str(arch), "--secret-file", str(sec), data=data)
    assert r.returncode == 0, (r.stdout, r.stderr)
    return arch, sec, data


def test_real_aes_gcm_full_decrypt_and_no_plaintext_on_disk(context):
    arch, sec, data = filled(context)
    assert {p.name for p in arch.iterdir()} == {"header.bin", "commit.bin", "part-0000.bin"}
    for p in arch.iterdir():
        assert p.stat().st_mode & 0o777 == 0o600
        assert data[:64] not in p.read_bytes()
    assert arch.stat().st_mode & 0o777 == 0o700
    r = call("verify", "--archive-dir", str(arch), "--secret-file", str(sec))
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert b"AUTHENTICATED_CIPHERTEXT_ROUNDTRIP=PASS" in r.stdout
    assert b"SOURCE_AUTHENTICITY_NOT_PROVEN" in r.stdout
    assert b"NOT_RETIREMENT_AUTHORITY" in r.stdout
    assert data[:64] not in r.stdout


def test_handles_incompressible_binary_over_one_megabyte(context):
    payload = os.urandom(1_900_031)
    arch, sec, _ = filled(context, payload)
    r = call("verify", "--archive-dir", str(arch), "--secret-file", str(sec))
    assert r.returncode == 0, r.stdout
    assert f"PLAINTEXT_BYTES={len(payload)}".encode() in r.stdout


def test_wrong_password_rejected_before_plaintext(context):
    arch, sec, data = filled(context)
    bad = sec.parent / "bad-secret"
    bad.write_bytes(os.urandom(32).hex().encode())
    bad.chmod(0o600)
    r = call("verify", "--archive-dir", str(arch), "--secret-file", str(bad))
    assert r.returncode == 42
    assert b"COMMIT_AUTHENTICATION_STOP" in r.stdout
    assert b"IMPORTANT" not in r.stdout


@pytest.mark.parametrize("filename", ["header.bin", "commit.bin", "part-0000.bin"])
def test_cipher_bitflip_fails_closed(context, filename):
    arch, sec, _ = filled(context)
    dest = arch / filename
    b = bytearray(dest.read_bytes())
    b[-1] ^= 0x40
    dest.write_bytes(b)
    r = call("verify", "--archive-dir", str(arch), "--secret-file", str(sec))
    assert r.returncode == 42
    assert b"ROUNDTRIP=PASS" not in r.stdout


def test_archive_truncated_chunk_fails(context):
    arch, sec, _ = filled(context)
    dst = arch / "part-0000.bin"
    dst.write_bytes(dst.read_bytes()[:-9])
    r = call("verify", "--archive-dir", str(arch), "--secret-file", str(sec))
    assert r.returncode == 42


def test_file_unlisted_rejected(context):
    arch, sec, _ = filled(context)
    extra = arch / "evil"
    extra.write_bytes(b"x")
    extra.chmod(0o600)
    r = call("verify", "--archive-dir", str(arch), "--secret-file", str(sec))
    assert r.returncode == 42
    assert b"UNEXPECTED_ARCHIVE_FILES_STOP" in r.stdout


def test_no_unsafe_overwrites_or_second_secret(context):
    arch, sec, data = filled(context)
    before = hashlib.sha256((arch / "commit.bin").read_bytes()).hexdigest()
    r = call("seal", "--archive-dir", str(arch), "--secret-file", str(sec), data=data)
    assert r.returncode == 42
    assert hashlib.sha256((arch / "commit.bin").read_bytes()).hexdigest() == before
    again = call("init-secret", "--secret-file", str(sec))
    assert again.returncode == 42


def test_reject_secret_permissions(context):
    _, sec, arch = context
    sec.chmod(0o644)
    r = call("seal", "--archive-dir", str(arch), "--secret-file", str(sec), data=b"hello")
    assert r.returncode == 42
    assert b"SECRET_FILE_CUSTODY_STOP" in r.stdout
    assert not arch.exists()


def test_reject_empty_source_and_leave_no_valid_commit(context):
    # In fixture context, first is private dir, so get explicit fixture fields.
    priv, sec, path = context
    r = call("seal", "--archive-dir", str(path), "--secret-file", str(sec), data=b"")
    assert r.returncode == 42
    assert b"EMPTY_SOURCE_REFUSED" in r.stdout
    assert path.is_dir()
    assert not (path / "commit.bin").exists()


def test_fail_symlinked_cipher_part_and_dir_escape(context):
    arch, sec, _ = filled(context)
    part = arch / "part-0000.bin"
    actual = sec.parent / "moved.part"
    part.replace(actual)
    part.symlink_to(actual)
    r = call("verify", "--archive-dir", str(arch), "--secret-file", str(sec))
    assert r.returncode == 42


def test_reject_world_readable_archive_dir(context):
    arch, sec, _ = filled(context)
    arch.chmod(0o755)
    r = call("verify", "--archive-dir", str(arch), "--secret-file", str(sec))
    assert r.returncode == 42
    assert b"DIR_CUSTODY_STOP" in r.stdout


def test_offhost_guard_rejects_actual_k137_and_flop_shadow(monkeypatch):
    spec = importlib.util.spec_from_file_location("r1001_host_guard", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod.os, "geteuid", lambda: 10001)
    for marker in ("/opt/tradebot-k137-private", "/opt/flop-shadow"):
        with monkeypatch.context() as patch:
            patch.setattr(mod.Path, "exists", lambda self: str(self) == marker)
            with pytest.raises(mod.Stop, match="LIVE_HOST_REFUSED"):
                mod.guard_offhost()


def test_not_wrongly_claim_source_snapshot_or_oci_retirement(context):
    body = SCRIPT.read_text()
    assert "WRITER_EPOCH_NOT_PROVEN" in body
    assert "ORIGINAL_SOURCE_AUTHENTICITY_NOT_PROVEN" in body
    assert "NOT_RETIREMENT_AUTHORITY" in body
    assert "create_vm" not in body and "ssh " not in body


def test_multi_part_noncompressed_data_matches_byte_stream(context, monkeypatch, capsys):
    # Exercise otherwise expensive 128MB shard boundary with a 1.5MB local limit.
    spec = importlib.util.spec_from_file_location("r1001_fixture", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "SHARD_LIMIT", 1_500_000)
    data = os.urandom(3_700_099)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))
    _, sec, arch = context
    mod.seal(arch, sec)
    parts = sorted(x.name for x in arch.iterdir() if x.name.startswith("part-"))
    assert len(parts) >= 3
    mod.verify(arch, sec)
    out = capsys.readouterr().out
    assert "AUTHENTICATED_CIPHERTEXT_ROUNDTRIP=PASS" in out
    assert f"PLAINTEXT_BYTES={len(data)}" in out


def test_part_swap_fails_closed(context, monkeypatch, capsys):
    spec = importlib.util.spec_from_file_location("r1001_fixture2", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "SHARD_LIMIT", 1_500_000)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(os.urandom(3_700_099))))
    _, sec, arch = context
    mod.seal(arch, sec)
    a, b = arch / "part-0000.bin", arch / "part-0001.bin"
    a_data, b_data = a.read_bytes(), b.read_bytes()
    a.write_bytes(b_data)
    b.write_bytes(a_data)
    with pytest.raises(mod.Stop):
        mod.verify(arch, sec)
