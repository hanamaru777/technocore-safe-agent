"""R1066: real ciphertext-only stream and quarantine synthetic filesystem tests."""
from __future__ import annotations
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import struct
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "packaging/migration/r1066_ciphertext_pipe.py"
spec = importlib.util.spec_from_file_location("r1066_cipher_pipe_test", FILE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
LINUX = pytest.mark.skipif(os.name != "posix", reason="POSIX owner, O_NOFOLLOW and mode guards")

@pytest.fixture
def paths(tmp_path):
    os.chmod(tmp_path, 0o700)
    src = tmp_path / "source"
    src.mkdir(mode=0o700)
    landing = tmp_path / "landing"
    landing.mkdir(mode=0o700)
    aid = bytes([0x36]) * 16
    archive_id = aid.hex()
    header = struct.pack(">8s16s16s4sII", b"FLOPENV1", b"s"*16, aid,
                         b"n"*4, 600000, m.CHUNK)
    files = {
        "header.bin": header,
        "part-0000.bin": b"encrypted-fixture-" * 2345 + bytes(range(256)),
        "commit.bin": b"authenticated-commit-only-in-actual-r1001-format",
    }
    for name, payload in files.items():
        path = src / name
        path.write_bytes(payload)
        path.chmod(0o600)
    return src, landing, archive_id, files

def get_sha(data):
    return hashlib.sha256(data).hexdigest()

def payload_from_source(src, aid, name, content, offset=0):
    stream = io.BytesIO()
    m.send_part(src, name, len(content), get_sha(content), offset, stream, archive_id=aid)
    assert stream.getvalue() == content[offset:]
    return stream.getvalue()

def receive(landing, aid, name, content, offset=0, prefix_sha=None, binary=None):
    return m.receive_part(landing, aid, name, len(content), get_sha(content),
                          offset, prefix_sha or get_sha(content[:offset]),
                          io.BytesIO(content[offset:] if binary is None else binary))

@LINUX
def test_real_ciphertext_pipe_full_archive_quarantine_no_restore(paths):
    src, landing, aid, files = paths
    report = m.init(landing, aid)
    assert report["oci_retirement"] == "STRICT_NO_GO"
    for name in ("header.bin", "part-0000.bin", "commit.bin"):
        value = files[name]
        binary = payload_from_source(src, aid, name, value)
        result = receive(landing, aid, name, value, binary=binary)
        assert result["operation"] == "CIPHERTEXT_STAGED_ONLY"
        assert result["live_restore"] == "NOT_PERFORMED"
        assert result["cutover"] == "NO_GO"
        assert result["oci_retirement"] == "STRICT_NO_GO"
        p = landing / "incoming" / aid / name
        assert p.read_bytes() == value and stat.S_IMODE(p.stat().st_mode) == 0o600
        assert m.status(landing, aid, name) == {
            "state":"COMPLETE", "offset":len(value), "sha256":get_sha(value)}
    assert not any((landing / "incoming" / aid).glob("*.partial"))
    assert m.init(landing, aid)["operation"] == "CIPHERTEXT_QUARANTINE_ONLY"

@LINUX
def test_resume_ciphertext_from_matching_prefix(paths):
    src, landing, aid, files = paths
    m.init(landing, aid)
    payload = files["part-0000.bin"]
    mid = len(payload) // 2
    partial = landing / "incoming" / aid / "part-0000.bin.partial"
    partial.write_bytes(payload[:mid]); partial.chmod(0o600)
    status = m.status(landing, aid, "part-0000.bin")
    assert status == {"state":"PARTIAL", "offset":mid, "sha256":get_sha(payload[:mid])}
    remaining = payload_from_source(src, aid, "part-0000.bin", payload, mid)
    receipt = m.receive_part(landing, aid, "part-0000.bin",len(payload),get_sha(payload),
                             mid,status["sha256"],io.BytesIO(remaining))
    assert receipt["bytes"] == len(payload)
    assert (landing / "incoming" / aid / "part-0000.bin").read_bytes() == payload

@LINUX
def test_zero_length_interrupted_partial_is_safe_to_resume(paths):
    src, landing, aid, files = paths
    m.init(landing, aid)
    partial = landing / "incoming" / aid / "part-0000.bin.partial"
    partial.touch(mode=0o600)
    s = m.status(landing, aid, "part-0000.bin")
    assert s == {"state":"PARTIAL", "offset":0, "sha256":get_sha(b"")}
    result = receive(landing, aid, "part-0000.bin", files["part-0000.bin"])
    assert result["operation"] == "CIPHERTEXT_STAGED_ONLY"

@LINUX
@pytest.mark.parametrize("mode", ["prefix", "truncated", "oversized", "wrong_digest",
                                  "wrong_offset", "wrong_permission", "outside_symlink"])
def test_attacker_or_interrupted_copy_cannot_commit(paths, mode):
    src, landing, aid, files = paths
    m.init(landing, aid)
    value = files["part-0000.bin"]
    root = landing / "incoming" / aid
    partial = root / "part-0000.bin.partial"
    offset = 0
    prefix = get_sha(b"")
    binary = value
    digest = get_sha(value)
    if mode in ("prefix", "wrong_offset", "wrong_permission"):
        partial.write_bytes(value[:99]); partial.chmod(0o600)
        offset = 99
        prefix = get_sha(value[:99])
        binary = value[99:]
    if mode == "prefix": prefix = get_sha(b"wrong")
    if mode == "truncated": binary = value[:-2]
    if mode == "oversized": binary = value + b"X"
    if mode == "wrong_digest": digest = get_sha(b"wrong")
    if mode == "wrong_offset": offset = 100
    if mode == "wrong_permission": partial.chmod(0o644)
    if mode == "outside_symlink":
        partial.symlink_to(src / "part-0000.bin")
    with pytest.raises((m.Stop, OSError)):
        m.receive_part(landing,aid,"part-0000.bin",len(value),digest,offset,prefix,
                       io.BytesIO(binary))
    assert not (root / "part-0000.bin").exists()
    assert (src / "part-0000.bin").read_bytes() == value

@LINUX
def test_unknown_ciphertext_or_linked_source_rejected(paths):
    src, landing, aid, files = paths
    m.init(landing, aid)
    for name in ("../part-0000.bin", "other.bin", "/abs", "part-99999.bin"):
        with pytest.raises(m.Stop):
            m.status(landing, aid, name)
    with pytest.raises(m.Stop):
        m.init(landing, "../wrong")
    entry = src / "part-0000.bin"
    extra = src / "linked"
    os.link(entry, extra)
    with pytest.raises(m.Stop, match="FILE_CUSTODY"):
        payload_from_source(src, aid, "part-0000.bin", files["part-0000.bin"])

@LINUX
def test_absent_root_and_existing_completed_ciphertext_never_overwritten(paths):
    src, landing, aid, files = paths
    with pytest.raises((m.Stop,OSError)):
        m.status(landing, aid, "header.bin")
    m.init(landing, aid)
    original = files["part-0000.bin"]
    receive(landing, aid, "part-0000.bin", original)
    with pytest.raises(m.Stop,match="ALREADY_COMPLETE"):
        receive(landing, aid, "part-0000.bin", original)
    assert (landing/"incoming"/aid/"part-0000.bin").read_bytes() == original

@LINUX
def test_commit_is_staged_last(paths):
    src, landing, aid, files = paths
    m.init(landing, aid)
    with pytest.raises(m.Stop,match="COMMIT_ORDER_STOP"):
        receive(landing, aid, "commit.bin", files["commit.bin"])
    root = landing / "incoming" / aid
    assert not (root/"commit.bin").exists()
    receive(landing, aid, "header.bin",files["header.bin"])
    with pytest.raises(m.Stop,match="COMMIT_ORDER_STOP"):
        receive(landing, aid, "commit.bin", files["commit.bin"])
    receive(landing, aid, "part-0000.bin",files["part-0000.bin"])
    receive(landing, aid, "commit.bin", files["commit.bin"])

@LINUX
def test_header_wrong_archive_identity_never_staged(paths):
    src, landing, aid, files = paths
    other = bytes([0x35])*16
    wrongid = other.hex()
    m.init(landing, wrongid)
    value = files["header.bin"]
    with pytest.raises(m.Stop, match="ARCHIVE_ID_MISMATCH"):
        receive(landing, wrongid, "header.bin", value)
    assert not (landing/"incoming"/wrongid/"header.bin").exists()
    with pytest.raises(m.Stop,match="ARCHIVE_ID_MISMATCH"):
        payload_from_source(src, wrongid, "part-0000.bin", files["part-0000.bin"])

@LINUX
def test_sender_rejects_incomplete_archive_source(paths):
    src, landing, aid, files = paths
    (src/"commit.bin").unlink()
    with pytest.raises(m.Stop,match="ARCHIVE_UNCOMMITTED"):
        payload_from_source(src, aid, "part-0000.bin", files["part-0000.bin"])

def test_ciphertext_pipe_has_no_secrets_production_unlock_or_generic_destination():
    source = FILE.read_text()
    assert 'LANDING = Path("/var/lib/flop-migration-r1066")' in source
    assert "STRICT_NO_GO" in source
    assert "NOT_PERFORMED" in source
    assert "InstancePrincipalsSecurityTokenSigner" not in source
    for marker in ("--password", "--key", "--host", "--command", "ssh-keyscan", "cutover=GO", "shell=True"):
        assert marker not in source
