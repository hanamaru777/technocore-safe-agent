"""No network, source guest or K137; mocked SSH handoff and real GCM envelope."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
from types import SimpleNamespace
import zipfile

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "packaging/archive/FLOP_R1003_CLOUDSHELL_SOURCE_WITNESS.py"
spec = importlib.util.spec_from_file_location("r1003", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def make_doc():
    entries = ([{"path": "observer", "type": "dir"},
                {"path": "observer/lobby-capture.sqlite3", "type": "file"},
                {"path": "observer/lobby-capture-service.sqlite3", "type": "file"}]
               + [{"path": f"observer/file-{n:03}", "type": "file"}
                  for n in range(98)]
               + [{"path": "outside-link", "type": "symlink"}])
    for e in entries:
        if e["type"] == "file": e["allocated"] = 512
    return {"allocated_bytes": 100*512, "schema": 1, "kind": "flop-original-full-tree-metadata-v1",
            "source_commit": m.ORIGINAL, "walk_complete": True,
            "writer_epoch_proven": False, "sqlite_coherent_backup_proven": False,
            "files": 100, "symlinks": 1, "directories": 2,
            "entries": entries}


@pytest.fixture
def cloud(tmp_path, monkeypatch):
    monkeypatch.setattr(m.Path, "home", staticmethod(lambda: tmp_path))
    based = tmp_path / ".flop-access-recovery-20261018"
    based.mkdir(mode=0o700)
    (based / "new-operator-ecdsa").write_bytes(b"test public fixture does not contain real key")
    (based / "new-operator-ecdsa").chmod(0o600)
    (based / "known_hosts").write_bytes(b"known host simulated")
    (based / "known_hosts").chmod(0o600)
    return tmp_path


def test_cloudshell_bridge_rejects_actual_k137_and_shadow(monkeypatch):
    monkeypatch.setattr(m.os, "geteuid", lambda: 10001)
    for marker in ("/opt/tradebot-k137-private", "/opt/flop-shadow"):
        with monkeypatch.context() as patch:
            patch.setattr(m.Path, "exists", lambda self: str(self) == marker)
            with pytest.raises(m.Stop, match="CLOUDSHELL_NONROOT_NOT_LIVE_HOST_REQUIRED"):
                m.main()


def test_pinned_remote_command_is_exact_code_only(cloud):
    src, rawcode = m.load_bundle(m.SOURCE, "sourcetmp")
    def fake_ssh(cmd, capture_output, check, timeout):
        assert cmd[0] == "ssh" and cmd[-2] == "ubuntu@" + m.HOST
        assert "StrictHostKeyChecking=yes" in cmd
        assert "IdentitiesOnly=yes" in cmd
        assert "IdentityAgent=none" in cmd
        parsed = shlex.split(cmd[-1])
        assert parsed[:4] == ["sudo", "-n", "/usr/bin/python3", "-c"]
        expression = parsed[4]
        assert "base64.b64decode" in expression
        encoded = expression.split('base64.b64decode("')[1].split('"')[0]
        assert base64.b64decode(encoded) == rawcode
        compile(expression, "<remote-readonly-fixture>", "exec")
        return SimpleNamespace(returncode=0, stdout=json.dumps(make_doc()).encode())
    raw, obj = m.original_manifest(rawcode, executor=fake_ssh)
    assert obj["files"] == 100
    assert b"outside-link" in raw


def test_cannot_claim_source_pass_on_ssh_error(cloud):
    _, rawcode = m.load_bundle(m.SOURCE, "srcfail")
    def fail(cmd, **kwargs):
        return SimpleNamespace(returncode=255, stdout=b'{"fake":"SUCCESS"}', stderr=b"")
    with pytest.raises(m.Stop, match="ORIGINAL_GUEST_MANIFEST_STOP"):
        m.original_manifest(rawcode, executor=fail)
    assert not (cloud / ".flop-r1003-private").exists()


def test_metadata_witness_sealed_verified_and_no_plaintext_disk(cloud, capsys):
    raw = json.dumps(make_doc()).encode()
    m.seal_manifest(raw)
    out = capsys.readouterr().out
    assert "AUTHENTICATED_CIPHERTEXT_ROUNDTRIP=PASS" in out
    assert "APPLICATION_STATE_DATA_NOT_BACKED_UP=YES" in out
    assert "ORIGINAL_WRITER_EPOCH_NOT_PROVEN=YES" in out
    assert "outside-link" not in out
    p = cloud / ".flop-r1003-private"
    keypath = p / "archive-secret"
    z = p / "FLOP_R1003_SOURCE_METADATA_ENCRYPTED.zip"
    assert keypath.stat().st_mode & 0o777 == 0o600
    assert z.stat().st_mode & 0o777 == 0o600
    with zipfile.ZipFile(z) as f:
        assert set(f.namelist()) == {"header.bin", "commit.bin", "part-0000.bin"}
        for name in f.namelist():
            assert raw[:50] not in f.read(name)
    assert not any(x.name == "manifest.json" for x in p.iterdir())
    before = hashlib.sha256(z.read_bytes()).digest()
    with pytest.raises(m.Stop, match="PRIOR_ENCRYPTED_ARCHIVE_EXISTS_STOP"):
        m.seal_manifest(raw)
    assert hashlib.sha256(z.read_bytes()).digest() == before


def test_reject_missing_required_capture_database(cloud):
    _, rawcode = m.load_bundle(m.SOURCE, "src_missing")
    data = make_doc()
    data['entries'][1]['path'] = 'observer/omitted.sqlite3'
    def fake(cmd, **kwargs):
        return SimpleNamespace(returncode=0, stdout=json.dumps(data).encode())
    with pytest.raises(m.Stop, match="MANIFEST_REQUIRED_STATE_STOP"):
        m.original_manifest(rawcode, executor=fake)


def test_embedded_exact_r1001_and_r1002_snapshots():
    a, a_bytes = m.load_bundle(m.SEALED, "sealed_v1")
    b, b_bytes = m.load_bundle(m.SOURCE, "source_v1")
    assert hashlib.sha256(a_bytes).hexdigest() == ("e6b257cd9de1592294f987e9556811ec" + "68b4d32b8b9751a20f3d4bacc8d1eb34")
    assert "FLOP_R1002_SOURCE_MANIFEST_STOP" in b_bytes.decode()
    assert a.HEADER_MAGIC == b"FLOPENV1"


def test_downloaded_encrypted_zip_independent_rehydrate_verify(cloud, capsys):
    # Real encrypted archive bytes are carried via copied ZIP, then decrypted
    # from a different workdir rather than checking only the original objects.
    raw = json.dumps(make_doc()).encode()
    m.seal_manifest(raw)
    zip_path = cloud / ".flop-r1003-private/FLOP_R1003_SOURCE_METADATA_ENCRYPTED.zip"
    backup = cloud / "offsite-copy.zip"
    backup.write_bytes(zip_path.read_bytes())
    restore = cloud / "disarmed-offsite-validation"
    restore.mkdir(mode=0o700)
    with zipfile.ZipFile(backup) as z:
        for name in z.namelist():
            assert name in ("header.bin", "commit.bin", "part-0000.bin")
            p = restore / name
            p.write_bytes(z.read(name))
            p.chmod(0o600)
    crypt, _ = m.load_bundle(m.SEALED, "R1001_restored_copy")
    crypt.verify(restore, cloud / ".flop-r1003-private/archive-secret")
    assert "AUTHENTICATED_CIPHERTEXT_ROUNDTRIP=PASS" in capsys.readouterr().out


def test_independent_zip_copy_cipher_tamper_fails(cloud):
    m.seal_manifest(json.dumps(make_doc()).encode())
    zpath = cloud / ".flop-r1003-private/FLOP_R1003_SOURCE_METADATA_ENCRYPTED.zip"
    restore = cloud / "restored_cipher_invalid"
    restore.mkdir(mode=0o700)
    with zipfile.ZipFile(zpath) as z:
        for name in z.namelist():
            file = restore / name
            b = bytearray(z.read(name))
            if name == "part-0000.bin": b[-1] ^= 0x01
            file.write_bytes(b)
            file.chmod(0o600)
    crypt, _ = m.load_bundle(m.SEALED, "R1001_restored_tamper")
    with pytest.raises(crypt.Stop):
        crypt.verify(restore, cloud / ".flop-r1003-private/archive-secret")
