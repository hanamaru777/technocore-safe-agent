"""Real byte/SQLite integration fixtures; never connect to any host."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

import pytest
from cryptography.exceptions import InvalidTag

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "packaging/migration/r1066_transfer.py"
spec = importlib.util.spec_from_file_location("r1066_test", FILE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
POSIX = pytest.mark.skipif(os.name != "posix", reason="Linux custody/inode/SQLite integration; authoritative CI")


@pytest.fixture
def work(tmp_path):
    os.chmod(tmp_path, 0o700)
    app, state = tmp_path / "app-source", tmp_path / "state-source"
    for p in (app, state):
        p.mkdir(mode=0o700)
    (app / "binary").write_bytes(bytes(range(256)) * 10000)
    (state / "nonces.json").write_text('{"dummy":1}')
    for name in m.G.DATABASES:
        with sqlite3.connect(state / name) as db:
            db.execute("CREATE TABLE messages(seq INTEGER PRIMARY KEY, text TEXT)")
            db.execute("INSERT INTO messages VALUES (1,'synthetic')")
    return tmp_path, app, state, os.urandom(48)


def archive(work):
    root, app, state, key = work
    out = root / "encrypted"
    m.seal(app, state, out, key, source_head=m.HEAD)
    return out


@POSIX
def test_real_binary_3000_files_links_and_independent_restore(work):
    root, app, state, key = work
    for i in range(3017):
        (app / f"f{i}").write_bytes(str(i).encode())
    (app / "link").symlink_to("binary")
    os.link(app / "binary", app / "linked")
    encrypted = archive(work)
    report = m.restore(encrypted, root / "restore", key, quota=32 * 1024**2)
    assert report["operation"] == "verified" and report["common_sqlite_epoch"] == "unknown"
    assert (root / "restore/app/binary").read_bytes() == (app / "binary").read_bytes()
    assert (root / "restore/app/link").readlink() == Path("binary")
    assert (root / "restore/app/binary").stat().st_ino == (root / "restore/app/linked").stat().st_ino
    assert len(list((root / "restore/app").iterdir())) == 3020
    receipt = json.loads((root / "restore/DISARMED-RESTORE-RECEIPT.json").read_bytes())
    assert receipt["sqlite_cursors"] == [[1, 1], [1, 1]]
    assert receipt["runtime_started"] is False


@POSIX
def test_r1001_independent_format_verifier(work, monkeypatch, capsys):
    out = archive(work)
    monkeypatch.setattr(m.C, "guard_offhost", lambda: None)  # synthetic CI root is not an operator host
    monkeypatch.setattr(m.C, "private_file", lambda _: work[3])
    m.C.verify(out, work[0] / "unused-dummy")
    assert "AUTHENTICATED_CIPHERTEXT_ROUNDTRIP=PASS" in capsys.readouterr().out


@POSIX
@pytest.mark.parametrize("failure", ["key", "tamper", "partial", "quota", "link", "missing_sqlite"])
def test_failure_never_promotes_restore(work, failure):
    root, app, state, key = work
    if failure == "link":
        (app / "external").symlink_to("/etc/ignored")
    if failure == "missing_sqlite":
        (state / m.G.DATABASES[0]).unlink()  # dummy fixture only
    out = archive(work)
    if failure == "tamper":
        p = out / "part-0000.bin"
        data = bytearray(p.read_bytes()); data[-1] ^= 1; p.write_bytes(data)
    if failure == "partial":
        (out / "commit.bin").unlink()
    target = root / "restore"
    with pytest.raises((m.Stop, m.C.Stop, InvalidTag, OSError)):
        m.restore(out, target, os.urandom(48) if failure == "key" else key,
                  quota=1 if failure == "quota" else 32 * 1024**2)
    assert not (target / "DISARMED-RESTORE-RECEIPT.json").exists()
    if failure != "missing_sqlite":
        assert not target.exists()


@POSIX
def test_ciphertext_resume_rechecks_partial_and_completed_bytes(work):
    out = archive(work)
    dst = work[0] / "received"
    dst.mkdir(mode=0o700)
    data = (out / "part-0000.bin").read_bytes()
    (dst / "part-0000.bin.partial").write_bytes(data[:111])
    m.copy_archive(out, dst)
    m.copy_archive(out, dst)  # idempotent completed copy
    assert (dst / "part-0000.bin").read_bytes() == data
    (dst / "part-0000.bin").write_bytes(b"corrupt")
    with pytest.raises(m.Stop):
        m.copy_archive(out, dst)


@POSIX
def test_interrupted_encryption_has_no_commit_and_is_not_reused(work, monkeypatch):
    real = m.pack
    def interrupted(*args):
        yield next(iter(real(*args)))
        raise m.Stop("INTERRUPTED_FIXTURE")
    monkeypatch.setattr(m, "pack", interrupted)
    with pytest.raises(m.Stop):
        archive(work)
    assert not (work[0] / "encrypted/commit.bin").exists()
    with pytest.raises(m.Stop):
        archive(work)


@POSIX
def test_live_wal_copy_integrity_is_not_common_epoch(work):
    root, app, state, key = work
    with sqlite3.connect(state / m.G.DATABASES[0]) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("INSERT INTO messages VALUES(2,'WAL fixture')"); conn.commit()
        out = archive(work)
        report = m.restore(out, root / "restored", key, quota=32 * 1024**2)
        assert report["common_sqlite_epoch"] == "unknown"
        receipt = json.loads((root / "restored/DISARMED-RESTORE-RECEIPT.json").read_bytes())
        assert [2, 2] in receipt["sqlite_cursors"]


@POSIX
def test_wrong_head_space_drift_and_no_overwrite(work, monkeypatch):
    root, app, state, key = work
    with pytest.raises(m.Stop, match="SOURCE_HEAD"):
        m.seal(app, state, root / "bad", key, source_head="wrong")
    actual = m.shutil.disk_usage(root)
    monkeypatch.setattr(m.shutil, "disk_usage", lambda _: actual._replace(free=0))
    with pytest.raises(m.Stop, match="SPACE"):
        archive(work)
    assert not (root / "encrypted").exists()


@POSIX
def test_no_restore_overwrite_or_corrupt_resume(work):
    out = archive(work)
    root = work[0]
    existing = root / "existing"
    existing.mkdir(mode=0o700)
    (existing / "keep").write_bytes(b"original fixture")
    with pytest.raises(m.Stop):
        m.restore(out, existing, work[3], quota=32 * 1024**2)
    assert (existing / "keep").read_bytes() == b"original fixture"
    with pytest.raises(m.Stop, match="RESTORE_SCOPE"):
        m.restore(out, out / "nested", work[3], quota=32 * 1024**2)
    assert not (out / "nested").exists()
    destination = root / "transfer"
    destination.mkdir(mode=0o700)
    (destination / "part-0000.bin.partial").write_bytes(b"wrong-prefix")
    with pytest.raises(m.Stop, match="RESUME_PREFIX"):
        m.copy_archive(out, destination)
    assert not (destination / "commit.bin").exists()


@POSIX
def test_changed_source_cannot_commit_archive(work, monkeypatch):
    original = m.pack
    def changed(roots, manifest, identities):
        iterator = iter(original(roots, manifest, identities))
        yield next(iterator)
        (work[1] / "binary").write_bytes(b"changed fixture")
        yield from iterator
    monkeypatch.setattr(m, "pack", changed)
    with pytest.raises(m.Stop, match="SOURCE_DRIFT"):
        archive(work)
    assert not (work[0] / "encrypted/commit.bin").exists()


def test_live_scope_and_restorer_permissions_fail_closed(tmp_path):
    with pytest.raises((m.Stop, OSError)):
        m.offline_source(Path("/var/lib/technocore-safe-agent"))
    if os.name != "posix":
        with pytest.raises(m.Stop, match="WINDOWS_ACL"):
            m.private_dir(tmp_path)


def test_reused_cipher_source_git_blob_is_exact():
    raw = FILE.with_name("r1066_sealed_dependency.py").read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == "f52bcea342cd5a08e7a0e9383d587404416d4785"


def test_windows_owner_entrypoint_no_secret_or_remote_action():
    script = FILE.with_name("r1066_owner_workflow.ps1")
    text = script.read_text()
    assert "K137_INDEPENDENT_ENROLLMENT_REQUIRED" in text
    assert "StrictHostKeyChecking=yes" in text
    assert "Invoke-Expression" not in text
    if os.name == "nt":
        p = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(script)],
                           capture_output=True, timeout=20)
        assert p.returncode == 42 and p.stderr == b""
        report = json.loads(p.stdout)
        assert report["operation"] == "blocked" and report["oci_retirement"] == "STRICT_NO_GO"


def test_no_write_authority_or_production_approval_from_reports():
    result = m.summary("archive", files=3017, bytes_count=20 * 1024**3)
    assert result["source_authority"] == "unknown" and result["cutover"] == "blocked"
    assert m.G.evaluate({"schema_version": 1, "packets": []}, now=2000000000)["cutover"] == "NO_GO"



@POSIX
def test_r1081_real_census_beyond_old_25000_object_ceiling(work):
    """Actual local source traversal: measured OCI 30682 > obsolete 25000."""
    root, app, state, _ = work
    # Keep the fixture small in bytes; the case is metadata cardinality.
    for i in range(25001):
        (app / f"asset{i:05d}").touch()
    roots, manifest, identities = m.census(app, state, m.HEAD)
    assert m.MAX_ARCHIVE_ENTRIES == 100000
    assert m.MAX_ARCHIVE_DEPTH == 48
    assert len(manifest["entries"]) > 25000
    assert len(manifest["entries"]) == len(identities)
    assert {row["path"] for row in manifest["entries"]} == set(identities)
    assert "state" in roots and "app" in roots
    assert len(m.G.canonical(manifest)) <= m.MAX_MANIFEST


@POSIX
def test_r1081_archive_census_still_stops_at_finite_entry_and_depth_limits(work, monkeypatch):
    root, app, state, _ = work
    monkeypatch.setattr(m, "MAX_ARCHIVE_ENTRIES", 4)
    with pytest.raises(m.Stop, match="CENSUS_BOUND"):
        m.census(app, state, m.HEAD)
    monkeypatch.setattr(m, "MAX_ARCHIVE_ENTRIES", 100000)
    monkeypatch.setattr(m, "MAX_ARCHIVE_DEPTH", 0)
    with pytest.raises(m.Stop, match="CENSUS_BOUND"):
        m.census(app, state, m.HEAD)


def test_r1081_no_production_writer_or_plaintext_backup_authority():
    text=FILE.read_text()
    assert "MAX_ARCHIVE_ENTRIES = 100000" in text
    assert "MAX_ARCHIVE_DEPTH = 48" in text
    assert "len(rows) < MAX_ARCHIVE_ENTRIES" in text
    assert 'len(m["entries"]) <= MAX_ARCHIVE_ENTRIES' in text
    assert "PROVISIONAL_UNFENCED" in text
    assert "LIVE_SOURCE_FENCE_UNPROVEN" in text
