"""R1055 synthetic, offhost-only dual SQLite image maker regression."""
import importlib.util
import os
from pathlib import Path
import sqlite3

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging/archive/r1055_offhost_two_sqlite_backup.py"
spec = importlib.util.spec_from_file_location("flop_r1055", SOURCE)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def make_db(path, *, valid=True, wal=False):
    conn = sqlite3.connect(str(path))
    if wal:
        conn.execute("PRAGMA journal_mode=WAL")
    if valid:
        conn.execute("CREATE TABLE messages(seq INTEGER PRIMARY KEY, payload TEXT)")
        conn.execute("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT)")
        conn.execute("INSERT INTO messages(seq,payload) VALUES(1,'offline example')")
        conn.execute("INSERT INTO meta(key,value) VALUES('version','1')")
    else:
        conn.execute("CREATE TABLE other(a INTEGER)")
    conn.commit()
    os.chmod(path, 0o600)
    return conn


@pytest.fixture
def source(tmp_path):
    loc = tmp_path / "source"
    loc.mkdir(mode=0o700)
    for name in r.NAMES:
        conn = make_db(loc / name)
        conn.close()
    return loc


def test_real_two_file_online_backup_and_r1005_integrity(source, tmp_path):
    out = tmp_path / "fresh"
    result = r.backup_pair(source, out)
    assert result["image_count"] == 2
    assert result["sql_integrity"] == "PASS"
    assert result["both_database_common_writer_epoch"] == "NOT_PROVEN"
    assert result["all_writers_fenced"] == "NO"
    assert result["original_oci_retirement"] == "STRICT_NO_GO"
    assert set(x.name for x in out.iterdir()) == set(r.NAMES)
    assert all(x["messages"] == 1 for x in result["images"].values())
    for name in r.NAMES:
        assert (out / name).stat().st_mode & 0o077 == 0


def test_wal_source_contains_committed_rows_even_if_wal_open(tmp_path):
    src = tmp_path / "wal-source"
    src.mkdir(mode=0o700)
    open_conn = [make_db(src / name, wal=True) for name in r.NAMES]
    try:
        for conn in open_conn:
            conn.execute("INSERT INTO messages(seq,payload) VALUES(2,'committed WAL')")
            conn.commit()
        result = r.backup_pair(src, tmp_path / "wal-out")
        assert all(x["messages"] == 2 for x in result["images"].values())
        assert result["both_database_common_writer_epoch"] == "NOT_PROVEN"
    finally:
        for conn in open_conn:
            conn.close()


def test_existing_target_never_overwritten(source, tmp_path):
    out = tmp_path / "already"
    out.mkdir(mode=0o700)
    old = out / "hold"
    old.write_text("remain", encoding="utf8")
    with pytest.raises((OSError, r.Stop, r.R1005.Stop)):
        r.backup_pair(source, out)
    assert old.read_text(encoding="utf8") == "remain"


def test_no_follow_source_db_symlink(source, tmp_path):
    item = source / r.NAMES[0]
    other = source / "link-target"
    item.rename(other)
    item.symlink_to(other)
    with pytest.raises(r.Stop, match="SOURCE_UNKNOWN_ENTRY_STOP"):
        r.backup_pair(source, tmp_path / "target")
    assert not (tmp_path / "target").exists()


def test_reject_unknown_source_entry(source, tmp_path):
    (source / "unknown").write_bytes(b"offline fixture")
    with pytest.raises(r.Stop, match="SOURCE_UNKNOWN_ENTRY_STOP"):
        r.backup_pair(source, tmp_path / "target")


def test_reject_nonprivate_source(source, tmp_path):
    os.chmod(source / r.NAMES[0], 0o644)
    with pytest.raises(r.Stop, match="SOURCE_FILE_CUSTODY_STOP"):
        r.backup_pair(source, tmp_path / "target")


def test_missing_second_source_never_creates_target(source, tmp_path):
    (source / r.NAMES[-1]).unlink()
    with pytest.raises(r.Stop, match="SOURCE_TWO_DATABASES_REQUIRED_STOP"):
        r.backup_pair(source, tmp_path / "target")
    assert not (tmp_path / "target").exists()


def test_invalid_second_schema_never_returns_pass(source, tmp_path):
    bad = source / r.NAMES[1]
    bad.unlink()
    c = make_db(bad, valid=False)
    c.close()
    target = tmp_path / "incomplete-quarantine"
    with pytest.raises((r.Stop, r.R1005.Stop)):
        r.backup_pair(source, target)
    assert target.exists()
    assert (target / r.NAMES[0]).exists()
    assert not (target / "accepted").exists()


def test_symlink_ancestor_refused(source, tmp_path):
    shadow = tmp_path / "shadow"
    shadow.symlink_to(source, target_is_directory=True)
    with pytest.raises((OSError, r.Stop, r.R1005.Stop)):
        r.backup_pair(shadow, tmp_path / "out")


def test_source_drift_at_post_verify_is_hard_stop(source, tmp_path, monkeypatch):
    real = r.R1005.verify_image
    calls = []
    def mutate_source_after_integrity(fd, name, digest, **kwargs):
        checked = real(fd, name, digest, **kwargs)
        calls.append(name)
        if len(calls) == 1:
            with sqlite3.connect(str(source / r.NAMES[0])) as db:
                db.execute("INSERT INTO messages(seq,payload) VALUES(3,'drift')")
        return checked
    monkeypatch.setattr(r.R1005, "verify_image", mutate_source_after_integrity)
    with pytest.raises(r.Stop, match="SOURCE_FINAL_DRIFT_STOP"):
        r.backup_pair(source, tmp_path / "not-accepted")


def test_prohibited_live_hosts_guard_is_not_skipped(source, tmp_path, monkeypatch):
    def deny():
        raise r.R1005.Stop("LIVE_HOST_FORBIDDEN")
    monkeypatch.setattr(r.R1005, "live_host_refusal", deny)
    with pytest.raises(r.R1005.Stop, match="LIVE_HOST_FORBIDDEN"):
        r.backup_pair(source, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_no_automation_or_live_signer_surface():
    src = SOURCE.read_text(encoding="utf8")
    for forbidden in ("systemctl", "subprocess.", "requests.", "httpx.",
                      "urllib.request", "vault_seed", "wallet", "ssh ",
                      "os.system", "Popen(", "os.unlink(", "shutil.rmtree"):
        assert forbidden not in src
