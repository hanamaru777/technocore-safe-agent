"""Offline WAL-mode consistency regression for Flop preliminary SQLite copy."""
from pathlib import Path
import importlib.util
import sqlite3
import time


def test_sqlite_backup_includes_committed_wal_rows(tmp_path, monkeypatch):
    source_file = Path(__file__).resolve().parents[1] / "packaging/oracle/retirement-low-io-capture-snapshot.py"
    spec = importlib.util.spec_from_file_location("flop_archive_wal", source_file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    src = tmp_path / "source.sqlite3"
    dest = tmp_path / "snapshot.sqlite3"
    writer = sqlite3.connect(str(src))
    assert writer.execute("pragma journal_mode=WAL").fetchone()[0] == "wal"
    writer.execute("create table t(i integer primary key, value text)")
    writer.executemany("insert into t(value) values(?)", [(str(i),) for i in range(700)])
    writer.commit()
    monkeypatch.setattr(m, "units", lambda: ((), (), ()))
    monkeypatch.setattr(m, "memory_and_pressure", lambda: None)
    monkeypatch.setattr(m.time, "sleep", lambda value: None)
    steps, length = m.copy_db(src, dest, time.monotonic() + 20)
    assert steps >= 1 and length > 0
    restored = sqlite3.connect(str(dest))
    assert restored.execute("pragma quick_check").fetchone()[0] == "ok"
    assert restored.execute("select count(*) from t").fetchone()[0] == 700
    restored.close()
    writer.close()
