"""Offline SQLite backup integration using disposable temporary files only."""
import importlib.util
import sqlite3
import time
from pathlib import Path


def _load():
    path = Path(__file__).resolve().parents[1] / "packaging/oracle/retirement-low-io-capture-snapshot.py"
    spec = importlib.util.spec_from_file_location("capture_prelim_draft", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_paged_backup_restores_exact_rows(tmp_path, monkeypatch):
    m = _load()
    source = tmp_path / "source.sqlite3"
    target = tmp_path / "target.sqlite3"
    db = sqlite3.connect(str(source))
    db.execute("create table events (id integer primary key, payload text)")
    db.executemany("insert into events(payload) values (?)", [(str(x),) for x in range(400)])
    db.commit()
    db.close()
    monkeypatch.setattr(m, "memory_and_pressure", lambda: None)
    monkeypatch.setattr(m, "units", lambda: ((), (), ()))
    monkeypatch.setattr(m.time, "sleep", lambda n: None)
    iterations, size = m.copy_db(source, target, time.monotonic() + 20)
    assert iterations > 0 and size > 0
    restored = sqlite3.connect(str(target))
    assert restored.execute("pragma quick_check").fetchone()[0] == "ok"
    assert restored.execute("select count(*) from events").fetchone()[0] == 400
    restored.close()
