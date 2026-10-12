"""Offline source validation for a preliminary snapshot experiment."""
from pathlib import Path


def test_snapshot_compiles():
    path = Path(__file__).resolve().parents[1] / "packaging/oracle/retirement-low-io-capture-snapshot.py"
    source = path.read_text()
    compile(source, str(path), "exec")
    assert "BATCH_PAGES = 32" in source
