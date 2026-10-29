"""R1096 does not inspect TradeBot and classifies only FLOP paths."""
import importlib.util
from pathlib import Path
import time
import pytest

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "packaging/migration/r1096_k137_flop_storage_readonly.py"
spec = importlib.util.spec_from_file_location("r1096", FILE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def test_flop_only_sizes_and_zero_mutation(tmp_path):
    d = tmp_path / "flop"
    d.mkdir()
    (d / "state.db").write_bytes(b"protected")
    (d / "old.tar").write_bytes(b"x" * 4096)
    (d / "unused.tmp").write_bytes(b"x" * 2048)
    x = mod.scan(d, time.monotonic())
    assert x["exists"] and x["regular_files"] == 3 and x["objects"] == 4
    assert x["classes"]["ARCHIVE_UNVERIFIED"]["files"] == 1
    assert x["classes"]["DATABASE_PROTECTED"]["files"] == 1
    assert len(x["largest"]) == 3
    assert (d / "old.tar").exists() and (d / "state.db").read_bytes() == b"protected"

def test_links_not_followed(tmp_path):
    root = tmp_path / "scope"
    root.mkdir()
    outside = tmp_path / "tradebot"
    outside.mkdir()
    (outside / "private.db").write_bytes(b"private")
    (root / "link").symlink_to(outside, target_is_directory=True)
    result = mod.scan(root, time.monotonic())
    assert result["symlinks"] == 1 and result["regular_files"] == 0
    assert (outside / "private.db").read_bytes() == b"private"

def test_exact_protected_names():
    assert mod.SHADOW == Path("/opt/flop-shadow")
    assert mod.LANDING == Path("/var/lib/flop-migration-r1066")
    assert mod.PINNED_RELEASE.name == "3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e"
    assert mod.category(Path("something.sqlite3-wal")) == "DATABASE_PROTECTED"
    assert mod.category(Path("last.jsonl")) == "LOG_OR_HISTORY_PROTECTED"
